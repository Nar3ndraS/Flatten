# =============================================================================
# generate_domain_objects.ps1 — Generate domain object GUID lookup file
#
# Pulls GUIDs for domain objects that appear in Event ID 4662 ObjectName field
# as %{guid} references. Filters out internal AD system containers that have
# no SOC investigative value.
#
# Sources:
#   1. Well-known containers — Domain Root, Users, Computers, Builtin,
#      Managed Service Accounts, Keys, Domain Controllers OU
#   2. All custom OUs in the domain
#   3. Operationally relevant containers (excludes CN=System and its children)
#
# Usage:
#   .\generate_domain_objects.ps1
#
# Recommended: Run on a Domain Controller
#
# Output:
#   lookups\domain_objects.json — array of { GUID, Name, Type }
# =============================================================================

Import-Module ActiveDirectory -ErrorAction Stop

$DomainDN   = (Get-ADDomain).DistinguishedName
$DomainFQDN = (Get-ADDomain).DNSRoot
$Results    = [System.Collections.Generic.List[PSCustomObject]]::new()

# DN prefixes to skip — internal AD plumbing with no SOC value
$FilteredPrefixes = @(
    "CN=System,$DomainDN",
    "CN=Configuration,$DomainDN",
    "CN=DomainUpdates",
    "CN=Operations",
    "CN=Policies",
    "CN=WinsockServices",
    "CN=RpcServices",
    "CN=MicrosoftDNS",
    "CN=Program Data",
    "CN=NTDS Quotas",
    "CN=Infrastructure",
    "CN=LostAndFound",
    "CN=ForeignSecurityPrincipals"
)

function Should-Skip {
    param([string]$DN)
    foreach ($prefix in $FilteredPrefixes) {
        if ($DN -like "*$prefix*") { return $true }
    }
    return $false
}

function Add-ObjectByDN {
    param(
        [string]$DN,
        [string]$FriendlyName,
        [string]$Type
    )
    if (Should-Skip -DN $DN) { return }
    try {
        $obj = Get-ADObject -Identity $DN -Properties ObjectGUID -ErrorAction Stop
        $guidStr = "{$($obj.ObjectGUID.ToString())}"
        $Results.Add([PSCustomObject]@{
            GUID = $guidStr
            Name = $FriendlyName
            Type = $Type
        })
    } catch {
        Write-Warning "Could not find: $DN"
    }
}

# ── 1. Well-known containers ──────────────────────────────────────────────────
Write-Host "Pulling well-known containers..."

# Domain root
try {
    $root = Get-ADObject -Identity $DomainDN -Properties ObjectGUID
    $Results.Add([PSCustomObject]@{
        GUID = "{$($root.ObjectGUID.ToString())}"
        Name = $DomainFQDN
        Type = "DomainRoot"
    })
} catch {
    Write-Warning "Could not find domain root: $DomainDN"
}

$WellKnown = @(
    @{ DN = "CN=Users,$DomainDN";                    Name = "CN=Users";                    Type = "Container" },
    @{ DN = "CN=Computers,$DomainDN";                Name = "CN=Computers";                Type = "Container" },
    @{ DN = "CN=Builtin,$DomainDN";                  Name = "CN=Builtin";                  Type = "Container" },
    @{ DN = "CN=Managed Service Accounts,$DomainDN"; Name = "CN=Managed Service Accounts"; Type = "Container" },
    @{ DN = "CN=Keys,$DomainDN";                     Name = "CN=Keys";                     Type = "Container" },
    @{ DN = "OU=Domain Controllers,$DomainDN";       Name = "OU=Domain Controllers";       Type = "OU"        }
)

foreach ($entry in $WellKnown) {
    Add-ObjectByDN -DN $entry.DN -FriendlyName $entry.Name -Type $entry.Type
}

Write-Host "  Found $($Results.Count) well-known containers"

# ── 2. All custom OUs ─────────────────────────────────────────────────────────
Write-Host "Pulling custom OUs..."

$OUs = Get-ADOrganizationalUnit `
    -Filter * `
    -SearchBase $DomainDN `
    -Properties ObjectGUID, DistinguishedName `
    -ErrorAction SilentlyContinue

$ouCount = 0
foreach ($ou in $OUs) {
    if (Should-Skip -DN $ou.DistinguishedName) { continue }

    $guidStr = "{$($ou.ObjectGUID.ToString())}"
    if ($Results | Where-Object { $_.GUID -eq $guidStr }) { continue }

    # Use relative path — strip domain suffix for readability
    $relativeName = $ou.DistinguishedName -replace ",DC=.*$", ""

    $Results.Add([PSCustomObject]@{
        GUID = $guidStr
        Name = $relativeName
        Type = "OU"
    })
    $ouCount++
}

Write-Host "  Found $ouCount custom OUs"

# ── 3. Operationally relevant containers (non-system) ─────────────────────────
Write-Host "Pulling operationally relevant containers..."

$Containers = Get-ADObject `
    -Filter { objectClass -eq "container" } `
    -SearchBase $DomainDN `
    -Properties ObjectGUID, DistinguishedName `
    -ErrorAction SilentlyContinue

$containerCount = 0
foreach ($container in $Containers) {
    if (Should-Skip -DN $container.DistinguishedName) { continue }

    $guidStr = "{$($container.ObjectGUID.ToString())}"
    if ($Results | Where-Object { $_.GUID -eq $guidStr }) { continue }

    # Use relative path — strip domain suffix for readability
    $relativeName = $container.DistinguishedName -replace ",DC=.*$", ""

    $Results.Add([PSCustomObject]@{
        GUID = $guidStr
        Name = $relativeName
        Type = "Container"
    })
    $containerCount++
}

Write-Host "  Found $containerCount operationally relevant containers"

# ── Deduplicate on GUID ───────────────────────────────────────────────────────
$Results = $Results | Sort-Object GUID -Unique

# ── Export ────────────────────────────────────────────────────────────────────
New-Item -ItemType Directory -Name "lookups" -Force | Out-Null

$Results |
    ConvertTo-Json -Depth 2 |
    Out-File ".\lookups\domain_objects.json" -Encoding utf8

Write-Host ""
Write-Host "Exported $($Results.Count) domain object entries to lookups\domain_objects.json"
