# =============================================================================
# generate_domain_objects.ps1 — Generate domain object GUID lookup file
#
# Pulls GUIDs for domain objects that appear in Event ID 4662 ObjectName field
# as %{guid} references. These are instance-level GUIDs specific to your
# environment — not found in schema or extended rights partitions.
#
# Sources:
#   1. Well-known containers — Domain Root, Users, Computers, Builtin,
#      System, Domain Controllers OU, Managed Service Accounts, Keys, etc.
#   2. All OUs and containers in the domain
#
# Usage:
#   .\generate_domain_objects.ps1
#
# Recommended: Run on a Domain Controller
#
# Output:
#   domain_objects.json — array of { GUID, Name, Type }
#
# Example output entry:
#   { "GUID": "{5206e6c4-9bf2-48cf-96fd-aa43f219c623}", "Name": "DC=blues,DC=lab", "Type": "DomainObject" }
# =============================================================================

Import-Module ActiveDirectory -ErrorAction Stop

$DomainDN   = (Get-ADDomain).DistinguishedName
$DomainFQDN = (Get-ADDomain).DNSRoot
$Results    = [System.Collections.Generic.List[PSCustomObject]]::new()

# Helper — safely get an AD object by DN and add to results
function Add-ObjectByDN {
    param(
        [string]$DN,
        [string]$FriendlyName,
        [string]$Type
    )
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
Add-ObjectByDN -DN $DomainDN -FriendlyName $DomainFQDN -Type "DomainRoot"

# Standard well-known containers
$WellKnown = @(
    @{ DN = "CN=Users,$DomainDN";                          Name = "CN=Users";                          Type = "Container" },
    @{ DN = "CN=Computers,$DomainDN";                      Name = "CN=Computers";                      Type = "Container" },
    @{ DN = "CN=Builtin,$DomainDN";                        Name = "CN=Builtin";                        Type = "Container" },
    @{ DN = "CN=System,$DomainDN";                         Name = "CN=System";                         Type = "Container" },
    @{ DN = "CN=ForeignSecurityPrincipals,$DomainDN";      Name = "CN=ForeignSecurityPrincipals";      Type = "Container" },
    @{ DN = "CN=Managed Service Accounts,$DomainDN";       Name = "CN=Managed Service Accounts";       Type = "Container" },
    @{ DN = "CN=Keys,$DomainDN";                           Name = "CN=Keys";                           Type = "Container" },
    @{ DN = "CN=Program Data,$DomainDN";                   Name = "CN=Program Data";                   Type = "Container" },
    @{ DN = "CN=NTDS Quotas,$DomainDN";                    Name = "CN=NTDS Quotas";                    Type = "Container" },
    @{ DN = "CN=Infrastructure,$DomainDN";                 Name = "CN=Infrastructure";                 Type = "Container" },
    @{ DN = "CN=LostAndFound,$DomainDN";                   Name = "CN=LostAndFound";                   Type = "Container" },
    @{ DN = "OU=Domain Controllers,$DomainDN";             Name = "OU=Domain Controllers";             Type = "OU"        }
)

foreach ($entry in $WellKnown) {
    Add-ObjectByDN -DN $entry.DN -FriendlyName $entry.Name -Type $entry.Type
}

Write-Host "  Found $($Results.Count) well-known containers"

# ── 2. All OUs in the domain ──────────────────────────────────────────────────
Write-Host "Pulling all OUs..."

$OUs = Get-ADOrganizationalUnit `
    -Filter * `
    -SearchBase $DomainDN `
    -Properties ObjectGUID, DistinguishedName `
    -ErrorAction SilentlyContinue

$ouCount = 0
foreach ($ou in $OUs) {
    $guidStr = "{$($ou.ObjectGUID.ToString())}"

    # Skip if already added (e.g. Domain Controllers OU)
    if ($Results | Where-Object { $_.GUID -eq $guidStr }) { continue }

    $Results.Add([PSCustomObject]@{
        GUID = $guidStr
        Name = $ou.DistinguishedName
        Type = "OU"
    })
    $ouCount++
}

Write-Host "  Found $ouCount OUs"

# ── 3. All containers in the domain ──────────────────────────────────────────
Write-Host "Pulling all containers..."

$Containers = Get-ADObject `
    -Filter { objectClass -eq "container" } `
    -SearchBase $DomainDN `
    -Properties ObjectGUID, DistinguishedName, Name `
    -ErrorAction SilentlyContinue

$containerCount = 0
foreach ($container in $Containers) {
    $guidStr = "{$($container.ObjectGUID.ToString())}"

    # Skip if already added
    if ($Results | Where-Object { $_.GUID -eq $guidStr }) { continue }

    $Results.Add([PSCustomObject]@{
        GUID = $guidStr
        Name = $container.DistinguishedName
        Type = "Container"
    })
    $containerCount++
}

Write-Host "  Found $containerCount additional containers"

# ── Deduplicate on GUID ───────────────────────────────────────────────────────
$Results = $Results | Sort-Object GUID -Unique

# ── Export ────────────────────────────────────────────────────────────────────
$Results |
    ConvertTo-Json -Depth 2 |
    Out-File ".\lookups\domain_objects.json" -Encoding utf8

Write-Host ""
Write-Host "Exported $($Results.Count) domain object entries to lookups\domain_objects.json"
