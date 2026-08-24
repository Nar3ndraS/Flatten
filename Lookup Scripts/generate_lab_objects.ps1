# =============================================================================
# generate_lab_objects.ps1 — Generate computer + user object instance GUID lookup
#
# LAB USE ONLY. Pulls ObjectGUID for every computer and user account object in
# the domain and exports them for resolving Event ID 4662 ObjectName references
# (%{guid} format) to a friendly account name.
#
# This is intentionally separate from generate_domain_objects.ps1, which only
# covers containers/OUs. Enumerating every user/computer account does not scale
# to production domains (thousands of entries, changes daily) but is fine for
# a lab where the object count is small and stable.
#
# Usage:
#   .\generate_lab_objects.ps1
#
# Optional:
#   .\generate_lab_objects.ps1 -IncludeDisabled
#       Also include disabled accounts (excluded by default to keep noise down)
#
#   .\generate_lab_objects.ps1 -SearchBase "OU=Corp,DC=blues,DC=lab"
#       Limit to a specific OU instead of the whole domain
#
# Recommended: Run on a Domain Controller
#
# Output:
#   lookups\lab_objects.json — array of { GUID, Name, Type }
#
# Example output entries:
#   { "GUID": "{3f2b1a9c-...}", "Name": "WORKSTATION1$",  "Type": "ComputerObject" }
#   { "GUID": "{7d8e9f01-...}", "Name": "jsmith",          "Type": "UserObject"     }
#
# NOTE: merge this file's contents into ad_guids.json (or load it alongside
# domain_objects.json) so enricher.py's ad_guids_map picks these up for the
# ObjectName field on Event ID 4662. See README for the --domain-objects /
# --ad-guids flags in main.py.
# =============================================================================

[CmdletBinding()]
param(
    [switch]$IncludeDisabled,
    [string]$SearchBase = ""
)

Import-Module ActiveDirectory -ErrorAction Stop

$DomainDN = if ($SearchBase) { $SearchBase } else { (Get-ADDomain).DistinguishedName }
$Results  = [System.Collections.Generic.List[PSCustomObject]]::new()

# ── 1. Computer objects ────────────────────────────────────────────────────
Write-Host "Pulling computer objects..."

$CompFilter = if ($IncludeDisabled) { "*" } else { "Enabled -eq `$true" }

$Computers = Get-ADComputer `
    -Filter $CompFilter `
    -SearchBase $DomainDN `
    -Properties ObjectGUID, SamAccountName `
    -ErrorAction SilentlyContinue

$compCount = 0
foreach ($comp in $Computers) {
    if ($null -eq $comp.ObjectGUID) { continue }

    $guidStr = "{$($comp.ObjectGUID.ToString())}"

    $Results.Add([PSCustomObject]@{
        GUID = $guidStr
        Name = $comp.SamAccountName
        Type = "ComputerObject"
    })
    $compCount++
}

Write-Host "  Found $compCount computer objects"

# ── 2. User objects ─────────────────────────────────────────────────────────
Write-Host "Pulling user objects..."

$UserFilter = if ($IncludeDisabled) { "*" } else { "Enabled -eq `$true" }

$Users = Get-ADUser `
    -Filter $UserFilter `
    -SearchBase $DomainDN `
    -Properties ObjectGUID, SamAccountName `
    -ErrorAction SilentlyContinue

$userCount = 0
foreach ($user in $Users) {
    if ($null -eq $user.ObjectGUID) { continue }

    $guidStr = "{$($user.ObjectGUID.ToString())}"

    $Results.Add([PSCustomObject]@{
        GUID = $guidStr
        Name = $user.SamAccountName
        Type = "UserObject"
    })
    $userCount++
}

Write-Host "  Found $userCount user objects"

# ── Deduplicate on GUID ───────────────────────────────────────────────────────
$Results = $Results |
    Sort-Object GUID -Unique

# ── Export ────────────────────────────────────────────────────────────────────
New-Item -ItemType Directory -Name "lookups" -Force | Out-Null

$Results |
    ConvertTo-Json -Depth 2 |
    Out-File ".\lookups\lab_objects.json" -Encoding utf8

Write-Host ""
Write-Host "Exported $($Results.Count) total lab object entries to lookups\lab_objects.json"
Write-Host "  ComputerObject : $compCount"
Write-Host "  UserObject     : $userCount"

if (-not $IncludeDisabled) {
    Write-Host ""
    Write-Host "Disabled accounts were skipped. Re-run with -IncludeDisabled to include them." -ForegroundColor Yellow
}
