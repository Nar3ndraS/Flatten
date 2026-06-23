# =============================================================================
# generate_ad_guids.ps1 — Generate AD schema + extended rights GUID lookup
#
# Pulls all resolvable GUIDs from Active Directory and exports them as a
# lookup file used by the evtx pipeline to enrich Event ID 4662 (operation
# performed on a DS object).
#
# GUIDs appear in these EventData fields for Event ID 4662:
#   - Properties  — the attribute or extended right being accessed
#   - ObjectType  — the object class being accessed
#
# Sources:
#   1. Schema partition  — object classes (ClassSchema) and attributes (AttributeSchema)
#   2. Extended Rights   — controlAccessRight objects (DCSync, replication, etc.)
#
# Usage:
#   .\generate_ad_guids.ps1
#
# Recommended: Run on a Domain Controller for full coverage
#   (Schema partition and Extended Rights are DC-only)
#
# Output:
#   ad_guids.json — array of { GUID, Name, Type }
#
# Example output entries:
#   { "GUID": "{bf967aba-0de6-11d0-a285-00aa003049e2}", "Name": "user",              "Type": "ClassSchema"   }
#   { "GUID": "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}", "Name": "DS-Replication-Get-Changes", "Type": "ExtendedRight" }
# =============================================================================

Import-Module ActiveDirectory -ErrorAction Stop

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

# ── 1. Schema partition — ClassSchema and AttributeSchema ─────────────────────
Write-Host "Pulling schema objects (ClassSchema + AttributeSchema)..."

$SchemaPath = (Get-ADRootDSE).schemaNamingContext

$SchemaObjects = Get-ADObject `
    -SearchBase $SchemaPath `
    -LDAPFilter "(|(objectClass=classSchema)(objectClass=attributeSchema))" `
    -Properties schemaIDGUID, lDAPDisplayName, objectClass `
    -ErrorAction SilentlyContinue

foreach ($obj in $SchemaObjects) {
    if ($null -eq $obj.schemaIDGUID) { continue }

    # Convert byte array GUID to standard GUID string format
    try {
        $guid = [System.Guid]::new([byte[]]$obj.schemaIDGUID)
        $guidStr = "{$($guid.ToString())}"
    } catch {
        continue
    }

    $type = if ($obj.objectClass -contains "classSchema") { "ClassSchema" } else { "AttributeSchema" }

    $Results.Add([PSCustomObject]@{
        GUID = $guidStr
        Name = $obj.lDAPDisplayName
        Type = $type
    })
}

Write-Host "  Found $($Results.Count) schema objects"

# ── 2. Extended Rights — controlAccessRight ───────────────────────────────────
Write-Host "Pulling extended rights (controlAccessRight)..."

$ConfigPath     = (Get-ADRootDSE).configurationNamingContext
$ExtRightsPath  = "CN=Extended-Rights,$ConfigPath"

$ExtendedRights = Get-ADObject `
    -SearchBase $ExtRightsPath `
    -LDAPFilter "(objectClass=controlAccessRight)" `
    -Properties rightsGuid, displayName, cn `
    -ErrorAction SilentlyContinue

$extCount = 0
foreach ($right in $ExtendedRights) {
    if ($null -eq $right.rightsGuid) { continue }

    # rightsGuid is already a string in {GUID} format on most DCs
    # Normalise to ensure consistent casing and braces
    try {
        $guid = [System.Guid]::new($right.rightsGuid.ToString())
        $guidStr = "{$($guid.ToString())}"
    } catch {
        continue
    }

    # Prefer displayName, fall back to cn
    $name = if (-not [string]::IsNullOrWhiteSpace($right.displayName)) {
        $right.displayName
    } else {
        $right.cn
    }

    $Results.Add([PSCustomObject]@{
        GUID = $guidStr
        Name = $name
        Type = "ExtendedRight"
    })
    $extCount++
}

Write-Host "  Found $extCount extended rights"

# ── Deduplicate on GUID ───────────────────────────────────────────────────────
$Results = $Results |
    Sort-Object GUID -Unique

# ── Export ────────────────────────────────────────────────────────────────────
$Results |
    ConvertTo-Json -Depth 2 |
    Out-File ".\lookups\ad_guids.json" -Encoding utf8

Write-Host ""
Write-Host "Exported $($Results.Count) total GUID entries to lookups\ad_guids.json"
