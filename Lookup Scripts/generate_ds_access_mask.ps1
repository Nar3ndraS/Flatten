# =============================================================================
# generate_ds_access_mask.ps1 — Generate DS object access mask lookup file
#
# Generates a lookup of Directory Services access right bit masks used in
# Event ID 4662 (An operation was performed on an object).
#
# These are the standard DS access rights defined in the Windows SDK and
# Active Directory documentation. Unlike msobjs.dll, these are not extractable
# from a DLL at runtime — they are fixed ADS_RIGHTS_ENUM constants defined
# by Microsoft for DS access control.
#
# Usage:
#   .\generate_ds_access_mask.ps1
#
# Recommended: Run on a Domain Controller
#
# Output:
#   ds_access_mask.json — array of { Mask, Description }
#
# Example output entry:
#   { "Mask": "0x100", "Description": "Control Access" }
#
# Reference:
#   https://learn.microsoft.com/en-us/windows/win32/api/iads/ne-iads-ads_rights_enum
# =============================================================================

# DS-specific access rights (ADS_RIGHTS_ENUM)
# These are fixed constants — not extractable from a DLL
$DSAccessRights = @(
    [PSCustomObject]@{ Mask = "0x1";        Description = "List Contents" },
    [PSCustomObject]@{ Mask = "0x2";        Description = "List Object" },
    [PSCustomObject]@{ Mask = "0x4";        Description = "Add/Delete Self" },
    [PSCustomObject]@{ Mask = "0x8";        Description = "Read Property" },
    [PSCustomObject]@{ Mask = "0x10";       Description = "Write Property" },
    [PSCustomObject]@{ Mask = "0x20";       Description = "Delete Tree" },
    [PSCustomObject]@{ Mask = "0x40";       Description = "List Object" },
    [PSCustomObject]@{ Mask = "0x100";      Description = "Control Access" },
    [PSCustomObject]@{ Mask = "0x10000";    Description = "Delete" },
    [PSCustomObject]@{ Mask = "0x20000";    Description = "Read Control" },
    [PSCustomObject]@{ Mask = "0x40000";    Description = "Write DACL" },
    [PSCustomObject]@{ Mask = "0x80000";    Description = "Write Owner" },
    [PSCustomObject]@{ Mask = "0x100000";   Description = "Synchronize" },
    [PSCustomObject]@{ Mask = "0x1000000";  Description = "Access System Security" },
    [PSCustomObject]@{ Mask = "0x2000000";  Description = "Maximum Allowed" },
    [PSCustomObject]@{ Mask = "0x10000000"; Description = "Generic All" },
    [PSCustomObject]@{ Mask = "0x20000000"; Description = "Generic Execute" },
    [PSCustomObject]@{ Mask = "0x40000000"; Description = "Generic Write" },
    [PSCustomObject]@{ Mask = "0x80000000"; Description = "Generic Read" }
)

# Export
$DSAccessRights |
    ConvertTo-Json -Depth 2 |
    Out-File ".\lookups\ds_access_mask.json" -Encoding utf8

Write-Host ""
Write-Host "Exported $($DSAccessRights.Count) DS access mask entries to lookups\ds_access_mask.json"
