# =============================================================================
# generate_lookups.ps1 -- Consolidated lookup generation for evtx-pipeline
#
# Replaces:
#   generate_all_message_lookup.ps1   -> Get-MsobjsLookup        (Core)
#   generate_ds_access_mask.ps1       -> Get-DsAccessMaskLookup  (Universal)
#   generate_lookup.ps1               -> Get-SocEventLookup      (Universal)
#   generate_ad_guids.ps1             -> Get-AdGuidsLookup       (Environment)
#   generate_domain_objects.ps1       -> Get-DomainObjectsLookup (Environment)
#   generate_lab_objects.ps1          -> folded into Get-DomainObjectsLookup
#
# Output layout:
#   core\msobjs_lookup.json                       (Core - never runs by default)
#   lookups\universal\universal_ds_access_mask.json
#   lookups\universal\universal_soc_event_lookup.json
#   lookups\environment\environment_ad_guids.json
#   lookups\environment\environment_domain_objects.json
#
# core\master_security_auditing_index_micosoft.json and
# lookups\universal\universal_logon_types.json are static, hand-authored
# files and are never touched by this script.
#
# Behaviour:
#   - Every run OVERWRITES its target file(s). Nothing is merged with
#     previous output. Re-run whenever the environment changes.
#   - If none of -Core / -Universal / -Environment are supplied, the script
#     runs Universal + Environment. Core is opt-in only, ever, because the
#     msobjs DLL walk is slow and rarely needs to be redone.
#   - -SkipCore / -SkipUniversal / -SkipEnvironment take an array of
#     function keys (see the dispatch tables below) to exclude specific
#     lookups from an otherwise-selected group.
#
# Usage:
#   .\generate_lookups.ps1
#   .\generate_lookups.ps1 -Core
#   .\generate_lookups.ps1 -Universal -SkipUniversal SocEventLookup
#   .\generate_lookups.ps1 -Environment -SkipEnvironment DomainObjects
#   .\generate_lookups.ps1 -Core -Universal -Environment
#
# Recommended: run on a Domain Controller for full coverage.
# =============================================================================

[CmdletBinding()]
param(
    [switch]$Core,
    [switch]$Universal,
    [switch]$Environment,

    [ValidateSet("Msobjs")]
    [string[]]$SkipCore = @(),

    [ValidateSet("DsAccessMask", "SocEventLookup")]
    [string[]]$SkipUniversal = @(),

    [ValidateSet("AdGuids", "DomainObjects")]
    [string[]]$SkipEnvironment = @(),

    # Passed through to Get-MsobjsLookup when -Core is used
    [int]$MsobjsMinId = 1000,
    [int]$MsobjsMaxId = 20000,

    # Passed through to Get-DomainObjectsLookup
    [switch]$IncludeDisabledAccounts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RootDir        = Get-Location
$CoreDir        = Join-Path $RootDir "core"
$LookupsDir     = Join-Path $RootDir "lookups"
$UniversalDir   = Join-Path $LookupsDir "universal"
$EnvironmentDir = Join-Path $LookupsDir "environment"


# -- Shared helpers ---------------------------------------------------------

function Write-LookupJson {
    param(
        [Parameter(Mandatory)] [object]$Data,
        [Parameter(Mandatory)] [string]$Path
    )
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $Data | ConvertTo-Json -Depth 3 | Out-File -LiteralPath $Path -Encoding utf8
}


# =============================================================================
# CORE - never runs unless -Core is explicitly passed
# =============================================================================

function Get-MsobjsLookup {
    <#
        Scans message DLLs (msobjs.dll, adtschema.dll, etc.) with FormatMessage()
        to resolve %%#### style codes used throughout Security auditing events.
        Writes: core\msobjs_lookup.json
    #>
    Write-Host "  [Core] Resolving msobjs %% codes ($MsobjsMinId-$MsobjsMaxId)..."

    Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;

namespace NativeMsg
{
    public static class WinAPIMsg
    {
        [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern int FormatMessage(
            uint dwFlags, IntPtr lpSource, uint dwMessageId, uint dwLanguageId,
            StringBuilder lpBuffer, uint nSize, IntPtr Arguments);
    }
}
'@ -ErrorAction SilentlyContinue

    $flags = 0x00000800 -bor 0x00000200  # FROM_HMODULE | IGNORE_INSERTS
    $dllNames = @(
        "msobjs.dll", "adtschema.dll", "authzmsg.dll", "scecli.dll",
        "netmsg.dll", "lsasrv.dll", "samlib.dll", "kdcsvc.dll",
        "kerberos.dll", "ntdsai.dll", "w32time.dll", "dnsapi.dll", "eventlog.dll"
    )
    $system32 = Join-Path $env:SystemRoot "System32"
    $dllPaths = $dllNames | ForEach-Object { Join-Path $system32 $_ }

    $junkPattern = @(
        'Unknown specific access \(bit', 'Undefined UserAccountControl Bit',
        'Undefined Access \(no effect\) Bit', 'Device Access Bit',
        'Unused message ID', '^Not used$', '^N/A$', '^Unknown$'
    ) -join '|'

    function Resolve-Code {
        param([int]$Id, [string[]]$Paths)
        $sb = New-Object System.Text.StringBuilder 2048
        foreach ($path in $Paths) {
            if (-not (Test-Path -LiteralPath $path)) { continue }
            $hModule = [NativeMsg.WinAPIMsg]::LoadLibraryEx($path, [IntPtr]::Zero, 0x00000002)
            if ($hModule -eq [IntPtr]::Zero) { continue }
            try {
                $sb.Clear() | Out-Null
                $len = [NativeMsg.WinAPIMsg]::FormatMessage($flags, $hModule, [uint32]$Id, 0, $sb, [uint32]$sb.Capacity, [IntPtr]::Zero)
                if ($len -gt 0) {
                    $desc = $sb.ToString().Trim()
                    if ($desc -and $desc -notmatch $junkPattern) {
                        return [PSCustomObject]@{ Code = "%%$Id"; Description = $desc }
                    }
                }
            } finally {
                [void][NativeMsg.WinAPIMsg]::FreeLibrary($hModule)
            }
        }
        return $null
    }

    $results = New-Object System.Collections.Generic.List[object]
    for ($id = $MsobjsMinId; $id -le $MsobjsMaxId; $id++) {
        $resolved = Resolve-Code -Id $id -Paths $dllPaths
        if ($null -ne $resolved) { $results.Add($resolved) }
    }
    $results = $results | Sort-Object Code -Unique

    $outPath = Join-Path $CoreDir "msobjs_lookup.json"
    Write-LookupJson -Data $results -Path $outPath
    Write-Host "    -> $($results.Count) codes -> $outPath"
}


# =============================================================================
# UNIVERSAL - same on every machine, independent of any specific AD forest
# =============================================================================

function Get-DsAccessMaskLookup {
    <#
        Fixed ADS_RIGHTS_ENUM bit masks used to decode the 4662 AccessMask field.
        Not extractable from a DLL - hardcoded per the Windows SDK.
        Writes: lookups\universal\universal_ds_access_mask.json
    #>
    Write-Host "  [Universal] Writing DS access mask constants..."

    $data = @(
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

    $outPath = Join-Path $UniversalDir "universal_ds_access_mask.json"
    Write-LookupJson -Data $data -Path $outPath
    Write-Host "    -> $($data.Count) entries -> $outPath"
}

function Get-SocEventLookup {
    <#
        Extracts EventID descriptions from registered providers via Get-WinEvent.
        Serves as a fallback behind core\master_security_auditing_index_micosoft.json.
        Writes: lookups\universal\universal_soc_event_lookup.json
    #>
    Write-Host "  [Universal] Extracting provider event descriptions..."

    $providers = @("Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Sysmon")
    $results = foreach ($providerName in $providers) {
        try {
            $provider = Get-WinEvent -ListProvider $providerName -ErrorAction Stop
            foreach ($eventDef in $provider.Events) {
                if ([string]::IsNullOrWhiteSpace($eventDef.Description)) { continue }
                $description = [regex]::Match($eventDef.Description, '^[^.?!]+[.?!]').Value.Trim()
                if ([string]::IsNullOrWhiteSpace($description)) {
                    $description = ($eventDef.Description -split '\r?\n')[0].Trim()
                }
                if ($description -match '^%[0-9]+$') { continue }
                [PSCustomObject]@{ Provider = $providerName; EventID = $eventDef.Id; Description = $description }
            }
        } catch {
            Write-Warning "    Provider not found: $providerName"
        }
    }

    $results = $results | Sort-Object Provider, EventID, Description -Unique

    $outPath = Join-Path $UniversalDir "universal_soc_event_lookup.json"
    Write-LookupJson -Data $results -Path $outPath
    Write-Host "    -> $($results.Count) entries -> $outPath"
}


# =============================================================================
# ENVIRONMENT - specific to this AD forest, regenerate whenever it changes
# =============================================================================

function Get-AdGuidsLookup {
    <#
        Schema-derived GUIDs used to decode Properties / ObjectType in Event 4662:
          - ClassSchema / AttributeSchema  (schema partition)
          - ExtendedRight                  (controlAccessRight objects)
          - PropertySet                    (attributeSecurityGUID-linked property
                                             sets - controlAccessRight with
                                             validAccesses = 48)
        Writes: lookups\environment\environment_ad_guids.json
    #>
    Write-Host "  [Environment] Pulling AD schema + extended rights GUIDs..."

    Import-Module ActiveDirectory -ErrorAction Stop
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -- Pass 1: ClassSchema + AttributeSchema --------------------------------
    $schemaPath = (Get-ADRootDSE).schemaNamingContext
    $schemaObjects = Get-ADObject -SearchBase $schemaPath `
        -LDAPFilter "(|(objectClass=classSchema)(objectClass=attributeSchema))" `
        -Properties schemaIDGUID, lDAPDisplayName, objectClass `
        -ErrorAction SilentlyContinue

    foreach ($obj in $schemaObjects) {
        if ($null -eq $obj.schemaIDGUID) { continue }
        try {
            $guid = [System.Guid]::new([byte[]]$obj.schemaIDGUID)
        } catch { continue }
        $type = if ($obj.objectClass -contains "classSchema") { "ClassSchema" } else { "AttributeSchema" }
        $results.Add([PSCustomObject]@{ GUID = "{$guid}"; Name = $obj.lDAPDisplayName; Type = $type })
    }
    Write-Host "    Pass 1 (schema): $($results.Count) objects"

    # -- Pass 2: Extended Rights ----------------------------------------------
    $configPath    = (Get-ADRootDSE).configurationNamingContext
    $extRightsPath = "CN=Extended-Rights,$configPath"
    $extendedRights = Get-ADObject -SearchBase $extRightsPath `
        -LDAPFilter "(objectClass=controlAccessRight)" `
        -Properties rightsGuid, displayName, cn, validAccesses `
        -ErrorAction SilentlyContinue

    $extCount = 0
    $propertySetCount = 0
    foreach ($right in $extendedRights) {
        if ($null -eq $right.rightsGuid) { continue }
        try {
            $guid = [System.Guid]::new($right.rightsGuid.ToString())
        } catch { continue }
        $name = if (-not [string]::IsNullOrWhiteSpace($right.displayName)) { $right.displayName } else { $right.cn }

        # -- Pass 3: Property Sets ---------------------------------------------
        # controlAccessRight objects with validAccesses = 48 are property sets,
        # referenced by AttributeSchema.attributeSecurityGUID rather than by
        # rightsGuid on a normal extended-right ACE.
        if ($right.validAccesses -eq 48) {
            $results.Add([PSCustomObject]@{ GUID = "{$guid}"; Name = $name; Type = "PropertySet" })
            $propertySetCount++
        } else {
            $results.Add([PSCustomObject]@{ GUID = "{$guid}"; Name = $name; Type = "ExtendedRight" })
            $extCount++
        }
    }
    Write-Host "    Pass 2 (extended rights): $extCount objects"
    Write-Host "    Pass 3 (property sets):   $propertySetCount objects"

    $results = $results | Sort-Object GUID -Unique

    $outPath = Join-Path $EnvironmentDir "environment_ad_guids.json"
    Write-LookupJson -Data $results -Path $outPath
    Write-Host "    -> $($results.Count) total entries -> $outPath"
}

function Get-DomainObjectsLookup {
    <#
        Instance-level GUIDs used to resolve %{guid} references in the
        Event 4662 ObjectName field:
          - Well-known containers (Users, Computers, Builtin, etc.)
          - Custom OUs
          - Operationally relevant (non-system) containers
          - Every enabled computer + user account object
            (lab-scale enumeration - see README; not recommended for
            production-size domains)
        Writes: lookups\environment\environment_domain_objects.json
    #>
    Write-Host "  [Environment] Pulling domain objects + account instance GUIDs..."

    Import-Module ActiveDirectory -ErrorAction Stop

    $domainDN   = (Get-ADDomain).DistinguishedName
    $domainFQDN = (Get-ADDomain).DNSRoot
    $results    = [System.Collections.Generic.List[PSCustomObject]]::new()

    $filteredPrefixes = @(
        "CN=System,$domainDN", "CN=Configuration,$domainDN", "CN=DomainUpdates",
        "CN=Operations", "CN=Policies", "CN=WinsockServices", "CN=RpcServices",
        "CN=MicrosoftDNS", "CN=Program Data", "CN=NTDS Quotas",
        "CN=Infrastructure", "CN=LostAndFound", "CN=ForeignSecurityPrincipals"
    )

    function Test-ShouldSkip {
        param([string]$DN)
        foreach ($prefix in $filteredPrefixes) {
            if ($DN -like "*$prefix*") { return $true }
        }
        return $false
    }

    # -- Domain root -----------------------------------------------------------
    try {
        $root = Get-ADObject -Identity $domainDN -Properties ObjectGUID
        $results.Add([PSCustomObject]@{ GUID = "{$($root.ObjectGUID)}"; Name = $domainFQDN; Type = "DomainRoot" })
    } catch {
        Write-Warning "    Could not find domain root: $domainDN"
    }

    # -- Well-known containers --------------------------------------------------
    $wellKnown = @(
        @{ DN = "CN=Users,$domainDN";                    Name = "CN=Users";                    Type = "Container" },
        @{ DN = "CN=Computers,$domainDN";                Name = "CN=Computers";                Type = "Container" },
        @{ DN = "CN=Builtin,$domainDN";                  Name = "CN=Builtin";                  Type = "Container" },
        @{ DN = "CN=Managed Service Accounts,$domainDN"; Name = "CN=Managed Service Accounts"; Type = "Container" },
        @{ DN = "CN=Keys,$domainDN";                     Name = "CN=Keys";                     Type = "Container" },
        @{ DN = "OU=Domain Controllers,$domainDN";       Name = "OU=Domain Controllers";       Type = "OU"        }
    )
    foreach ($entry in $wellKnown) {
        if (Test-ShouldSkip -DN $entry.DN) { continue }
        try {
            $obj = Get-ADObject -Identity $entry.DN -Properties ObjectGUID -ErrorAction Stop
            $results.Add([PSCustomObject]@{ GUID = "{$($obj.ObjectGUID)}"; Name = $entry.Name; Type = $entry.Type })
        } catch {
            Write-Warning "    Could not find: $($entry.DN)"
        }
    }
    Write-Host "    Well-known containers: $($results.Count)"

    # -- Custom OUs --------------------------------------------------------------
    $ous = Get-ADOrganizationalUnit -Filter * -SearchBase $domainDN `
        -Properties ObjectGUID, DistinguishedName -ErrorAction SilentlyContinue
    $ouCount = 0
    foreach ($ou in $ous) {
        if (Test-ShouldSkip -DN $ou.DistinguishedName) { continue }
        $relativeName = $ou.DistinguishedName -replace ",DC=.*$", ""
        $results.Add([PSCustomObject]@{ GUID = "{$($ou.ObjectGUID)}"; Name = $relativeName; Type = "OU" })
        $ouCount++
    }
    Write-Host "    Custom OUs: $ouCount"

    # -- Operationally relevant containers ----------------------------------------
    $containers = Get-ADObject -Filter { objectClass -eq "container" } -SearchBase $domainDN `
        -Properties ObjectGUID, DistinguishedName -ErrorAction SilentlyContinue
    $containerCount = 0
    foreach ($container in $containers) {
        if (Test-ShouldSkip -DN $container.DistinguishedName) { continue }
        $relativeName = $container.DistinguishedName -replace ",DC=.*$", ""
        $results.Add([PSCustomObject]@{ GUID = "{$($container.ObjectGUID)}"; Name = $relativeName; Type = "Container" })
        $containerCount++
    }
    Write-Host "    Operational containers: $containerCount"

    # -- Computer + user account instance GUIDs (lab-scale) ------------------------
    $acctFilter = if ($IncludeDisabledAccounts) { "*" } else { "Enabled -eq `$true" }

    $computers = Get-ADComputer -Filter $acctFilter -SearchBase $domainDN `
        -Properties ObjectGUID, SamAccountName -ErrorAction SilentlyContinue
    $compCount = 0
    foreach ($comp in $computers) {
        if ($null -eq $comp.ObjectGUID) { continue }
        $results.Add([PSCustomObject]@{ GUID = "{$($comp.ObjectGUID)}"; Name = $comp.SamAccountName; Type = "ComputerObject" })
        $compCount++
    }
    Write-Host "    Computer objects: $compCount"

    $users = Get-ADUser -Filter $acctFilter -SearchBase $domainDN `
        -Properties ObjectGUID, SamAccountName -ErrorAction SilentlyContinue
    $userCount = 0
    foreach ($user in $users) {
        if ($null -eq $user.ObjectGUID) { continue }
        $results.Add([PSCustomObject]@{ GUID = "{$($user.ObjectGUID)}"; Name = $user.SamAccountName; Type = "UserObject" })
        $userCount++
    }
    Write-Host "    User objects: $userCount"

    if (-not $IncludeDisabledAccounts) {
        Write-Host "    (disabled accounts skipped - pass -IncludeDisabledAccounts to include them)"
    }

    $results = $results | Sort-Object GUID -Unique

    $outPath = Join-Path $EnvironmentDir "environment_domain_objects.json"
    Write-LookupJson -Data $results -Path $outPath
    Write-Host "    -> $($results.Count) total entries -> $outPath"
}


# =============================================================================
# Dispatch
# =============================================================================

$CoreFunctions = [ordered]@{
    Msobjs = { Get-MsobjsLookup }
}

$UniversalFunctions = [ordered]@{
    DsAccessMask   = { Get-DsAccessMaskLookup }
    SocEventLookup = { Get-SocEventLookup }
}

$EnvironmentFunctions = [ordered]@{
    AdGuids       = { Get-AdGuidsLookup }
    DomainObjects = { Get-DomainObjectsLookup }
}

# No category flag supplied -> default to Universal + Environment. Core is
# opt-in only and never runs implicitly.
if (-not ($Core -or $Universal -or $Environment)) {
    $Universal   = $true
    $Environment = $true
}

Write-Host ""
Write-Host "evtx-pipeline :: generate_lookups.ps1"
Write-Host "======================================"

if ($Core) {
    Write-Host ""
    Write-Host "-- Core --"
    foreach ($key in $CoreFunctions.Keys) {
        if ($SkipCore -contains $key) {
            Write-Host "  [Core] Skipping $key (--SkipCore)"
            continue
        }
        & $CoreFunctions[$key]
    }
}

if ($Universal) {
    Write-Host ""
    Write-Host "-- Universal --"
    foreach ($key in $UniversalFunctions.Keys) {
        if ($SkipUniversal -contains $key) {
            Write-Host "  [Universal] Skipping $key (--SkipUniversal)"
            continue
        }
        & $UniversalFunctions[$key]
    }
}

if ($Environment) {
    Write-Host ""
    Write-Host "-- Environment --"
    foreach ($key in $EnvironmentFunctions.Keys) {
        if ($SkipEnvironment -contains $key) {
            Write-Host "  [Environment] Skipping $key (--SkipEnvironment)"
            continue
        }
        & $EnvironmentFunctions[$key]
    }
}

Write-Host ""
Write-Host "Done."
Write-Host ""