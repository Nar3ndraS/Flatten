# =============================================================================
# generate_all_message_lookup.ps1
#
# Build a lookup JSON for Windows message placeholders like %%1538 and %%14674.
#
# What this script does:
#   1. Scans one or more DLL message tables with FormatMessage()
#   2. Resolves codes in a configurable numeric range
#   3. Filters junk / placeholder entries
#   4. Writes a JSON array of { Code, Description }
#
# Why this is better than only msobjs.dll:
#   AD / Security auditing logs use several different message tables.
#   msobjs.dll covers access-rights style codes (%%1537 etc).
#   adtschema.dll and others can contain directory-service codes like %%14674.
#
# Usage:
#   .\generate_all_message_lookup.ps1
#
# Optional examples:
#   .\generate_all_message_lookup.ps1 -OutputFile .\lookup.json
#   .\generate_all_message_lookup.ps1 -MinId 1000 -MaxId 20000
#   .\generate_all_message_lookup.ps1 -DllNames msobjs.dll,adtschema.dll
#
# Output:
#   JSON array of objects:
#     { "Code": "%%1538", "Description": "READ_CONTROL" }
#
# Notes:
#   - Run on a Windows Server / DC for the widest coverage.
#   - 64-bit PowerShell is recommended.
#   - If you already have logs, you can limit the scan using -InputFile.
# =============================================================================

[CmdletBinding()]
param(
    [string]$OutputFile = ".\msobjs_lookup.json",

    # Optional source file (ndjson/json/text). If supplied, only codes found here are resolved.
    [string]$InputFile = "",

    # Search space when no InputFile is provided.
    [int]$MinId = 1000,
    [int]$MaxId = 20000,

    # Message DLLs to try. Order matters.
    [string[]]$DllNames = @(
        "msobjs.dll",
        "adtschema.dll",
        "authzmsg.dll",
        "scecli.dll",
        "netmsg.dll",
        "lsasrv.dll",
        "samlib.dll",
        "kdcsvc.dll",
        "kerberos.dll",
        "ntdsai.dll",
        "w32time.dll",
        "dnsapi.dll",
        "eventlog.dll"
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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
            uint dwFlags,
            IntPtr lpSource,
            uint dwMessageId,
            uint dwLanguageId,
            StringBuilder lpBuffer,
            uint nSize,
            IntPtr Arguments);
    }
}
'@

# Flags:
#   FORMAT_MESSAGE_FROM_HMODULE = 0x00000800
#   FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200
$flags = 0x00000800 -bor 0x00000200

# Load DLLs from System32. LoadLibraryEx with AS_DATAFILE is enough for FormatMessage.
$system32 = Join-Path $env:SystemRoot "System32"
$dllPaths = foreach ($dll in $DllNames) {
    Join-Path $system32 $dll
}

# Clean up noisy placeholders that are not useful for investigation.
$junkPattern = @(
    'Unknown specific access \(bit',
    'Undefined UserAccountControl Bit',
    'Undefined Access \(no effect\) Bit',
    'Device Access Bit',
    'Unused message ID',
    '^Not used$',
    '^N/A$',
    '^Unknown$'
) -join '|'

function Get-CodesFromFile {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "InputFile not found: $Path"
    }

    # Works for ndjson/json/text. We only need the %%#### strings.
    $content = Get-Content -LiteralPath $Path -Raw
    [regex]::Matches($content, '%%\d+') |
        ForEach-Object { $_.Value } |
        Sort-Object -Unique
}

function Resolve-Code {
    param(
        [int]$Id,
        [string[]]$Paths
    )

    $sb = New-Object System.Text.StringBuilder 2048

    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path)) {
            continue
        }

        $hModule = [NativeMsg.WinAPIMsg]::LoadLibraryEx($path, [IntPtr]::Zero, 0x00000002)
        if ($hModule -eq [IntPtr]::Zero) {
            continue
        }

        try {
            $sb.Clear() | Out-Null
            $len = [NativeMsg.WinAPIMsg]::FormatMessage($flags, $hModule, [uint32]$Id, 0, $sb, [uint32]$sb.Capacity, [IntPtr]::Zero)
            if ($len -gt 0) {
                $desc = $sb.ToString().Trim()

                if ($desc -and $desc -notmatch $junkPattern) {
                    return [PSCustomObject]@{
                        Code        = "%%$Id"
                        Description = $desc
                    }
                }
            }
        }
        finally {
            [void][NativeMsg.WinAPIMsg]::FreeLibrary($hModule)
        }
    }

    return $null
}

# Build the set of ids to resolve.
$ids = New-Object System.Collections.Generic.HashSet[int]

if ($InputFile -and $InputFile.Trim()) {
    $codes = Get-CodesFromFile -Path $InputFile
    foreach ($code in $codes) {
        $num = [int]($code -replace '%%', '')
        [void]$ids.Add($num)
    }
}
else {
    for ($i = $MinId; $i -le $MaxId; $i++) {
        [void]$ids.Add($i)
    }
}

$results = New-Object System.Collections.Generic.List[object]

Write-Host "Resolving $($ids.Count) codes across $($dllPaths.Count) DLLs..."

foreach ($id in ($ids | Sort-Object)) {
    $resolved = Resolve-Code -Id $id -Paths $dllPaths
    if ($null -ne $resolved) {
        $results.Add($resolved)
    }
}

$results = $results |
    Sort-Object Code -Unique

$results |
    ConvertTo-Json -Depth 3 |
    Set-Content -LiteralPath $OutputFile -Encoding UTF8

Write-Host "Exported $($results.Count) entries to $OutputFile"
