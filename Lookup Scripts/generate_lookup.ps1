# =============================================================================
# generate_lookup.ps1 — Generate Event ID description lookup file
#
# Run this on a Windows Domain Controller or Server to extract event descriptions
# from registered providers. The output JSON file is used by evtx_pipeline.sh
# to enrich logs with human-readable EventDescription fields.
#
# Usage:
#   .\generate_lookup.ps1
#
# Output:
#   soc_event_lookup.json — array of { Provider, EventID, Description }
#
# Recommended: Run on a Domain Controller for widest provider coverage
#   (includes AD, Kerberos, replication events not present on workstations)
# =============================================================================

# Add or remove providers as needed.
# Run on a DC for full coverage including AD/Kerberos/replication events.
$Providers = @(
    "Microsoft-Windows-Security-Auditing",
    "Microsoft-Windows-Sysmon"
)

$Results = foreach ($ProviderName in $Providers) {

    Write-Host "Processing $ProviderName..."

    try {
        $Provider = Get-WinEvent -ListProvider $ProviderName -ErrorAction Stop

        foreach ($Event in $Provider.Events) {

            if ([string]::IsNullOrWhiteSpace($Event.Description)) {
                continue
            }

            # Extract first sentence
            $Description = [regex]::Match(
                $Event.Description,
                '^[^.?!]+[.?!]'
            ).Value.Trim()

            # Fallback to first line if no sentence boundary found
            if ([string]::IsNullOrWhiteSpace($Description)) {
                $Description = ($Event.Description -split '\r?\n')[0].Trim()
            }

            # Skip pure placeholders like "%1"
            if ($Description -match '^%[0-9]+$') {
                continue
            }

            [PSCustomObject]@{
                Provider    = $ProviderName
                EventID     = $Event.Id
                Description = $Description
            }
        }
    }
    catch {
        Write-Warning "Provider not found: $ProviderName"
    }
}

# Deduplicate
$Results = $Results |
    Sort-Object Provider, EventID, Description -Unique

# Export
$Results |
    ConvertTo-Json -Depth 3 |
    Out-File ".\soc_event_lookup.json" -Encoding utf8

Write-Host ""
Write-Host "Exported $($Results.Count) events to soc_event_lookup.json"
