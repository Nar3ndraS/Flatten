# evtx-pipeline

Converts raw Windows Event Log exports into clean, enriched NDJSON for ingestion into Azure Data Explorer (ADX) or Microsoft Sentinel.

---

## What it does

1. Flattens raw `evtx_dump` NDJSON — unwraps nested `#attributes`, promotes System fields to top level
2. Normalizes schema — renames `TimeCreated_SystemTime` → `TimeGenerated`, packs low-value metadata into `AdditionalFields`, drops `xmlns`
3. Enriches each record:
   - `EventDescription` via two-tier lookup (master → fallback)
   - `%%` placeholder codes via `msobjs_lookup.json`
   - `LogonType` for Events 4624, 4625, 4648
   - `AccessMask` for Event 4662 (bitwise decode)
   - `Properties`, `ObjectType` GUIDs for Event 4662 (schema objects + extended rights)
   - `ObjectName` `%{guid}` references for Event 4662 (domain objects + OUs + containers)
4. Outputs one JSON object per line — ready for ADX ingest

---

## Requirements

- Python 3.10+
- [`evtx_dump`](https://github.com/omerbenamram/evtx)
- `orjson` (optional, recommended for speed) — `pip install orjson`
- Domain Controller access for generating environment-specific lookup files

---

## Project structure

```
evtx-pipeline/
├── main.py
├── parser.py
├── transform.py
├── enricher.py
├── writer.py
├── warnings_collector.py
├── generate_lookup.ps1
├── generate_msobjs_lookup.ps1
├── generate_ds_access_mask.ps1
├── generate_ad_guids.ps1
├── generate_domain_objects.ps1
└── lookups/
    ├── master_security_auditing_index_micosoft.json   ← required
    ├── msobjs_lookup.json                             ← required
    ├── logon_types.json                               ← included
    ├── soc_event_lookup.json                          ← optional
    ├── ds_access_mask.json                            ← generate on DC
    ├── ad_guids.json                                  ← generate on DC
    └── domain_objects.json                            ← generate on DC
```

---

## Lookup files

| File | Profile | Source | Purpose |
|------|---------|--------|---------|
| `master_security_auditing_index_micosoft.json` | Both | Included | EventID → description (Microsoft source) |
| `msobjs_lookup.json` | Both | `generate_msobjs_lookup.ps1` on DC | `%%` code resolution |
| `logon_types.json` | Both | Included | LogonType decode for 4624, 4625, 4648 |
| `soc_event_lookup.json` | Both | `generate_lookup.ps1` on DC | Fallback EventID descriptions |
| `ds_access_mask.json` | Both | `generate_ds_access_mask.ps1` on DC | AccessMask bitwise decode for 4662 |
| `ad_guids.json` | Default only | `generate_ad_guids.ps1` on DC | Schema + extended rights GUIDs for 4662 |
| `domain_objects.json` | Default only | `generate_domain_objects.ps1` on DC | Domain object `%{guid}` resolution for 4662 |

**Generate on DC1** (run once, re-run when AD schema changes):

```powershell
New-Item -ItemType Directory -Name "lookups" -Force

.\generate_msobjs_lookup.ps1       # lookups\msobjs_lookup.json
.\generate_lookup.ps1              # lookups\soc_event_lookup.json
.\generate_ds_access_mask.ps1      # lookups\ds_access_mask.json
.\generate_ad_guids.ps1            # lookups\ad_guids.json
.\generate_domain_objects.ps1      # lookups\domain_objects.json
```

Copy the `lookups\` folder to the machine where you run the pipeline.

---

## Workflow

**Step 1 — Convert `.evtx` to raw JSON**

```bash
# Single file
evtx_dump -o jsonl -t 1 Security.evtx > raw_Security.json

# Multiple files combined
find . -name '*.evtx' -exec evtx_dump -o jsonl -t 2 {} \; > combined.json
```

**Step 2 — Run the pipeline**

```bash
# Any logs — universal profile (default), skips env-specific lookups
python main.py raw.json out.ndjson

# Any logs + fallback EventID descriptions
python main.py raw.json out.ndjson --lookup lookups/soc_event_lookup.json

# Lab / domain logs — loads all lookups including AD GUIDs and domain objects
python main.py raw.json out.ndjson --profile default

# Lab logs + fallback — full enrichment
python main.py raw.json out.ndjson --profile default --lookup lookups/soc_event_lookup.json

# Debug mode — shows detailed logging
python main.py raw.json out.ndjson --verbose
```

**Step 3 — Ingest into ADX**

Use the ADX **Get data** wizard to ingest `out.ndjson`.

> ⚠️ On the Inspect step, keep **Nested levels = 1**.
> Increasing it expands `EventData` into flat columns and breaks `todynamic()` queries.

---

## Output format

```json
{
  "TimeGenerated": "2026-05-25T20:43:10.511558Z",
  "EventID": 4624,
  "EventDescription": "An account was successfully logged on.",
  "Computer": "DC1.blues.lab",
  "Provider_Name": "Microsoft-Windows-Security-Auditing",
  "Channel": "Security",
  "AdditionalFields": {
    "Provider_Guid": "54849625-5478-4994-A5BA-3E3B0328C30D",
    "Version": 2,
    "Level": 0,
    "Task": 12544,
    "Opcode": 0,
    "Keywords": "0x8020000000000000",
    "EventRecordID": 655588,
    "Execution_ProcessID": 808,
    "Execution_ThreadID": 868
  },
  "EventData": {
    "SubjectUserName": "-",
    "TargetUserName": "Administrator",
    "LogonType": "3 (Network)",
    "IpAddress": "10.10.10.99"
  }
}
```

**Field order:** `TimeGenerated → EventID → EventDescription → Computer → remaining flat fields → AdditionalFields → EventData`

| Field | Notes |
|-------|-------|
| `TimeGenerated` | Renamed from `TimeCreated_SystemTime` |
| `EventDescription` | `null` if not found in either lookup |
| `AdditionalFields` | `null` if all packed fields are absent |
| `EventData` | Nested object — query with `todynamic()` in KQL |

**Fields packed into `AdditionalFields`:**

`Provider_Guid`, `Version`, `Level`, `Task`, `Opcode`, `Keywords`, `EventRecordID`, `Execution_ProcessID`, `Execution_ThreadID`, `Correlation`, `Security`

---

## Enrichment reference

| Event ID | Field | Enrichment |
|----------|-------|------------|
| All | `EventDescription` | Two-tier lookup — master → fallback |
| All | `EventData.*` | `%%` code resolution via `msobjs_lookup.json` |
| 4624, 4625, 4648 | `EventData.LogonType` | Numeric → friendly name e.g. `3 (Network)` |
| 4662 | `EventData.AccessMask` | Bitwise decode e.g. `0x100 (Control Access)` |
| 4662 | `EventData.Properties` | `{guid}` → `{guid} (Name)` |
| 4662 | `EventData.ObjectType` | `{guid}` → `{guid} (Name)` |
| 4662 | `EventData.ObjectName` | `%{guid}` → `%{guid} (Name)` |

---

## CLI reference

Running `python main.py` with no arguments shows the full help menu.

```
python main.py <input> <output> [options]

Profiles:
  (none)              Universal — skips ad_guids + domain_objects (default)
  --profile default   Full — loads all lookups including environment-specific

Options:
  --profile         <name>   universal or default (default: universal)
  --lookup          <file>   Fallback EventID lookup
  --master          <file>   Override master lookup path
  --msobjs          <file>   Override msobjs lookup path
  --logon-types     <file>   Override logon types lookup path
  --ds-access-mask  <file>   Override DS access mask lookup path
  --ad-guids        <file>   Override AD GUIDs lookup path (default profile only)
  --domain-objects  <file>   Override domain objects lookup path (default profile only)
  --verbose                  Enable debug logging
  -h, --help                 Show help
```
