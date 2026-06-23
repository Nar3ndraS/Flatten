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
   - GUIDs for Event 4662 (schema objects + extended rights)
4. Outputs one JSON object per line — ready for ADX ingest

---

## Requirements

- Python 3.10+
- [`evtx_dump`](https://github.com/omerbenamram/evtx)
- `orjson` (optional, recommended for speed) — `pip install orjson`
- Active Directory lab for generating lookup files (run scripts on DC)

---

## Project structure

```
evtx-pipeline/
├── main.py
├── parser.py
├── transform.py
├── enricher.py
├── writer.py
├── generate_lookup.ps1
├── generate_msobjs_lookup.ps1
├── generate_ds_access_mask.ps1
├── generate_ad_guids.ps1
└── lookups/
    ├── master_security_auditing_index_micosoft.json   ← required
    ├── msobjs_lookup.json                             ← required
    ├── soc_event_lookup.json                          ← optional
    ├── logon_types.json                               ← optional
    ├── ds_access_mask.json                            ← optional
    └── ad_guids.json                                  ← optional
```

---

## Lookup files

| File | Required | Generate via | Purpose |
|------|----------|-------------|---------|
| `master_security_auditing_index_micosoft.json` | Yes | included | EventID → description (Microsoft source) |
| `msobjs_lookup.json` | Yes | `generate_msobjs_lookup.ps1` on DC | `%%` code resolution |
| `soc_event_lookup.json` | No | `generate_lookup.ps1` on DC | Fallback EventID descriptions |
| `logon_types.json` | No | included | LogonType decode for 4624/4625/4648 |
| `ds_access_mask.json` | No | `generate_ds_access_mask.ps1` | AccessMask decode for 4662 |
| `ad_guids.json` | No | `generate_ad_guids.ps1` on DC | GUID resolution for 4662 |

**Generate lookup files on DC1:**

```powershell
New-Item -ItemType Directory -Name "lookups" -Force

.\generate_msobjs_lookup.ps1      # produces lookups\msobjs_lookup.json
.\generate_lookup.ps1             # produces lookups\soc_event_lookup.json
.\generate_ds_access_mask.ps1     # produces lookups\ds_access_mask.json
.\generate_ad_guids.ps1           # produces lookups\ad_guids.json
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
# Minimal — required lookups only
python main.py raw_Security.json out.ndjson

# With fallback EventID lookup
python main.py raw_Security.json out.ndjson --lookup lookups/soc_event_lookup.json

# Full — all lookups
python main.py raw_Security.json out.ndjson --lookup lookups/soc_event_lookup.json --verbose
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

**Fields packed into `AdditionalFields`:** `Provider_Guid`, `Version`, `Level`, `Task`, `Opcode`, `Keywords`, `EventRecordID`, `Execution_ProcessID`, `Execution_ThreadID`, `Correlation`, `Security`

---

## CLI reference

```
python main.py <input> <output> [options]

Options:
  --lookup        <file>   Fallback EventID lookup (soc_event_lookup.json)
  --master        <file>   Override master lookup path
  --msobjs        <file>   Override msobjs lookup path
  --logon-types   <file>   Override logon types lookup path
  --ds-access-mask <file>  Override DS access mask lookup path
  --ad-guids      <file>   Override AD GUIDs lookup path
  --warnings      <file>   Warnings log path (default: warnings.log)
  --verbose                Enable debug logging
```
