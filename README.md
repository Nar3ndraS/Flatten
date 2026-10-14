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
   - `Properties`, `ObjectType` GUIDs for Event 4662 (schema objects + extended rights + property sets)
   - `ObjectName` `%{guid}` references for Event 4662 (domain objects + OUs + containers + account instances)
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
├── generate_lookups.ps1        ← single consolidated generator script
├── core/                        ← MANDATORY, outside lookups/
│   ├── master_security_auditing_index_micosoft.json   (static)
│   └── msobjs_lookup.json                              (generated with -Core)
└── lookups/                     ← optional — presence of a file turns its enrichment on
    ├── universal/                (same on any machine, not forest-specific)
    │   ├── universal_ds_access_mask.json          (generated)
    │   ├── universal_soc_event_lookup.json        (generated)
    │   └── universal_logon_types.json             (static)
    └── environment/               (specific to the AD forest you generated it in)
        ├── environment_ad_guids.json              (generated)
        └── environment_domain_objects.json        (generated)
```

---

## Lookup loading model

Lookup loading is **detection-based**, not flag-based. There is no `--profile` flag anymore.

- `core/` is mandatory. If either file is missing, the pipeline refuses to start.
- Everything under `lookups/universal/` and `lookups/environment/` is optional. If a file is present, that enrichment step runs. If it's absent, that step is silently skipped. No flags needed — you control behavior purely by what you put in the folder.

| File | Tier | Purpose |
|------|------|---------|
| `core/master_security_auditing_index_micosoft.json` | Core (mandatory) | EventID → description (Microsoft source) |
| `core/msobjs_lookup.json` | Core (mandatory) | `%%` code resolution |
| `lookups/universal/universal_ds_access_mask.json` | Universal (optional) | AccessMask bitwise decode for 4662 |
| `lookups/universal/universal_soc_event_lookup.json` | Universal (optional) | Fallback EventID descriptions |
| `lookups/universal/universal_logon_types.json` | Universal (optional) | LogonType decode for 4624, 4625, 4648 |
| `lookups/environment/environment_ad_guids.json` | Environment (optional) | Schema + extended rights + property set GUIDs for 4662 |
| `lookups/environment/environment_domain_objects.json` | Environment (optional) | OUs, containers, and computer/user instance GUID resolution for 4662 |

---

## Generating lookups

One script, three function groups (Core / Universal / Environment), each independently skippable by name.

```powershell
# Default: Universal + Environment. Core never runs unless explicitly requested.
.\generate_lookups.ps1

# Core only — slow DLL walk, run rarely, only when you need msobjs regenerated
.\generate_lookups.ps1 -Core

# Universal only, skip one function
.\generate_lookups.ps1 -Universal -SkipUniversal SocEventLookup

# Environment only, skip domain objects (e.g. you only need schema GUIDs today)
.\generate_lookups.ps1 -Environment -SkipEnvironment DomainObjects

# Everything, including Core
.\generate_lookups.ps1 -Core -Universal -Environment

# Environment, including disabled accounts in the instance GUID pull
.\generate_lookups.ps1 -Environment -IncludeDisabledAccounts
```

Every run **overwrites** its target file(s) — nothing is merged with previous output. Re-run whenever the environment changes.

`generate_lookups.ps1` replaces the five previous scripts (`generate_all_message_lookup.ps1`, `generate_ds_access_mask.ps1`, `generate_lookup.ps1`, `generate_ad_guids.ps1`, `generate_domain_objects.ps1`, `generate_lab_objects.ps1`) — those are removed. Instance-level user/computer GUIDs, previously written to a separate `lab_objects.json`, are now folded directly into `environment_domain_objects.json`.

Copy the `core/` and `lookups/` folders to the machine where you run the pipeline.

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
# Loads whatever's present in ./core and ./lookups
python main.py raw.json out.ndjson

# Point at a different environment's generated lookups
python main.py raw.json out.ndjson --core-dir /path/to/core --lookups-dir /path/to/lookups

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

Options:
  --core-dir     <dir>   Directory with the mandatory lookups (default: ./core)
  --lookups-dir  <dir>   Directory with universal/ + environment/ subfolders (default: ./lookups)
  --verbose               Enable debug logging
  -h, --help              Show help
```
