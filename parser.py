"""
parser.py — Load and flatten raw evtx_dump NDJSON output.

Responsibilities:
- Read raw evtx_dump NDJSON line by line (streaming, memory-safe)
- Unwrap #attributes nodes
- Flatten all System-level fields to top level
- Preserve EventData and UserData as nested objects
- Skip malformed records with a warning
- Yield one flat dict per record

Raw input shape (from evtx_dump -o jsonl):
    {
        "Event": {
            "#attributes": {"xmlns": "..."},
            "System": {
                "Provider": {"#attributes": {"Name": "...", "Guid": "..."}},
                "EventID": 4624,
                "TimeCreated": {"#attributes": {"SystemTime": "..."}},
                "Execution": {"#attributes": {"ProcessID": 4, "ThreadID": 172}},
                ...
            },
            "EventData": { ... }
        }
    }

Output shape (flat dict, EventData preserved as nested):
    {
        "Provider_Name": "Microsoft-Windows-Security-Auditing",
        "Provider_Guid": "...",
        "EventID": 4624,
        "TimeCreated_SystemTime": "2026-05-25T22:29:32.247822Z",
        "Execution_ProcessID": 4,
        "Execution_ThreadID": 172,
        "Channel": "Security",
        "Computer": "SRV1.blues.lab",
        ...
        "EventData": { ... }
    }
"""

import json
import logging
from pathlib import Path
from typing import Generator

logger = logging.getLogger(__name__)


def _unwrap_attributes(obj: dict) -> dict:
    """
    Unwrap #attributes dicts by hoisting their keys to the parent level.

    Example:
        {"Provider": {"#attributes": {"Name": "Foo", "Guid": "Bar"}}}
        → {"Provider": {"Name": "Foo", "Guid": "Bar"}}

    Operates recursively on all nested dicts.
    """
    if not isinstance(obj, dict):
        return obj

    result = {}
    for key, value in obj.items():
        if key == "#attributes":
            # Hoist attributes up — they merge into the parent
            if isinstance(value, dict):
                for attr_key, attr_val in value.items():
                    result[attr_key] = _unwrap_attributes(attr_val) if isinstance(attr_val, dict) else attr_val
        elif isinstance(value, dict):
            unwrapped = _unwrap_attributes(value)
            # If after unwrapping the value is a flat dict with only hoisted keys,
            # merge into parent; otherwise keep as nested
            result[key] = unwrapped
        elif isinstance(value, list):
            result[key] = [
                _unwrap_attributes(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            result[key] = value

    return result


def _flatten(prefix: str, obj: dict, out: dict) -> None:
    """
    Recursively flatten a nested dict into out with underscore-joined keys.

    Skips None values at intermediate levels.
    Arrays are flattened with index suffixes: key_0, key_1, ...

    Example:
        prefix="Execution", obj={"ProcessID": 4, "ThreadID": 172}
        → out["Execution_ProcessID"] = 4
           out["Execution_ThreadID"] = 172
    """
    for key, value in obj.items():
        full_key = f"{prefix}_{key}" if prefix else key

        if isinstance(value, dict):
            _flatten(full_key, value, out)
        elif isinstance(value, list):
            for i, item in enumerate(value):
                indexed_key = f"{full_key}_{i}"
                if isinstance(item, dict):
                    _flatten(indexed_key, item, out)
                else:
                    out[indexed_key] = item
        else:
            out[full_key] = value


def _process_event(raw_event: dict) -> dict:
    """
    Convert a raw Event dict (already parsed from JSON) into a flat record.

    Steps:
    1. Unwrap all #attributes nodes
    2. Separate EventData / UserData from System sections
    3. Flatten all System-level sections to top level
    4. Re-attach EventData as a nested object

    Returns a flat dict ready for transform.py.
    """
    # Step 1: Unwrap #attributes throughout the entire Event
    event = _unwrap_attributes(raw_event)

    # Step 2: Separate EventData and UserData — these stay nested
    event_data = event.get("EventData") or event.get("UserData") or None

    # Step 3: Flatten everything except EventData/UserData/xmlns
    flat = {}
    for section_key, section_val in event.items():
        if section_key in ("EventData", "UserData"):
            continue  # handled separately
        if section_key == "xmlns":
            continue  # dropped — no analytical value

        if isinstance(section_val, dict):
            _flatten("", section_val, flat)
        elif isinstance(section_val, list):
            for i, item in enumerate(section_val):
                indexed_key = f"{section_key}_{i}"
                if isinstance(item, dict):
                    _flatten(indexed_key, item, flat)
                else:
                    flat[indexed_key] = item
        elif section_val is None:
            pass  # skip nulls at section level
        else:
            flat[section_key] = section_val

    # Step 4: Attach EventData as nested object
    flat["EventData"] = event_data

    return flat


def load(input_path: str | Path) -> Generator[dict, None, None]:
    """
    Stream-parse a raw evtx_dump NDJSON file, yielding one flat dict per record.

    Malformed lines (invalid JSON, missing .Event) are logged as warnings
    and skipped — the pipeline keeps running.

    Args:
        input_path: Path to the raw evtx_dump NDJSON file.

    Yields:
        Flat dicts ready for transform.py.
    """
    path = Path(input_path)

    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    with path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue

            # Parse JSON
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning("[WARN] Line %d: invalid JSON — skipped. (%s)", lineno, exc)
                continue

            # Must have top-level .Event
            if not isinstance(raw, dict) or "Event" not in raw:
                logger.warning("[WARN] Line %d: missing .Event field — skipped.", lineno)
                continue

            # Flatten and yield
            try:
                record = _process_event(raw["Event"])
                yield record
            except Exception as exc:  # noqa: BLE001
                logger.warning("[WARN] Line %d: failed to process record — skipped. (%s)", lineno, exc)
                continue
