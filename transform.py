"""
transform.py — Event filtering, schema normalization, field ordering, and AdditionalFields packing.

Responsibilities:
- Filter records per provider (see PROVIDER_EVENT_ALLOWLIST)
- Rename TimeCreated_SystemTime → TimeGenerated
- Pack low-value metadata fields into AdditionalFields
- Drop noise fields (xmlns already dropped in parser)
- Enforce output field order:
    TimeGenerated → EventID → EventDescription → Computer →
    remaining flat fields → AdditionalFields → EventData

Note:
- EventDescription is not set here — enricher.py adds it after transform
- This module operates on the flat dicts produced by parser.py
"""

from typing import Generator

# Fields to pack into AdditionalFields (low-value metadata)
# These are removed from top level and packed into a nested object.
# AdditionalFields is set to null if all of these are absent.
ADDITIONAL_FIELDS = {
    "Provider_Guid",
    "Version",
    "Level",
    "Task",
    "Opcode",
    "Keywords",
    "EventRecordID",
    "EventID_Qualifiers",  # only present on System/Application style logs
    "Execution_ProcessID",
    "Execution_ThreadID",
    "Correlation",   # bare form, when the element has no attributes
    "Security",      # bare form, when the element has no attributes
}

# Correlation and Security normally carry attributes, so after flattening they
# appear as Correlation_ActivityID, Security_UserID, etc. Match them by prefix.
ADDITIONAL_PREFIXES = ("Correlation_", "Security_")

# Fields to drop entirely — no analytical value
DROPPED_FIELDS = {
    "xmlns",
}

# Per-provider EventID allowlists. A provider listed here keeps ONLY the listed
# EventIDs; every other record from that provider is dropped. Providers not
# listed are passed through untouched.
PROVIDER_EVENT_ALLOWLIST = {
    "Microsoft-Windows-PowerShell": {4103, 4104},
}


def _is_additional(key: str) -> bool:
    return key in ADDITIONAL_FIELDS or key.startswith(ADDITIONAL_PREFIXES)


def filter_events(
    records: Generator[dict, None, None],
    stats: dict | None = None,
) -> Generator[dict, None, None]:
    """
    Drop records whose provider has an allowlist and whose EventID is not on it.

    Args:
        records: Generator of flat dicts from parser.py
        stats:   Optional dict; stats["filtered"] is incremented per dropped record.
                 The count is only final once the generator is fully consumed.

    Yields:
        Records that passed the filter.
    """
    for record in records:
        allowed = PROVIDER_EVENT_ALLOWLIST.get(record.get("Provider_Name"))
        if allowed is not None:
            try:
                event_id = int(record.get("EventID"))
            except (TypeError, ValueError):
                event_id = None
            if event_id not in allowed:
                if stats is not None:
                    stats["filtered"] = stats.get("filtered", 0) + 1
                continue
        yield record


def _pack_additional_fields(record: dict) -> dict | None:
    """
    Extract additional (low-value metadata) fields from the record and return them as a dict.
    Returns None if none of the fields are present in the record.
    """
    packed = {
        key: value
        for key, value in record.items()
        if value is not None and _is_additional(key)
    }
    return packed if packed else None


def normalize(record: dict) -> dict:
    """
    Normalize a single flat record from parser.py.

    Steps:
    1. Rename TimeCreated_SystemTime → TimeGenerated
    2. Drop noise fields
    3. Pack metadata into AdditionalFields
    4. Build output with enforced field order

    Args:
        record: Flat dict from parser.py

    Returns:
        Normalized dict with enforced field order, ready for enricher.py.
        EventDescription placeholder is set to None — enricher fills it in.
    """
    # Step 1: Rename TimeCreated_SystemTime → TimeGenerated
    if "TimeCreated_SystemTime" in record:
        record["TimeGenerated"] = record.pop("TimeCreated_SystemTime")

    # Step 2: Drop noise fields
    for field in DROPPED_FIELDS:
        record.pop(field, None)

    # Step 3: Pack AdditionalFields
    additional_fields_val = _pack_additional_fields(record)

    # Step 4: Build output with enforced field order
    # Priority fields first
    out = {
        "TimeGenerated": record.get("TimeGenerated"),
        "EventID":       record.get("EventID"),
        "EventDescription": None,  # enricher.py fills this in
        "Computer":      record.get("Computer"),
    }

    # Remaining flat fields — exclude the four priority fields already written,
    # packed fields (going to AdditionalFields), dropped fields, and EventData.
    # Provider_Name and Channel stay in the middle section.
    already_written = {"TimeGenerated", "EventID", "EventDescription", "Computer"}
    exclude = (
        already_written
        | DROPPED_FIELDS
        | {"EventData", "TimeCreated_SystemTime"}
    )

    for key, value in record.items():
        if key not in exclude and not _is_additional(key):
            out[key] = value

    # AdditionalFields second to last
    out["AdditionalFields"] = additional_fields_val

    # EventData always last
    out["EventData"] = record.get("EventData")

    return out


def reduce_schema(
    records: Generator[dict, None, None]
) -> Generator[dict, None, None]:
    """
    Stream records through normalize(), yielding one normalized dict per record.

    Args:
        records: Generator of flat dicts from parser.py

    Yields:
        Normalized dicts ready for enricher.py
    """
    for record in records:
        yield normalize(record)
