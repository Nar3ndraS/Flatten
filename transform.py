"""
transform.py — Schema normalization, field ordering, and AdditionalFields packing.

Responsibilities:
- Rename TimeCreated_SystemTime → TimeGenerated
- Pack low-value metadata fields into AdditionalFields
- Pin forensic identity fields (Subject*, Target*) at top level always
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
    "Execution_ProcessID",
    "Execution_ThreadID",
    "Correlation",   # sometimes populated — preserved but low-value at top level
    "Security",      # preserve in case populated in non-Security logs
}

# Fields that are always pinned at top level regardless of schema reduction.
# These are forensic identity fields critical for SOC queries.
PINNED_FIELDS = {
    "TimeGenerated",
    "EventID",
    "EventDescription",
    "Computer",
    "Provider_Name",
    "Channel",
}

# Fields to drop entirely — no analytical value
DROPPED_FIELDS = {
    "xmlns",
}


def _pack_additional_fields(record: dict) -> dict | None:
    """
    Extract ADDITIONAL_FIELDS from the record and return them as a dict.
    Returns None if none of the fields are present in the record.
    """
    packed = {
        field: record[field]
        for field in ADDITIONAL_FIELDS
        if field in record and record[field] is not None
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
    # Provider_Name and Channel are in PINNED_FIELDS but should also appear in
    # the middle section — only exclude the four fields already written above.
    already_written = {"TimeGenerated", "EventID", "EventDescription", "Computer"}
    exclude = (
        already_written
        | ADDITIONAL_FIELDS
        | DROPPED_FIELDS
        | {"EventData", "TimeCreated_SystemTime"}
    )

    for key, value in record.items():
        if key not in exclude:
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
