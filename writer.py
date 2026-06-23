"""
writer.py — Write enriched records to NDJSON output for ADX ingest.

Responsibilities:
- Write one JSON object per line (NDJSON format)
- Use orjson for fast serialization if available, fall back to stdlib json
- Flush output progressively — safe for large files
- Return count of records written

orjson advantages over stdlib json:
- ~3-5x faster serialization
- Handles datetime objects natively
- More compact output
"""

import json
import logging
from pathlib import Path
from typing import Generator

logger = logging.getLogger(__name__)

# Try to import orjson — fall back to stdlib json if not installed
try:
    import orjson

    def _serialize(record: dict) -> bytes:
        return orjson.dumps(record)

    logger.debug("Using orjson for serialization.")

except ImportError:
    logger.warning(
        "orjson not installed — falling back to stdlib json. "
        "Install with: pip install orjson"
    )

    def _serialize(record: dict) -> bytes:
        return json.dumps(record, ensure_ascii=False).encode("utf-8")


def write_ndjson(
    records: Generator[dict, None, None],
    output_path: str | Path,
) -> int:
    """
    Write enriched records to an NDJSON file, one record per line.

    Args:
        records:     Generator of enriched dicts from enricher.py
        output_path: Path to the output NDJSON file

    Returns:
        Number of records written.
    """
    output_path = Path(output_path)
    count = 0

    with output_path.open("wb") as fh:
        for record in records:
            fh.write(_serialize(record))
            fh.write(b"\n")
            count += 1

            # Log progress every 10,000 records
            if count % 10_000 == 0:
                logger.info("  Written: %d records...", count)

    return count
