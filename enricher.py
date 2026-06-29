"""
enricher.py — Lookup-based enrichment of normalized records.

Responsibilities:
- Load all JSON lookup files once at startup into memory
- Resolve EventDescription via two-tier lookup:
    Priority 1: master_security_auditing_index_micosoft.json (required)
    Priority 2: soc_event_lookup.json via --lookup flag (optional fallback)
    Lookup key: Provider_Name + "_" + str(EventID)
    Result: None if not found in either
- Resolve %% placeholder codes in EventData string values:
    Strategy: Option B — keep original code, append description
    Example: "%%1538" → "%%1538 (READ_CONTROL)"
    Codes not in msobjs_lookup → left as-is
- Resolve EventID-scoped fields (field only resolved for specific EventIDs):
    LogonType in EventIDs {4624, 4625, 4648}
        Strategy: Option B — keep original value, append description
        Example: "3" → "3 (Network)"
        Values not in logon_types.json → left as-is
    AccessMask in EventID 4662 only
        Strategy: decode all set bits, join with |
        Example: "0x41000" → "0x41000 (Write DACL | Delete)"
        Hex values not in ds_access_mask.json bits → left as-is
    GUIDs in EventID 4662 only (Properties, ObjectType fields)
        Strategy: Option B — keep GUID, append name
        Example: "{1131f6aa...}" → "{1131f6aa...} (DS-Replication-Get-Changes)"
        GUIDs not in ad_guids.json → left as-is
        Multiple GUIDs in one field each resolved independently
- Preserve \r\n\t delimiters in EventData — do NOT strip

Design:
- All lookups loaded once at startup (Lookups.__init__)
- Per-record enrichment is O(1) dict lookup
- EventData walk is recursive to handle nested structures
- EventID-scoped enrichment only runs for matching EventIDs — never blindly
- AccessMask decoding is bitwise — each set bit resolved independently
"""

import json
import logging
import re
from pathlib import Path
from typing import Generator

logger = logging.getLogger(__name__)

# Compiled pattern to find %% codes in strings
_PCT_CODE_RE = re.compile(r'%%\d+')

# Compiled pattern to find GUIDs in strings
# Matches {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} — case insensitive
_GUID_RE = re.compile(r'\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}')

# Compiled pattern to find %{guid} format — used in ObjectName field
_PCT_GUID_RE = re.compile(r'%\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}')


class Lookups:
    """
    Container for all loaded lookup tables.
    Loaded once at startup, reused for every record.
    """

    def __init__(
        self,
        master_path: str | Path,
        msobjs_path: str | Path,
        fallback_path: str | Path | None = None,
        logon_types_path: str | Path | None = None,
        ds_access_mask_path: str | Path | None = None,
        ad_guids_path: str | Path | None = None,
        domain_objects_path: str | Path | None = None,
    ):
        """
        Load all lookup files from disk.

        Args:
            master_path:          Path to master_security_auditing_index_micosoft.json (required)
            msobjs_path:          Path to msobjs_lookup.json (required)
            fallback_path:        Path to soc_event_lookup.json (optional)
            logon_types_path:     Path to logon_types.json (optional)
            ds_access_mask_path:  Path to ds_access_mask.json (optional)
            ad_guids_path:        Path to ad_guids.json (optional)
            domain_objects_path:  Path to domain_objects.json (optional)

        Raises:
            FileNotFoundError: If a required lookup file is missing.
        """
        self.event_map: dict[str, str] = {}           # "Provider_EventID" → description
        self.msobjs_map: dict[str, str] = {}          # "%%XXXX" → "%%XXXX (Description)"
        self.logon_types_map: dict[str, str] = {}     # "3" → "3 (Network)"
        self.ds_access_mask_map: dict[int, str] = {}  # 0x40000 → "Write DACL"
        self.ad_guids_map: dict[str, str] = {}        # "{guid}" → "{guid} (Name)"

        # Unresolved value tracking — populated during enrichment, read by main.py
        self.unresolved_pct_codes: set[str] = set()   # %%XXXX codes not in msobjs_map
        self.unresolved_guids: set[str] = set()       # {guid} not in ad_guids_map
        self.unresolved_pct_guids: set[str] = set()   # %{guid} not in ad_guids_map

        self._load_event_map(master_path, fallback_path)
        self._load_msobjs_map(msobjs_path)
        self._load_logon_types_map(logon_types_path)
        self._load_ds_access_mask_map(ds_access_mask_path)
        self._load_ad_guids_map(ad_guids_path)
        self._load_domain_objects_map(domain_objects_path)

    def _load_event_map(
        self,
        master_path: str | Path,
        fallback_path: str | Path | None,
    ) -> None:
        """
        Build event description map.
        Fallback loaded first, master overlays it (master takes priority).
        """
        master_path = Path(master_path)
        if not master_path.exists():
            raise FileNotFoundError(f"Master lookup not found: {master_path}")

        # Load fallback first (lower priority)
        if fallback_path is not None:
            fallback_path = Path(fallback_path)
            if not fallback_path.exists():
                raise FileNotFoundError(f"Fallback lookup not found: {fallback_path}")
            fallback_data = json.loads(fallback_path.read_text(encoding="utf-8-sig"))
            for entry in fallback_data:
                key = f"{entry['Provider']}_{entry['EventID']}"
                self.event_map[key] = entry["Description"]
            logger.info("Loaded %d entries from fallback lookup: %s", len(fallback_data), fallback_path)

        # Load master (overlays fallback — master wins on conflict)
        master_data = json.loads(master_path.read_text(encoding="utf-8-sig"))
        master_count = 0
        for entry in master_data:
            key = f"{entry['Provider']}_{entry['EventID']}"
            self.event_map[key] = entry["Description"]
            master_count += 1
        logger.info("Loaded %d entries from master lookup: %s", master_count, master_path)

    def _load_msobjs_map(self, msobjs_path: str | Path) -> None:
        """
        Build msobjs %% code map.
        Maps "%%XXXX" → "%%XXXX (Description)" for Option B replacement.
        """
        msobjs_path = Path(msobjs_path)
        if not msobjs_path.exists():
            raise FileNotFoundError(f"msobjs lookup not found: {msobjs_path}")

        msobjs_data = json.loads(msobjs_path.read_text(encoding="utf-8-sig"))
        for entry in msobjs_data:
            code = entry["Code"]                            # e.g. "%%1538"
            desc = entry["Description"]                     # e.g. "READ_CONTROL"
            self.msobjs_map[code] = f"{code} ({desc})"     # "%%1538 (READ_CONTROL)"

        logger.info("Loaded %d entries from msobjs lookup: %s", len(msobjs_data), msobjs_path)

    def _load_logon_types_map(self, logon_types_path: str | Path | None) -> None:
        """
        Build logon type map.
        Maps logon type string → "value (Description)" for Option B replacement.

        If logon_types_path is None or file doesn't exist, skips silently —
        logon type enrichment is optional.
        """
        if logon_types_path is None:
            return

        logon_types_path = Path(logon_types_path)
        if not logon_types_path.exists():
            logger.warning("Logon types lookup not found — skipping: %s", logon_types_path)
            return

        data = json.loads(logon_types_path.read_text(encoding="utf-8-sig"))
        for entry in data:
            val = str(entry["LogonType"])           # e.g. "3"
            desc = entry["Description"]             # e.g. "Network"
            self.logon_types_map[val] = f"{val} ({desc})"  # "3 (Network)"

        logger.info("Loaded %d logon type entries from: %s", len(data), logon_types_path)

    def _load_ds_access_mask_map(self, ds_access_mask_path: str | Path | None) -> None:
        """
        Build DS AccessMask bit map.
        Maps integer bit value → human-readable description.
        Keys stored as int for fast bitwise AND checks.

        If ds_access_mask_path is None or file doesn't exist, skips silently.
        """
        if ds_access_mask_path is None:
            return

        ds_access_mask_path = Path(ds_access_mask_path)
        if not ds_access_mask_path.exists():
            logger.warning("DS AccessMask lookup not found — skipping: %s", ds_access_mask_path)
            return

        data = json.loads(ds_access_mask_path.read_text(encoding="utf-8-sig"))
        for entry in data:
            bit = int(entry["Mask"], 16)          # "0x40000" → 262144
            self.ds_access_mask_map[bit] = entry["Description"]

        logger.info("Loaded %d DS AccessMask entries from: %s", len(data), ds_access_mask_path)

    def _load_ad_guids_map(self, ad_guids_path: str | Path | None) -> None:
        """
        Build AD GUID map.
        Maps "{guid}" → "{guid} (Name)" for Option B replacement.
        GUID keys stored in lowercase for case-insensitive matching.

        If ad_guids_path is None or file doesn't exist, skips silently.
        """
        if ad_guids_path is None:
            return

        ad_guids_path = Path(ad_guids_path)
        if not ad_guids_path.exists():
            logger.warning("AD GUIDs lookup not found — skipping: %s", ad_guids_path)
            return

        data = json.loads(ad_guids_path.read_text(encoding="utf-8-sig"))
        for entry in data:
            guid = entry["GUID"].lower()              # normalize to lowercase
            name = entry["Name"]
            self.ad_guids_map[guid] = name            # "{guid}" → "Name"

        logger.info("Loaded %d AD GUID entries from: %s", len(data), ad_guids_path)

    def _load_domain_objects_map(self, domain_objects_path: str | Path | None) -> None:
        """
        Load domain_objects.json and merge into ad_guids_map.
        Merging means both resolve_guids() and resolve_pct_guids() automatically
        benefit from domain object GUIDs without any extra code.

        domain_objects.json takes lower priority — ad_guids_map entries
        already loaded from ad_guids.json are not overwritten.

        If domain_objects_path is None or file doesn't exist, skips silently.
        """
        if domain_objects_path is None:
            return

        domain_objects_path = Path(domain_objects_path)
        if not domain_objects_path.exists():
            logger.warning("Domain objects lookup not found — skipping: %s", domain_objects_path)
            return

        data = json.loads(domain_objects_path.read_text(encoding="utf-8-sig"))
        added = 0
        for entry in data:
            guid = entry["GUID"].lower()
            if guid not in self.ad_guids_map:   # don't overwrite ad_guids entries
                self.ad_guids_map[guid] = entry["Name"]
                added += 1

        logger.info("Merged %d domain object entries from: %s", added, domain_objects_path)

    def resolve_event_description(
        self, provider_name: str | None, event_id: int | str | None
    ) -> str | None:
        """
        Resolve EventDescription for a given Provider + EventID.

        Returns None if not found in either lookup.
        """
        if not provider_name or event_id is None:
            return None
        key = f"{provider_name}_{event_id}"
        return self.event_map.get(key)

    def resolve_logon_type(self, value: str | int | None) -> str | None:
        """
        Resolve a LogonType value using Option B format.
        Returns None if value is None.
        Returns the original value (as string) if not found in map.

        Example:
            "3"  → "3 (Network)"
            "99" → "99"   (unknown — left as-is)
        """
        if value is None:
            return None
        str_val = str(value)
        return self.logon_types_map.get(str_val, str_val)

    def resolve_access_mask(self, value: str | None) -> str | None:
        """
        Decode all set bits in a hex AccessMask value.
        Returns Option B format — original hex kept, descriptions appended.

        Example:
            "0x40100" → "0x40100 (Write DACL | Read Property)"
            "0x0"     → "0x0"       (no bits set — left as-is)
            "garbage" → "garbage"   (not parseable — left as-is)

        Only resolves bits present in ds_access_mask_map.
        Unknown bits are silently ignored (preserved in the hex value).
        """
        if value is None:
            return None

        # Parse hex string to int
        try:
            mask_int = int(value, 16)
        except (ValueError, TypeError):
            return value  # not a valid hex string — leave as-is

        if mask_int == 0:
            return value  # no bits set — leave as-is

        # Decode each set bit via bitwise AND against all known bits
        descriptions = [
            desc
            for bit, desc in sorted(self.ds_access_mask_map.items())
            if mask_int & bit
        ]

        if not descriptions:
            return value  # no known bits matched — leave as-is

        return f"{value} ({' | '.join(descriptions)})"

    def resolve_guids(self, value: str, warnings=None) -> str:
        """
        Replace all GUIDs in a string with Option B format.
        GUIDs not in ad_guids_map are left as-is.
        Unresolved GUIDs added to warnings collector if provided.
        """
        def _replace(match: re.Match) -> str:
            guid = match.group(0)
            name = self.ad_guids_map.get(guid.lower())
            if name:
                return f"{guid} ({name})"
            if warnings is not None:
                warnings.unresolved_guids.add(guid.lower())
            return guid

        return _GUID_RE.sub(_replace, value)

    def resolve_pct_guids(self, value: str, warnings=None) -> str:
        """
        Replace all %{guid} format GUIDs in a string with Option B format.
        Used specifically for the ObjectName field in Event 4662.
        Unresolved GUIDs added to warnings collector if provided.
        """
        def _replace(match: re.Match) -> str:
            pct_guid = match.group(0)
            bare_guid = pct_guid[1:]
            name = self.ad_guids_map.get(bare_guid.lower())
            if name:
                return f"{pct_guid} ({name})"
            if warnings is not None:
                warnings.unresolved_pct_guids.add(pct_guid)
            return pct_guid

        return _PCT_GUID_RE.sub(_replace, value)

    def resolve_pct_codes(self, value: str, warnings=None) -> str:
        """
        Replace all %% codes in a string with Option B format.
        Codes not in msobjs_map are left as-is.
        Unresolved codes added to warnings collector if provided.
        Preserves \r\n\t delimiters.
        """
        def _replace(match: re.Match) -> str:
            code = match.group(0)
            resolved = self.msobjs_map.get(code)
            if resolved:
                return resolved
            if warnings is not None:
                warnings.unresolved_pct_codes.add(code)
            return code

        return _PCT_CODE_RE.sub(_replace, value)


# EventIDs that carry a LogonType field in EventData.
LOGON_TYPE_EVENT_IDS = {4624, 4625, 4648}

# EventIDs that carry an AccessMask field in EventData requiring bitwise decode.
DS_ACCESS_MASK_EVENT_IDS = {4662}

# EventIDs that carry GUIDs in EventData fields (Properties, ObjectType).
DS_GUID_EVENT_IDS = {4662}


def _walk_event_data(obj, fn) -> object:
    """
    Recursively walk EventData, applying fn to all string values.
    Preserves structure — only string leaf values are modified.
    """
    if isinstance(obj, str):
        return fn(obj)
    elif isinstance(obj, dict):
        return {k: _walk_event_data(v, fn) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_walk_event_data(item, fn) for item in obj]
    else:
        return obj


def enrich(
    records: Generator[dict, None, None],
    lookups: Lookups,
    warnings=None,
) -> Generator[dict, None, None]:
    """
    Stream records through enrichment, yielding one enriched dict per record.

    Per record:
    1. Resolve EventDescription from Provider_Name + EventID
    2. Resolve %% codes in all EventData string values (blind — %% prefix is unambiguous)
    3. Resolve LogonType in EventData — scoped to LOGON_TYPE_EVENT_IDS only
    4. Resolve AccessMask in EventData — scoped to DS_ACCESS_MASK_EVENT_IDS only
    5. Resolve GUIDs in EventData — scoped to DS_GUID_EVENT_IDS only

    Args:
        records:  Generator of normalized dicts from transform.py
        lookups:  Loaded Lookups instance
        warnings: Optional PipelineWarnings instance for collecting unresolved values

    Yields:
        Enriched dicts ready for writer.py
    """
    for record in records:
        event_id = record.get("EventID")

        # 1. Resolve EventDescription
        record["EventDescription"] = lookups.resolve_event_description(
            record.get("Provider_Name"),
            event_id,
        )

        # 2. Resolve %% codes in EventData (blind — safe because %% prefix is unambiguous)
        if record.get("EventData") is not None:
            record["EventData"] = _walk_event_data(
                record["EventData"],
                lambda v: lookups.resolve_pct_codes(v, warnings),
            )

        # 3. Resolve LogonType — only for EventIDs that actually carry this field
        if event_id in LOGON_TYPE_EVENT_IDS and isinstance(record.get("EventData"), dict):
            logon_type = record["EventData"].get("LogonType")
            if logon_type is not None:
                record["EventData"]["LogonType"] = lookups.resolve_logon_type(logon_type)

        # 4. Resolve AccessMask — only for EventID 4662 (operation on DS object)
        if event_id in DS_ACCESS_MASK_EVENT_IDS and isinstance(record.get("EventData"), dict):
            access_mask = record["EventData"].get("AccessMask")
            if access_mask is not None:
                record["EventData"]["AccessMask"] = lookups.resolve_access_mask(access_mask)

        # 5. Resolve GUIDs — only for EventID 4662, field-specific:
        #    Properties, ObjectType → bare {guid} format
        #    ObjectName            → %{guid} format
        if event_id in DS_GUID_EVENT_IDS and isinstance(record.get("EventData"), dict):
            ed = record["EventData"]

            for field in ("Properties", "ObjectType"):
                if isinstance(ed.get(field), str):
                    ed[field] = lookups.resolve_guids(ed[field], warnings)

            if isinstance(ed.get("ObjectName"), str):
                ed["ObjectName"] = lookups.resolve_pct_guids(ed["ObjectName"], warnings)

        yield record
