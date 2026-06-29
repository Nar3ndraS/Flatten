"""
warnings_collector.py — Shared warning collector for the evtx pipeline.

A single PipelineWarnings instance is created in main.py and passed
to parser.load() and enricher.enrich(). Each module appends to the
relevant set. At the end main.py writes the file only if non-empty.

Deduplication is automatic — sets are used for GUID/code warnings
so each unique value is recorded once regardless of occurrence count.
"""

from dataclasses import dataclass, field


@dataclass
class PipelineWarnings:
    # Skipped records — list (order matters, includes line numbers)
    skipped_records: list[str] = field(default_factory=list)

    # Unresolved values — sets (deduplicated automatically)
    unresolved_pct_codes:  set[str] = field(default_factory=set)
    unresolved_guids:      set[str] = field(default_factory=set)   # {guid} in Properties/ObjectType
    unresolved_pct_guids:  set[str] = field(default_factory=set)   # %{guid} in ObjectName

    @property
    def is_empty(self) -> bool:
        return (
            not self.skipped_records
            and not self.unresolved_pct_codes
            and not self.unresolved_guids
            and not self.unresolved_pct_guids
        )

    @property
    def total_count(self) -> int:
        return (
            len(self.skipped_records)
            + len(self.unresolved_pct_codes)
            + len(self.unresolved_guids)
            + len(self.unresolved_pct_guids)
        )

    def write(self, path: str) -> None:
        """
        Write warnings to a structured file with sections.
        Only sections with entries are written.
        Should only be called if is_empty is False.
        """
        lines = []

        if self.skipped_records:
            lines.append("── SKIPPED RECORDS " + "─" * 40)
            for msg in self.skipped_records:
                lines.append(msg)
            lines.append("")

        if self.unresolved_pct_codes:
            lines.append("── UNRESOLVED %% CODES " + "─" * 36)
            lines.append("These codes were not found in msobjs_lookup.json — left as-is in output.")
            for code in sorted(self.unresolved_pct_codes):
                lines.append(f"  {code}")
            lines.append("")

        if self.unresolved_guids:
            lines.append("── UNRESOLVED GUIDS (Properties / ObjectType) " + "─" * 13)
            lines.append("These GUIDs were not found in ad_guids.json — left as-is in output.")
            for guid in sorted(self.unresolved_guids):
                lines.append(f"  {guid}")
            lines.append("")

        if self.unresolved_pct_guids:
            lines.append("── UNRESOLVED %{GUID} (ObjectName) " + "─" * 23)
            lines.append("These GUIDs were not found in domain_objects.json — left as-is in output.")
            for guid in sorted(self.unresolved_pct_guids):
                lines.append(f"  {guid}")
            lines.append("")

        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
