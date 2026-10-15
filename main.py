"""
main.py — CLI entrypoint for evtx_pipeline.

Usage:
    python main.py <input> <output> [options]

Lookup loading is detection-based, not flag-based:
    core/       — mandatory. Must contain master_security_auditing_index_micosoft.json,
                  msobjs_lookup.json and logon_types.json, or the pipeline refuses
                  to start.
    lookups/    — optional. universal/ and environment/ subfolders are scanned;
                  whatever files are present get loaded, whatever's absent is
                  silently skipped. No profile flag needed — presence of a file
                  is the on/off switch for that enrichment step.

Options:
    --core-dir     <dir>   Directory with the mandatory lookups (default: ./core)
    --lookups-dir  <dir>   Directory with universal/ and environment/ subfolders (default: ./lookups)
    --verbose               Enable debug logging

Pipeline flow:
    parser.load()             → raw evtx_dump NDJSON → flat dicts
    transform.filter_events() → drops disallowed events (e.g. PowerShell other than 4103/4104)
    transform.reduce_schema() → normalized dicts
    enricher.enrich()         → enriched dicts
    writer.write_ndjson()     → NDJSON output for ADX
"""

import argparse
import logging
import sys
from pathlib import Path

import enricher as enricher_mod
import parser as parser_mod
import transform as transform_mod
import writer as writer_mod
from warnings_collector import PipelineWarnings


# ── Terminal colors ───────────────────────────────────────────────────────────
class C:
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    DIM    = "\033[2m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def _c(color: str, text: str) -> str:
    return f"{color}{text}{C.RESET}"

def _row(label: str, value: str, label_width: int = 18) -> None:
    print(f"  {_c(C.DIM, label.ljust(label_width))}  {_c(C.WHITE, str(value))}")

def _sep() -> None:
    print(f"  {_c(C.DIM, '─' * 52)}")

def _stage(n: int, label: str) -> None:
    print(f"\n  {_c(C.CYAN, f'[{n}/4]')} {_c(C.WHITE, label)}")


def print_help() -> None:
    """Print styled help menu matching the pipeline UI."""
    print()
    print(f"  {_c(C.CYAN + C.BOLD, 'evtx-pipeline')}{_c(C.DIM, '  ·  python edition')}")
    _sep()
    print(f"  {_c(C.WHITE, 'Flatten and enrich Windows evtx_dump NDJSON for ADX / Sentinel ingest.')}")
    print()

    # Quick examples
    print(f"  {_c(C.CYAN + C.BOLD, 'quick start')}")
    _sep()

    examples = [
        ("basic run",
         "python main.py raw.json out.ndjson",
         "Loads whatever's present in ./core and ./lookups"),
        ("custom lookup dirs",
         "python main.py raw.json out.ndjson --core-dir /path/to/core --lookups-dir /path/to/lookups",
         "Point at a different environment's generated lookups"),
        ("debug mode",
         "python main.py raw.json out.ndjson --verbose",
         "Shows detailed logging output"),
    ]

    for label, cmd, desc in examples:
        print(f"  {_c(C.DIM, label)}")
        print(f"    {_c(C.WHITE, cmd)}")
        print(f"    {_c(C.DIM, desc)}")
        print()

    # Lookup layout
    print(f"  {_c(C.CYAN + C.BOLD, 'lookup layout (detection-based — no profile flag)')}")
    _sep()
    print(f"  {_c(C.WHITE, 'core/')}  {_c(C.DIM, '(mandatory — pipeline refuses to start without all three)')}")
    print(f"  {_c(C.DIM, '  master_security_auditing_index_micosoft.json')}")
    print(f"  {_c(C.DIM, '  msobjs_lookup.json')}")
    print(f"  {_c(C.DIM, '  logon_types.json')}")
    print()
    print(f"  {_c(C.WHITE, 'lookups/universal/')}  {_c(C.DIM, '(optional — loaded if present)')}")
    print(f"  {_c(C.DIM, '  universal_ds_access_mask.json')}")
    print(f"  {_c(C.DIM, '  universal_soc_event_lookup.json')}")
    print()
    print(f"  {_c(C.WHITE, 'lookups/environment/')}  {_c(C.DIM, '(optional — loaded if present, forest-specific)')}")
    print(f"  {_c(C.DIM, '  environment_ad_guids.json')}")
    print(f"  {_c(C.DIM, '  environment_domain_objects.json')}")
    print()

    # Options
    print(f"  {_c(C.CYAN + C.BOLD, 'options')}")
    _sep()

    opts = [
        ("--core-dir <dir>",     "directory with the mandatory lookups  (default: ./core)"),
        ("--lookups-dir <dir>",  "directory with universal/ + environment/  (default: ./lookups)"),
        ("--verbose",             "enable debug logging"),
        ("-h, --help",            "show this help"),
    ]

    for flag, desc in opts:
        print(f"  {_c(C.WHITE, flag.ljust(24))}  {_c(C.DIM, desc)}")

    print()


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="evtx_pipeline",
        add_help=False,  # we handle help ourselves
        description="Flatten and enrich Windows evtx_dump NDJSON for ADX/Sentinel ingest.",
    )
    p.add_argument("input",  nargs="?", help="Raw evtx_dump NDJSON input file")
    p.add_argument("output", nargs="?", help="Enriched NDJSON output file")

    p.add_argument("--core-dir",    default="core")
    p.add_argument("--lookups-dir", default="lookups")
    p.add_argument("--verbose",     action="store_true")
    p.add_argument("-h", "--help",  action="store_true")
    return p


def setup_logging(verbose: bool) -> None:
    """
    Configure logging:
    - Normal mode: all log output is suppressed. Skipped records and unresolved
      values are reported through PipelineWarnings / warnings.log instead.
    - --verbose: DEBUG+ to stdout.
    """
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.WARNING)

    if verbose:
        fmt = logging.Formatter("%(levelname)s %(message)s")
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(logging.DEBUG)
        console.setFormatter(fmt)
        root.addHandler(console)
    else:
        # A handler must exist, otherwise Python's last-resort handler prints
        # every WARNING to stderr and duplicates warnings.log.
        root.addHandler(logging.NullHandler())


def _detect_active_lookups(core_dir: Path, lookups_dir: Path) -> dict[str, bool]:
    """
    Report which optional lookup files are present, for the header display.
    Detection logic mirrors enricher.Lookups.__init__ exactly.
    (core/ files are mandatory, so they are not listed here.)
    """
    universal_dir = lookups_dir / "universal"
    environment_dir = lookups_dir / "environment"

    return {
        "universal_ds_access_mask.json":   (universal_dir / "universal_ds_access_mask.json").exists(),
        "universal_soc_event_lookup.json": (universal_dir / "universal_soc_event_lookup.json").exists(),
        "environment_ad_guids.json":       (environment_dir / "environment_ad_guids.json").exists(),
        "environment_domain_objects.json": (environment_dir / "environment_domain_objects.json").exists(),
    }


def print_header(args, core_dir: Path, lookups_dir: Path, active: dict[str, bool]) -> None:
    print()
    print(f"  {_c(C.CYAN + C.BOLD, 'evtx-pipeline')}{_c(C.DIM, '  ·  python edition')}")
    _sep()

    _row("input",  args.input)
    _row("output", args.output)
    _sep()

    _row("core dir",    str(core_dir))
    _row("lookups dir", str(lookups_dir))
    _sep()

    for filename, is_active in active.items():
        status = _c(C.GREEN, "active") if is_active else _c(C.DIM, "not found — skipped")
        _row(filename, status)
    print()


def print_summary(args, written: int, pipeline_warnings: PipelineWarnings, stats: dict) -> None:
    print()
    _sep()
    print(f"  {_c(C.CYAN + C.BOLD, 'summary')}")
    _sep()
    _row("records written", _c(C.GREEN, f"{written:,}"))

    filtered = stats.get("filtered", 0)
    if filtered:
        _row("filtered out", _c(C.DIM, f"{filtered:,}"))

    _row("output",          args.output)

    if not pipeline_warnings.is_empty:
        _row("warnings", _c(C.RED, f"{pipeline_warnings.total_count} — see warnings.log"))
    else:
        _row("warnings", _c(C.DIM, "none"))

    _sep()
    status = _c(C.GREEN, "✓  done") if pipeline_warnings.is_empty else _c(C.YELLOW, "✓  done with warnings")
    print(f"\n  {status}\n")


def main() -> None:
    parser = build_arg_parser()
    args   = parser.parse_args()

    # Show help if -h or no input/output provided
    if args.help or not args.input or not args.output:
        print_help()
        sys.exit(0)

    setup_logging(args.verbose)

    pw = PipelineWarnings()
    stats = {"filtered": 0}

    core_dir    = Path(args.core_dir)
    lookups_dir = Path(args.lookups_dir)

    active = _detect_active_lookups(core_dir, lookups_dir)
    print_header(args, core_dir, lookups_dir, active)

    # ── Load lookups ──────────────────────────────────────────────────────────
    _stage(0, "Loading lookups...")
    try:
        lookups = enricher_mod.Lookups(
            core_dir=core_dir,
            lookups_dir=lookups_dir,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"\n  {_c(C.RED, '✗')} {_c(C.WHITE, str(exc))}\n")
        sys.exit(1)

    # ── Pipeline ──────────────────────────────────────────────────────────────
    _stage(1, "Parsing and flattening...")
    records = parser_mod.load(args.input, warnings=pw)

    _stage(2, "Filtering and normalizing schema...")
    records = transform_mod.filter_events(records, stats)
    records = transform_mod.reduce_schema(records)

    _stage(3, "Enriching records...")
    records = enricher_mod.enrich(records, lookups, warnings=pw)

    _stage(4, "Writing output...")
    try:
        written = writer_mod.write_ndjson(records, args.output)
    except Exception as exc:
        print(f"\n  {_c(C.RED, '✗')} {_c(C.WHITE, str(exc))}\n")
        sys.exit(1)

    # ── Write warnings file only if non-empty ────────────────────────────────
    if not pw.is_empty:
        pw.write("warnings.log")

    print_summary(args, written, pw, stats)


if __name__ == "__main__":
    main()
