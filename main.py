"""
main.py — CLI entrypoint for evtx_pipeline.

Usage:
    python main.py <input> <output> [options]

Profiles:
    (none)            Universal — skips environment-specific lookups (ad_guids, domain_objects)
    --profile default Full — loads all lookups including environment-specific ones

Options:
    --profile  <name>    Lookup profile: default (full) or universal (default: universal)
    --master   <file>    Master EventID lookup (default: lookups/master_security_auditing_index_micosoft.json)
    --msobjs   <file>    msobjs %% code lookup (default: lookups/msobjs_lookup.json)
    --lookup   <file>    Optional fallback EventID lookup (e.g. soc_event_lookup.json)
    --verbose            Enable debug logging

Pipeline flow:
    parser.load()             → raw evtx_dump NDJSON → flat dicts
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


# ── In-memory warning collector ───────────────────────────────────────────────
class WarningCollector(logging.Handler):
    """Captures all WARNING+ log records into a list for display at summary time."""
    def __init__(self):
        super().__init__(logging.WARNING)
        self.records: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record.getMessage())


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
        ("universal (default)",
         "python main.py raw.json out.ndjson",
         "Any logs — skips environment-specific lookups"),
        ("with fallback lookup",
         "python main.py raw.json out.ndjson --lookup lookups/soc_event_lookup.json",
         "Adds fallback EventID descriptions"),
        ("lab / domain logs",
         "python main.py raw.json out.ndjson --profile default",
         "Loads all lookups including AD GUIDs and domain objects"),
        ("lab + fallback",
         "python main.py raw.json out.ndjson --profile default --lookup lookups/soc_event_lookup.json",
         "Full enrichment for blues.lab logs"),
        ("debug mode",
         "python main.py raw.json out.ndjson --verbose",
         "Shows detailed logging output"),
    ]

    for label, cmd, desc in examples:
        print(f"  {_c(C.DIM, label)}")
        print(f"    {_c(C.WHITE, cmd)}")
        print(f"    {_c(C.DIM, desc)}")
        print()

    # Profiles
    print(f"  {_c(C.CYAN + C.BOLD, 'profiles')}")
    _sep()
    print(f"  {_c(C.CYAN, 'universal')}  {_c(C.DIM, '(default)')}")
    print(f"  {_c(C.DIM, '  Skips ad_guids.json and domain_objects.json.')}")
    print(f"  {_c(C.DIM, '  Use for any logs — CTF, DFIR, unknown environments.')}")
    print()
    print(f"  {_c(C.YELLOW, 'default')}")
    print(f"  {_c(C.DIM, '  Loads all lookups including environment-specific ones.')}")
    print(f"  {_c(C.DIM, '  Use for blues.lab domain logs.')}")
    print()

    # Options
    print(f"  {_c(C.CYAN + C.BOLD, 'options')}")
    _sep()

    opts = [
        ("--profile <name>",      "universal or default  (default: universal)"),
        ("--lookup  <file>",      "fallback EventID lookup  e.g. soc_event_lookup.json"),
        ("--master  <file>",      "override master lookup path"),
        ("--msobjs  <file>",      "override msobjs lookup path"),
        ("--logon-types <file>",  "override logon types lookup path"),
        ("--ds-access-mask <f>",  "override DS access mask lookup path"),
        ("--ad-guids <file>",     "override AD GUIDs lookup path  (default profile only)"),
        ("--domain-objects <f>",  "override domain objects lookup path  (default profile only)"),
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

    p.add_argument("--profile",        choices=["universal", "default"], default="universal")
    p.add_argument("--master",         default=None)
    p.add_argument("--msobjs",         default=None)
    p.add_argument("--lookup",         default=None)
    p.add_argument("--logon-types",    default=None)
    p.add_argument("--domain-objects", default=None)
    p.add_argument("--ad-guids",       default=None)
    p.add_argument("--ds-access-mask", default=None)
    p.add_argument("--verbose",        action="store_true")
    p.add_argument("-h", "--help",     action="store_true")
    return p


def setup_logging(collector: WarningCollector, verbose: bool) -> None:
    """
    Configure logging:
    - WARNING+ captured by WarningCollector for summary display
    - DEBUG+ to stdout only if --verbose
    - INFO suppressed in normal mode (stages handle progress display)
    """
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.WARNING)

    # Always attach warning collector
    root.addHandler(collector)

    if verbose:
        fmt = logging.Formatter("%(levelname)s %(message)s")
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(logging.DEBUG)
        console.setFormatter(fmt)
        root.addHandler(console)


def resolve_lookup_paths(args: argparse.Namespace):
    script_dir = Path(__file__).parent
    lookups_dir = script_dir / "lookups"

    master_path         = Path(args.master) if args.master else lookups_dir / "master_security_auditing_index_micosoft.json"
    msobjs_path         = Path(args.msobjs) if args.msobjs else lookups_dir / "msobjs_lookup.json"
    fallback_path       = Path(args.lookup) if args.lookup else None
    logon_types_path    = Path(args.logon_types) if args.logon_types else lookups_dir / "logon_types.json"
    ds_access_mask_path = Path(args.ds_access_mask) if args.ds_access_mask else lookups_dir / "ds_access_mask.json"

    if args.profile == "default":
        ad_guids_path       = Path(args.ad_guids) if args.ad_guids else lookups_dir / "ad_guids.json"
        domain_objects_path = Path(args.domain_objects) if args.domain_objects else lookups_dir / "domain_objects.json"
    else:
        ad_guids_path       = None
        domain_objects_path = None

    return master_path, msobjs_path, fallback_path, logon_types_path, ds_access_mask_path, ad_guids_path, domain_objects_path


def print_header(args, master_path, msobjs_path, fallback_path, logon_types_path, ds_access_mask_path, ad_guids_path, domain_objects_path) -> None:
    print()
    print(f"  {_c(C.CYAN + C.BOLD, 'evtx-pipeline')}{_c(C.DIM, '  ·  python edition')}")
    _sep()

    profile_color = C.YELLOW if args.profile == "default" else C.CYAN
    _row("profile", _c(profile_color, args.profile))
    _sep()

    _row("input",  args.input)
    _row("output", args.output)
    _sep()

    _row("master",         master_path.name)
    _row("msobjs",         msobjs_path.name)
    _row("fallback",       fallback_path.name if fallback_path else _c(C.DIM, "none"))
    _row("logon types",    logon_types_path.name if logon_types_path else _c(C.DIM, "none"))
    _row("ds access mask", ds_access_mask_path.name if ds_access_mask_path else _c(C.DIM, "none"))
    _row("ad guids",       ad_guids_path.name if ad_guids_path else _c(C.DIM, "none"))
    _row("domain objects", domain_objects_path.name if domain_objects_path else _c(C.DIM, "none"))
    print()


def print_summary(args, written: int, pipeline_warnings: PipelineWarnings) -> None:
    print()
    _sep()
    print(f"  {_c(C.CYAN + C.BOLD, 'summary')}")
    _sep()
    _row("records written", _c(C.GREEN, f"{written:,}"))
    _row("output",          args.output)
    _row("profile",         args.profile)

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

    collector = WarningCollector()
    setup_logging(collector, args.verbose)

    pw = PipelineWarnings()

    master_path, msobjs_path, fallback_path, logon_types_path, ds_access_mask_path, ad_guids_path, domain_objects_path = resolve_lookup_paths(args)

    print_header(args, master_path, msobjs_path, fallback_path, logon_types_path, ds_access_mask_path, ad_guids_path, domain_objects_path)

    # ── Load lookups ──────────────────────────────────────────────────────────
    _stage(0, "Loading lookups...")
    try:
        lookups = enricher_mod.Lookups(
            master_path=master_path,
            msobjs_path=msobjs_path,
            fallback_path=fallback_path,
            logon_types_path=logon_types_path,
            ds_access_mask_path=ds_access_mask_path,
            ad_guids_path=ad_guids_path,
            domain_objects_path=domain_objects_path,
        )
    except FileNotFoundError as exc:
        print(f"\n  {_c(C.RED, '✗')} {_c(C.WHITE, str(exc))}\n")
        sys.exit(1)

    # ── Pipeline ──────────────────────────────────────────────────────────────
    _stage(1, "Parsing and flattening...")
    records = parser_mod.load(args.input, warnings=pw)

    _stage(2, "Normalizing schema...")
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

    print_summary(args, written, pw)


if __name__ == "__main__":
    main()
