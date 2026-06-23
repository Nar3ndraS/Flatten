"""
main.py — CLI entrypoint for evtx_pipeline.

Usage:
    python main.py <input> <output> [options]

Options:
    --master   <file>    Master EventID lookup (default: lookups/master_security_auditing_index_micosoft.json)
    --msobjs   <file>    msobjs %% code lookup (default: lookups/msobjs_lookup.json)
    --lookup   <file>    Optional fallback EventID lookup (e.g. soc_event_lookup.json)
    --warnings <file>    Warnings log path (default: warnings.log)
    --verbose            Enable debug logging

Pipeline flow:
    parser.load()        → raw evtx_dump NDJSON → flat dicts
    transform.reduce_schema() → normalized dicts
    enricher.enrich()    → enriched dicts
    writer.write_ndjson() → NDJSON output for ADX
"""

import argparse
import logging
import sys
from pathlib import Path

import enricher as enricher_mod
import parser as parser_mod
import transform as transform_mod
import writer as writer_mod


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="evtx_pipeline",
        description="Flatten and enrich Windows evtx_dump NDJSON for ADX/Sentinel ingest.",
    )
    p.add_argument("input",  help="Raw evtx_dump NDJSON input file")
    p.add_argument("output", help="Enriched NDJSON output file")

    p.add_argument(
        "--master",
        default=None,
        help="Master EventID lookup JSON (default: lookups/master_security_auditing_index_micosoft.json)",
    )
    p.add_argument(
        "--msobjs",
        default=None,
        help="msobjs %% code lookup JSON (default: lookups/msobjs_lookup.json)",
    )
    p.add_argument(
        "--lookup",
        default=None,
        help="Optional fallback EventID lookup JSON (e.g. soc_event_lookup.json)",
    )
    p.add_argument(
        "--logon-types",
        default=None,
        help="Logon type lookup JSON (default: lookups/logon_types.json)",
    )
    p.add_argument(
        "--ds-access-mask",
        default=None,
        help="DS AccessMask lookup JSON (default: lookups/ds_access_mask.json)",
    )
    p.add_argument(
        "--warnings",
        default="warnings.log",
        help="Path to write skipped-record warnings (default: warnings.log)",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    return p


def setup_logging(warnings_path: str, verbose: bool) -> None:
    """
    Configure logging:
    - INFO+ to stdout
    - WARNING+ to warnings file
    - DEBUG+ to stdout if --verbose
    """
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)

    fmt = logging.Formatter("%(levelname)s %(message)s")

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(fmt)
    root.addHandler(console)

    # Warnings file handler — captures all warnings from all modules
    warn_file = logging.FileHandler(warnings_path, mode="w", encoding="utf-8")
    warn_file.setLevel(logging.WARNING)
    warn_file.setFormatter(fmt)
    root.addHandler(warn_file)


def resolve_lookup_paths(args: argparse.Namespace) -> tuple[Path, Path, Path | None, Path | None, Path | None]:
    script_dir = Path(__file__).parent
    lookups_dir = script_dir / "lookups"

    master_path          = Path(args.master) if args.master else lookups_dir / "master_security_auditing_index_micosoft.json"
    msobjs_path          = Path(args.msobjs) if args.msobjs else lookups_dir / "msobjs_lookup.json"
    fallback_path        = Path(args.lookup) if args.lookup else None
    logon_types_path     = Path(args.logon_types) if args.logon_types else lookups_dir / "logon_types.json"
    ds_access_mask_path  = Path(args.ds_access_mask) if args.ds_access_mask else lookups_dir / "ds_access_mask.json"

    return master_path, msobjs_path, fallback_path, logon_types_path, ds_access_mask_path


def print_header(args, master_path, msobjs_path, fallback_path, logon_types_path, ds_access_mask_path) -> None:
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║         EVTX Pipeline — Python Edition               ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()
    print(f"  Input           : {args.input}")
    print(f"  Output          : {args.output}")
    print(f"  Master          : {master_path}")
    print(f"  msobjs          : {msobjs_path}")
    print(f"  Fallback        : {fallback_path or '(none)'}")
    print(f"  Logon types     : {logon_types_path or '(none)'}")
    print(f"  DS AccessMask   : {ds_access_mask_path or '(none)'}")
    print(f"  Warnings        : {args.warnings}")
    print()


def print_summary(args, master_path, msobjs_path, fallback_path, logon_types_path, ds_access_mask_path, written) -> None:
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║                      SUMMARY                        ║")
    print("╚══════════════════════════════════════════════════════╝")
    print(f"  {'Output records:':<30} {written}")
    print(f"  {'Output:':<30} {args.output}")
    print(f"  {'Master lookup:':<30} {master_path}")
    print(f"  {'msobjs lookup:':<30} {msobjs_path}")
    if fallback_path:
        print(f"  {'Fallback lookup:':<30} {fallback_path}")
    if logon_types_path:
        print(f"  {'Logon types lookup:':<30} {logon_types_path}")
    if ds_access_mask_path:
        print(f"  {'DS AccessMask lookup:':<30} {ds_access_mask_path}")
    print(f"  {'Warnings:':<30} {args.warnings}")
    print()
    print("  Done.")
    print()


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    setup_logging(args.warnings, args.verbose)
    logger = logging.getLogger(__name__)

    master_path, msobjs_path, fallback_path, logon_types_path, ds_access_mask_path = resolve_lookup_paths(args)

    print_header(args, master_path, msobjs_path, fallback_path, logon_types_path, ds_access_mask_path)

    # ── Load lookups ──────────────────────────────────────────────────────────
    logger.info("[ INIT ] Loading lookup files...")
    try:
        lookups = enricher_mod.Lookups(
            master_path=master_path,
            msobjs_path=msobjs_path,
            fallback_path=fallback_path,
            logon_types_path=logon_types_path,
            ds_access_mask_path=ds_access_mask_path,
        )
    except FileNotFoundError as exc:
        logger.error("ERROR: %s", exc)
        sys.exit(1)

    print()

    # ── Pipeline ──────────────────────────────────────────────────────────────
    logger.info("[ STAGE 1 ] Parsing and flattening...")
    records = parser_mod.load(args.input)

    logger.info("[ STAGE 2 ] Normalizing schema...")
    records = transform_mod.reduce_schema(records)

    logger.info("[ STAGE 3 ] Enriching records...")
    records = enricher_mod.enrich(records, lookups)

    logger.info("[ STAGE 4 ] Writing output...")
    print()

    try:
        written = writer_mod.write_ndjson(records, args.output)
    except Exception as exc:
        logger.error("ERROR writing output: %s", exc)
        sys.exit(1)

    print_summary(args, master_path, msobjs_path, fallback_path, logon_types_path, ds_access_mask_path, written)


if __name__ == "__main__":
    main()
