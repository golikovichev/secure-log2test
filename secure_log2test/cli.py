"""CLI entry for secure-log2test.

Wired through `console_scripts` entry в pyproject.toml so installs expose
a `secure-log2test` command. Also runnable via `python -m secure_log2test`.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .core.generator import KibanaTestGenerator
from .core.parser import KibanaLogParser


DEFAULT_MAX_INPUT_MB = 100
SKIP_RATIO_LIMIT = 0.5


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="secure-log2test",
        description="Convert Kibana API log export to executable pytest suite",
    )
    parser.add_argument("input", type=Path, help="Path to Kibana JSON export")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("tests_generated.py"),
        help="Output pytest module (default: tests_generated.py)",
    )
    parser.add_argument(
        "--base-url",
        default="",
        help="Base URL prefix for generated requests (default: empty)",
    )
    parser.add_argument(
        "--templates",
        type=Path,
        default=Path(__file__).parent / "templates",
        help="Templates directory (default: bundled package templates)",
    )
    parser.add_argument(
        "--max-input-mb",
        type=int,
        default=DEFAULT_MAX_INPUT_MB,
        help=(
            "Reject input files larger than this size in MB "
            f"(default: {DEFAULT_MAX_INPUT_MB}). Use 0 to disable the check."
        ),
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    if not args.input.exists():
        print(f"Input file not found: {args.input}", file=sys.stderr)
        return 1

    if args.max_input_mb > 0:
        size_bytes = args.input.stat().st_size
        size_mb = size_bytes / (1024 * 1024)
        if size_mb > args.max_input_mb:
            print(
                f"Input file is {size_mb:.1f} MB which exceeds the "
                f"--max-input-mb limit of {args.max_input_mb} MB. "
                f"Re-run with --max-input-mb 0 to disable the check "
                f"or pass a larger limit.",
                file=sys.stderr,
            )
            return 1

    log_parser = KibanaLogParser(args.input)
    entries = log_parser.parse()
    if not entries:
        print("No entries parsed from input log.", file=sys.stderr)
        return 1

    generator = KibanaTestGenerator(args.templates)
    generator.write(entries, args.output, base_url=args.base_url)

    attempted = log_parser.attempted
    skipped = log_parser.skipped
    ratio = (skipped / attempted) if attempted else 0.0
    summary = (
        f"Generated {len(entries)} tests -> {args.output} "
        f"(attempted {attempted}, skipped {skipped}, ratio {ratio:.0%})"
    )
    print(summary)

    if ratio > SKIP_RATIO_LIMIT:
        print(
            f"Skip ratio {ratio:.0%} exceeds {SKIP_RATIO_LIMIT:.0%}. "
            f"Run with --verbose to inspect parser warnings, "
            f"or fix the source export.",
            file=sys.stderr,
        )
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
