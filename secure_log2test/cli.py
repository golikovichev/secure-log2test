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
        "--format",
        choices=["pytest", "json", "csv"],
        default="pytest",
        help="Output format (default: pytest)",
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

    log_parser = KibanaLogParser(args.input)
    entries = log_parser.parse()
    if not entries:
        print("No entries parsed from input log.", file=sys.stderr)
        return 1

    generator = KibanaTestGenerator(args.templates)
    generator.write(
        entries, args.output, base_url=args.base_url, output_format=args.format
    )
    print(f"Generated {len(entries)} tests -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
