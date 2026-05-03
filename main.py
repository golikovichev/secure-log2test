import argparse
import logging
import sys
from pathlib import Path

from core.parser import KibanaLogParser
from core.generator import KibanaTestGenerator


def main():
    parser = argparse.ArgumentParser(
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
        help="Templates directory (default: ./templates)",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

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
    generator.write(entries, args.output, base_url=args.base_url)
    print(f"Generated {len(entries)} tests -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
