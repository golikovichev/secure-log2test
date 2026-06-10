"""CLI entry for secure-log2test.

Wired through `console_scripts` entry in pyproject.toml so installs expose
a `secure-log2test` command. Also runnable via `python -m secure_log2test`.

The CLI forces stdout and stderr to UTF-8 before any write. Without this,
Windows shells default to cp1252 and the moment a generated test name or
parser warning includes a non-ASCII byte (Cyrillic header values, accented
endpoint slugs, emoji in log payloads) Python raises UnicodeEncodeError and
the run dies before producing the output file. This is the same family of
bug that v1.0.1 patched on the read side; the write side now matches.
"""

from __future__ import annotations

import argparse
import io
import logging
import sys
from pathlib import Path

from .core.generator import KibanaTestGenerator
from .core.parser import REDACTED, KibanaLogParser


DEFAULT_MAX_INPUT_MB = 100
SKIP_RATIO_LIMIT = 0.5


def _nonempty_marker(value: str) -> str:
    """argparse type for --redact-marker: reject an empty / whitespace marker.

    An empty marker would silently strip the value with nothing in its place,
    defeating the point of redaction, so it is rejected with a clear message.
    """
    if not value.strip():
        raise argparse.ArgumentTypeError(
            "--redact-marker must not be empty; pass a non-blank string "
            'such as "[SCRUBBED]"'
        )
    return value


def _ensure_utf8_stream(stream):
    """Reconfigure a text stream to UTF-8 if the platform allows it.

    Returns True when the stream now writes UTF-8, False when the call was
    a no-op (stream lacks `reconfigure`, e.g. it was replaced with a plain
    `io.StringIO` in tests, the attribute exists but is not callable, or
    the reconfigure raised). The boolean is primarily for unit-test
    assertions; callers can ignore it.
    """
    reconfigure = getattr(stream, "reconfigure", None)
    if not callable(reconfigure):
        return False
    try:
        reconfigure(encoding="utf-8", errors="backslashreplace")
    except (OSError, ValueError, TypeError, io.UnsupportedOperation):
        return False
    return True


def ensure_utf8_streams():
    """Apply UTF-8 to both stdout and stderr; safe to call more than once.

    Called from `main()` rather than at module import on purpose. Mutating
    `sys.stdout` at import would surprise embedders and pytest plugins that
    capture stdio before our code runs.
    """
    _ensure_utf8_stream(sys.stdout)
    _ensure_utf8_stream(sys.stderr)


def main(argv: list[str] | None = None) -> int:
    ensure_utf8_streams()
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
    parser.add_argument(
        "--max-input-mb",
        type=int,
        default=DEFAULT_MAX_INPUT_MB,
        help=(
            "Reject input files larger than this size in MB "
            f"(default: {DEFAULT_MAX_INPUT_MB}). Use 0 to disable the check."
        ),
    )
    parser.add_argument(
        "--redact-marker",
        type=_nonempty_marker,
        default=REDACTED,
        help=(
            "Replacement string for redacted secrets "
            f'(default: "{REDACTED}"). Example: --redact-marker "[SCRUBBED]"'
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

    log_parser = KibanaLogParser(args.input, redact_marker=args.redact_marker)
    entries = log_parser.parse()
    if not entries:
        print("No entries parsed from input log.", file=sys.stderr)
        return 1

    generator = KibanaTestGenerator(args.templates)
    generator.write(
        entries,
        args.output,
        base_url=args.base_url,
        output_format=args.format,
        redact_marker=args.redact_marker,
    )

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
