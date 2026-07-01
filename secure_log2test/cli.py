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

from .core.assertions import AssertionMatcher, load_assertion_config
from .core.generator import KibanaTestGenerator
from .core.parser import (
    REDACTED,
    KibanaLogParser,
    LokiLogParser,
    SplunkLogParser,
    detect_source,
)


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


def _nonneg_int(value: str) -> int:
    """argparse type for --max-input-mb: reject a negative size limit.

    0 disables the size check on purpose. A negative value is a typo (for
    example -100 meant as 100) that would otherwise fall through the
    `> 0` guard and silently disable the check, removing the size
    protection without warning. Reject it with a clear message instead.
    """
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"--max-input-mb must be an integer, got {value!r}"
        ) from None
    if parsed < 0:
        raise argparse.ArgumentTypeError(
            "--max-input-mb must be 0 (disable) or a positive number of MB; "
            f"got {parsed}"
        )
    return parsed


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
        description="Convert a Kibana or Splunk API log export to an "
        "executable pytest suite",
    )
    parser.add_argument(
        "input", type=Path, help="Path to a Kibana JSON or Splunk CSV/JSON export"
    )
    parser.add_argument(
        "--source",
        choices=["auto", "kibana", "splunk", "loki"],
        default="auto",
        help=(
            "Input log source (default: auto-detect). kibana = Elasticsearch "
            "hits export; splunk = Splunk search export (CSV or JSON); "
            "loki = Grafana Loki Explore export (JSON or CSV)."
        ),
    )
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
        type=_nonneg_int,
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
    parser.add_argument(
        "--assert-config",
        type=Path,
        default=None,
        help=(
            "Path to a JSON assertion config that adds response-body checks "
            "(field equality and optional JSON Schema) per endpoint to the "
            "generated pytest suite. Only applies to --format pytest."
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

    source = args.source if args.source != "auto" else detect_source(args.input)
    parsers = {
        "kibana": KibanaLogParser,
        "splunk": SplunkLogParser,
        "loki": LokiLogParser,
    }
    parser_cls = parsers.get(source, KibanaLogParser)
    log_parser = parser_cls(args.input, redact_marker=args.redact_marker)
    entries = log_parser.parse()
    if not entries:
        print("No entries parsed from input log.", file=sys.stderr)
        return 1

    matcher = None
    if args.assert_config is not None:
        if args.format != "pytest":
            print(
                "--assert-config only applies to --format pytest; ignoring it "
                f"for --format {args.format}.",
                file=sys.stderr,
            )
        else:
            try:
                matcher = AssertionMatcher(load_assertion_config(args.assert_config))
            except ValueError as e:
                print(str(e), file=sys.stderr)
                return 1
            # An assertion rule that matches no request is almost always a typo
            # in method/url; warn so it is not silently dropped.
            matched_ids = {id(rule) for e in entries for rule in matcher.for_entry(e)}
            for rule in matcher.rules:
                if id(rule) not in matched_ids:
                    print(
                        f"Assertion rule for {rule.method} {rule.url} matched no "
                        f"requests in the log; check its method and url.",
                        file=sys.stderr,
                    )

    generator = KibanaTestGenerator(args.templates)
    generator.write(
        entries,
        args.output,
        base_url=args.base_url,
        output_format=args.format,
        redact_marker=args.redact_marker,
        matcher=matcher,
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
