"""Targeted tests for the few branches not exercised by the main suites.

Each test here covers one specific line or branch. Splitting them out keeps
the topical files (parser, CLI guards, generator safety) focused on what
they document rather than on chasing the last percent.

Branches covered:

- ``secure_log2test.__init__`` fallback when the package is not installed
  (``PackageNotFoundError`` from ``importlib.metadata.version``).
- ``secure_log2test.__main__`` import path for ``python -m secure_log2test``.
- ``cli.main`` returning 1 when the input file does not exist.
- ``cli.main`` returning 1 when the parser produces zero entries.
- ``KibanaTestGenerator.render`` accepting raw dicts as well as model
  instances.
- ``KibanaLogParser.parse`` wrapping a ``UnicodeDecodeError`` from the open
  call into a ``ValueError`` with a helpful hint.
"""

import importlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from secure_log2test.cli import main as cli_main
from secure_log2test.core.generator import KibanaTestGenerator
from secure_log2test.core.parser import KibanaLogParser


def test_version_falls_back_when_distribution_metadata_missing(monkeypatch):
    """If the package is imported from a source checkout (no installed
    distribution) the version helper raises ``PackageNotFoundError`` and the
    module exposes the ``0.0.0+unknown`` sentinel instead of crashing."""
    import importlib.metadata as md
    import secure_log2test as pkg

    def _raise(_name):
        raise md.PackageNotFoundError("secure-log2test")

    monkeypatch.setattr(md, "version", _raise)
    reloaded = importlib.reload(pkg)
    try:
        assert reloaded.__version__ == "0.0.0+unknown"
    finally:
        # Reload once more without the patch so other tests see the real
        # version string.
        monkeypatch.undo()
        importlib.reload(pkg)


def test_python_dash_m_entry_runs_cli(tmp_path):
    """``python -m secure_log2test`` should reach the CLI parser. We pass a
    missing-input path so the run exits 1 quickly without doing real work."""
    missing = tmp_path / "does_not_exist.json"
    result = subprocess.run(
        [sys.executable, "-m", "secure_log2test", str(missing)],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert result.returncode == 1
    assert "Input file not found" in result.stderr


def test_main_module_imports_cli_main():
    """Direct import covers the ``from .cli import main`` line in
    ``__main__.py``. The subprocess test above exercises behaviour but
    runs in a separate interpreter so its coverage does not roll up here."""
    import secure_log2test.__main__ as dunder_main

    assert dunder_main.main is not None
    assert callable(dunder_main.main)


def test_cli_reports_missing_input(tmp_path, capsys):
    missing = tmp_path / "nope.json"
    exit_code = cli_main([str(missing), "--output", str(tmp_path / "out.py")])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Input file not found" in captured.err


def test_cli_returns_one_when_no_entries_parsed(tmp_path, capsys):
    """Empty ``hits`` list parses cleanly but yields zero entries; the CLI
    should bail out with exit 1 rather than write an empty test file."""
    path = tmp_path / "empty.json"
    path.write_text(
        json.dumps({"hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}}),
        encoding="utf-8",
    )
    out = tmp_path / "out.py"
    exit_code = cli_main([str(path), "--output", str(out)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "No entries parsed" in captured.err
    assert not out.exists()


def test_generator_accepts_raw_dict_entries(tmp_path):
    """The render path coerces plain dicts into ``KibanaLogEntry`` so callers
    that already validated their data upstream do not have to double-wrap."""
    templates_dir = (
        Path(__file__).resolve().parents[1] / "secure_log2test" / "templates"
    )
    generator = KibanaTestGenerator(templates_dir)
    raw = {
        "method": "GET",
        "url": "/api/v1/ping",
        "status": 200,
        "duration": 1,
        "headers": {"Accept": "application/json"},
        "body": None,
    }
    rendered = generator.render([raw], base_url="https://example.test")
    assert "def test_get_api_v1_ping" in rendered
    assert "https://example.test" in rendered


def test_parser_wraps_unicode_decode_error(tmp_path):
    """The parser opens the export as utf-8-sig. A file that starts with a
    legitimate-looking byte but contains an invalid utf-8 continuation
    should surface as a ``ValueError`` that names the path."""
    path = tmp_path / "broken.json"
    # 0xFF on its own is not valid utf-8 and is not the utf-8 BOM.
    path.write_bytes(b"\xff\xfe not really utf-8 here")
    parser = KibanaLogParser(path)
    with pytest.raises(ValueError) as exc:
        parser.parse()
    assert "Could not decode" in str(exc.value)
    assert str(path) in str(exc.value) or path.name in str(exc.value)
