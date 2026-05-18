"""Tests for the CLI safeguards added in v1.2:

- --max-input-mb rejects oversized files before the parser runs.
- Skip count surfaces on the success path so users see how much got dropped.
- Exit code is non-zero when the skip ratio exceeds 50%, which usually
  means the input shape is wrong and the generated suite is useless.
"""

import json
from pathlib import Path


from secure_log2test.cli import main as cli_main
from secure_log2test.core.parser import KibanaLogParser


def _write_kibana_export(path: Path, source_records):
    payload = {
        "hits": {
            "total": {"value": len(source_records), "relation": "eq"},
            "hits": [{"_source": rec} for rec in source_records],
        }
    }
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def _good_record(method="GET", status=200):
    return {
        "method": method,
        "url": "/api/v1/items",
        "status": status,
        "duration": 5,
        "headers": {"Accept": "application/json"},
        "body": None,
    }


def _broken_record():
    # Missing required fields: method, url, status.
    return {"foo": "bar"}


def test_parser_tracks_attempted_and_skipped_counts(tmp_path):
    path = tmp_path / "mixed.json"
    _write_kibana_export(
        path,
        [_good_record(), _broken_record(), _good_record("POST", 201), _broken_record()],
    )
    parser = KibanaLogParser(path)
    entries = parser.parse()
    assert len(entries) == 2
    assert parser.attempted == 4
    assert parser.skipped == 2


def test_cli_rejects_input_above_max_input_mb(tmp_path, capsys):
    path = tmp_path / "big.json"
    # 2 MB body of arbitrary JSON-safe ASCII.
    path.write_text(
        '{"hits": {"hits": []}}\n' + ("x" * (2 * 1024 * 1024)), encoding="utf-8"
    )
    exit_code = cli_main(
        [str(path), "--max-input-mb", "1", "--output", str(tmp_path / "out.py")]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "exceeds the --max-input-mb limit" in captured.err


def test_cli_zero_disables_size_check(tmp_path, capsys):
    path = tmp_path / "small_but_zero_check.json"
    _write_kibana_export(path, [_good_record()])
    out = tmp_path / "out.py"
    exit_code = cli_main([str(path), "--max-input-mb", "0", "--output", str(out)])
    assert exit_code == 0
    assert out.exists()


def test_cli_surfaces_skip_summary_in_stdout(tmp_path, capsys):
    path = tmp_path / "with_skip.json"
    _write_kibana_export(
        path,
        [
            _good_record(),
            _good_record("POST", 201),
            _good_record("PUT", 204),
            _broken_record(),
        ],
    )
    out = tmp_path / "out.py"
    exit_code = cli_main([str(path), "--output", str(out)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "attempted 4" in captured.out
    assert "skipped 1" in captured.out
    assert "ratio 25%" in captured.out


def test_cli_exits_non_zero_when_skip_ratio_exceeds_limit(tmp_path, capsys):
    path = tmp_path / "mostly_broken.json"
    # 3 broken, 1 good = 75% skipped, well above the 50% threshold.
    _write_kibana_export(
        path,
        [_broken_record(), _broken_record(), _broken_record(), _good_record()],
    )
    out = tmp_path / "out.py"
    exit_code = cli_main([str(path), "--output", str(out)])
    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Skip ratio" in captured.err
