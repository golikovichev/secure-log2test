"""Tests for Grafana Loki Explore export parsing (issue #4).

Loki exports from the Grafana Explore UI as a top-level list (JSON) or a
flat table (CSV) where each row carries a stringified inner JSON payload in
``line`` / ``Line`` plus Loki label columns. The inner payload is
service-specific; we keep only the entries that carry HTTP request data
(``server_http_route`` + method + status), resolve Loki field names through a
small alias list, and map each onto the same KibanaLogEntry shape used by the
Kibana and Splunk paths, so redaction and generation are reused unchanged.
"""

from pathlib import Path

from secure_log2test.core.parser import (
    REDACTED,
    KibanaLogEntry,
    LokiLogParser,
    detect_source,
)


DATA = Path(__file__).resolve().parent.parent / "data"
JSON = DATA / "sample_loki_export.json"
CSV = DATA / "sample_loki_export.csv"


# --- JSON --------------------------------------------------------------


def test_json_parses_http_rows_and_skips_the_rest():
    parser = LokiLogParser(JSON)
    entries = parser.parse()
    # 4 rows: 2 HTTP, 1 non-HTTP payload, 1 line that is not JSON -> 2 skipped
    assert parser.attempted == 4
    assert parser.skipped == 2
    assert len(entries) == 2
    assert all(isinstance(e, KibanaLogEntry) for e in entries)


def test_json_maps_loki_field_names():
    entries = LokiLogParser(JSON).parse()
    first = entries[0]
    assert first.method == "GET"
    assert first.url == "/api/v1/users"  # server_http_route -> url
    assert first.status == 200  # http_status -> status (int)
    assert first.duration == 42  # duration_ms -> duration


def test_json_redacts_url_token():
    entries = LokiLogParser(JSON).parse()
    login = next(e for e in entries if e.method == "POST")
    assert "supersecret" not in login.url
    assert "access_token=" + REDACTED in login.url


def test_json_redacts_header_secret():
    entries = LokiLogParser(JSON).parse()
    login = next(e for e in entries if e.method == "POST")
    assert "secret-token" not in str(login.headers)
    assert login.headers.get("Authorization") == REDACTED


# --- CSV ---------------------------------------------------------------


def test_csv_parses_http_rows_and_skips_non_http():
    parser = LokiLogParser(CSV)
    entries = parser.parse()
    # 3 rows: 2 HTTP, 1 non-HTTP payload -> 1 skipped
    assert parser.attempted == 3
    assert parser.skipped == 1
    assert len(entries) == 2


def test_csv_maps_fields():
    entries = LokiLogParser(CSV).parse()
    first = entries[0]
    assert first.method == "GET"
    assert first.url == "/api/v1/users"
    assert first.status == 200


# --- detect_source -----------------------------------------------------


def test_detect_source_loki_json():
    assert detect_source(JSON) == "loki"


def test_detect_source_loki_csv_has_line_column():
    assert detect_source(CSV) == "loki"


def test_detect_source_splunk_csv_without_line_column(tmp_path: Path):
    p = tmp_path / "splunk.csv"
    p.write_text("method,uri,status,duration\nGET,/x,200,5\n", encoding="utf-8")
    assert detect_source(p) == "splunk"


def test_detect_source_kibana_unchanged(tmp_path: Path):
    p = tmp_path / "kibana.json"
    p.write_text('{"hits": {"hits": []}}', encoding="utf-8")
    assert detect_source(p) == "kibana"


def test_detect_source_splunk_json_with_line_and_timestamp_stays_splunk(tmp_path: Path):
    # A Splunk event may carry a "line"/"timestamp" field; the _raw marker must
    # keep it on the Splunk path, not the looser Loki shape check.
    p = tmp_path / "splunk.json"
    p.write_text(
        '[{"line": "GET /x 200", "timestamp": "t", "_raw": "GET /x 200"}]',
        encoding="utf-8",
    )
    assert detect_source(p) == "splunk"


def test_detect_source_splunk_csv_with_line_field_not_first(tmp_path: Path):
    # "Line" present but not leading, plus a Splunk _time marker -> not Loki.
    p = tmp_path / "splunk.csv"
    p.write_text("_time,Line,host\n1,GET /x 200,web01\n", encoding="utf-8")
    assert detect_source(p) == "splunk"


def test_detect_source_loki_single_object_json(tmp_path: Path):
    # A single Loki row (not wrapped in a list) still auto-detects as loki, so
    # --source auto matches what LokiLogParser._load_rows accepts.
    p = tmp_path / "loki.json"
    p.write_text(
        '{"line": "{\\"method\\": \\"GET\\"}", "timestamp": "t", "fields": {"app": "x"}}',
        encoding="utf-8",
    )
    assert detect_source(p) == "loki"


# --- CLI integration ---------------------------------------------------


def test_cli_generates_from_loki_export(tmp_path: Path):
    from secure_log2test.cli import main

    out = tmp_path / "tests_generated.py"
    rc = main([str(JSON), "--source", "loki", "--output", str(out)])
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert "/api/v1/users" in text
    assert "supersecret" not in text  # secret never reaches generated source
    compile(text, str(out), "exec")
