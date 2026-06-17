"""Tests for Splunk search-export parsing (1.2.0 feature).

Splunk exports search results as CSV or JSON (one {"result": {...}} object
per line for the export endpoint). Each event carries _time / _raw plus
whatever fields the sourcetype extracted. HTTP field names are extraction
dependent, so the parser accepts a small set of aliases (method/http_method,
uri/uri_path/url/request, status/status_code, duration/response_time) and
maps each event onto the same KibanaLogEntry shape used by the Kibana path,
so redaction and generation are reused unchanged.
"""

from pathlib import Path

import pytest

from secure_log2test.core.parser import (
    REDACTED,
    KibanaLogEntry,
    SplunkLogParser,
    detect_source,
)


DATA = Path(__file__).resolve().parent.parent / "data"
CSV = DATA / "sample_splunk_export.csv"
JSON = DATA / "sample_splunk_export.json"


# --- CSV ---------------------------------------------------------------


def test_csv_parses_valid_rows_and_skips_bad():
    parser = SplunkLogParser(CSV)
    entries = parser.parse()
    # 4 rows, the last has an empty status -> skipped
    assert parser.attempted == 4
    assert parser.skipped == 1
    assert len(entries) == 3
    assert all(isinstance(e, KibanaLogEntry) for e in entries)


def test_csv_maps_fields():
    entries = SplunkLogParser(CSV).parse()
    first = entries[0]
    assert first.method == "GET"
    assert first.url == "/api/v1/users"
    assert first.status == 200
    assert first.duration == 42


def test_csv_redacts_url_token():
    entries = SplunkLogParser(CSV).parse()
    login = next(e for e in entries if e.method == "POST")
    assert "supersecret" not in login.url
    assert "access_token=" + REDACTED in login.url


# --- JSON (export endpoint: one {"result": {...}} per line) ------------


def test_json_parses_result_wrapper_and_skips_non_http():
    parser = SplunkLogParser(JSON)
    entries = parser.parse()
    # 3 events, the 3rd (syslog junk, no http fields) -> skipped
    assert parser.attempted == 3
    assert parser.skipped == 1
    assert len(entries) == 2


def test_json_alias_fields():
    # 2nd event uses http_method / uri_path / status_code / response_time
    entries = SplunkLogParser(JSON).parse()
    post = next(e for e in entries if e.method == "POST")
    assert post.url == "/api/v1/login"
    assert post.status == 201
    assert post.duration == 110


def test_json_redacts_headers_and_body():
    entries = SplunkLogParser(JSON).parse()
    get = next(e for e in entries if e.method == "GET")
    assert get.headers["Authorization"] == REDACTED
    assert get.headers["Accept"] == "application/json"
    post = next(e for e in entries if e.method == "POST")
    assert post.body["password"] == REDACTED
    assert post.body["username"] == "ada"


def test_custom_redact_marker():
    entries = SplunkLogParser(JSON, redact_marker="[X]").parse()
    get = next(e for e in entries if e.method == "GET")
    assert get.headers["Authorization"] == "[X]"


# --- source auto-detection --------------------------------------------


def test_detect_source_splunk_csv():
    assert detect_source(CSV) == "splunk"


def test_detect_source_splunk_json():
    assert detect_source(JSON) == "splunk"


def test_detect_source_kibana():
    kibana = DATA / "sample_kibana_export.json"
    assert detect_source(kibana) == "kibana"


# --- CLI integration ---------------------------------------------------


def test_cli_auto_detects_splunk_csv(tmp_path):
    from secure_log2test.cli import main

    out = tmp_path / "out.py"
    rc = main([str(CSV), "--output", str(out)])
    assert rc == 0
    assert out.exists()
    assert "/api/v1/users" in out.read_text(encoding="utf-8")


def test_cli_explicit_source_splunk_json(tmp_path):
    from secure_log2test.cli import main

    out = tmp_path / "out.py"
    rc = main([str(JSON), "--source", "splunk", "--output", str(out)])
    assert rc == 0
    assert out.exists()


def test_cli_kibana_still_works(tmp_path):
    from secure_log2test.cli import main

    out = tmp_path / "out.py"
    rc = main([str(DATA / "sample_kibana_export.json"), "--output", str(out)])
    assert rc == 0
    assert out.exists()


# --- robustness fixes (code review 2026-06-17: C1 / I1 / I2) ------------


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_json_one_bad_ndjson_line_is_skipped_not_crash(tmp_path):
    # C1: a single corrupt NDJSON line must not abort the whole run.
    good = '{"result":{"method":"GET","uri":"/a","status":"200","duration":"1"}}'
    bad = "{not valid json"
    f = _write(tmp_path, "x.json", good + "\n" + bad + "\n" + good + "\n")
    parser = SplunkLogParser(f)
    entries = parser.parse()
    assert len(entries) == 2
    assert parser.skipped == 1  # the corrupt line is counted, not silent


def test_json_whole_file_malformed_raises_valueerror(tmp_path):
    # C1: a fully unparseable file raises a clean ValueError (like Kibana),
    # not a raw JSONDecodeError.
    f = _write(tmp_path, "x.json", "{this is : not json at all")
    with pytest.raises(ValueError):
        SplunkLogParser(f).parse()


def test_json_results_array_document(tmp_path):
    # CHANGELOG claims {"results": [...]} support; pin it.
    doc = (
        '{"results":[{"method":"GET","uri":"/a","status":"200"},'
        '{"method":"POST","uri":"/b","status":"201"}]}'
    )
    f = _write(tmp_path, "x.json", doc)
    entries = SplunkLogParser(f).parse()
    assert [e.method for e in entries] == ["GET", "POST"]


def test_fractional_and_unit_duration_keeps_event(tmp_path):
    # I1: 0.042 / 42ms durations must not skip the event.
    doc = (
        '{"result":{"method":"GET","uri":"/a","status":"200","duration":"0.042"}}\n'
        '{"result":{"method":"POST","uri":"/b","status":"201","response_time":"42ms"}}'
    )
    f = _write(tmp_path, "x.json", doc)
    parser = SplunkLogParser(f)
    entries = parser.parse()
    assert parser.skipped == 0
    assert len(entries) == 2


def test_decimal_status_coerced(tmp_path):
    # I1: "200.0" should parse to 200, not skip.
    f = _write(
        tmp_path,
        "x.json",
        '{"result":{"method":"GET","uri":"/a","status":"200.0"}}',
    )
    entries = SplunkLogParser(f).parse()
    assert entries[0].status == 200


def test_headerless_csv_content_without_csv_suffix(tmp_path):
    # I2: CSV content saved as .log must still parse as Splunk CSV.
    f = _write(
        tmp_path,
        "export.log",
        "method,uri,status,duration\nGET,/a,200,5\nPOST,/b,201,9\n",
    )
    entries = SplunkLogParser(f).parse()
    assert [e.method for e in entries] == ["GET", "POST"]
