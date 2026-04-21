import json
import pytest
from pathlib import Path
from core.parser import KibanaLogParser, LogEntry


def _write_kibana_json(tmp_path: Path, hits: list) -> Path:
    payload = {"hits": {"hits": [{"_source": h} for h in hits]}}
    log_file = tmp_path / "test_export.json"
    log_file.write_text(json.dumps(payload), encoding="utf-8")
    return log_file


class TestKibanaLogParserInit:
    def test_raises_when_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            KibanaLogParser(file_path="/nonexistent/path/export.json")

    def test_accepts_existing_file(self, tmp_path):
        log_file = _write_kibana_json(tmp_path, [])
        parser = KibanaLogParser(file_path=str(log_file))
        assert parser.file_path == log_file


class TestKibanaLogParserParse:
    def test_parses_valid_entry(self, tmp_path):
        log_file = _write_kibana_json(tmp_path, [
            {"url": "/api/orders", "method": "get", "status": 200, "duration": 120}
        ])
        entries = KibanaLogParser(str(log_file)).parse()
        assert len(entries) == 1
        assert entries[0].endpoint == "/api/orders"
        assert entries[0].method == "GET"
        assert entries[0].status_code == 200
        assert entries[0].response_time_ms == 120

    def test_method_is_uppercased(self, tmp_path):
        log_file = _write_kibana_json(tmp_path, [
            {"url": "/api/users", "method": "post", "status": 201, "duration": 80}
        ])
        entries = KibanaLogParser(str(log_file)).parse()
        assert entries[0].method == "POST"

    def test_optional_payload_is_none_when_absent(self, tmp_path):
        log_file = _write_kibana_json(tmp_path, [
            {"url": "/api/ping", "method": "GET", "status": 200, "duration": 5}
        ])
        entries = KibanaLogParser(str(log_file)).parse()
        assert entries[0].payload is None

    def test_optional_payload_captured_when_present(self, tmp_path):
        log_file = _write_kibana_json(tmp_path, [
            {"url": "/api/login", "method": "POST", "status": 200,
             "duration": 95, "request_body": {"username": "qa"}}
        ])
        entries = KibanaLogParser(str(log_file)).parse()
        assert entries[0].payload == {"username": "qa"}

    def test_returns_empty_list_when_no_hits(self, tmp_path):
        log_file = tmp_path / "empty.json"
        log_file.write_text(json.dumps({"hits": {"hits": []}}), encoding="utf-8")
        entries = KibanaLogParser(str(log_file)).parse()
        assert entries == []

    def test_skips_malformed_entry_continues_parsing(self, tmp_path):
        log_file = _write_kibana_json(tmp_path, [
            {"url": "/api/ok", "method": "GET", "status": 200, "duration": 10},
            {"url": "/api/bad", "method": "GET", "status": "not_an_int", "duration": 10},
        ])
        entries = KibanaLogParser(str(log_file)).parse()
        assert len(entries) == 1
        assert entries[0].endpoint == "/api/ok"

    def test_raises_on_invalid_json_file(self, tmp_path):
        broken = tmp_path / "broken.json"
        broken.write_text("{ this is not json ", encoding="utf-8")
        with pytest.raises(json.JSONDecodeError):
            KibanaLogParser(str(broken)).parse()

    def test_duration_as_float_is_coerced_to_int(self, tmp_path):
        log_file = _write_kibana_json(tmp_path, [
            {"url": "/api/search", "method": "GET", "status": 200, "duration": 123.7}
        ])
        entries = KibanaLogParser(str(log_file)).parse()
        assert entries[0].response_time_ms == 123
        assert isinstance(entries[0].response_time_ms, int)

    def test_defaults_applied_when_fields_missing(self, tmp_path):
        log_file = _write_kibana_json(tmp_path, [{}])
        entries = KibanaLogParser(str(log_file)).parse()
        assert len(entries) == 1
        assert entries[0].endpoint == "/"
        assert entries[0].method == "GET"
        assert entries[0].status_code == 200
        assert entries[0].response_time_ms == 0
