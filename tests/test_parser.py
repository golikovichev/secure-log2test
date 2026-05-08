import json
from pathlib import Path

import pytest

from secure_log2test.core.parser import KibanaLogEntry, KibanaLogParser


SAMPLE = Path(__file__).parent.parent / "data" / "sample_kibana_export.json"


def test_parser_reads_sample():
    parser = KibanaLogParser(SAMPLE)
    entries = parser.parse()
    assert len(entries) == 4


def test_method_normalised_to_upper():
    parser = KibanaLogParser(SAMPLE)
    entries = parser.parse()
    methods = {e.method for e in entries}
    assert methods == {"GET", "POST", "PUT", "DELETE"}


def test_status_codes_preserved():
    parser = KibanaLogParser(SAMPLE)
    entries = parser.parse()
    statuses = sorted(e.status for e in entries)
    assert statuses == [200, 201, 204, 404]


def test_skips_malformed_entry(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({
        "hits": {
            "hits": [
                {"_source": {"method": "GET", "url": "/ok", "status": 200}},
                {"_source": {"url": "/missing-method", "status": 200}},
            ]
        }
    }))
    parser = KibanaLogParser(bad)
    entries = parser.parse()
    assert len(entries) == 1
    assert entries[0].url == "/ok"


def test_empty_hits(tmp_path):
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"hits": {"hits": []}}))
    parser = KibanaLogParser(empty)
    assert parser.parse() == []


def test_invalid_method_still_normalised():
    entry = KibanaLogEntry(method="get", url="/", status=200)
    assert entry.method == "GET"


def test_default_duration_zero():
    entry = KibanaLogEntry(method="GET", url="/", status=200)
    assert entry.duration == 0
