"""Input validation tests for the Kibana log parser.

These cover the failure modes that v1.0.0 missed: non-ASCII content
under a Windows cp1252 default, malformed input shapes, empty files,
and accidental Grafana Loki Explore exports.

The fixtures are written as utf-8 and decoded by the parser the same
way. If the parser ever drops the explicit utf-8 open, the Cyrillic /
CJK / emoji cases blow up on Windows runners only, which is exactly
the regression we want to catch.
"""

import json
from pathlib import Path

import pytest

from secure_log2test.core.parser import KibanaLogParser


def _write_kibana_export(path: Path, source_records):
    payload = {
        "hits": {
            "total": {"value": len(source_records), "relation": "eq"},
            "hits": [{"_source": rec} for rec in source_records],
        }
    }
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def test_cyrillic_in_url_and_body_parses(tmp_path):
    path = tmp_path / "cyrillic.json"
    _write_kibana_export(
        path,
        [
            {
                "method": "POST",
                "url": "/api/v1/пользователи/профиль",
                "status": 200,
                "duration": 12,
                "body": {"имя": "Михаил", "город": "Брайтон"},
            }
        ],
    )

    entries = KibanaLogParser(path).parse()

    assert len(entries) == 1
    assert entries[0].url == "/api/v1/пользователи/профиль"
    assert entries[0].body == {"имя": "Михаил", "город": "Брайтон"}


def test_cjk_in_url_parses(tmp_path):
    path = tmp_path / "cjk.json"
    _write_kibana_export(
        path,
        [
            {
                "method": "GET",
                "url": "/api/v1/用户/個人資料",
                "status": 200,
                "duration": 5,
            }
        ],
    )

    entries = KibanaLogParser(path).parse()

    assert len(entries) == 1
    assert entries[0].url == "/api/v1/用户/個人資料"


def test_emoji_in_body_parses(tmp_path):
    path = tmp_path / "emoji.json"
    _write_kibana_export(
        path,
        [
            {
                "method": "POST",
                "url": "/api/v1/messages",
                "status": 201,
                "duration": 8,
                "body": {"text": "Hello world 🚀 ✨"},
            }
        ],
    )

    entries = KibanaLogParser(path).parse()

    assert len(entries) == 1
    assert entries[0].body == {"text": "Hello world 🚀 ✨"}


def test_loki_explore_shape_raises_with_helpful_hint(tmp_path):
    path = tmp_path / "loki.json"
    loki_payload = [
        {
            "line": '{"log":{"level":"INFO","msg":"hello"}}',
            "timestamp": "1778495997463979482",
            "fields": {"app": "api-gateway", "namespace": "production"},
        }
    ]
    path.write_text(json.dumps(loki_payload), encoding="utf-8")

    with pytest.raises(ValueError) as exc_info:
        KibanaLogParser(path).parse()

    message = str(exc_info.value)
    assert "Loki" in message
    assert "issue #4" in message


def test_plain_array_without_loki_keys_raises_generic(tmp_path):
    path = tmp_path / "array.json"
    path.write_text(json.dumps([{"foo": "bar"}]), encoding="utf-8")

    with pytest.raises(ValueError) as exc_info:
        KibanaLogParser(path).parse()

    message = str(exc_info.value)
    assert "hits.hits[]" in message
    assert "Loki" not in message


def test_empty_object_raises(tmp_path):
    path = tmp_path / "empty_object.json"
    path.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError) as exc_info:
        KibanaLogParser(path).parse()

    assert "hits.hits[]" in str(exc_info.value)


def test_invalid_json_raises_with_path(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not valid json", encoding="utf-8")

    with pytest.raises(ValueError) as exc_info:
        KibanaLogParser(path).parse()

    assert "not valid JSON" in str(exc_info.value)


def test_utf8_bom_is_handled(tmp_path):
    path = tmp_path / "bom.json"
    payload = {
        "hits": {
            "total": {"value": 1, "relation": "eq"},
            "hits": [
                {"_source": {"method": "GET", "url": "/api", "status": 200}}
            ],
        }
    }
    path.write_text(json.dumps(payload), encoding="utf-8-sig")

    entries = KibanaLogParser(path).parse()

    assert len(entries) == 1
    assert entries[0].url == "/api"
