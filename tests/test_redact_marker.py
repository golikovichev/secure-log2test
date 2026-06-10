"""Tests for the custom redaction marker (--redact-marker, issue #6)."""

import json

import pytest

from secure_log2test.cli import main
from secure_log2test.core.parser import (
    REDACTED,
    KibanaLogEntry,
    KibanaLogParser,
    redact_body,
    redact_headers,
)


def test_default_marker_preserved_in_headers():
    out = redact_headers({"Authorization": "Bearer abc"})
    assert out["Authorization"] == REDACTED


def test_custom_marker_applied_to_headers():
    out = redact_headers({"Authorization": "Bearer abc"}, marker="[SCRUBBED]")
    assert out["Authorization"] == "[SCRUBBED]"


def test_custom_marker_applied_to_body():
    out = redact_body({"password": "p", "user": "u"}, marker="[SCRUBBED]")
    assert out == {"password": "[SCRUBBED]", "user": "u"}


def test_default_marker_when_no_context():
    entry = KibanaLogEntry(
        method="get", url="/x", status=200, headers={"x-api-key": "k"}
    )
    assert entry.headers["x-api-key"] == REDACTED


def test_custom_marker_via_validation_context():
    entry = KibanaLogEntry.model_validate(
        {
            "method": "get",
            "url": "/x",
            "status": 200,
            "headers": {"x-api-key": "k"},
            "body": {"token": "t"},
        },
        context={"redact_marker": "<<scrubbed>>"},
    )
    assert entry.headers["x-api-key"] == "<<scrubbed>>"
    assert entry.body["token"] == "<<scrubbed>>"


def _write_log(tmp_path, marker_field="secret"):
    log = {
        "hits": {
            "hits": [
                {
                    "_source": {
                        "method": "POST",
                        "url": "/api/login",
                        "status": 200,
                        "headers": {"Authorization": "Bearer xyz"},
                        "body": {marker_field: "shh", "keep": "ok"},
                    }
                }
            ]
        }
    }
    p = tmp_path / "in.json"
    p.write_text(json.dumps(log), encoding="utf-8")
    return p


def test_parser_propagates_custom_marker(tmp_path):
    p = _write_log(tmp_path)
    entries = KibanaLogParser(p, redact_marker="[S2LT]").parse()
    assert entries[0].headers["Authorization"] == "[S2LT]"
    assert entries[0].body["secret"] == "[S2LT]"


def test_custom_marker_applied_to_nested_body():
    out = redact_body({"items": [{"token": "t", "name": "n"}]}, marker="[X]")
    assert out == {"items": [{"token": "[X]", "name": "n"}]}


def test_cli_empty_marker_rejected(tmp_path):
    p = _write_log(tmp_path)
    with pytest.raises(SystemExit) as exc:
        main([str(p), "--redact-marker", ""])
    assert exc.value.code != 0


def test_cli_whitespace_marker_rejected(tmp_path):
    p = _write_log(tmp_path)
    with pytest.raises(SystemExit) as exc:
        main([str(p), "--redact-marker", "   "])
    assert exc.value.code != 0


def test_generated_pytest_uses_custom_marker(tmp_path):
    p = _write_log(tmp_path)
    out = tmp_path / "tests_generated.py"
    rc = main([str(p), "--output", str(out), "--redact-marker", "[SCRUBBED]"])
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert "[SCRUBBED]" in text
    assert REDACTED not in text  # docstring + values both reflect the marker
