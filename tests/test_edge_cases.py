"""Edge cases: header redaction, empty bodies, server error codes."""

import json

import pytest

from secure_log2test.core.parser import (
    KibanaLogEntry,
    KibanaLogParser,
    REDACTED,
    redact_headers,
)


# ---------------------------------------------------------------------------
# Header redaction
# ---------------------------------------------------------------------------

def test_authorization_header_redacted():
    cleaned = redact_headers({"Authorization": "Bearer secret-token-xyz"})
    assert cleaned == {"Authorization": REDACTED}


def test_cookie_header_redacted():
    cleaned = redact_headers({"Cookie": "session=abc123"})
    assert cleaned["Cookie"] == REDACTED


def test_redaction_is_case_insensitive():
    cleaned = redact_headers({
        "AUTHORIZATION": "Bearer x",
        "x-api-key": "k1",
        "X-Auth-Token": "t1",
    })
    assert cleaned["AUTHORIZATION"] == REDACTED
    assert cleaned["x-api-key"] == REDACTED
    assert cleaned["X-Auth-Token"] == REDACTED


def test_safe_headers_preserved():
    headers = {
        "Content-Type": "application/json",
        "Accept": "*/*",
        "User-Agent": "pytest/7",
    }
    assert redact_headers(headers) == headers


def test_redaction_does_not_mutate_input():
    original = {"Authorization": "Bearer x", "Accept": "*/*"}
    snapshot = dict(original)
    redact_headers(original)
    assert original == snapshot


def test_empty_headers_return_empty_dict():
    assert redact_headers({}) == {}
    assert redact_headers(None) == {}


def test_entry_redacts_headers_at_construction():
    entry = KibanaLogEntry(
        method="GET",
        url="/api/v1/users",
        status=200,
        headers={"Authorization": "Bearer leaky", "Accept": "json"},
    )
    assert entry.headers["Authorization"] == REDACTED
    assert entry.headers["Accept"] == "json"


def test_entry_redaction_on_parser_output(tmp_path):
    payload = {
        "hits": {
            "hits": [
                {"_source": {
                    "method": "POST",
                    "url": "/api/v1/login",
                    "status": 200,
                    "headers": {"Authorization": "Bearer leaked"},
                }},
            ]
        }
    }
    src = tmp_path / "with_auth.json"
    src.write_text(json.dumps(payload))
    entries = KibanaLogParser(src).parse()
    assert len(entries) == 1
    assert entries[0].headers["Authorization"] == REDACTED


# ---------------------------------------------------------------------------
# Empty / missing body
# ---------------------------------------------------------------------------

def test_body_defaults_to_none():
    entry = KibanaLogEntry(method="GET", url="/", status=200)
    assert entry.body is None


def test_empty_string_body_preserved():
    entry = KibanaLogEntry(method="POST", url="/api/echo", status=200, body="")
    assert entry.body == ""


def test_empty_dict_body_preserved():
    entry = KibanaLogEntry(method="POST", url="/api/echo", status=200, body={})
    assert entry.body == {}


def test_parser_handles_entries_without_body(tmp_path):
    payload = {
        "hits": {
            "hits": [
                {"_source": {"method": "GET", "url": "/a", "status": 200}},
                {"_source": {"method": "GET", "url": "/b", "status": 200, "body": ""}},
                {"_source": {"method": "GET", "url": "/c", "status": 200, "body": None}},
            ]
        }
    }
    src = tmp_path / "no_body.json"
    src.write_text(json.dumps(payload))
    entries = KibanaLogParser(src).parse()
    assert len(entries) == 3
    assert [e.body for e in entries] == [None, "", None]


# ---------------------------------------------------------------------------
# Server-error status codes (5xx)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code", [500, 502, 503, 504, 599])
def test_5xx_codes_accepted(code):
    entry = KibanaLogEntry(method="GET", url="/api/health", status=code)
    assert entry.status == code


def test_parser_preserves_5xx_codes(tmp_path):
    payload = {
        "hits": {
            "hits": [
                {"_source": {"method": "GET", "url": "/x", "status": 500}},
                {"_source": {"method": "GET", "url": "/y", "status": 503}},
                {"_source": {"method": "GET", "url": "/z", "status": 504}},
            ]
        }
    }
    src = tmp_path / "errors.json"
    src.write_text(json.dumps(payload))
    entries = KibanaLogParser(src).parse()
    statuses = sorted(e.status for e in entries)
    assert statuses == [500, 503, 504]
