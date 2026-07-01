"""Redaction coverage for the 'pwd' password-field abbreviation.

`pwd` is a common field/param name for a password, but the name pattern
only knew `password` and `passwd`, so a `pwd` field leaked into the
generated suite. These tests pin that it is now redacted across body,
header, and URL, and that adding it does not over-redact unrelated fields.
"""

import pytest

from secure_log2test.core.parser import (
    REDACTED,
    redact_body,
    redact_headers,
    redact_url,
)


@pytest.mark.parametrize("key", ["pwd", "PWD", "user_pwd", "pwdHash"])
def test_pwd_body_field_redacted(key):
    assert redact_body({key: "SECRET"})[key] == REDACTED


def test_pwd_header_redacted():
    assert redact_headers({"X-Pwd": "SECRET"})["X-Pwd"] == REDACTED


def test_pwd_url_param_redacted():
    assert "SECRET" not in redact_url("/login?pwd=SECRET")


def test_benign_fields_not_over_redacted():
    # adding pwd must not touch unrelated field names.
    assert redact_body({"user": "alice", "amount": "10"}) == {
        "user": "alice",
        "amount": "10",
    }
