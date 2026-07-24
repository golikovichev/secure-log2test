"""Config-driven custom redaction rules (issue #2).

The built-in blacklist is fixed. Real deployments need to add their own
sensitive names (an internal tenant token, a bespoke secret field) without
patching the source. These tests pin the config loader and the install
hook that extends the built-in matcher with user rules, while keeping the
defaults always on.
"""

import pytest

from secure_log2test.core import parser
from secure_log2test.core.parser import (
    REDACTED,
    redact_body,
    redact_headers,
    redact_url,
)
from secure_log2test.core.redaction_config import load_redaction_rules


@pytest.fixture(autouse=True)
def _reset_rules():
    # Every test starts from the built-in defaults and restores them after,
    # so installing custom rules in one test cannot leak into another.
    parser.reset_redaction_rules()
    yield
    parser.reset_redaction_rules()


def test_defaults_still_redact_without_config():
    assert redact_headers({"Authorization": "Bearer x"})["Authorization"] == REDACTED
    assert redact_body({"password": "x"})["password"] == REDACTED


def test_custom_header_name_redacted_after_install():
    # A bespoke header the built-in list does not know about.
    assert redact_headers({"X-Tenant-Ref": "SECRET"})["X-Tenant-Ref"] == "SECRET"
    parser.install_redaction_rules(extra_header_names=["x-tenant-ref"])
    assert redact_headers({"X-Tenant-Ref": "SECRET"})["X-Tenant-Ref"] == REDACTED


def test_custom_field_pattern_redacts_body_and_url():
    assert redact_body({"ssn": "123"})["ssn"] == "123"
    parser.install_redaction_rules(extra_field_patterns=[r"ssn|account_number"])
    assert redact_body({"ssn": "123"})["ssn"] == REDACTED
    assert redact_body({"account_number": "1"})["account_number"] == REDACTED
    assert "SECRET" not in redact_url("/pay?account_number=SECRET")


def test_custom_rules_do_not_over_redact():
    parser.install_redaction_rules(extra_field_patterns=[r"ssn"])
    assert redact_body({"user": "alice", "amount": "10"}) == {
        "user": "alice",
        "amount": "10",
    }


def test_install_extends_rather_than_replaces_defaults():
    parser.install_redaction_rules(extra_field_patterns=[r"ssn"])
    # built-in password rule must still fire alongside the custom one.
    assert redact_body({"password": "x", "ssn": "y"}) == {
        "password": REDACTED,
        "ssn": REDACTED,
    }


def test_load_rules_absent_config_returns_empty(tmp_path):
    names, patterns, paths = load_redaction_rules(start_dir=tmp_path)
    assert names == []
    assert patterns == []
    assert paths == []


def test_load_rules_reads_toml(tmp_path):
    (tmp_path / "secure-log2test.toml").write_text(
        "[redaction]\n"
        'extra_header_names = ["x-tenant-ref", "x-internal-token"]\n'
        'extra_field_patterns = ["ssn", "account_number"]\n',
        encoding="utf-8",
    )
    names, patterns, _paths = load_redaction_rules(start_dir=tmp_path)
    assert names == ["x-tenant-ref", "x-internal-token"]
    assert patterns == ["ssn", "account_number"]


def test_load_rules_invalid_regex_raises_clear_error(tmp_path):
    (tmp_path / "secure-log2test.toml").write_text(
        '[redaction]\nextra_field_patterns = ["(unclosed"]\n', encoding="utf-8"
    )
    with pytest.raises(ValueError, match="invalid redaction regex"):
        _names, patterns, _paths = load_redaction_rules(start_dir=tmp_path)
        parser.install_redaction_rules(extra_field_patterns=patterns)


def test_end_to_end_load_then_install(tmp_path):
    (tmp_path / "secure-log2test.toml").write_text(
        '[redaction]\nextra_field_patterns = ["ssn"]\n', encoding="utf-8"
    )
    names, patterns, paths = load_redaction_rules(start_dir=tmp_path)
    parser.install_redaction_rules(
        extra_header_names=names,
        extra_field_patterns=patterns,
        extra_field_paths=paths,
    )
    assert redact_body({"ssn": "1"})["ssn"] == REDACTED


def test_malformed_toml_fails_closed(tmp_path):
    # A broken config must abort loudly, never silently disable redaction.
    (tmp_path / "secure-log2test.toml").write_text(
        "[redaction]\nextra_field_patterns = [", encoding="utf-8"
    )
    with pytest.raises(ValueError):
        load_redaction_rules(start_dir=tmp_path)


def test_non_list_value_rejected(tmp_path):
    # A bare string instead of a list would otherwise iterate into
    # single-character rules; reject it instead.
    (tmp_path / "secure-log2test.toml").write_text(
        '[redaction]\nextra_field_patterns = "ssn"\n', encoding="utf-8"
    )
    with pytest.raises(ValueError, match="must be a list of strings"):
        load_redaction_rules(start_dir=tmp_path)


def test_exact_name_matches_any_surface():
    # extra_header_names uses the shared matcher, so an exact name also
    # redacts a body field / URL parameter of that name (over-redacts, safe).
    parser.install_redaction_rules(extra_header_names=["x-tenant-ref"])
    assert redact_headers({"X-Tenant-Ref": "s"})["X-Tenant-Ref"] == REDACTED
    assert redact_body({"x-tenant-ref": "s"})["x-tenant-ref"] == REDACTED


def test_bad_pattern_does_not_partially_install():
    # install is all-or-nothing: a bad regex must not leave header names
    # applied while patterns are rejected.
    parser.reset_redaction_rules()
    with pytest.raises(ValueError):
        parser.install_redaction_rules(
            extra_header_names=["x-tenant-ref"], extra_field_patterns=["(unclosed"]
        )
    assert redact_headers({"X-Tenant-Ref": "s"})["X-Tenant-Ref"] == "s"
