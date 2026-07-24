"""JSON-path body-field redaction (issue #2, last open box).

Name-based redaction misses a field whose key is innocuous but whose value
is sensitive: a free-text note, an internal reference id, a support ticket
body. A user who knows the shape of their payload targets it by path,
``data.user.note``. Lists are transparent so ``items.ref`` reaches every
element, and ``*`` matches any one key. Paths only add; the built-in and
name-pattern rules always stay on.
"""

import pytest

from secure_log2test.core import parser
from secure_log2test.core.parser import REDACTED, redact_body
from secure_log2test.core.redaction_config import load_redaction_rules


@pytest.fixture(autouse=True)
def _reset_rules():
    parser.reset_redaction_rules()
    yield
    parser.reset_redaction_rules()


def test_field_path_redacts_innocuously_named_value():
    payload = {"data": {"user": {"note": "SECRET", "name": "alice"}}}
    # Off by default: `note` is not a sensitive name.
    assert redact_body(payload)["data"]["user"]["note"] == "SECRET"
    parser.install_redaction_rules(extra_field_paths=["data.user.note"])
    out = redact_body(payload)
    assert out["data"]["user"]["note"] == REDACTED
    assert out["data"]["user"]["name"] == "alice"  # sibling untouched


def test_field_path_does_not_match_same_name_at_other_path():
    parser.install_redaction_rules(extra_field_paths=["data.user.note"])
    payload = {"data": {"audit": {"note": "keep"}}, "note": "keep2"}
    out = redact_body(payload)
    assert out["data"]["audit"]["note"] == "keep"
    assert out["note"] == "keep2"


def test_field_path_wildcard_matches_any_key():
    parser.install_redaction_rules(extra_field_paths=["data.*.token"])
    payload = {"data": {"a": {"token": "x"}, "b": {"token": "y"}}}
    out = redact_body(payload)
    assert out["data"]["a"]["token"] == REDACTED
    assert out["data"]["b"]["token"] == REDACTED


def test_field_path_traverses_list_transparently():
    parser.install_redaction_rules(extra_field_paths=["items.ref"])
    payload = {"items": [{"ref": "a"}, {"ref": "b"}, {"other": "keep"}]}
    out = redact_body(payload)
    assert out["items"][0]["ref"] == REDACTED
    assert out["items"][1]["ref"] == REDACTED
    assert out["items"][2]["other"] == "keep"


def test_field_path_off_without_install():
    payload = {"a": {"b": "SECRET"}}
    assert redact_body(payload)["a"]["b"] == "SECRET"


def test_field_path_partial_prefix_does_not_redact():
    # A configured path must match in full, not as a prefix: `data.user`
    # alone must not wipe the whole user object.
    parser.install_redaction_rules(extra_field_paths=["data.user.note"])
    payload = {"data": {"user": {"name": "alice"}}}
    out = redact_body(payload)
    assert out["data"]["user"] == {"name": "alice"}


def test_field_path_segments_are_whitespace_trimmed():
    # A stray space around a segment (`data. user.note`) must normalise, not
    # silently install a rule that can never match.
    parser.install_redaction_rules(extra_field_paths=["data. user .note"])
    payload = {"data": {"user": {"note": "SECRET"}}}
    assert redact_body(payload)["data"]["user"]["note"] == REDACTED


def test_field_path_matching_is_case_insensitive():
    # Name-based redaction is case-insensitive; paths match the rest of the
    # redactor so a casing typo copied from a schema does not leak.
    parser.install_redaction_rules(extra_field_paths=["data.user.Note"])
    payload = {"data": {"user": {"note": "SECRET"}}}
    assert redact_body(payload)["data"]["user"]["note"] == REDACTED

    parser.install_redaction_rules(extra_field_paths=["data.user.note"])
    payload = {"data": {"user": {"Note": "SECRET"}}}
    assert redact_body(payload)["data"]["user"]["Note"] == REDACTED


def test_install_rejects_empty_field_path():
    with pytest.raises(ValueError):
        parser.install_redaction_rules(extra_field_paths=[""])
    with pytest.raises(ValueError):
        parser.install_redaction_rules(extra_field_paths=["   "])
    with pytest.raises(ValueError):
        parser.install_redaction_rules(extra_field_paths=["a..b"])


def test_install_field_paths_all_or_nothing_on_bad_path():
    # A later bad path must not leave an earlier good one installed.
    with pytest.raises(ValueError):
        parser.install_redaction_rules(extra_field_paths=["data.user.note", ""])
    payload = {"data": {"user": {"note": "SECRET"}}}
    assert redact_body(payload)["data"]["user"]["note"] == "SECRET"


def test_name_based_redaction_still_wins_alongside_paths():
    parser.install_redaction_rules(extra_field_paths=["data.user.note"])
    payload = {"data": {"user": {"note": "n", "password": "p"}}}
    out = redact_body(payload)
    assert out["data"]["user"]["note"] == REDACTED
    assert out["data"]["user"]["password"] == REDACTED  # built-in name rule


def test_load_field_paths_from_config(tmp_path):
    (tmp_path / "secure-log2test.toml").write_text(
        '[redaction]\nextra_field_paths = ["data.user.note", "items.ref"]\n',
        encoding="utf-8",
    )
    names, patterns, paths = load_redaction_rules(start_dir=tmp_path)
    assert names == []
    assert patterns == []
    assert paths == ["data.user.note", "items.ref"]


def test_load_field_paths_absent_yields_empty(tmp_path):
    (tmp_path / "secure-log2test.toml").write_text(
        '[redaction]\nextra_header_names = ["x-tenant"]\n',
        encoding="utf-8",
    )
    names, patterns, paths = load_redaction_rules(start_dir=tmp_path)
    assert names == ["x-tenant"]
    assert paths == []
