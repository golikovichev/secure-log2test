"""Tests for v1.1 response body assertions (issue #1).

The generator can weave optional response-body checks into the emitted
pytest module, driven by a JSON assertion config that the user supplies
per endpoint. These tests pin the config loading, the endpoint matching,
and the generated test source (field equality, optional JSON Schema, and
the content-type guard that skips non-JSON responses).
"""

import ast
import json

import pytest

from secure_log2test.core.assertions import (
    AssertionMatcher,
    AssertionRule,
    load_assertion_config,
)
from secure_log2test.core.generator import KibanaTestGenerator
from secure_log2test.core.parser import KibanaLogEntry

TEMPLATES = "secure_log2test/templates"


def _render(entries, matcher=None):
    gen = KibanaTestGenerator(TEMPLATES)
    return gen.render(entries, base_url="http://example.test", matcher=matcher)


def _entry(method="GET", url="/api/users/1", status=200):
    return KibanaLogEntry(method=method, url=url, status=status)


def _write_config(tmp_path, config, name="assertions.json"):
    path = tmp_path / name
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


def _assert_valid_python(source):
    ast.parse(source)  # raises SyntaxError if the generated module is broken


# --- config loading -------------------------------------------------------


def test_load_config_parses_rules(tmp_path):
    path = _write_config(
        tmp_path,
        {
            "rules": [
                {"method": "get", "url": "/api/users/1", "expect_fields": {"id": 1}}
            ]
        },
    )
    config = load_assertion_config(path)
    assert len(config.rules) == 1
    # method is normalised to upper case so matching is case-insensitive.
    assert config.rules[0].method == "GET"
    assert config.rules[0].expect_fields == {"id": 1}


def test_load_config_rejects_invalid_json(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        load_assertion_config(path)


def test_load_config_rejects_missing_required_fields(tmp_path):
    path = _write_config(tmp_path, {"rules": [{"expect_fields": {"id": 1}}]})
    with pytest.raises(ValueError):
        load_assertion_config(path)


def test_load_config_resolves_schema_file_relative_to_config(tmp_path):
    (tmp_path / "user.schema.json").write_text(
        json.dumps({"type": "object", "required": ["id"]}), encoding="utf-8"
    )
    path = _write_config(
        tmp_path,
        {
            "rules": [
                {"method": "GET", "url": "/api/users/1", "schema": "user.schema.json"}
            ]
        },
    )
    config = load_assertion_config(path)
    assert config.rules[0].schema_obj == {"type": "object", "required": ["id"]}


def test_load_config_missing_schema_file_errors(tmp_path):
    path = _write_config(
        tmp_path,
        {"rules": [{"method": "GET", "url": "/api/users/1", "schema": "nope.json"}]},
    )
    with pytest.raises(ValueError):
        load_assertion_config(path)


# --- matching -------------------------------------------------------------


def test_matcher_matches_method_and_url_case_insensitively(tmp_path):
    path = _write_config(
        tmp_path,
        {
            "rules": [
                {"method": "get", "url": "/api/users/1", "expect_fields": {"id": 1}}
            ]
        },
    )
    matcher = AssertionMatcher(load_assertion_config(path))
    matched = matcher.for_entry(_entry("GET", "/api/users/1"))
    assert len(matched) == 1
    assert matched[0].expect_fields == {"id": 1}


def test_matcher_no_match_returns_empty(tmp_path):
    path = _write_config(
        tmp_path,
        {
            "rules": [
                {"method": "GET", "url": "/api/users/1", "expect_fields": {"id": 1}}
            ]
        },
    )
    matcher = AssertionMatcher(load_assertion_config(path))
    assert matcher.for_entry(_entry("GET", "/api/orders/9")) == []
    assert matcher.for_entry(_entry("POST", "/api/users/1")) == []


# --- generated source -----------------------------------------------------


def test_render_without_matcher_emits_no_body_assert():
    source = _render([_entry()])
    _assert_valid_python(source)
    assert "response.json()" not in source
    assert "assert response.status_code == 200" in source


def test_render_field_equality_emits_json_and_asserts(tmp_path):
    path = _write_config(
        tmp_path,
        {
            "rules": [
                {
                    "method": "GET",
                    "url": "/api/users/1",
                    "expect_fields": {"id": 1, "name": "Ada"},
                }
            ]
        },
    )
    matcher = AssertionMatcher(load_assertion_config(path))
    source = _render([_entry("GET", "/api/users/1")], matcher=matcher)
    _assert_valid_python(source)
    assert "body = response.json()" in source
    assert "assert body['id'] == 1" in source
    assert "assert body['name'] == 'Ada'" in source


def test_render_skips_body_assert_for_non_json(tmp_path):
    path = _write_config(
        tmp_path,
        {
            "rules": [
                {"method": "GET", "url": "/api/users/1", "expect_fields": {"id": 1}}
            ]
        },
    )
    matcher = AssertionMatcher(load_assertion_config(path))
    source = _render([_entry("GET", "/api/users/1")], matcher=matcher)
    _assert_valid_python(source)
    # the content-type guard is what makes a non-JSON response skip the check.
    assert "content-type" in source.lower()
    assert "application/json" in source


def test_render_schema_match_inlines_schema_and_validates(tmp_path):
    (tmp_path / "user.schema.json").write_text(
        json.dumps({"type": "object", "required": ["id"]}), encoding="utf-8"
    )
    path = _write_config(
        tmp_path,
        {
            "rules": [
                {"method": "GET", "url": "/api/users/1", "schema": "user.schema.json"}
            ]
        },
    )
    matcher = AssertionMatcher(load_assertion_config(path))
    source = _render([_entry("GET", "/api/users/1")], matcher=matcher)
    _assert_valid_python(source)
    assert "import jsonschema" in source
    assert "jsonschema.validate(" in source
    # the schema object is inlined so the generated test is self-contained.
    assert "'required'" in source and "'id'" in source


def test_render_unmatched_entry_gets_no_body_assert(tmp_path):
    path = _write_config(
        tmp_path,
        {
            "rules": [
                {"method": "GET", "url": "/api/users/1", "expect_fields": {"id": 1}}
            ]
        },
    )
    matcher = AssertionMatcher(load_assertion_config(path))
    entries = [_entry("GET", "/api/users/1"), _entry("GET", "/api/orders/9")]
    source = _render(entries, matcher=matcher)
    _assert_valid_python(source)
    # exactly one endpoint carries a body assertion.
    assert source.count("body = response.json()") == 1


# --- hardening from code review -------------------------------------------


def test_load_config_rejects_rule_with_nothing_to_assert(tmp_path):
    # a rule with no expect_fields and no schema would emit a dead body read.
    path = _write_config(
        tmp_path, {"rules": [{"method": "GET", "url": "/api/users/1"}]}
    )
    with pytest.raises(ValueError):
        load_assertion_config(path)


def test_load_config_rejects_unknown_key(tmp_path):
    # a typo like expect_field (singular) must not be silently dropped.
    path = _write_config(
        tmp_path,
        {
            "rules": [
                {"method": "GET", "url": "/api/users/1", "expect_field": {"id": 1}}
            ]
        },
    )
    with pytest.raises(ValueError):
        load_assertion_config(path)


def test_schema_alias_round_trip():
    # the config key is `schema`; it maps to schema_path without shadowing
    # pydantic's own BaseModel.schema.
    rule = AssertionRule(method="GET", url="/x", schema="user.json")
    assert rule.schema_path == "user.json"


def test_matcher_returns_all_rules_for_one_endpoint(tmp_path):
    # field checks and a schema can be split across two rules on one endpoint.
    (tmp_path / "s.json").write_text(json.dumps({"type": "object"}), encoding="utf-8")
    path = _write_config(
        tmp_path,
        {
            "rules": [
                {"method": "GET", "url": "/api/users/1", "expect_fields": {"id": 1}},
                {"method": "GET", "url": "/api/users/1", "schema": "s.json"},
            ]
        },
    )
    matcher = AssertionMatcher(load_assertion_config(path))
    source = _render([_entry("GET", "/api/users/1")], matcher=matcher)
    _assert_valid_python(source)
    assert "assert body['id'] == 1" in source
    assert "jsonschema.validate(" in source


def test_render_imports_jsonschema_once_for_multiple_schema_rules(tmp_path):
    (tmp_path / "s.json").write_text(json.dumps({"type": "object"}), encoding="utf-8")
    path = _write_config(
        tmp_path,
        {
            "rules": [
                {"method": "GET", "url": "/api/users/1", "schema": "s.json"},
                {"method": "GET", "url": "/api/orders/9", "schema": "s.json"},
            ]
        },
    )
    matcher = AssertionMatcher(load_assertion_config(path))
    entries = [_entry("GET", "/api/users/1"), _entry("GET", "/api/orders/9")]
    source = _render(entries, matcher=matcher)
    _assert_valid_python(source)
    # import is hoisted to module top and emitted once, not per matched rule.
    assert source.count("import jsonschema") == 1
