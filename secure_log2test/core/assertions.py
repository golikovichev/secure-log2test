"""Response-body assertion config (issue #1, v1.1).

Log exports carry the request (method, url, headers, body) but rarely the
response body, so body assertions are driven by a small config the user
writes, not scraped from the logs. Each rule targets an endpoint by method
and url and declares what the response should look like: field-level
equality on the parsed JSON and, optionally, a JSON Schema to validate
against. The generator turns matched rules into checks inside the emitted
pytest module; see ``core/generator.py`` and the module template.

The config is JSON so the tool keeps its dependency-light footprint (no
YAML runtime dep). Schema files referenced by a rule are read at generation
time and inlined into the generated test, so the emitted suite is
self-contained and needs no schema file alongside it at run time.
"""

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AssertionRule(BaseModel):
    """One endpoint's response-body expectations.

    ``method`` and ``url`` identify the endpoint and must match the request
    as it appears in the generated test (the url is compared after
    redaction). ``expect_fields`` maps a top-level JSON key to its expected
    value. ``schema`` (config key ``schema``) points to a JSON Schema file
    relative to the config file; it is loaded into ``schema_obj`` by
    ``load_assertion_config``.
    """

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    method: str
    url: str
    expect_fields: dict[str, Any] = Field(default_factory=dict)
    schema_path: str | None = Field(default=None, alias="schema")
    schema_obj: Any = None

    @field_validator("method")
    @classmethod
    def _normalize_method(cls, v):
        return v.upper()


class AssertionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: list[AssertionRule] = Field(default_factory=list)


def load_assertion_config(path):
    """Load and validate an assertion config, resolving any schema files.

    Raises ValueError with a clear message when the file cannot be read, is
    not valid JSON, fails schema validation (for example a rule missing
    method or url), or references a schema file that cannot be read. The
    friendly ValueError mirrors the parser's error style so the CLI can
    surface a single readable line.
    """
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as e:
        raise ValueError(f"Could not read assertion config {path}: {e}") from e
    except json.JSONDecodeError as e:
        raise ValueError(f"Assertion config {path} is not valid JSON: {e}") from e

    try:
        config = AssertionConfig.model_validate(raw)
    except Exception as e:
        raise ValueError(f"Invalid assertion config {path}: {e}") from e

    base = path.parent
    for rule in config.rules:
        if not rule.expect_fields and not rule.schema_path:
            raise ValueError(
                f"Assertion rule for {rule.method} {rule.url} in {path} has "
                f"neither expect_fields nor schema; there is nothing to assert. "
                f"Add at least one expected field or a schema, or remove the rule."
            )
        if rule.schema_path:
            schema_path = base / rule.schema_path
            try:
                rule.schema_obj = json.loads(
                    schema_path.read_text(encoding="utf-8-sig")
                )
            except OSError as e:
                raise ValueError(
                    f"Could not read schema file {schema_path} referenced by "
                    f"assertion config {path}: {e}"
                ) from e
            except json.JSONDecodeError as e:
                raise ValueError(
                    f"Schema file {schema_path} referenced by assertion config "
                    f"{path} is not valid JSON: {e}"
                ) from e
    return config


class AssertionMatcher:
    """Return the assertion rules that apply to a given log entry.

    Matching is exact on method (case-insensitive, both sides upper-cased)
    and on url as it appears in the generated request. An entry can match
    more than one rule, so callers get a list; splitting field checks and a
    schema match across two rules for the same endpoint is allowed.
    """

    def __init__(self, config):
        self.rules = config.rules

    def for_entry(self, entry):
        method = (getattr(entry, "method", "") or "").upper()
        url = getattr(entry, "url", "")
        return [r for r in self.rules if r.method == method and r.url == url]
