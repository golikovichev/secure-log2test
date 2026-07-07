"""Fuzz / property-based tests for the Kibana log parser.

These feed arbitrary and deliberately malformed input to ``KibanaLogParser``
and assert it fails gracefully: it either returns a list of parsed entries or
raises a clear ``ValueError``. It must never crash with an unhandled
``AttributeError``, ``TypeError`` or ``RecursionError``, which is what a user
would otherwise see when handed a corrupt or non-standard export file.

Regression guards for the malformed-input classes found by fuzzing: a ``hits``
value that is not an object, and an inner ``hits.hits`` value that is not an
array.
"""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from secure_log2test.core.parser import KibanaLogParser

# Quiet the per-skip warnings the parser emits on bad rows; we assert on
# behaviour (return value or exception type), not on log noise.
logging.getLogger("secure_log2test.core.parser").setLevel(logging.CRITICAL)

# Any JSON-serialisable value: scalars at the leaves, lists and string-keyed
# dicts as containers. Covers both well-shaped and malformed exports.
json_values = st.recursive(
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(),
    lambda children: (
        st.lists(children, max_size=5)
        | st.dictionaries(st.text(), children, max_size=5)
    ),
    max_leaves=30,
)


def _parse(value: object) -> list:
    with tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(json.dumps(value))
        path = Path(tmp.name)
    try:
        return KibanaLogParser(path).parse()
    finally:
        path.unlink(missing_ok=True)


@given(value=json_values)
@settings(max_examples=300, deadline=None)
def test_parser_is_graceful_on_arbitrary_json(value: object) -> None:
    """Any JSON value parses to a list or raises a clear ValueError, never a crash."""
    try:
        result = _parse(value)
    except ValueError:
        return  # the one deliberate, documented failure mode
    assert isinstance(result, list)


# Kibana-shaped fuzzing: keep the hits.hits[] envelope and fuzz the _source the
# entry validator reads, so generation reaches deeper into the parser.
def _kibana_shaped() -> st.SearchStrategy:
    source = st.dictionaries(
        st.sampled_from(
            ["method", "url", "status", "duration", "headers", "body", "other"]
        ),
        st.none() | st.integers() | st.text() | st.lists(st.text(), max_size=3),
        max_size=6,
    )
    hit = st.fixed_dictionaries({"_source": source}) | st.none() | st.text()
    return st.fixed_dictionaries(
        {"hits": st.fixed_dictionaries({"hits": st.lists(hit, max_size=6)})}
    )


@given(export=_kibana_shaped())
@settings(max_examples=200, deadline=None)
def test_parser_is_graceful_on_kibana_shaped_input(export: dict) -> None:
    try:
        result = _parse(export)
    except ValueError:
        return
    assert isinstance(result, list)


# --- targeted regression guards for the specific crash classes found ---


def test_non_object_hits_raises_value_error() -> None:
    for hits in ([], 42, None, "x"):
        try:
            _parse({"hits": hits})
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for hits={hits!r}")


def test_non_array_inner_hits_raises_value_error() -> None:
    for inner in (42, None, "abc", {"a": 1}):
        try:
            _parse({"hits": {"hits": inner}})
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for inner hits={inner!r}")


def test_valid_minimal_export_parses() -> None:
    assert _parse({"hits": {"hits": []}}) == []
