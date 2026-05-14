"""Generator safety tests.

Generated test files run under pytest in the user's environment. Any log
field that flows from captured traffic into rendered Python source must
land as a safe string literal, never as raw bytes that the parser would
interpret as code.
"""

import ast
import os
import pathlib

import pytest

from secure_log2test.core.generator import KibanaTestGenerator
from secure_log2test.core.parser import KibanaLogEntry


TEMPLATES_DIR = (
    pathlib.Path(__file__).parent.parent
    / "secure_log2test"
    / "templates"
)


def _render(entries, base_url=""):
    gen = KibanaTestGenerator(TEMPLATES_DIR)
    return gen.render(entries, base_url=base_url)


def test_url_with_double_quote_is_escaped():
    entry = KibanaLogEntry(
        method="GET",
        url='/api"; import os; os.system("rm -rf ~"); #',
        status=200,
    )
    rendered = _render([entry])
    # Must parse as valid Python with no extra statements injected.
    tree = ast.parse(rendered)
    # No Call to os.system anywhere in the AST.
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            target = (
                f"{fn.value.id}.{fn.attr}"
                if isinstance(fn, ast.Attribute)
                and isinstance(fn.value, ast.Name)
                else None
            )
            assert target != "os.system", "URL injection reached AST"


def test_url_with_newline_does_not_break_source():
    entry = KibanaLogEntry(
        method="GET",
        url="/api\nimport os\nos.system('evil')",
        status=200,
    )
    rendered = _render([entry])
    # Must still parse.
    ast.parse(rendered)
    # Injected statement must not appear at module level.
    assert "import os" not in rendered.splitlines()


def test_url_with_backslash_renders_literal():
    entry = KibanaLogEntry(
        method="GET",
        url="/api/\\x00\\u0000",
        status=200,
    )
    rendered = _render([entry])
    ast.parse(rendered)


def test_method_with_quote_does_not_break_source():
    entry = KibanaLogEntry(
        method='GET"; print("pwned"); "',
        url="/api",
        status=200,
    )
    rendered = _render([entry])
    ast.parse(rendered)
    assert 'print("pwned")' not in rendered


def test_base_url_with_quote_does_not_break_source():
    entry = KibanaLogEntry(method="GET", url="/api", status=200)
    rendered = _render(
        [entry],
        base_url='https://api.example.com"; import os; "',
    )
    ast.parse(rendered)
    assert "import os" not in rendered.splitlines()


def test_unicode_url_renders_clean():
    entry = KibanaLogEntry(
        method="GET",
        url="/api/пользователи/日本/🚀",
        status=200,
    )
    rendered = _render([entry])
    ast.parse(rendered)


def test_rendered_output_is_importable():
    """End-to-end: rendered module must compile without SyntaxError."""
    entries = [
        KibanaLogEntry(method="GET", url="/api/users", status=200),
        KibanaLogEntry(method="POST", url="/api/login", status=201),
        KibanaLogEntry(method="DELETE", url="/api/items/42", status=204),
    ]
    rendered = _render(entries, base_url="https://api.example.com")
    compile(rendered, "<generated>", "exec")


# ---------------------------------------------------------------------------
# Headers + body emission (H1 fix - generated tests must replay full request)
# ---------------------------------------------------------------------------


def _request_call_kwargs(rendered):
    """Return set of keyword argument names in every requests.request call."""
    tree = ast.parse(rendered)
    seen = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if (
                isinstance(fn, ast.Attribute)
                and fn.attr == "request"
                and isinstance(fn.value, ast.Name)
                and fn.value.id == "requests"
            ):
                for kw in node.keywords:
                    if kw.arg:
                        seen.add(kw.arg)
    return seen


def test_entry_with_headers_emits_headers_arg():
    entry = KibanaLogEntry(
        method="GET",
        url="/api/users",
        status=200,
        headers={"Content-Type": "application/json"},
    )
    rendered = _render([entry])
    assert "headers" in _request_call_kwargs(rendered)
    assert "'Content-Type': 'application/json'" in rendered
    compile(rendered, "<generated>", "exec")


def test_entry_with_auth_header_carries_redaction_marker():
    """Sensitive header lands as REDACTED in the generated test, not as
    the original secret value."""
    entry = KibanaLogEntry(
        method="POST",
        url="/api/login",
        status=200,
        headers={"Authorization": "Bearer real-secret-token-xyz"},
    )
    rendered = _render([entry])
    assert "real-secret-token-xyz" not in rendered
    assert "***REDACTED***" in rendered
    compile(rendered, "<generated>", "exec")


def test_entry_without_headers_omits_headers_arg():
    entry = KibanaLogEntry(method="GET", url="/api/ping", status=200)
    rendered = _render([entry])
    # Check via AST so the docstring mention of `headers={...}` does not
    # trip the test.
    assert "headers" not in _request_call_kwargs(rendered)
    compile(rendered, "<generated>", "exec")


def test_dict_body_renders_as_json_arg():
    entry = KibanaLogEntry(
        method="POST",
        url="/api/items",
        status=201,
        body={"name": "widget", "qty": 7},
    )
    rendered = _render([entry])
    kwargs = _request_call_kwargs(rendered)
    assert "json" in kwargs
    assert "data" not in kwargs
    assert "'name': 'widget'" in rendered
    compile(rendered, "<generated>", "exec")


def test_list_body_renders_as_json_arg():
    entry = KibanaLogEntry(
        method="POST",
        url="/api/bulk",
        status=200,
        body=[{"id": 1}, {"id": 2}],
    )
    rendered = _render([entry])
    assert "json" in _request_call_kwargs(rendered)
    compile(rendered, "<generated>", "exec")


def test_string_body_renders_as_data_arg():
    entry = KibanaLogEntry(
        method="POST",
        url="/api/upload",
        status=200,
        body="<xml><name>thing</name></xml>",
    )
    rendered = _render([entry])
    kwargs = _request_call_kwargs(rendered)
    assert "data" in kwargs
    assert "json" not in kwargs
    compile(rendered, "<generated>", "exec")


def test_none_body_omits_both_args():
    entry = KibanaLogEntry(method="GET", url="/api/ping", status=200)
    rendered = _render([entry])
    kwargs = _request_call_kwargs(rendered)
    assert "json" not in kwargs
    assert "data" not in kwargs
    compile(rendered, "<generated>", "exec")


def test_empty_string_body_omits_data_arg():
    entry = KibanaLogEntry(
        method="POST",
        url="/api/ping",
        status=200,
        body="",
    )
    rendered = _render([entry])
    kwargs = _request_call_kwargs(rendered)
    assert "data" not in kwargs
    assert "json" not in kwargs
    compile(rendered, "<generated>", "exec")


def test_body_with_injection_payload_lands_as_literal():
    entry = KibanaLogEntry(
        method="POST",
        url="/api/items",
        status=200,
        body={"name": "alpha\"; import os; os.system('evil'); \""},
    )
    rendered = _render([entry])
    tree = ast.parse(rendered)
    # The injected text exists in the source as a Python string literal
    # (inside the dict value passed to json=), but must NOT appear as a
    # Call node, which is what would actually execute it.
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            target = (
                f"{fn.value.id}.{fn.attr}"
                if isinstance(fn, ast.Attribute)
                and isinstance(fn.value, ast.Name)
                else None
            )
            assert target != "os.system", (
                "Body injection produced a real os.system call"
            )


def test_top_of_file_mentions_redaction_marker():
    """Generated module docstring should explain redaction so test users
    know to fill in real credentials."""
    entry = KibanaLogEntry(method="GET", url="/api/x", status=200)
    rendered = _render([entry])
    assert "***REDACTED***" in rendered
    assert "environment variables" in rendered.lower() or "env vars" in rendered.lower()
