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
