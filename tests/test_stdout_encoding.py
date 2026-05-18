"""Tests for the CLI UTF-8 stdout / stderr enforcement.

The CLI calls ``ensure_utf8_streams`` at the top of ``main`` so any
non-ASCII byte that survives the parser (Cyrillic header value, accented
endpoint slug, emoji in payload) does not blow up the run with a
``UnicodeEncodeError`` on Windows shells defaulting to cp1252.

Coverage:

- The helper reconfigures real text streams when possible.
- It is a quiet no-op when the stream cannot be reconfigured (e.g. tests
  patch ``sys.stdout`` with a plain ``io.StringIO``).
- It does not crash when ``reconfigure`` raises (closed stream, weird
  buffered wrappers).
"""

from __future__ import annotations

import io
import sys

import pytest

from secure_log2test.cli import (
    _ensure_utf8_stream,
    ensure_utf8_streams,
)


def test_helper_actually_switches_a_cp1252_stream_to_utf8(tmp_path):
    """Open a file in cp1252, reconfigure to UTF-8, and prove Cyrillic survives.

    The previous test only checked that `reconfigure` exists. This one
    proves the helper performs the actual switch by writing non-ASCII text
    that cp1252 cannot represent.
    """
    path = tmp_path / "out.txt"
    with path.open("w", encoding="cp1252") as fh:
        assert _ensure_utf8_stream(fh) is True
        assert fh.encoding == "utf-8"
        fh.write("Кириллица")
    assert path.read_text(encoding="utf-8") == "Кириллица"


def test_helper_returns_false_for_a_stream_without_reconfigure():
    """``io.StringIO`` has no ``reconfigure`` method, so the helper bows out."""
    buffer = io.StringIO()
    assert _ensure_utf8_stream(buffer) is False


def test_helper_returns_false_when_reconfigure_is_not_callable():
    """A non-callable attribute named `reconfigure` must not crash the helper."""

    class _StreamWithNonCallableReconfigure:
        reconfigure = "not a function"

    assert _ensure_utf8_stream(_StreamWithNonCallableReconfigure()) is False


def test_helper_does_not_crash_when_reconfigure_raises():
    class _StreamThatRefuses:
        def reconfigure(self, **_kwargs):
            raise ValueError("nope")

    assert _ensure_utf8_stream(_StreamThatRefuses()) is False


def test_ensure_utf8_streams_does_not_crash_with_patched_stdio(monkeypatch):
    """``capsys`` and other test harnesses swap stdout / stderr for StringIO.

    The CLI is meant to call ``ensure_utf8_streams`` unconditionally, so the
    helper must not crash on those replacements.
    """
    fake_out = io.StringIO()
    fake_err = io.StringIO()
    monkeypatch.setattr(sys, "stdout", fake_out)
    monkeypatch.setattr(sys, "stderr", fake_err)
    # Should not raise, returns nothing, and leaves the streams usable.
    ensure_utf8_streams()
    fake_out.write("ok")
    fake_err.write("warn")
    assert fake_out.getvalue() == "ok"
    assert fake_err.getvalue() == "warn"


@pytest.mark.parametrize(
    "text",
    [
        "ascii only",
        "Кириллица в имени теста",
        "Café au lait",
        "日本語",
        "emoji \U0001f680",
    ],
)
def test_helper_lets_a_real_stream_swallow_non_ascii(tmp_path, text):
    """After reconfigure, writing non-ASCII text must succeed."""
    path = tmp_path / "out.txt"
    with path.open("w") as fh:
        _ensure_utf8_stream(fh)
        fh.write(text)
    assert path.read_text(encoding="utf-8") == text
