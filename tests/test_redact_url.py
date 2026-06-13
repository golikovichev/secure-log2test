from secure_log2test.core.parser import REDACTED, KibanaLogEntry, redact_url


def test_redacts_sensitive_query_param():
    out = redact_url("/api/login?access_token=abc123&page=2")
    assert "abc123" not in out
    assert REDACTED in out
    assert "page=2" in out


def test_keeps_non_sensitive_query_untouched():
    out = redact_url("/search?q=widgets&limit=10")
    assert out == "/search?q=widgets&limit=10"


def test_no_query_string_returned_as_is():
    assert redact_url("/api/users") == "/api/users"


def test_redacts_multiple_sensitive_params():
    out = redact_url("/cb?api_key=keyval&password=pwval&ok=1")
    assert "keyval" not in out
    assert "pwval" not in out
    assert "ok=1" in out
    assert out.count(REDACTED) == 2


def test_custom_marker_used_in_url():
    out = redact_url("/api?token=secret", marker="[HIDDEN]")
    assert "secret" not in out
    assert "[HIDDEN]" in out


def test_entry_url_query_redacted_on_construction():
    entry = KibanaLogEntry(
        method="GET", url="/oauth/callback?access_token=leakme&state=ok", status=200
    )
    assert "leakme" not in entry.url
    assert "state=ok" in entry.url
    assert REDACTED in entry.url


def test_url_without_query_unchanged_on_entry():
    entry = KibanaLogEntry(method="GET", url="/api/health", status=200)
    assert entry.url == "/api/health"


def test_redacts_oauth_implicit_flow_fragment():
    out = redact_url("/cb?state=ok#access_token=leakme&token_type=bearer")
    assert "leakme" not in out
    assert "state=ok" in out
    assert "#" in out
    assert out.count(REDACTED) >= 1


def test_bare_flag_param_without_value_kept():
    assert redact_url("/api?token") == "/api?token"


def test_value_containing_equals_redacted_whole():
    assert redact_url("/api?token=a=b=c") == f"/api?token={REDACTED}"


def test_non_sensitive_fragment_untouched():
    assert redact_url("/docs?q=1#section-2") == "/docs?q=1#section-2"
