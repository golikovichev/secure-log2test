---
name: secure-log2test
description: Turn a Kibana JSON log export into a runnable pytest suite using the secure-log2test CLI. Use when the user has a Kibana or Elasticsearch JSON export of API traffic and wants a regression suite from production logs, when extracting test cases from staging traffic, when scrubbing auth headers or secret-looking body fields before logs leave the laptop, when bridging Kibana-captured requests into a pytest-based suite for CI, when the user mentions Kibana logs, Elasticsearch JSON export, log-to-test conversion, log replay tests, auth header redaction, PII in logs, or regression tests from production traffic.
license: MIT
metadata:
  category: "api-testing"
  homepage: "https://github.com/golikovichev/secure-log2test"
  pypi: "https://pypi.org/project/secure-log2test/"
  version: "1.1.0"
---

# secure-log2test

Read a Kibana JSON log export, write a single pytest module that replays every request and asserts on the response status. Authorization headers and secret-looking body fields get replaced with `***REDACTED***` before they reach the generated file.

The Kibana export stays the source of truth. The generated suite is committable code: no live Elasticsearch dependency at run time, no hand-copied requests. Re-run the converter when you pull a fresh export; the file regenerates cleanly.

## Quick start

1. Install the CLI from PyPI:
   ```bash
   pip install secure-log2test
   ```
2. Export the request log from Kibana as JSON. Discover view, Share, Export, JSON. The tool expects an array of entries with `method`, `url`, `status`, optional `duration`, `headers`, and `body`.
3. Run the converter against the export file:
   ```bash
   secure-log2test data/sample_kibana_export.json --output tests_generated.py
   ```
4. Set the base URL the suite should hit (the generated tests prepend it to the relative paths from the log):
   ```bash
   secure-log2test data/sample_kibana_export.json --output tests_generated.py --base-url https://staging.example.com
   ```
5. Run the suite:
   ```bash
   pytest tests_generated.py -v
   ```
6. Commit the generated module into the repo if you want it in CI. Re-run step 3 whenever you refresh the export.

### Error handling

- **Schema mismatch:** the converter exits non-zero with a clear message when an entry is missing `method` or `url`. Either fix the export or open an issue with a redacted sample.
- **File too large:** `--max-input-mb` (default 100) refuses exports above the limit. Pass a larger value if the export is genuinely that big, or split it externally first.
- **Pytest failures on first run:** check `--base-url` matches the host the log came from, and that the API is reachable. The generated module hits real endpoints; it does not mock responses.

## Inputs and outputs

**Input:** a Kibana or Elasticsearch JSON export. Each entry needs `method` and `url` at minimum. `status`, `duration`, `headers`, and `body` are picked up when present. Grafana Loki Explore exports are tracked separately ([#4](https://github.com/golikovichev/secure-log2test/issues/4)).

**Output:** a single pytest module. One `test_*` function per log entry. The slug filter turns `/api/v1/users/42` into a stable function name. Headers and JSON request body are emitted verbatim except for the redaction layer. The HTTP status code from the log is asserted against the live response.

**Redaction layer (runs at parse time, before generation):**

- A static list of well-known auth headers: `authorization`, `proxy-authorization`, `proxy-authenticate`, `cookie`, `set-cookie`, `x-api-key`, `x-auth-token`, `x-csrf-token`, `x-access-token`, `refresh-token`, `id-token`, `x-amz-security-token`, `authentication`.
- A regex pattern that catches custom names: `auth|token|secret|key|session|cookie|credential|bearer|password|passwd`. Header-name matching is case-insensitive.
- The same regex walks request bodies recursively, so nested fields like `{"password": "..."}`, `{"client_secret": "..."}`, and OAuth `{"refresh_token": "..."}` get scrubbed too.

Redacted values are replaced with the literal string `***REDACTED***`. The original input dict is not mutated.

## Example walkthrough

Bundled `data/sample_kibana_export.json` contains a few representative entries.

Given an input entry like:

```json
{
  "method": "POST",
  "url": "/api/v1/users",
  "status": 201,
  "headers": {"Authorization": "Bearer abc.xyz", "Content-Type": "application/json"},
  "body": {"name": "Test", "email": "test@example.com"}
}
```

The generator emits:

```python
def test_post_api_v1_users():
    response = requests.post(
        f"{BASE_URL}/api/v1/users",
        headers={"Authorization": "***REDACTED***", "Content-Type": "application/json"},
        json={"name": "Test", "email": "test@example.com"},
    )
    assert response.status_code == 201, (
        f"Expected 201, got {response.status_code}: {response.text[:200]}"
    )
```

The `Authorization` value never leaves the parser intact. You set the real token in the test environment at run time:

```bash
export BASE_URL=https://staging.example.com
# The generated module reads BASE_URL at test time; tokens come from your own env
pytest tests_generated.py -v
```

The generated module is self-contained. It imports `os`, `pytest`, and `requests`; nothing else. No `conftest.py` is required.

## Limitations and known gaps

What v1.1.0 does **not** handle yet. Calling them out so the tool stays trustworthy.

- **Kibana / Elasticsearch JSON export shape only.** Grafana Loki Explore exports are tracked in [#4](https://github.com/golikovichev/secure-log2test/issues/4).
- **Single-file input.** Multi-file batch mode is on the roadmap, not in v1.1.
- **Response body assertions.** Only the HTTP status code is asserted. If a request returns 200 with a wrong payload, the generated test passes anyway. Body match plus optional schema validation is the v1.1 line ([#1](https://github.com/golikovichev/secure-log2test/issues/1)).
- **Custom redaction rules.** Marker string `***REDACTED***` is hardcoded ([#6](https://github.com/golikovichev/secure-log2test/issues/6)); rule-file support is the v1.2 line ([#2](https://github.com/golikovichev/secure-log2test/issues/2)).
- **OAuth replay.** Static `Authorization` headers only, redacted at parse time. Token refresh and signature flows are not generated; set the real token in your env at run time.
- **Multipart bodies and file uploads.** Not generated.
- **Streaming responses or chunked transfer.** Not handled.

If something on this list blocks you, open an issue with a redacted sample.

## Security note

The redaction layer catches the well-known auth headers plus anything whose name matches the sensitive regex. This works for both header names and JSON body field names. If your team uses something the pattern misses (a truly opaque internal name), add it to `SENSITIVE_HEADERS` in `core/parser.py` before generating output. PRs welcome.

Never commit a generated suite that includes real production tokens. The redaction layer is a safety net, not a substitute for review. Inspect the generated file before pushing.

## References

- Project README and full design write-up: https://github.com/golikovichev/secure-log2test
- Article on the redaction layer and the v1.0.0 to v1.0.1 user-feedback story: https://dev.to/golikovichev/your-kibana-logs-are-full-of-test-cases-here-is-a-cli-that-extracts-them-with-auth-scrubbed-by-4433
