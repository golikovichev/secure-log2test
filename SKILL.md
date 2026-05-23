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

Full CLI reference, redaction rules, validation steps, limitations, and CI workflow templates live in `REFERENCE.md` next to this file.

## Quick start

1. Install the CLI from PyPI:
   ```bash
   pip install secure-log2test
   ```
2. Export from Kibana as JSON. Discover view → Share → Export → JSON. The tool expects an array of entries with `method`, `url`, `status`, optional `duration`, `headers`, `body`.
3. Run the converter:
   ```bash
   secure-log2test data/sample_kibana_export.json --output tests_generated.py
   ```
4. Sanity-check the output (test count matches the log entry count, no plaintext credentials leaked):
   ```bash
   grep -c '^def test_' tests_generated.py
   grep -E '(authorization|x-api-key).*Bearer\s+[A-Za-z0-9]' tests_generated.py  # expect zero matches
   ```
5. Set the base URL the suite should hit:
   ```bash
   export BASE_URL=https://staging.example.com
   ```
6. Run the suite:
   ```bash
   pytest tests_generated.py -v
   ```
7. Commit the generated module if you want it in CI. Re-run step 3 whenever the export changes.

## Example

Given an input entry:

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

The `Authorization` value never leaves the parser intact. The real token is read from `AUTHORIZATION` env var at run time. The generated module is self-contained: imports `os`, `pytest`, `requests`; nothing else, no `conftest.py` required.

## Common errors

- **Schema mismatch:** an entry is missing `method` or `url`; check the export.
- **`BASE_URL` not set:** generated module reads it at run time.
- **File too large:** pass `--max-input-mb` higher, or split externally first.

Full error-handling tree, redaction-rule reference, and validation commands in `REFERENCE.md`.

## Security note

Redaction is a safety net, not a substitute for review. Inspect the generated file before pushing; never commit a suite that includes real production tokens. The pattern errs toward over-scrubbing; full rule list and tuning instructions in `REFERENCE.md`.

## CI

For GitHub Actions / GitLab CI templates that run the converter + suite on every push, see `REFERENCE.md` section "CI integration".

## References

- Bundle: `REFERENCE.md` (CLI flags, redaction layer rules, validation, error tree, CI templates)
- Project: https://github.com/golikovichev/secure-log2test
- PyPI: https://pypi.org/project/secure-log2test/
- Article: https://dev.to/golikovichev/your-kibana-logs-are-full-of-test-cases-here-is-a-cli-that-extracts-them-with-auth-scrubbed-by-4433
