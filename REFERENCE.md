# secure-log2test reference

Detailed inputs, outputs, CLI flags, redaction layer rules, validation, limitations, and CI integration. SKILL.md keeps the quick-start and one example. Read this file when you need the full surface.

## Inputs and outputs

**Input:** a Kibana or Elasticsearch JSON export. Each entry needs `method` and `url` at minimum. `status`, `duration`, `headers`, and `body` are picked up when present. Discover view → Share → Export → JSON in Kibana produces the expected shape.

**Output:** a single pytest module. One `test_*` function per log entry. The slug filter turns `/api/v1/users/42` into a stable function name. Headers and JSON request body are emitted verbatim except for the redaction layer. The HTTP status code from the log is asserted against the live response.

## CLI flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `INPUT_FILE` (positional) | required | Kibana JSON export file. |
| `--output PATH` | `tests_generated.py` | Output `.py` file path. |
| `--base-url URL` | none | Base URL prepended to relative paths from the log. Can also come from `BASE_URL` env at test time. |
| `--max-input-mb N` | 100 | Refuse exports above this size in MB. |
| `--format` | `pytest` | Output format. Currently `pytest`; `json` and `csv` were added by external contributor PR #7. |
| `--help` | - | Full CLI reference. |
| `--version` | - | Print installed version. |

## Redaction layer

Runs at parse time, before any test code is generated. Two passes, both case-insensitive:

**1. Static allowlist of well-known auth headers:**

`authorization`, `proxy-authorization`, `proxy-authenticate`, `cookie`, `set-cookie`, `x-api-key`, `x-auth-token`, `x-csrf-token`, `x-access-token`, `refresh-token`, `id-token`, `x-amz-security-token`, `authentication`.

**2. Regex pattern catching custom names:**

`auth|token|secret|key|session|cookie|credential|bearer|password|passwd`.

This regex walks request bodies recursively, so nested fields like `{"password": "..."}`, `{"client_secret": "..."}`, and OAuth `{"refresh_token": "..."}` are scrubbed alongside header names.

**Replacement marker:** literal string `***REDACTED***`. The original input dict is not mutated; the generator copies before redacting.

**Adding custom rules:** if your team uses an opaque internal name the pattern misses (e.g. `X-MyCo-Token`), add it to `SENSITIVE_HEADERS` in `core/parser.py` before generating output. Rule-file support is tracked in issue #2 for v1.2.

## Validation after generation

```bash
# Count generated test functions
grep -c '^def test_' tests_generated.py
# Confirm log entry count matches
python -c "import json; print(len(json.load(open('data/sample_kibana_export.json'))))"
# Sanity-check no plaintext credentials leaked
grep -E '(authorization|x-api-key).*Bearer\s+[A-Za-z0-9]' tests_generated.py
# Lint the generated module
python -m py_compile tests_generated.py
```

The third command should return ZERO matches if redaction worked. If it fires, the header name uses a pattern the redaction layer misses; report it via issue with a redacted sample.

## Error handling

- **Schema mismatch:** the converter exits non-zero with a clear message when an entry is missing `method` or `url`. Either fix the export or open an issue with a redacted sample.
- **File too large:** `--max-input-mb` (default 100) refuses exports above the limit. Pass a larger value if the export is genuinely that big, or split it externally first.
- **Pytest failures on first run:** check `--base-url` matches the host the log came from, and that the API is reachable. The generated module hits real endpoints; it does not mock responses.
- **Empty output:** the input array is empty, or every entry is missing required fields. Validate the JSON in a viewer first.

## Limitations

- Kibana / Elasticsearch JSON export shape only. Splunk + Datadog + Grafana Loki on roadmap.
- Single-file input. Multi-file batch mode is roadmap, not v1.1.
- Response body assertions: only the HTTP status code is asserted. Body content is not validated.
- Custom redaction rules: the marker string `***REDACTED***` is hardcoded; rule-file support is roadmap.
- OAuth replay: static `Authorization` headers only, redacted at parse time. Token refresh and signature flows are not generated.
- Multipart bodies and file uploads: not generated.
- Streaming responses or chunked transfer: not handled.

If a missing feature blocks you, open an issue with a redacted sample.

## Security note

The redaction layer is a safety net, not a substitute for review. Never commit a generated suite that includes real production tokens. Inspect the generated file before pushing. The pattern is permissive on purpose so it errs toward over-scrubbing; if a non-sensitive header gets caught (e.g. `X-Cookie-Banner-Shown`), the test still passes because the value is read from the env at run time.

## CI integration

Minimal GitHub Actions workflow that runs the converter and the suite on every push:

```yaml
name: API tests
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install secure-log2test
      - run: secure-log2test data/kibana_export.json --output tests/test_api.py --base-url $BASE_URL
        env:
          BASE_URL: ${{ secrets.STAGING_BASE_URL }}
      - run: pytest tests/test_api.py -v
        env:
          BASE_URL: ${{ secrets.STAGING_BASE_URL }}
          AUTHORIZATION: ${{ secrets.STAGING_API_TOKEN }}
```

## External links

- Project README and full design write-up: https://github.com/golikovichev/secure-log2test
- Article on redaction layer + v1.0.0 to v1.0.1 user-feedback story: https://dev.to/golikovichev/your-kibana-logs-are-full-of-test-cases-here-is-a-cli-that-extracts-them-with-auth-scrubbed-by-4433
- PyPI package: https://pypi.org/project/secure-log2test/
