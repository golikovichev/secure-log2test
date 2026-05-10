# secure-log2test

[![CI](https://github.com/golikovichev/secure-log2test/actions/workflows/ci.yml/badge.svg)](https://github.com/golikovichev/secure-log2test/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://pypi.org/project/secure-log2test/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Turn a Kibana API log export into an executable pytest suite. Auth headers redacted by default.

Status: alpha. v1.0.0 lands May 2026.

## Why

You have Kibana logs from staging or production. Each entry is a real request: method, URL, status, duration, headers, body. That's a regression suite waiting to happen. Most teams either ignore it, screenshot interesting failures into Jira, or hand-write pytest cases from log entries one at a time.

I needed a faster path. `secure-log2test` reads a Kibana JSON export and writes a pytest module you can run and commit. Auth values get replaced with `***REDACTED***` before they ever touch the output, so a generated suite is safe to push to a public repo.

The tool exists because at Лента I kept doing the same five steps by hand for every production incident: open Kibana, scroll, copy the failing request, paste into a new test, repeat. Five minutes per request times ten requests means an hour gone before any actual debugging starts.

## Quickstart

```bash
git clone https://github.com/golikovichev/secure-log2test
cd secure-log2test
python -m venv .venv && source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt

python main.py data/sample_kibana_export.json --output tests_generated.py
pytest tests_generated.py -v
```

The sample export ships with the repo (`data/sample_kibana_export.json`), so you can see real output without setting up a Kibana instance first.

PyPI install (`pip install secure-log2test`) lands with v1.0.0.

## How it works

Two stages, kept separate.

**Parse** (`core/parser.py`). Reads the Kibana JSON and validates each entry through Pydantic v2. Sensitive headers are redacted before any further processing. The redaction list lives in `SENSITIVE_HEADERS`: `authorization`, `proxy-authorization`, `cookie`, `set-cookie`, `x-api-key`, `x-auth-token`, `authentication`. Match is case-insensitive. Header values get replaced with `***REDACTED***`. The original input dict is not mutated.

**Generate** (`core/generator.py`). Takes the cleaned entries and renders a Jinja2 template (`templates/test_module.py.j2`) into a pytest module. Each log entry becomes one `test_*` function. The slug filter turns `/api/v1/users/42` into a stable function name. A `--base-url` flag lets you target staging vs production at runtime.

The split lets you reuse the parser for other formats. If you want to generate Locust scripts, k6 scenarios, or an OpenAPI spec from the same logs, the parser stays. Only the template changes.

## Sample output

Given this Kibana log entry:

```json
{
  "method": "POST",
  "url": "/api/v1/users",
  "status": 201,
  "headers": {"Authorization": "Bearer abc.xyz", "Content-Type": "application/json"},
  "body": {"name": "Test", "email": "test@example.com"}
}
```

The generator emits something like:

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

The `Authorization` value never leaves the parser intact. You set the real token in your environment at run time.

## Limitations

This is what v0.2.0 does **not** handle. Calling them out so the tool stays trustworthy.

- OAuth flows. Only static `Authorization` headers, redacted to a placeholder.
- Multipart bodies and file uploads.
- Streaming responses or chunked transfer.
- Kibana exports older than the schema in `data/sample_kibana_export.json`. Fixture-driven; if your export looks different, open an issue with a redacted sample.
- Response body assertions. Status code only for now.
- Pre-request scripts or test scripts (the project takes only what is in the log entry).

If something on this list blocks you, open an issue. v1.0 stays small on purpose; the roadmap below is where new scope goes.

## Roadmap

| Version | Adds |
| --- | --- |
| 0.3 | Response body assertions, optional schema match. |
| 0.4 | Custom redaction rules via config file. |
| 0.5 | Multiple output formats (k6, Locust). |
| 1.0 | First stable API, PyPI release, full docs site. |

Target dates live in `CHANGELOG.md` once the work is in flight.

## Tests

```bash
pytest tests/ -v
```

Coverage as of 0.2.0:
- Parser unit tests for valid input, malformed input, header redaction, empty bodies.
- Edge cases for 5xx responses and missing fields.
- CI smoke test that runs the CLI end-to-end on the sample export and parses the generated Python with `ast.parse`.

CI runs on Python 3.10 and 3.11 via GitHub Actions.

## Security note

The default redaction list is conservative. If your team uses a custom auth header (`X-Company-Token`, anything not in the standard list), add it to `SENSITIVE_HEADERS` in `core/parser.py` before generating output. PRs welcome.

Never commit a generated suite that includes real production tokens. The redaction is a safety net, not a substitute for review.

## Contributing

Issue templates and PR guidance live in [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports with a redacted sample log are the most useful kind.

## Licence

MIT. See [LICENSE](LICENSE).
