# secure-log2test

[![CI](https://github.com/golikovichev/secure-log2test/actions/workflows/ci.yml/badge.svg)](https://github.com/golikovichev/secure-log2test/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/secure-log2test)](https://pypi.org/project/secure-log2test/)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://pypi.org/project/secure-log2test/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Turn a Kibana API log export into an executable pytest suite. Auth headers and secret-looking body fields redacted before they reach the output.

Status: v1.0.1 on PyPI. Stable per semver. Active roadmap, see open issues.

📖 **[Read the design write-up on Dev.to](https://dev.to/golikovichev/your-kibana-logs-are-full-of-test-cases-here-is-a-cli-that-extracts-them-with-auth-scrubbed-by-4433)** — privacy constraint, three-layer redaction, the v1.0.0 → v1.0.1 user-feedback story.

## Why

You have Kibana logs from staging or production. Each entry is a real request: method, URL, status, duration, headers, body. That's a regression suite waiting to happen. Most teams either ignore it, screenshot interesting failures into Jira, or hand-write pytest cases from log entries one at a time.

I needed a faster path. `secure-log2test` reads a Kibana JSON export and writes a pytest module you can run and commit. Auth values get replaced with `***REDACTED***` before they ever touch the output, so a generated suite is safe to push to a public repo.

The tool exists because at Лента I kept doing the same five steps by hand for every production incident: open Kibana, scroll, copy the failing request, paste into a new test, repeat. Five minutes per request times ten requests means an hour gone before any actual debugging starts.

## Quickstart

```bash
pip install secure-log2test

secure-log2test data/sample_kibana_export.json --output tests_generated.py
pytest tests_generated.py -v
```

A sample export ships with the repo (`data/sample_kibana_export.json`), so you can see real output without setting up a Kibana instance first. Grab it from the GitHub repo if you installed from PyPI.

For local development:

```bash
git clone https://github.com/golikovichev/secure-log2test
cd secure-log2test
python -m venv .venv && source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
pytest tests/ -v
```

## How it works

Two stages, kept separate.

**Parse** (`core/parser.py`). Reads the Kibana JSON and validates each entry through Pydantic v2. Two layers of redaction run before any further processing:

- A static list of well-known headers (`authorization`, `proxy-authorization`, `proxy-authenticate`, `cookie`, `set-cookie`, `x-api-key`, `x-auth-token`, `x-csrf-token`, `x-access-token`, `refresh-token`, `id-token`, `x-amz-security-token`, `authentication`).
- A regex pattern (`auth|token|secret|key|session|cookie|credential|bearer|password|passwd`) that catches custom header names and body field names project teams invent.

The same logic walks request bodies recursively, so `{"password": "..."}`, `{"client_secret": "..."}`, OAuth `{"refresh_token": "..."}` all get scrubbed at parse time. Header name matching is case-insensitive. Values get replaced with `***REDACTED***`. The original input dict is not mutated.

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

What v1.0.1 does **not** handle yet. Calling them out so the tool stays trustworthy.

- Kibana / Elasticsearch JSON export shape only. Grafana Loki Explore exports are tracked in [#4](https://github.com/golikovichev/secure-log2test/issues/4).
- Single-file input. Multi-file batch mode is on the roadmap.
- Output format: pytest only. JSON / CSV for downstream pipelines is tracked in [#5](https://github.com/golikovichev/secure-log2test/issues/5).
- Custom redaction marker string. The default `***REDACTED***` is hardcoded; configurable marker is tracked in [#6](https://github.com/golikovichev/secure-log2test/issues/6).
- Response body assertions. Status code only for now, full body match is on the v1.1 list ([#1](https://github.com/golikovichev/secure-log2test/issues/1)).
- Custom redaction rules via config file are on the v1.2 list ([#2](https://github.com/golikovichev/secure-log2test/issues/2)).
- OAuth replay. Only static `Authorization` headers, redacted to a placeholder.
- Multipart bodies and file uploads.
- Streaming responses or chunked transfer.

If something on this list blocks you, open an issue.

## Roadmap

| Version | Tracks | Adds |
| --- | --- | --- |
| v1.1 | [#1](https://github.com/golikovichev/secure-log2test/issues/1) | Response body assertions plus optional schema match. |
| v1.2 | [#2](https://github.com/golikovichev/secure-log2test/issues/2) | Custom redaction rules via config file. |
| Future | [#4](https://github.com/golikovichev/secure-log2test/issues/4) | Grafana Loki Explore export format support. |

Open the [issue tracker](https://github.com/golikovichev/secure-log2test/issues) for the live picture; two `good first issue` slots are currently open if you want to jump in.

## Tests

```bash
pytest tests/ -v
```

59 tests as of v1.0.1, covering:

- Parser unit tests for valid input, malformed input, header redaction, body redaction walker, empty bodies.
- Edge cases for 5xx responses, missing fields, custom auth header patterns, OAuth refresh tokens in request bodies.
- CI smoke test that runs the CLI end-to-end on the sample export and parses the generated Python with `ast.parse`.

CI runs on Python 3.10, 3.11, 3.12, and 3.13 via GitHub Actions.

## Security note

The redaction layer catches the well-known auth headers plus anything whose name contains `auth`, `token`, `secret`, `key`, `session`, `cookie`, `credential`, `bearer`, `password`, or `passwd`. This works for both header names and JSON body field names. If your team uses something the pattern misses (truly opaque internal name), add it to `SENSITIVE_HEADERS` in `core/parser.py` before generating output. PRs welcome.

Never commit a generated suite that includes real production tokens. The redaction layer is a safety net, not a substitute for review.

## Contributing

Issue templates and PR guidance live in [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports with a redacted sample log are the most useful kind.

## Licence

MIT. See [LICENSE](LICENSE).
