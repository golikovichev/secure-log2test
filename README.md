# Secure Log2Test Engine

[![CI](https://github.com/golikovichev/secure-log2test/actions/workflows/ci.yml/badge.svg)](https://github.com/golikovichev/secure-log2test/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/release/python-3100/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A deterministic, privacy-first CLI tool for enterprise QA and SDET teams.
Generates executable `pytest` regression suites by parsing production API logs
exported from Kibana/Elasticsearch — without sending any NDA or PII data to external services.

## Problem

Modern QA teams struggle to maintain test coverage parity with real production traffic.
Existing LLM-based tools can generate tests from logs, but transmit raw production data
to external servers, violating enterprise NDAs and cloud security policies.

## Solution

**Secure Log2Test Engine** runs entirely on-premises. It applies strict Pydantic
validation to Elasticsearch JSON exports and uses deterministic Jinja2 templating
to produce ready-to-run Python automation code — no AI inference, no data egress,
no hallucinations.

### Core Features

- **Privacy-First Architecture:** No data leaves the corporate perimeter.
- **Deterministic Generation:** Reliable, reproducible test suites on every run.
- **Strict Validation:** Drops malformed or suspicious log entries via Pydantic schemas.
- **SLA Enforcement:** Auto-generates response time assertions based on production baselines.

## Quick Start

### Installation

```bash
git clone https://github.com/golikovichev/secure-log2test.git
cd secure-log2test
pip install -r requirements.txt
```

### Run with sample data

A sample Kibana export is included for immediate testing:

```bash
python main.py --log data/sample_kibana_export.json --out test_sample.py
```

Expected output:

```
2026-04-22 00:00:00 - Initializing Secure Log2Test Engine...
2026-04-22 00:00:00 - Successfully parsed 4 valid log entries.
2026-04-22 00:00:00 - Successfully generated test suite: generated_tests/test_sample.py
2026-04-22 00:00:00 - SUCCESS: Generated 4 test cases in generated_tests/test_sample.py
2026-04-22 00:00:00 - Run tests with: pytest generated_tests/test_sample.py -v
```

### Run your own logs

Export your API logs from Kibana in JSON format, then run:

```bash
python main.py --log data/kibana_export.json --out test_loyalty_api.py
```

## Input Format

The parser expects an Elasticsearch-style JSON export with records under `hits.hits[*]._source`.
It reads the following fields when present:

- `url` — API endpoint path
- `method` — HTTP method (case-insensitive)
- `status` — Expected HTTP response code
- `request_body` — Optional request payload (dict)
- `duration` — Response time in milliseconds (int or float)

Missing values fall back to safe defaults during parsing.
See `data/sample_kibana_export.json` for a reference input.

## Architecture

- **Core Parser:** Python, Pydantic — validates and normalises log records.
- **Templating Engine:** Jinja2 — deterministic, auditable code generation.
- **Output Framework:** Pytest, Requests — production-ready test suites.

## Test Coverage

The repository includes 17 unit tests across parser and generator, covering:
valid input, malformed records, empty exports, float duration coercion,
template rendering, SLA assertion presence, payload injection, and output file generation.

Run the suite locally:

```bash
pytest tests/ -v
```

## Limitations

- Loads the full JSON export into memory; not optimized for multi-GB log files.
- Generated tests use a template-defined base URL and require environment-specific adjustment.
- Currently supports Kibana/Elasticsearch export structure only.

## Author

**Mikhail Golikov** — Senior QA Automation Engineer / SDET.
Focused on building infrastructure tools that bridge the gap between quality assurance
and enterprise security requirements.
