# Secure Log2Test Engine 🛡️

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/release/python-3100/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A deterministic, privacy-first tool designed for Enterprise QA and SDET teams. It automatically generates executable `pytest` suites by parsing production API logs (Elasticsearch/Kibana), **without leaking NDA or PII data** to external AI/LLM APIs.

## 🎯 The Problem It Solves
Modern QA teams often struggle to maintain test coverage parity with real-world production usage. While LLMs (like ChatGPT or Claude) can generate tests from logs, sending raw production data to external servers violates Enterprise security policies and NDAs. 

## 💡 The Solution
**Secure Log2Test Engine** runs 100% locally. It uses strict data validation (`Pydantic`) to parse Elasticsearch JSON exports and deterministic templating (`Jinja2`) to generate production-ready Python automation code.

### Core Features
- **Privacy-First Architecture:** No data leaves the corporate perimeter.
- **Deterministic Generation:** Reliable, reproducible test suites without AI hallucinations.
- **Strict Validation:** Drops malformed or suspicious log entries via Pydantic schemas.
- **SLA Enforcement:** Auto-generates response time assertions based on production baselines.

## 🚀 Quick Start

### Installation
```bash
git clone https://github.com/golikovichev/secure-log2test.git
cd secure-log2test
pip install -r requirements.txt
```

### Usage
Export your API logs from Kibana in JSON format, then run the engine:

```bash
python main.py --log data/kibana_export.json --out test_loyalty_api.py
```

The engine will parse the logs, validate the payloads, and generate a ready-to-run `test_loyalty_api.py` file in the `generated_tests/` directory. Run the suite instantly:

```bash
pytest generated_tests/test_loyalty_api.py -v
```

## 🏗️ Architecture Stack
- **Core Parser:** Python, Pydantic (for DTO validation and data sanitization).
- **Templating Engine:** Jinja2.
- **Output Framework:** Pytest, Requests.

## 👨‍💻 Author
**Mikhail Golikov** - Senior QA Automation Engineer / SDET.
Focused on building infrastructure tools that bridge the gap between quality assurance and enterprise security.