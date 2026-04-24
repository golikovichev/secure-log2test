# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-04-24

### Added
- `KibanaLogParser`: parses Elasticsearch/Kibana JSON exports (`hits.hits[*]._source`) using Pydantic 2.x validation
- `PytestGenerator`: renders parsed log entries into executable `pytest` + `requests` test suites via Jinja2 templating
- CLI entry point (`main.py`) with `--log` and `--out` arguments
- Strict Pydantic schema validation — malformed or incomplete log entries are dropped with a warning, not silently skipped
- SLA assertion generation: response time assertions based on `duration` field from production logs
- Privacy-first architecture: all processing runs locally, no external API calls, no telemetry
- 20 unit tests covering parser, generator, and CLI across valid input, malformed records, empty exports, and template rendering edge cases
- GitHub Actions CI: runs full test suite on every push and pull request (Python 3.10, 3.11, 3.12)

### Dependencies
- `pydantic==2.6.4`
- `jinja2==3.1.3`
- `pytest==8.1.1`
