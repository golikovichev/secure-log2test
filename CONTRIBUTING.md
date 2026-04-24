# Contributing to secure-log2test

Thank you for your interest in contributing. This document covers the development setup, testing requirements, and pull request process.

## Development Setup

```bash
git clone https://github.com/golikovichev/secure-log2test.git
cd secure-log2test
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Running Tests

```bash
pytest tests/ -v
```

All 20 tests must pass before submitting a pull request. The CI pipeline runs the same suite on every push and pull request.

## Code Style

- Follow existing patterns in `core/parser.py` and `core/generator.py`
- Use Pydantic models for all data structures; do not bypass validation
- Keep the privacy-first constraint: no external API calls, no network requests in core logic
- Add or update tests for any behaviour you change

## Pull Request Process

1. Fork the repository and create a branch from `main`
2. Make your changes with clear, focused commits
3. Ensure `pytest tests/ -v` passes locally
4. Open a pull request with a description of what the change does and why
5. The maintainer will review and merge

## Reporting Issues

Open a GitHub Issue with:
- Python version (`python --version`)
- A minimal reproduction (log input + command + error output)
- Expected vs actual behaviour

## Privacy Constraint

This tool is designed for environments where log data cannot leave the organisation's infrastructure. Contributions must not add external network calls, telemetry, or third-party data uploads.
