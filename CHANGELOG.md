# Changelog

All notable changes to this project will be documented here. Format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.0] - 2026-05-15

### Added
- Generated tests now emit `headers={...}` and `json={...}` (or `data=...` for non-JSON bodies) blocks reflecting the original log entry, so the redaction work done at parse time is visible in the output file. Previously the template emitted only `method`, `url`, and `status`, hiding the redacted values from the reader.
- Recursive body redaction walker (`redact_body`) wired into `KibanaLogEntry` as a Pydantic field validator. Scrubs values whose dict key matches the sensitive-name pattern at any depth: `{"password": ...}`, `{"client_secret": ...}`, OAuth `{"refresh_token": ...}`, nested dicts, lists of dicts.
- Substring pattern fallback (`auth|token|secret|key|session|cookie|credential|bearer|password|passwd`) for header and body field names that fall outside the static `SENSITIVE_HEADERS` list. Catches custom names project teams invent (`X-Custom-Token`, `Refresh-Token`, etc.).
- Six new entries in the static `SENSITIVE_HEADERS` list: `proxy-authenticate`, `x-csrf-token`, `x-access-token`, `refresh-token`, `id-token`, `x-amz-security-token`.
- New Jinja2 filter `python_repr` and tests `json_body` / `string_body` for safer rendering of header values and request bodies in generated tests.
- 10 new unit tests covering custom-token header pattern matching, body walker on nested dicts and lists, OAuth refresh-token scrubbing, and the integrated validator path. Test suite is now 59 tests, up from 33.
- Python 3.13 added to CI matrix and pyproject classifiers.

### Changed
- Generator now renders log field values via `repr()` so any quote, backslash, or curly brace inside an original header or body literal cannot break the generated Python source.
- README expanded with current redaction coverage (13 static headers + regex pattern + recursive body walker), live issue cross-links for Limitations and Roadmap, and a link to the Dev.to design write-up.

## [1.0.1] - 2026-05-12

### Fixed
- Parser now opens input files with explicit `encoding="utf-8-sig"`. On Windows the default file encoding is cp1252, so any input containing non-ASCII characters (Cyrillic, CJK, accented Latin, emoji, etc.) crashed with `UnicodeDecodeError` before the format check ran. Linux and macOS hid the bug because their default is already utf-8. Closes #3.
- `utf-8-sig` accepts both BOM and non-BOM utf-8 inputs, so files saved by Windows tools (Notepad, some Excel CSV exports) load cleanly.

### Changed
- When the input does not match the Kibana ES export shape (top-level `hits.hits[]`), the parser now raises `ValueError` with a clear diagnostic instead of silently returning zero entries.
- If the input looks like a Grafana Loki Explore export (top-level array with `line` / `timestamp` / `fields` keys), the error message points at issue #4 where Loki support is tracked.
- Invalid JSON now raises `ValueError` with the file path included.

### Added
- `tests/test_input_validation.py` with eight new test cases: Cyrillic in URL and body, CJK characters in URL, emoji in body, Loki shape detection, plain non-Kibana array, empty object, invalid JSON, utf-8 BOM input. Test suite is now 33 tests, up from 25.

## [1.0.0] - 2026-05-10

First stable release. Public API surface (CLI flags, JSON input shape, generated test layout) is now considered stable. Future minor versions will add features without breaking existing usage.

### Added
- `pyproject.toml` with PEP 621 metadata, hatchling build backend, console-script entry point.
- `secure-log2test` console command available after `pip install -e .` or `pip install secure-log2test` (post-PyPI publish).
- `python -m secure_log2test` invocation via `__main__.py`.
- Python 3.12 added to CI matrix.
- CONTRIBUTING guide for issue reports and pull requests.
- MIT license file.
- This changelog.
- README badges for CI status, supported Python versions, and licence.
- Self-roadmap GitHub issues for v1.1 (response body assertions, schema match) and v1.2 (custom redaction rules via config file).

### Changed
- Repackaged into `secure_log2test/` Python package. `core/` moved to `secure_log2test/core/`. `templates/` moved to `secure_log2test/templates/`.
- `main.py` removed at top level; CLI entry now lives in `secure_log2test/cli.py`.
- CI workflow installs the project as a package (`pip install -e ".[dev]"`) and exercises the installed CLI.
- Test imports updated to reference `secure_log2test.core.parser`.
- `secure_log2test.__version__` now reads from installed package metadata via `importlib.metadata`, so it always matches the wheel version. Previously hardcoded.

## [0.2.0] - 2026-05-05

### Added
- GitHub Actions CI workflow with a Python 3.10 and 3.11 matrix.
- CLI smoke test inside CI: generate a suite from `data/sample_kibana_export.json` and run `ast.parse` on the output.
- Edge-case tests covering auth headers, empty request bodies, and 5xx responses.

## [0.1.0] - 2026-05-03

### Added
- Pytest test generator and CLI entry point (`python main.py <kibana_export.json>`).
- Parser unit tests and a sample Kibana fixture under `data/`.
- Core parser that turns Kibana request logs into pytest test cases.
- Initial project scaffold and README.
