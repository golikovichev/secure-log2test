# Changelog

All notable changes to this project will be documented here. Format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `pyproject.toml` with PEP 621 metadata, hatchling build backend, console-script entry point.
- `secure-log2test` console command available after `pip install -e .` or `pip install secure-log2test` (post-PyPI publish).
- `python -m secure_log2test` invocation via `__main__.py`.
- Python 3.12 added to CI matrix.
- CONTRIBUTING guide for issue reports and pull requests.
- MIT license file.
- This changelog.

### Changed
- Repackaged into `secure_log2test/` Python package. `core/` moved to `secure_log2test/core/`. `templates/` moved to `secure_log2test/templates/`.
- `main.py` removed at top level; CLI entry now lives in `secure_log2test/cli.py`.
- CI workflow installs the project as a package (`pip install -e ".[dev]"`) and exercises the installed CLI.
- Test imports updated to reference `secure_log2test.core.parser`.

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
