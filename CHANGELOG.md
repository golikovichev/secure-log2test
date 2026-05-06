# Changelog

All notable changes to this project will be documented here. Format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- CONTRIBUTING guide for issue reports and pull requests.
- MIT license file.
- This changelog.

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
