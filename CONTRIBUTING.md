# Contributing

Thanks for your interest in secure-log2test. This is a small project, so the contribution flow is simple.

## Reporting a bug

Open an issue with:

- What you ran (command + Python version)
- What you expected
- What happened instead
- A minimal Kibana export sample if the bug is parser-related (strip secrets first)

## Suggesting a feature

Open an issue first so we can talk through the use case before you write code. Keeps both of us from wasting time.

## Submitting a pull request

1. Fork the repo and create a branch from `main`.
2. Make your changes. Keep the diff focused on one thing.
3. Add or update tests in `tests/`. The CI runs `pytest -v` on Python 3.10 and 3.11.
4. Run the tests locally before pushing:
   ```bash
   pip install -r requirements.txt
   pytest -v
   ```
5. Open the PR with a short description of what changed and why.

## Code style

- Plain Python, no extra dependencies unless there's a real reason.
- Function and variable names in English, lowercase with underscores.
- One responsibility per function. If a function grows past 30-40 lines, split it.

## Security

If you find something that could leak secrets from a real log file, please email me directly instead of opening a public issue. Address is on my GitHub profile.
