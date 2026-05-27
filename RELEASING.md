# Releasing secure-log2test

Reproducible PyPI release checklist. Catches breakage before upload, because
PyPI publish is irreversible: a bad wheel cannot be replaced under the same
version, only yanked and bumped to the next patch.

The flow assumes the maintainer holds `twine` credentials locally (project-
scoped API token recommended) and runs commands from an activated virtual
environment in the repo root. Replace `<version>` placeholders with the
target release (e.g. `1.1.0`).

---

## Step 0. Working tree sanity (1 min)

```
git status                          # working tree clean
git log --oneline -3                # confirm latest commit is the intended release tip
git tag -l v<version>               # release tag exists
```

If anything is dirty, stop. Resolve before publish.

---

## Step 1. Clean rebuild (2 min)

```
python -m pip install --upgrade build twine
rm -rf dist build *.egg-info
python -m build
```

Expected:

```
Successfully built secure_log2test-<version>.tar.gz and secure_log2test-<version>-py3-none-any.whl
```

Verify both artifacts exist:

```
ls dist/
# secure_log2test-<version>-py3-none-any.whl
# secure_log2test-<version>.tar.gz
```

If only one of the two artifacts appears: stop, investigate.

---

## Step 2. Static distribution check (1 min)

```
python -m twine check dist/*
```

Expected:

```
Checking dist/secure_log2test-<version>-py3-none-any.whl: PASSED
Checking dist/secure_log2test-<version>.tar.gz: PASSED
```

If FAILED, read the error, fix `pyproject.toml` metadata, rebuild, recheck.

---

## Step 3. Clean-venv install smoke (3 min)

This catches missing files in the wheel (templates not bundled, missing
`__init__`, packaging layout mistakes).

```
# Throwaway clean venv outside the project tree
python -m venv /tmp/sl2t-smoke-venv
/tmp/sl2t-smoke-venv/bin/python -m pip install --upgrade pip
/tmp/sl2t-smoke-venv/bin/python -m pip install dist/secure_log2test-<version>-py3-none-any.whl

# Verify version
/tmp/sl2t-smoke-venv/bin/python -c "import secure_log2test; print(secure_log2test.__version__)"
# Expect: <version>

# Verify console script entry point
/tmp/sl2t-smoke-venv/bin/secure-log2test --help
# Expect: argparse usage screen
```

On Windows, swap paths to `%TEMP%\sl2t-smoke-venv\Scripts\` and use the
`.exe` console script. If `--help` errors with "module not found" or "template
missing", the wheel is broken. Do not publish.

---

## Step 4. End-to-end CLI run on sample (2 min)

```
/tmp/sl2t-smoke-venv/bin/secure-log2test data/sample_kibana_export.json --output /tmp/sl2t-smoke-output.py

# Verify output exists and parses
/tmp/sl2t-smoke-venv/bin/python -c "import ast; ast.parse(open('/tmp/sl2t-smoke-output.py').read()); print('OK')"

# Verify generated tests collect
/tmp/sl2t-smoke-venv/bin/python -m pip install pytest requests
/tmp/sl2t-smoke-venv/bin/python -m pytest --collect-only -q /tmp/sl2t-smoke-output.py
# Expect: 4 tests collected (sample contains 4 entries)
```

If pytest cannot collect: wheel package layout is broken. Stop.

---

## Step 5. TestPyPI dry run (optional, 5 min)

A true upload rehearsal before real PyPI:

```
python -m twine upload --repository testpypi dist/*
# Asks for a TestPyPI token (separate account from PyPI)
```

Then install from TestPyPI in another clean venv and repeat Steps 3 and 4.
Skip if the maintainer is confident the wheel is correct.

---

## Step 6. Real PyPI upload (1 min)

```
python -m twine upload dist/*
# Asks for the PyPI API token (or reads ~/.pypirc)
```

Token security:

- Use a project-scoped token (PyPI account settings, "Add API token",
  scope = "secure-log2test").
- Never paste the token into chat, commit, or shell history.
- Token format starts with `pypi-AgEIcHl...`.
- Save the token in `~/.pypirc` under the `[pypi]` block, or pass via the
  `TWINE_PASSWORD` env var for a one-off upload.

Expected output:

```
Uploading secure_log2test-<version>-py3-none-any.whl
Uploading secure_log2test-<version>.tar.gz
View at: https://pypi.org/project/secure-log2test/<version>/
```

---

## Step 7. Post-publish verification (3 min)

```
# Install from real PyPI in a third clean venv
python -m venv /tmp/sl2t-pypi-venv
/tmp/sl2t-pypi-venv/bin/python -m pip install secure-log2test==<version>
/tmp/sl2t-pypi-venv/bin/secure-log2test --help

# Open https://pypi.org/project/secure-log2test/ in a browser
# Confirm: README rendering, version tag, MIT license, project URLs all correct
```

---

## Step 8. Add or refresh PyPI badge in README (5 min)

After a successful first publish, ensure the README header contains:

```markdown
[![PyPI version](https://img.shields.io/pypi/v/secure-log2test.svg)](https://pypi.org/project/secure-log2test/)
[![PyPI downloads](https://img.shields.io/pypi/dm/secure-log2test.svg)](https://pypi.org/project/secure-log2test/)
```

For subsequent releases the badges read live from PyPI, so no commit is
required unless the README changes elsewhere.

---

## Drop conditions

Stop and verify with a second pair of eyes (or sleep on it) before proceeding
if any of the following happens:

- Step 1 build produces only one of the two artifacts.
- Step 2 twine check FAILED.
- Step 3 wheel install errors with `import` or `module-not-found`.
- Step 4 pytest cannot collect generated tests.
- Step 6 twine upload errors with HTTP 4xx (auth or metadata). Fix and
  retry. HTTP 5xx is PyPI server side: wait, retry once.

If the irrecoverable bad-wheel scenario hits (Step 6 succeeded but Step 7
reveals a broken install): yank the version on PyPI, bump to the next patch
in `pyproject.toml` and `CHANGELOG.md`, repeat from Step 1.

---

## Time budget

| Phase | Duration |
|---|---|
| Steps 0 to 4 (mandatory) | ~10 min |
| Step 5 (optional TestPyPI) | +5 min |
| Steps 6 to 8 | ~10 min |
| **Total** | **20-25 min** |
