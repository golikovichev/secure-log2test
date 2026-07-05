"""Load user redaction rules from a project config file.

The built-in blacklist covers the common credential names, but a real
deployment often has its own: an internal tenant token, a bespoke secret
field, a national ID field. Rather than patch the source, a user drops a
``secure-log2test.toml`` next to where they run the tool:

    [redaction]
    extra_header_names = ["x-tenant-ref", "x-internal-token"]
    extra_field_patterns = ["ssn", "account_number"]

``extra_header_names`` are exact names, matched case-insensitively; the
common case is a custom header, but the matcher is shared, so an exact name
also redacts a matching body field or URL parameter. ``extra_field_patterns``
are regexes matched as a substring against the same names. The built-in
defaults always stay on; config only adds. Patterns must come from a trusted
config: they run against semi-trusted log field names, so a
catastrophic-backtracking regex could hang the run.
"""

from __future__ import annotations

import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on the 3.10 CI leg
    import tomli as tomllib

CONFIG_FILENAME = "secure-log2test.toml"


def load_redaction_rules(
    start_dir: Path | str | None = None,
) -> tuple[list[str], list[str]]:
    """Read redaction rules from ``secure-log2test.toml`` in ``start_dir``.

    Returns ``(extra_header_names, extra_field_patterns)`` as raw strings.
    A missing file, or a file with no ``[redaction]`` table, yields two
    empty lists so the caller falls back to the built-in defaults. Pattern
    strings are returned verbatim; they are compiled (and validated) at
    install time, not here.
    """
    base = Path(start_dir) if start_dir is not None else Path.cwd()
    config_path = base / CONFIG_FILENAME
    if not config_path.is_file():
        return [], []

    with config_path.open("rb") as fh:
        data = tomllib.load(fh)

    section = data.get("redaction", {})
    names = _string_list(section, "extra_header_names")
    patterns = _string_list(section, "extra_field_patterns")
    return names, patterns


def _string_list(section: dict, key: str) -> list[str]:
    """Return ``section[key]`` as a list of strings, or ``[]`` if absent.

    Rejects a non-list value (e.g. a bare string) so a config typo fails
    loudly instead of iterating a string into single-character rules.
    """
    value = section.get(key, [])
    if not value:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"redaction.{key} must be a list of strings, got {value!r}")
    return list(value)
