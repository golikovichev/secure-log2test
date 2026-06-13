import json
import logging
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator


logger = logging.getLogger(__name__)


SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "proxy-authenticate",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-access-token",
        "refresh-token",
        "id-token",
        "x-amz-security-token",
        "authentication",
        "dpop",
        "x-hub-signature",
        "x-hub-signature-256",
    }
)

# Catches custom headers and body field names that imply credentials.
# Matched case-insensitively against the full name as a substring.
SENSITIVE_NAME_PATTERN = re.compile(
    r"auth|token|secret|key|session|cookie|credential|bearer|password|passwd",
    re.IGNORECASE,
)

REDACTED = "***REDACTED***"


def _is_sensitive_name(name: str) -> bool:
    lowered = name.lower()
    if lowered in SENSITIVE_HEADERS:
        return True
    return bool(SENSITIVE_NAME_PATTERN.search(lowered))


def redact_headers(headers, marker=REDACTED):
    """Replace sensitive header values with a redaction marker.

    Header name match is case-insensitive. The static SENSITIVE_HEADERS
    list catches the well-known names; SENSITIVE_NAME_PATTERN catches
    custom names that contain auth / token / secret / key / etc. Returns
    a new dict; the input is not mutated. ``marker`` overrides the default
    ``***REDACTED***`` replacement string.
    """
    if not headers:
        return {}
    return {
        name: (marker if _is_sensitive_name(name) else value)
        for name, value in headers.items()
    }


def _redact_param_string(params: str, marker: str) -> str:
    """Redact sensitive ``name=value`` pairs in an ``&``-joined string.

    A pair is rewritten only when it has a value (``name=value``) and the
    name looks sensitive. Bare flags (``token``) and non-sensitive pairs
    are kept byte-for-byte. Values containing ``=`` are redacted whole
    because the split happens on the first ``=`` only.
    """
    redacted_pairs = []
    for pair in params.split("&"):
        name, eq, _value = pair.partition("=")
        if eq and _is_sensitive_name(name):
            redacted_pairs.append(f"{name}={marker}")
        else:
            redacted_pairs.append(pair)
    return "&".join(redacted_pairs)


def redact_url(url, marker=REDACTED):
    """Redact sensitive parameter values in a URL.

    Auth headers and secret body fields are scrubbed elsewhere, but
    credentials also travel in the URL: query strings (``?access_token=``,
    ``?api_key=``) and OAuth2 implicit-flow fragments (``#access_token=``).
    Both would otherwise reach the generated test verbatim. The function
    assumes the standard ``path?query#fragment`` ordering, redacts only
    values whose parameter name looks sensitive, and keeps the path and
    non-sensitive parameters byte-for-byte so the request still
    reproduces. ``marker`` overrides the default ``***REDACTED***``.
    """
    if not url or ("?" not in url and "#" not in url):
        return url
    path_and_query, hash_sep, fragment = url.partition("#")
    base, query_sep, query = path_and_query.partition("?")
    if query_sep:
        query = _redact_param_string(query, marker)
    if hash_sep and fragment:
        fragment = _redact_param_string(fragment, marker)
    return f"{base}{query_sep}{query}{hash_sep}{fragment}"


def redact_body(body, marker=REDACTED):
    """Recursively redact values whose key looks sensitive.

    Walks dicts and lists. A dict value is replaced with ``marker`` if its
    key matches SENSITIVE_NAME_PATTERN; lists and nested dicts are
    walked further. Other types (str, int, bool, None) are returned as-is.

    Catches request payloads like {"password": "..."},
    {"client_secret": "..."}, OAuth {"refresh_token": "..."}.
    ``marker`` overrides the default ``***REDACTED***`` replacement string.
    """
    if isinstance(body, dict):
        return {
            k: (
                marker
                if isinstance(k, str) and _is_sensitive_name(k)
                else redact_body(v, marker)
            )
            for k, v in body.items()
        }
    if isinstance(body, list):
        return [redact_body(item, marker) for item in body]
    return body


def _marker_from_context(info) -> str:
    """Read the active redaction marker from Pydantic validation context.

    Falls back to the default ``REDACTED`` when no context is supplied, so
    direct ``KibanaLogEntry(...)`` construction keeps the original behaviour.
    """
    context = getattr(info, "context", None) or {}
    return context.get("redact_marker", REDACTED)


class KibanaLogEntry(BaseModel):
    method: str
    url: str
    status: int
    duration: int = 0
    headers: dict[str, str] = Field(default_factory=dict)
    body: Any = None

    @field_validator("method")
    @classmethod
    def normalize_method(cls, v):
        return v.upper()

    @field_validator("url")
    @classmethod
    def redact_sensitive_url(cls, v, info):
        return redact_url(v, _marker_from_context(info))

    @field_validator("headers")
    @classmethod
    def redact_sensitive_headers(cls, v, info):
        return redact_headers(v, _marker_from_context(info))

    @field_validator("body")
    @classmethod
    def redact_sensitive_body(cls, v, info):
        return redact_body(v, _marker_from_context(info))


class KibanaLogParser:
    def __init__(self, path, redact_marker=REDACTED):
        self.path = Path(path)
        self.redact_marker = redact_marker
        self.attempted = 0
        self.skipped = 0

    def parse(self):
        try:
            with open(self.path, encoding="utf-8-sig") as f:
                data = json.load(f)
        except UnicodeDecodeError as e:
            raise ValueError(
                f"Could not decode {self.path} as utf-8. "
                f"Kibana JSON exports should be utf-8 per RFC 8259. "
                f"Original error: {e}"
            ) from e
        except json.JSONDecodeError as e:
            raise ValueError(f"{self.path} is not valid JSON: {e}") from e

        if not isinstance(data, dict) or "hits" not in data:
            hint = ""
            if (
                isinstance(data, list)
                and data
                and isinstance(data[0], dict)
                and "line" in data[0]
                and "fields" in data[0]
            ):
                hint = (
                    " The file looks like a Grafana Loki Explore export "
                    "(top-level array with line/timestamp/fields keys). "
                    "That format is tracked in issue #4 and not yet supported."
                )
            raise ValueError(
                f"Expected Kibana ES export shape with top-level "
                f"hits.hits[], got {type(data).__name__}.{hint}"
            )

        hits = data.get("hits", {}).get("hits", [])
        self.attempted = len(hits)
        self.skipped = 0

        entries = []
        for hit in hits:
            try:
                entries.append(
                    KibanaLogEntry.model_validate(
                        hit["_source"],
                        context={"redact_marker": self.redact_marker},
                    )
                )
            except Exception as e:
                self.skipped += 1
                logger.warning(f"Skipping bad entry: {e}")

        return entries
