import csv
import io
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

        hits_container = data["hits"]
        hits = hits_container.get("hits") if isinstance(hits_container, dict) else None
        if not isinstance(hits, list):
            raise ValueError(
                f"Expected Kibana ES export shape with top-level hits.hits[] as an array, "
                f"got hits={type(hits_container).__name__}."
            )
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


# --- Splunk search export (CSV / JSON) ---------------------------------
#
# Splunk exports one event per CSV row or per {"result": {...}} JSON line
# (the /search/jobs/export endpoint). Each event carries _time / _raw plus
# whatever fields the sourcetype extracted, so the HTTP field names are not
# fixed. We resolve each of method/url/status/duration through a short alias
# list and map the event onto the same KibanaLogEntry shape, reusing its
# redaction validators and the existing generator unchanged.

SPLUNK_FIELD_ALIASES = {
    "method": ("method", "http_method"),
    "url": ("uri", "uri_path", "url", "request"),
    "status": ("status", "status_code"),
    "duration": ("duration", "response_time"),
}


def _pick_alias(row, names):
    """Return the first present, non-empty value among ``names``."""
    for name in names:
        value = row.get(name)
        if value not in (None, ""):
            return value
    return None


def _decode_json_field(value):
    """Decode a field that may carry a JSON object/array as a string.

    Splunk fields are flat strings; a sourcetype may stash structured
    headers or a request body as a JSON-encoded string. Decode those so the
    KibanaLogEntry validators can redact inside them. Non-JSON values are
    returned unchanged.
    """
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str) and value.strip()[:1] in "{[":
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _unwrap_result(obj):
    """Splunk export wraps each event as {"result": {...}}; unwrap it."""
    if isinstance(obj, dict) and isinstance(obj.get("result"), dict):
        return obj["result"]
    return obj


def _load_splunk_csv(text):
    return list(csv.DictReader(io.StringIO(text)))


def _coerce_int(value):
    """Coerce a Splunk numeric field to int.

    Splunk extractions are strings and may be fractional or unit-suffixed:
    "200", "200.0", "0.042", "42ms". Parse the leading numeric token via
    float so none of those are silently dropped. Raises ValueError when no
    number is present (for example a status of "OK").
    """
    match = re.match(r"[-+]?\d*\.?\d+", str(value).strip())
    if not match:
        raise ValueError(f"non-numeric value {value!r}")
    return int(float(match.group()))


def _load_splunk_json(text):
    """Load Splunk JSON into ``(rows, malformed_count)``.

    Tries the whole document first (a plain array, a ``{"results": [...]}``
    document, or a single object), then falls back to NDJSON (one object per
    line, the export-endpoint shape). A single corrupt NDJSON line is skipped
    and counted rather than aborting the run. Raises ValueError only when the
    whole input is unparseable, mirroring KibanaLogParser's friendly error.
    """
    text = text.strip()
    if not text:
        return [], 0
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        rows, malformed = [], 0
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(_unwrap_result(json.loads(line)))
            except json.JSONDecodeError:
                malformed += 1
        if not rows:
            raise ValueError(
                "Input is not valid Splunk JSON: neither a JSON document nor "
                "newline-delimited JSON lines could be parsed."
            ) from None
        return rows, malformed
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        data = data["results"]
    if isinstance(data, list):
        return [_unwrap_result(o) for o in data], 0
    return [_unwrap_result(data)], 0


class SplunkLogParser:
    """Parse a Splunk search export (CSV or JSON) into KibanaLogEntry rows.

    Same surface as KibanaLogParser: ``parse()`` returns a list of
    KibanaLogEntry, and ``attempted`` / ``skipped`` count the events seen and
    dropped. An event missing any of method / url / status is skipped and
    counted, so a syslog line with no HTTP fields does not abort the run.
    """

    def __init__(self, path, redact_marker=REDACTED):
        self.path = Path(path)
        self.redact_marker = redact_marker
        self.attempted = 0
        self.skipped = 0

    def parse(self):
        rows, load_skipped = self._load_rows()
        self.attempted = len(rows) + load_skipped
        self.skipped = load_skipped
        entries = []
        for row in rows:
            try:
                entries.append(self._row_to_entry(row))
            except Exception as e:
                self.skipped += 1
                logger.warning(f"Skipping bad Splunk event: {e}")
        return entries

    def _load_rows(self):
        try:
            text = self.path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError as e:
            raise ValueError(
                f"Could not decode {self.path} as utf-8. "
                f"Splunk exports should be utf-8. Original error: {e}"
            ) from e
        first_line = text.lstrip().splitlines()[0] if text.strip() else ""
        looks_json = first_line[:1] in "{["
        if self.path.suffix.lower() == ".csv" or ("," in first_line and not looks_json):
            return _load_splunk_csv(text), 0
        return _load_splunk_json(text)

    def _row_to_entry(self, row):
        method = _pick_alias(row, SPLUNK_FIELD_ALIASES["method"])
        url = _pick_alias(row, SPLUNK_FIELD_ALIASES["url"])
        status = _pick_alias(row, SPLUNK_FIELD_ALIASES["status"])
        if method is None or url is None or status is None:
            raise ValueError("event missing method/url/status")
        duration_raw = _pick_alias(row, SPLUNK_FIELD_ALIASES["duration"])
        try:
            duration = (
                _coerce_int(duration_raw) if duration_raw not in (None, "") else 0
            )
        except ValueError:
            duration = 0
        payload = {
            "method": method,
            "url": url,
            "status": _coerce_int(status),
            "duration": duration,
        }
        headers = _pick_alias(row, ("headers",))
        if headers is not None:
            payload["headers"] = _decode_json_field(headers)
        body = _pick_alias(row, ("body", "request_body"))
        if body is not None:
            payload["body"] = _decode_json_field(body)
        return KibanaLogEntry.model_validate(
            payload, context={"redact_marker": self.redact_marker}
        )


# --- Grafana Loki Explore export (issue #4) ----------------------------
# Loki exports from the Explore UI as a top-level list (JSON) or a flat table
# (CSV) where each row carries a stringified inner JSON payload in line/Line
# plus Loki label columns. The inner payload is service-specific; we keep only
# the rows that carry HTTP request data, resolve Loki field names through an
# alias list, and map each onto the same KibanaLogEntry shape.

LOKI_FIELD_ALIASES = {
    "method": ("method", "http_method", "request_method"),
    "url": ("server_http_route", "uri", "uri_path", "url", "path", "route", "request"),
    "status": ("http_status", "status", "status_code", "response_status"),
    "duration": ("duration_ms", "duration", "response_time", "latency"),
}


def _loki_inner_payloads(rows):
    """Parse the stringified inner JSON in each Loki row's line/Line field.

    Returns ``(payloads, skipped)``. A row whose line is missing, blank, not
    valid JSON, or not a JSON object is counted as skipped rather than parsed,
    so a plain-text syslog line does not abort the run.
    """
    payloads, skipped = [], 0
    for row in rows:
        raw_line = row.get("line") if "line" in row else row.get("Line")
        if not isinstance(raw_line, str) or not raw_line.strip():
            skipped += 1
            continue
        try:
            inner = json.loads(raw_line)
        except json.JSONDecodeError:
            skipped += 1
            continue
        if not isinstance(inner, dict):
            skipped += 1
            continue
        payloads.append(inner)
    return payloads, skipped


class LokiLogParser:
    """Parse a Grafana Loki Explore export (JSON or CSV) into KibanaLogEntry rows.

    Same surface as KibanaLogParser/SplunkLogParser: ``parse()`` returns a list
    of KibanaLogEntry, and ``attempted`` / ``skipped`` count rows seen and
    dropped. A row whose inner payload carries no HTTP request data
    (server_http_route + method + status) is skipped and counted, the same way
    a non-HTTP log line is ignored rather than aborting the run.
    """

    def __init__(self, path, redact_marker=REDACTED):
        self.path = Path(path)
        self.redact_marker = redact_marker
        self.attempted = 0
        self.skipped = 0

    def parse(self):
        payloads, load_skipped = self._load_rows()
        self.attempted = len(payloads) + load_skipped
        self.skipped = load_skipped
        entries = []
        for inner in payloads:
            try:
                entry = self._row_to_entry(inner)
            except Exception as e:
                self.skipped += 1
                logger.warning(f"Skipping bad Loki event: {e}")
                continue
            if entry is None:
                self.skipped += 1  # no HTTP data: not a request line, skip
                continue
            entries.append(entry)
        return entries

    def _load_rows(self):
        try:
            text = self.path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError as e:
            raise ValueError(
                f"Could not decode {self.path} as utf-8. "
                f"Loki exports should be utf-8. Original error: {e}"
            ) from e
        first_line = text.lstrip().splitlines()[0] if text.strip() else ""
        looks_json = first_line[:1] in "{["
        if self.path.suffix.lower() == ".csv" or ("," in first_line and not looks_json):
            rows = list(csv.DictReader(io.StringIO(text)))
        else:
            try:
                data = json.loads(text) if text.strip() else []
            except json.JSONDecodeError as e:
                raise ValueError(
                    "Input is not valid Loki JSON (expected a top-level list of "
                    f"{{line, timestamp, fields}} rows). Original error: {e.msg}"
                ) from e
            rows = data if isinstance(data, list) else [data]
        return _loki_inner_payloads(rows)

    def _row_to_entry(self, inner):
        method = _pick_alias(inner, LOKI_FIELD_ALIASES["method"])
        url = _pick_alias(inner, LOKI_FIELD_ALIASES["url"])
        status = _pick_alias(inner, LOKI_FIELD_ALIASES["status"])
        if method is None or url is None or status is None:
            # Not an HTTP request line. SplunkLogParser raises here instead; both
            # styles end up skip-counted, so leave this as a quiet None (a Loki
            # stream has many non-HTTP lines and raising would spam warnings).
            return None
        duration_raw = _pick_alias(inner, LOKI_FIELD_ALIASES["duration"])
        try:
            duration = (
                _coerce_int(duration_raw) if duration_raw not in (None, "") else 0
            )
        except ValueError:
            duration = 0
        payload = {
            "method": method,
            "url": url,
            "status": _coerce_int(status),
            "duration": duration,
        }
        headers = _pick_alias(inner, ("headers",))
        if headers is not None:
            payload["headers"] = _decode_json_field(headers)
        body = _pick_alias(inner, ("body", "request_body"))
        if body is not None:
            payload["body"] = _decode_json_field(body)
        return KibanaLogEntry.model_validate(
            payload, context={"redact_marker": self.redact_marker}
        )


def detect_source(path):
    """Best-effort input-source detection: "kibana", "splunk", or "loki".

    A ``.csv`` file with a ``Line`` column is a Loki Explore export; any other
    ``.csv`` is Splunk. A JSON object with a top-level ``hits`` key is a Kibana
    ES export. A top-level JSON list whose rows carry ``line`` plus
    ``fields``/``timestamp`` is Loki. Anything carrying Splunk markers (``_raw``
    / ``_time`` / a ``result`` wrapper) is Splunk. Defaults to "kibana" so
    existing behaviour is unchanged when detection is ambiguous.
    """
    path = Path(path)
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    has_splunk_markers = "_raw" in text or '"result"' in text or "_time" in text

    if path.suffix.lower() == ".csv":
        # A Loki Explore CSV leads with a "Line" column and carries no Splunk
        # _raw/_time markers; any other .csv stays Splunk. Requiring "Line"
        # first (not merely present) avoids grabbing a Splunk file that happens
        # to have a field named Line.
        first_line = text.lstrip().splitlines()[0] if text.strip() else ""
        columns = [c.strip().strip('"') for c in first_line.split(",")]
        if columns[:1] == ["Line"] and not has_splunk_markers:
            return "loki"
        return "splunk"

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, dict) and "hits" in data:
        return "kibana"
    # Splunk markers win over the looser Loki shape check: a Splunk JSON event
    # may also carry a "line"/"timestamp" field, so disambiguate on _raw/_time
    # first.
    if has_splunk_markers:
        return "splunk"
    # Loki Explore JSON: a top-level list (or a single object) whose rows carry
    # "line" plus the Loki "fields" label bag. "fields" (not a bare timestamp)
    # is the disambiguating marker.
    loki_row = None
    if isinstance(data, list) and data and isinstance(data[0], dict):
        loki_row = data[0]
    elif isinstance(data, dict):
        loki_row = data
    if loki_row is not None and "line" in loki_row and "fields" in loki_row:
        return "loki"
    return "kibana"
