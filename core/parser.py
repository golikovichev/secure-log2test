import json
import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator


logger = logging.getLogger(__name__)


SENSITIVE_HEADERS = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "authentication",
})

REDACTED = "***REDACTED***"


def redact_headers(headers):
    """Replace sensitive header values with a fixed redaction marker.

    Header name match is case-insensitive. Returns a new dict; the input
    is not mutated.
    """
    if not headers:
        return {}
    return {
        name: (REDACTED if name.lower() in SENSITIVE_HEADERS else value)
        for name, value in headers.items()
    }


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

    @field_validator("headers")
    @classmethod
    def redact_sensitive_headers(cls, v):
        return redact_headers(v)


class KibanaLogParser:
    def __init__(self, path):
        self.path = Path(path)

    def parse(self):
        with open(self.path) as f:
            data = json.load(f)

        entries = []
        for hit in data.get("hits", {}).get("hits", []):
            try:
                entries.append(KibanaLogEntry(**hit["_source"]))
            except Exception as e:
                logger.warning(f"Skipping bad entry: {e}")

        return entries
