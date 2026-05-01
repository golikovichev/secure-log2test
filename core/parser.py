import json
import logging
from pathlib import Path

from pydantic import BaseModel, field_validator


logger = logging.getLogger(__name__)


class KibanaLogEntry(BaseModel):
    method: str
    url: str
    status: int
    duration: int = 0

    @field_validator("method")
    @classmethod
    def normalize_method(cls, v):
        return v.upper()


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
