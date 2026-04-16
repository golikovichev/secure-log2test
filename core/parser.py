import json
import logging
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, ValidationError

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class LogEntry(BaseModel):
    """Data Transfer Object for parsed API logs."""
    endpoint: str
    method: str
    status_code: int
    payload: Optional[dict] = None
    response_time_ms: int


class KibanaLogParser:
    """
    Parses Kibana/Elasticsearch JSON exports deterministically.
    Ensures no PII/NDA data leaves the local enterprise perimeter.
    """

    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        if not self.file_path.exists():
            raise FileNotFoundError(f"Log file not found: {self.file_path}")

    def parse(self) -> List[LogEntry]:
        parsed_entries = []
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

                # Assuming standard Elasticsearch hit structure
                hits = data.get("hits", {}).get("hits", [])
                if not hits:
                    logger.warning("No hits found in the provided JSON log.")
                    return parsed_entries

                for item in hits:
                    source = item.get("_source", {})
                    try:
                        entry = LogEntry(
                            endpoint=source.get("url", "/"),
                            method=source.get("method", "GET").upper(),
                            status_code=source.get("status", 200),
                            payload=source.get("request_body"),
                            response_time_ms=source.get("duration", 0)
                        )
                        parsed_entries.append(entry)
                    except ValidationError as e:
                        logger.debug(f"Skipping malformed log entry: {e.error_count()} errors")
                        continue

        except json.JSONDecodeError as e:
            logger.error(f"Critical: Failed to decode JSON log file. {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during parsing: {e}")
            raise

        logger.info(f"Successfully parsed {len(parsed_entries)} valid log entries.")
        return parsed_entries


# Optional block for local manual testing
if __name__ == "__main__":
    pass