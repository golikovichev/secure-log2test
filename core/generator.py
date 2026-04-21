import logging
from pathlib import Path
from typing import List, Optional

from jinja2 import Environment, FileSystemLoader

from core.parser import LogEntry

logger = logging.getLogger(__name__)


class PytestGenerator:
    """
    Generates deterministic pytest suites from parsed log entries.
    Designed for zero-data-leakage enterprise environments.
    """

    def __init__(self, template_dir: str = "templates", output_dir: str = "generated_tests"):
        self.template_dir = Path(template_dir)
        self.output_dir = Path(output_dir)

        if not self.template_dir.exists():
            raise FileNotFoundError(f"Template directory missing: {self.template_dir}")

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.env = Environment(loader=FileSystemLoader(str(self.template_dir)))

    def generate_suite(self, entries: List[LogEntry], template_name: str, output_filename: str) -> Optional[Path]:
        """Renders the Jinja2 template with log data and writes the test file."""
        if not entries:
            logger.warning("No log entries provided. Skipping generation.")
            return None

        try:
            template = self.env.get_template(template_name)
            rendered_code = template.render(entries=entries)

            output_path = self.output_dir / output_filename
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(rendered_code)

            logger.info(f"Successfully generated test suite: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to generate test suite: {e}")
            raise
