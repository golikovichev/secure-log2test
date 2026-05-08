import logging
import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .parser import KibanaLogEntry


logger = logging.getLogger(__name__)


def _slugify(value):
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    value = value.strip("_")
    return value or "endpoint"


class KibanaTestGenerator:
    def __init__(self, templates_dir):
        self.env = Environment(
            loader=FileSystemLoader(str(templates_dir)),
            autoescape=select_autoescape([]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.env.filters["slug"] = _slugify

    def render(self, entries, base_url=""):
        template = self.env.get_template("test_module.py.j2")
        cleaned = []
        for e in entries:
            if isinstance(e, KibanaLogEntry):
                cleaned.append(e)
            else:
                cleaned.append(KibanaLogEntry(**e))
        return template.render(entries=cleaned, base_url=base_url)

    def write(self, entries, output_path, base_url=""):
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        rendered = self.render(entries, base_url=base_url)
        output_path.write_text(rendered, encoding="utf-8")
        logger.info("Wrote %d entries to %s", len(entries), output_path)
        return output_path
