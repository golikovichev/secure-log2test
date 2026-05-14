import logging
import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .parser import KibanaLogEntry, REDACTED


logger = logging.getLogger(__name__)


def _slugify(value):
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    value = value.strip("_")
    return value or "endpoint"


def _python_repr(value):
    """Render value as a safe Python literal.

    Generated tests are executed by the user via pytest. Without repr()
    the template inlines log entry strings as raw Python source, so a
    captured URL containing a quote or backslash can produce invalid or
    arbitrary code. repr() escapes everything correctly and emits a
    quoted literal the parser will accept. For dicts and lists repr()
    also produces a valid Python literal.
    """
    return repr(value)


def _is_json_body(value):
    """Body should be sent as `json=` argument (dict or list)."""
    return isinstance(value, (dict, list))


def _is_string_body(value):
    """Body should be sent as `data=` argument (non-empty string)."""
    return isinstance(value, str) and bool(value)


class KibanaTestGenerator:
    def __init__(self, templates_dir):
        self.env = Environment(
            loader=FileSystemLoader(str(templates_dir)),
            # autoescape disabled because we render Python source, not
            # HTML. String safety comes from the python_repr filter
            # applied to every log-derived value in the template.
            autoescape=select_autoescape([]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.env.filters["slug"] = _slugify
        self.env.filters["python_repr"] = _python_repr
        self.env.tests["json_body"] = _is_json_body
        self.env.tests["string_body"] = _is_string_body

    def render(self, entries, base_url=""):
        template = self.env.get_template("test_module.py.j2")
        cleaned = []
        for e in entries:
            if isinstance(e, KibanaLogEntry):
                cleaned.append(e)
            else:
                cleaned.append(KibanaLogEntry(**e))
        return template.render(
            entries=cleaned,
            base_url=base_url,
            redacted_marker=REDACTED,
        )

    def write(self, entries, output_path, base_url=""):
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        rendered = self.render(entries, base_url=base_url)
        output_path.write_text(rendered, encoding="utf-8")
        logger.info("Wrote %d entries to %s", len(entries), output_path)
        return output_path
