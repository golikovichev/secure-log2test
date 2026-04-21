import pytest
from pathlib import Path
from core.parser import LogEntry
from core.generator import PytestGenerator


def _make_entries(count: int = 2) -> list[LogEntry]:
    return [
        LogEntry(endpoint=f"/api/resource/{i}", method="GET", status_code=200, response_time_ms=100)
        for i in range(count)
    ]


class TestPytestGeneratorInit:
    def test_raises_when_template_dir_missing(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            PytestGenerator(template_dir=str(tmp_path / "nonexistent"), output_dir=str(tmp_path / "out"))

    def test_creates_output_dir_if_missing(self, tmp_path):
        template_dir = tmp_path / "templates"
        template_dir.mkdir()
        (template_dir / "test_api.jinja2").write_text("# empty", encoding="utf-8")
        output_dir = tmp_path / "generated_tests"

        PytestGenerator(template_dir=str(template_dir), output_dir=str(output_dir))

        assert output_dir.exists()


class TestPytestGeneratorSuite:
    @pytest.fixture()
    def generator(self, tmp_path) -> PytestGenerator:
        template_dir = tmp_path / "templates"
        template_dir.mkdir()
        # Mirrors key elements of the real template for integration-level assertions.
        template = (
            "{% for entry in entries %}\n"
            "def test_{{ entry.method | lower }}_{{ loop.index }}():\n"
            "    # {{ entry.method }} {{ entry.endpoint }} status={{ entry.status_code }}\n"
            "    sla_limit_ms = {{ entry.response_time_ms }} + 500\n"
            "    payload = {{ entry.payload | tojson }}\n"
            "{% endfor %}"
        )
        (template_dir / "test_api.jinja2").write_text(template, encoding="utf-8")
        return PytestGenerator(
            template_dir=str(template_dir),
            output_dir=str(tmp_path / "out")
        )

    def test_returns_output_path(self, generator):
        result = generator.generate_suite(_make_entries(), "test_api.jinja2", "test_out.py")
        assert result is not None
        assert result.name == "test_out.py"

    def test_output_file_is_created(self, generator):
        result = generator.generate_suite(_make_entries(), "test_api.jinja2", "test_out.py")
        assert result.exists()

    def test_output_contains_entry_data(self, generator):
        entries = [LogEntry(endpoint="/api/orders", method="POST", status_code=201, response_time_ms=50)]
        result = generator.generate_suite(entries, "test_api.jinja2", "test_out.py")
        content = result.read_text(encoding="utf-8")
        assert "/api/orders" in content
        assert "POST" in content

    def test_returns_none_for_empty_entries(self, generator):
        result = generator.generate_suite([], "test_api.jinja2", "test_out.py")
        assert result is None

    def test_generates_correct_number_of_test_functions(self, generator):
        entries = _make_entries(count=5)
        result = generator.generate_suite(entries, "test_api.jinja2", "test_out.py")
        content = result.read_text(encoding="utf-8")
        assert content.count("def test_") == 5

    def test_output_contains_sla_assertion(self, generator):
        """Verifies that SLA enforcement logic is rendered into generated output."""
        entries = [LogEntry(endpoint="/api/health", method="GET",
                            status_code=200, response_time_ms=95)]
        result = generator.generate_suite(entries, "test_api.jinja2", "test_sla.py")
        content = result.read_text(encoding="utf-8")
        assert "sla_limit_ms" in content
        assert "95" in content

    def test_output_contains_payload_when_provided(self, generator):
        """Verifies that non-null payload is rendered into the generated test body."""
        entries = [LogEntry(
            endpoint="/api/orders", method="POST",
            status_code=201, response_time_ms=120,
            payload={"product_id": "SKU-001"}
        )]
        result = generator.generate_suite(entries, "test_api.jinja2", "test_payload.py")
        content = result.read_text(encoding="utf-8")
        assert "SKU-001" in content

    def test_generated_function_names_include_http_method(self, generator):
        """Verifies that generated test names are unique and method-specific."""
        entries = [
            LogEntry(endpoint="/api/a", method="GET", status_code=200, response_time_ms=10),
            LogEntry(endpoint="/api/b", method="POST", status_code=201, response_time_ms=20),
        ]
        result = generator.generate_suite(entries, "test_api.jinja2", "test_names.py")
        content = result.read_text(encoding="utf-8")
        assert "def test_get_1" in content
        assert "def test_post_2" in content
