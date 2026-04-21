from pathlib import Path
import main


def test_main_logs_error_when_input_file_missing(monkeypatch, caplog):
    monkeypatch.setattr(main, "PytestGenerator", lambda: None)
    monkeypatch.setattr(main, "KibanaLogParser", lambda file_path: None)
    monkeypatch.setattr(
        "sys.argv",
        ["main.py", "--log", "missing-file.json"],
    )

    main.main()

    assert "Input file not found" in caplog.text


def test_main_generates_suite_for_valid_input(tmp_path, monkeypatch):
    log_file = tmp_path / "export.json"
    log_file.write_text('{"hits": {"hits": []}}', encoding="utf-8")

    class FakeParser:
        def __init__(self, file_path: str):
            self.file_path = file_path

        def parse(self):
            return [object(), object()]

    calls = {}

    class FakeGenerator:
        def generate_suite(self, entries, template_name, output_filename):
            calls["entries"] = entries
            calls["template_name"] = template_name
            calls["output_filename"] = output_filename
            return Path("generated_tests/test_cli.py")

    monkeypatch.setattr(main, "KibanaLogParser", FakeParser)
    monkeypatch.setattr(main, "PytestGenerator", FakeGenerator)
    monkeypatch.setattr(
        "sys.argv",
        ["main.py", "--log", str(log_file), "--out", "test_cli.py"],
    )

    main.main()

    assert len(calls["entries"]) == 2
    assert calls["template_name"] == "test_api.jinja2"
    assert calls["output_filename"] == "test_cli.py"
