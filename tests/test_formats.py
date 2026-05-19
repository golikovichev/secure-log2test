import json
import csv
from pathlib import Path
from secure_log2test.core.parser import KibanaLogEntry
from secure_log2test.core.generator import KibanaTestGenerator

def test_write_json(tmp_path):
    entries = [
        KibanaLogEntry(
            method="POST",
            url="/api/login",
            status=200,
            headers={"Authorization": "Bearer secret"},
            body={"password": "123"}
        )
    ]
    output = tmp_path / "output.json"
    generator = KibanaTestGenerator(tmp_path)
    generator.write(entries, output, output_format="json")
    
    with open(output, encoding="utf-8") as f:
        data = json.load(f)
    
    assert len(data) == 1
    assert data[0]["method"] == "POST"
    assert data[0]["headers"]["Authorization"] == "***REDACTED***"
    assert data[0]["body"]["password"] == "***REDACTED***"

def test_write_csv(tmp_path):
    entries = [
        KibanaLogEntry(
            method="GET",
            url="/api/users",
            status=200,
            headers={"X-Auth": "key"},
            body=None
        )
    ]
    output = tmp_path / "output.csv"
    generator = KibanaTestGenerator(tmp_path)
    generator.write(entries, output, output_format="csv")
    
    with open(output, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    
    assert len(rows) == 1
    assert rows[0]["method"] == "GET"
    assert rows[0]["url"] == "/api/users"
    # CSV values are strings
    headers = json.loads(rows[0]["headers"])
    assert headers["X-Auth"] == "***REDACTED***"


def test_cyrillic_output_formats(tmp_path):
    entries = [
        KibanaLogEntry(
            method="POST",
            url="/api/v1/пользователи/профиль",
            status=200,
            headers={"X-User-Language": "русский"},
            body={"имя": "Михаил", "город": "Брайтон"},
        )
    ]

    # Test JSON output preserves Cyrillic characters without escaping to \uXXXX
    json_output = tmp_path / "cyrillic.json"
    generator = KibanaTestGenerator(tmp_path)
    generator.write(entries, json_output, output_format="json")

    json_text = json_output.read_text(encoding="utf-8")
    assert "пользователи" in json_text
    assert "Михаил" in json_text
    assert "\\u" not in json_text

    with open(json_output, encoding="utf-8") as f:
        data = json.load(f)
    assert data[0]["url"] == "/api/v1/пользователи/профиль"
    assert data[0]["headers"]["X-User-Language"] == "русский"
    assert data[0]["body"]["имя"] == "Михаил"

    # Test CSV output preserves Cyrillic characters without escaping to \uXXXX
    csv_output = tmp_path / "cyrillic.csv"
    generator.write(entries, csv_output, output_format="csv")

    csv_text = csv_output.read_text(encoding="utf-8")
    assert "пользователи" in csv_text
    assert "Михаил" in csv_text
    assert "\\u" not in csv_text

    with open(csv_output, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert len(rows) == 1
    assert rows[0]["url"] == "/api/v1/пользователи/профиль"
    headers = json.loads(rows[0]["headers"])
    assert headers["X-User-Language"] == "русский"
    body = json.loads(rows[0]["body"])
    assert body["имя"] == "Михаил"


def test_bogus_format_raises_error(tmp_path):
    import pytest
    entries = []
    output = tmp_path / "output.bogus"
    generator = KibanaTestGenerator(tmp_path)
    with pytest.raises(ValueError, match="Unsupported output format: bogus"):
        generator.write(entries, output, output_format="bogus")

