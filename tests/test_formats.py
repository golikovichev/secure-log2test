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
    generator = KibanaTestGenerator(tmp_path) # templates dir not needed for json
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
