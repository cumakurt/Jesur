"""Tests for reporting exporters."""
import json
import os
import tempfile

from jesur.reporting.exporter import export_to_json, export_to_csv


def test_export_to_json_roundtrip():
    stats = {"start_time": 1.0, "end_time": 2.0, "hosts_scanned": 1}
    data = [{"ip": "10.0.0.1", "share": "s", "path": "a.txt", "size": 1}]
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "out.json")
        out = export_to_json(data, stats, path)
        assert out == path
        with open(path, encoding="utf-8") as f:
            loaded = json.load(f)
        assert loaded["results"] == data
        assert loaded["scan_info"]["statistics"] == stats
        assert loaded["scan_info"]["duration_seconds"] == 1.0


def test_export_to_csv_files():
    data = [
        {
            "ip": "10.0.0.1",
            "share": "s",
            "path": "a.txt",
            "size": 10,
            "file_type": "text",
            "create_time": "t1",
            "last_write_time": "t2",
        }
    ]
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "out.csv")
        out = export_to_csv(data, path, "files")
        assert out == path
        with open(path, encoding="utf-8") as f:
            content = f.read()
        assert "10.0.0.1" in content
        assert "a.txt" in content


def test_export_to_csv_escapes_spreadsheet_formulas():
    data = [
        {
            "ip": "10.0.0.1",
            "share": "s",
            "path": "=HYPERLINK(\"http://example.test\")",
            "size": 10,
            "file_type": "text",
            "create_time": "t1",
            "last_write_time": "t2",
        }
    ]
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "out.csv")
        export_to_csv(data, path, "files")
        with open(path, encoding="utf-8") as f:
            content = f.read()
        assert "'=HYPERLINK" in content
