"""Tests for HTML report generation."""
import os
import tempfile
from types import SimpleNamespace

from jesur.reporting.generator import save_results


def test_save_results_writes_single_unified_report():
    scan_args = SimpleNamespace(network="192.168.1.0/24", username="u", domain="d")
    with tempfile.TemporaryDirectory() as tmp:
        reports = os.path.join(tmp, "reports")
        path, second = save_results(
            [{"ip": "192.168.1.1", "share": "S", "path": "x.txt", "size": 1,
              "create_time": "c", "last_write_time": "w"}],
            [{"ip": "192.168.1.1", "share": "S", "path": "y.txt", "category": "test",
              "match": "m", "file_type": "t", "downloaded_file": None}],
            "t",
            scan_args,
            stats={"hosts_scanned": 1, "bytes_read": 100, "start_time": 0, "end_time": 1},
            reports_dir=reports,
            download_href_prefix="../out_download/",
        )
        assert path and os.path.isfile(path)
        assert second is None
        assert os.path.dirname(path) == reports
        assert "_report_" in os.path.basename(path)
        with open(path, encoding="utf-8") as f:
            html = f.read()
        assert "JESUR" in html or "Jesur" in html
        assert "Accessed files" in html
        assert "Sensitive content" in html
        assert "chartCategories" in html
        assert "filter-category-sensitive" in html
        assert "back-to-top" in html
        assert "pagination-sensitive" in html
        assert 'class="brand-logo"' in html
        assert "jesur_logo.png" in html
        logo_path = os.path.join(reports, "jesur_logo.png")
        assert os.path.isfile(logo_path)


def test_save_results_does_not_mutate_input_paths():
    scan_args = SimpleNamespace(network="<net>", username="u", domain="d")
    files = [{"ip": "1.1.1.1", "share": "S", "path": "a/b.txt", "size": 1}]
    results = [{"ip": "1.1.1.1", "share": "S", "path": "c/d.txt", "category": "x", "match": "<secret>"}]
    with tempfile.TemporaryDirectory() as tmp:
        save_results(files, results, "t", scan_args, reports_dir=tmp)

    assert files[0]["path"] == "a/b.txt"
    assert results[0]["path"] == "c/d.txt"
