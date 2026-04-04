"""Ensure .txt files remain eligible for full content scanning (regression guard)."""
from jesur.core.analyzer import TEXT_EXTENSIONS_FOR_CONTENT_SCAN


def test_txt_is_in_text_extensions_for_content_scan():
    assert '.txt' in TEXT_EXTENSIONS_FOR_CONTENT_SCAN


def test_txt_used_for_octet_stream_path_in_scanner_import():
    from jesur.core.scanner import TEXT_EXTENSIONS_FOR_CONTENT_SCAN as s
    assert '.txt' in s
    assert s is TEXT_EXTENSIONS_FOR_CONTENT_SCAN
