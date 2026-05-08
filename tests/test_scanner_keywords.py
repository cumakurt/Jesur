"""Tests for filename sensitive-keyword matching (reduces false positives)."""
import pytest

from jesur.core.scanner import _match_sensitive_keyword_filename, _is_known_benign_filename


@pytest.mark.parametrize(
    "name,expected",
    [
        ("x64_3_FXSAPI.DLL", None),
        ("FXSAPI.dll", None),
        ("kernel32.dll", None),
        ("my_api_key.txt", "API File"),
        ("rest_api_config.json", "API File"),
        ("api_key.pem", "API File"),
        ("apikey.txt", "API File"),
        ("secrets_backup.zip", "Secret File"),
        ("topsecret.doc", None),
        ("passwords.txt", "Password File"),
        ("passwd.bak", "Password File"),
        ("password-reset.js", None),
        ("password-policy.css", None),
        ("passwd-reset.mjs", None),
        ("password_reset.tsx", None),
        ("password.txt", "Password File"),
        ("company_credentials.csv", "Credential File"),
        ("sacred.txt", None),
        ("id_rsa", "Key File"),
        ("nessus_report.xml", "Nessus Scan File"),
    ],
)
def test_keyword_filename_matches(name, expected):
    assert _match_sensitive_keyword_filename(name.lower()) == expected


def test_known_benign_filename_excludes_thumbs_db():
    assert _is_known_benign_filename("thumbs.db") is True
    assert _is_known_benign_filename("users.db") is False
