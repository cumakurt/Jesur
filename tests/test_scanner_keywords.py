"""Tests for filename sensitive-keyword matching (reduces false positives)."""
import pytest

from jesur.core.scanner import (
    _get_safe_output_path,
    _is_known_benign_filename,
    _lookup_sensitive_filename,
    _match_sensitive_path,
    _match_sensitive_keyword_filename,
    _sanitize_path,
    _severity_for_sensitive_file,
)


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
        ("backup.zip", "Backup or Export File"),
        ("db_dump.sql", "Backup or Export File"),
        ("SharpHound.zip", "Assessment Tool Output"),
        ("lsass.dmp", "Credential Extraction Artifact"),
    ],
)
def test_keyword_filename_matches(name, expected):
    assert _match_sensitive_keyword_filename(name.lower()) == expected


def test_known_benign_filename_excludes_thumbs_db():
    assert _is_known_benign_filename("thumbs.db") is True
    assert _is_known_benign_filename("users.db") is False


def test_sensitive_filename_lookup_is_case_insensitive():
    assert _lookup_sensitive_filename("ID_RSA") == "SSH RSA Private Key"
    assert _lookup_sensitive_filename("LOGIN DATA") == "Chrome/Edge Saved Passwords"
    assert _lookup_sensitive_filename("NTDS.DIT") == "Active Directory Database"


def test_path_aware_sensitive_matching():
    assert _match_sensitive_path(r"Users\bob\.aws\credentials") == "AWS CLI Credentials"
    assert _match_sensitive_path(r"Users\bob\.ssh\id_ed25519") == "SSH Credential Artifact"
    assert _match_sensitive_path(r"Windows\System32\config\SAM") == "Windows Registry Hive"


def test_sensitive_file_severity_mapping():
    assert _severity_for_sensitive_file("SSH RSA Private Key") == "Critical"
    assert _severity_for_sensitive_file("Active Directory Database") == "Critical"
    assert _severity_for_sensitive_file("Environment Variables File") == "High"


def test_sanitize_path_allows_normal_smb_names_and_blocks_traversal():
    assert _sanitize_path(r"Team Share\My File (Final).txt") == "Team Share/My File (Final).txt"
    assert _sanitize_path("../secret.txt") is None
    assert _sanitize_path("safe/%2e%2e/secret.txt") is None
    assert _sanitize_path("C:/Users/user/secret.txt") is None


def test_download_output_filename_is_bounded(tmp_path, monkeypatch):
    from jesur.core import context

    monkeypatch.setattr(context, "output_dir", str(tmp_path))
    long_path = "/".join(["verylongfoldername"] * 30) + "/passwords.txt"
    out_path, relative = _get_safe_output_path(long_path, "Finance Share", "2001:db8::1")
    assert len(out_path.rsplit("/", 1)[-1]) < 220
    assert relative.startswith("2001_db8__1/")
