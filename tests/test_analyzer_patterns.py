"""Content pattern detection (defaults + patterns.json)."""
from jesur.core import analyzer


def test_password_line_detected_in_txt_even_if_octet_stream():
    raw = b"# openvpn\nremote 10.0.0.1\npassword = SuperSecret123\n"
    matches = analyzer.check_sensitive_patterns(
        raw, 'application/octet-stream', '10.0.0.1', filename='vpn.txt'
    )
    assert matches, 'expected default regex to match password assignment'
    cats = {m['category'] for m in matches}
    assert 'password_assignment' in cats


def test_pem_block_detected():
    raw = b"-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----\n"
    matches = analyzer.check_sensitive_patterns(
        raw, 'text/plain', '10.0.0.1', filename='key.pem'
    )
    assert any(m['category'] == 'pem_private_block' for m in matches)


def test_extract_text_uses_filename_for_unknown_mime():
    raw = b"password: x\n"
    text = analyzer._extract_text_for_pattern_scan(
        raw, 'application/octet-stream', 'notes.txt'
    )
    assert text and 'password' in text


def test_minified_js_skips_credential_defaults():
    raw = b'password:!0,image:!0});'
    matches = analyzer.check_sensitive_patterns(
        raw, 'application/javascript', '1.1.1.1', filename='jquery-2.2.3.min.js'
    )
    assert not any(m['category'] in (
        'password_assignment', 'password_spaced_value', 'secret_assignment',
        'api_key_assignment', 'vpn_or_tunnel',
    ) for m in matches)


def test_turkish_keywords_colon():
    raw = "parola: gizli12\nşifre: abcdefgh\n".encode('utf-8')
    matches = analyzer.check_sensitive_patterns(
        raw, 'text/plain', '10.0.0.1', filename='notlar.txt'
    )
    cats = {m['category'] for m in matches}
    assert 'password_assignment' in cats


def test_utf16_le_content_decodes_and_matches():
    # Windows-style UTF-16 LE without BOM (NUL-heavy buffer triggers utf-16-le path)
    raw = 'sifre = mypassword\n'.encode('utf-16-le')
    matches = analyzer.check_sensitive_patterns(
        raw, 'application/octet-stream', '10.0.0.1', filename='vpn.txt'
    )
    assert any(m['category'] == 'password_assignment' for m in matches)


def test_decode_utf16_le_bom():
    inner = 'parola: test123\n'.encode('utf-16-le')
    raw = b'\xff\xfe' + inner
    text = analyzer._decode_text_bytes(raw)
    assert text and 'parola' in text.lower() and 'test123' in text


def test_dic_skips_vpn_psk_noise():
    raw = b'capsicum\nupskilling\n'
    matches = analyzer.check_sensitive_patterns(
        raw, 'text/plain', '10.0.0.1', filename='en_US.dic'
    )
    assert not any(m['category'] == 'vpn_or_tunnel' for m in matches)


def test_password_not_matched_on_minified_boolean():
    raw = b'password:!0,foo:bar'
    matches = analyzer.check_sensitive_patterns(
        raw, 'application/javascript', '10.0.0.1', filename='app.js'
    )
    assert not any(m['category'] == 'password_assignment' for m in matches)


def test_ruby_module_password_not_matched():
    raw = b'Password::TaskConfig.module_refname'
    matches = analyzer.check_sensitive_patterns(
        raw, 'text/x-ruby', '10.0.0.1', filename='tasks.rb'
    )
    assert not any(m['category'] == 'password_assignment' for m in matches)
