import pytest

from security.ssrf_guard import (
    normalize_ip,
    is_private_ip,
    protocol_ok,
    resolve_and_check,
    check_redirects,
    is_metadata_ip
)


def test_normalize4():
    assert normalize_ip('127.0.0.1') == '127.0.0.1'

def test_normalize_decimal():
    assert normalize_ip('2130706433') == '127.0.0.1'

def test_normalize_mapped():
    assert normalize_ip('::ffff:127.0.0.1') == '127.0.0.1'

def test_private():
    assert is_private_ip('10.0.0.1') is True

def test_public():
    assert is_private_ip('8.8.8.8') is False

def test_metadata():
    assert is_metadata_ip('169.254.169.254') is True

def test_protocol_http():
    assert protocol_ok('http://example.com/a') is True

def test_protocol_file():
    assert protocol_ok('file:///etc/passwd') is False

def test_resolve_public():
    assert resolve_and_check('example.com', lambda h: '8.8.8.8', {'example.com'}) is True

def test_resolve_private():
    assert resolve_and_check('evil.com', lambda h: '127.0.0.1', set()) is False

def test_allowlist_private():
    assert resolve_and_check('trusted.example', lambda h: '10.0.0.1', {'trusted.example'}) is False

def test_redirects_ok():
    assert check_redirects(['https://a', 'https://b'], lambda u: True) is True

def test_redirects_bad():
    assert check_redirects(['https://a', 'http://127.0.0.1'], lambda u: '127.0.0.1' not in u) is False

def test_empty_host():
    assert resolve_and_check('', lambda h: '8.8.8.8', set()) is False

def test_gopher():
    assert protocol_ok('gopher://example.com') is False
