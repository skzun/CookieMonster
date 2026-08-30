"""Testes do matcher RFC 6265 e da selecao de vitima (M1)."""

from cookiemonster.domain.matcher import (
    domain_match,
    path_match,
    matches,
    applicable_cookies,
)
from cookiemonster.domain.selection import classify_name, is_auth_candidate


def test_domain_match_host_only():
    assert domain_match("www.amazon.com", "www.amazon.com", host_only=True) is True
    assert domain_match("amazon.com", "www.amazon.com", host_only=True) is False


def test_domain_match_domain_cookie():
    assert domain_match("www.amazon.com", "amazon.com", host_only=False) is True
    assert domain_match("amazon.com", "amazon.com", host_only=False) is True
    assert domain_match("evil.com", "amazon.com", host_only=False) is False


def test_domain_match_rejects_public_suffix():
    # .com nao pode ser tratado como dominio de cookie (public suffix).
    assert domain_match("www.example.com", "com", host_only=False) is False


def test_domain_match_rejects_suffix_spoof():
    assert domain_match("notamazon.com", "amazon.com", host_only=False) is False


def test_path_match():
    assert path_match("/", "/") is True
    assert path_match("/account", "/") is True
    assert path_match("/a/b", "/a") is True
    assert path_match("/a", "/a") is True
    assert path_match("/ab", "/a") is False  # boundary: "/ab" nao e "/a" + "/..."
    assert path_match("/a/b", "/a/b") is True


def test_matches_secure_and_http():
    cookie = {"domain": "amazon.com", "host_only": False, "path": "/",
              "secure": True, "expires_epoch": 0}
    assert matches(cookie, "https", "www.amazon.com", "/") is True
    assert matches(cookie, "http", "www.amazon.com", "/") is False  # Secure exige https


def test_matches_expiry():
    expired = {"domain": "amazon.com", "host_only": False, "path": "/",
               "secure": False, "expires_epoch": 1000}
    assert matches(expired, "https", "www.amazon.com", "/", current_time=2000) is False
    assert matches(expired, "https", "www.amazon.com", "/", current_time=500) is True


def test_applicable_cookies_dedupes_by_name():
    cookies = [
        {"name": "session", "domain": ".amazon.com", "host_only": False, "path": "/",
         "secure": False, "expires_epoch": 0},
        {"name": "session", "domain": ".amazon.com", "host_only": False, "path": "/",
         "secure": False, "expires_epoch": 0},
    ]
    result = applicable_cookies(cookies, "https", "www.amazon.com", "/")
    assert len(result) == 1


def test_classify_auth_names():
    assert classify_name("session-id") == "auth"
    assert classify_name("am-token") == "auth"
    assert classify_name("__Host-GAPS") == "auth"
    assert classify_name("i18n-prefs") == "anon"
    assert classify_name("random-cookie") == "other"
    assert is_auth_candidate("session-token") is True
    assert is_auth_candidate("i18n-prefs") is False