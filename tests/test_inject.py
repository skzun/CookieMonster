"""Testes do M2 (montagem de cookie header, captura de envio, conversao Playwright)."""

import pytest

from cookiemonster.inject.httpx_client import cookies_to_header
from cookiemonster.inject.capture import summarize_sent, sent_cookie_names
from cookiemonster.inject.playwright_client import _to_playwright_cookies


def test_cookies_to_header():
    cookies = [
        {"name": "a", "value": "1"},
        {"name": "b", "value": "2"},
    ]
    assert cookies_to_header(cookies) == "a=1; b=2"


def test_cookies_to_header_skips_empty_name():
    assert cookies_to_header([{"name": "", "value": "x"}, {"name": "k", "value": "v"}]) == "k=v"


def test_summarize_sent_is_deprecated():
    replay = {
        "sent_cookies": [
            {"url": "https://x.com/", "headers": {"cookie": "a=1; b=2"}},
        ]
    }
    with pytest.warns(DeprecationWarning):
        summary = summarize_sent(replay, ["a", "b", "c"])
    assert summary["sent"] == ["a", "b"]
    assert summary["not_sent"] == ["c"]


def test_sent_cookie_names_handles_case():
    replay = {
        "sent_cookies": [
            {"url": "https://x.com/", "headers": {"Cookie": "SID=x; token=y"}},
        ]
    }
    with pytest.warns(DeprecationWarning):
        assert sent_cookie_names(replay) == ["SID", "token"]


def test_to_playwright_cookies_strips_dot_and_handles_session():
    cookies = [
        {"name": "s", "value": "v", "domain": ".amazon.com", "path": "/",
         "secure": True, "http_only": False, "expires_epoch": 0},
        {"name": "t", "value": "w", "domain": "www.amazon.com", "path": "/",
         "secure": False, "http_only": True, "expires_epoch": 1799519127},
    ]
    pw = _to_playwright_cookies(cookies)
    assert pw[0]["domain"] == "amazon.com"
    assert pw[0]["secure"] is True
    assert "expires" not in pw[0]
    assert pw[1]["domain"] == "www.amazon.com"
    assert pw[1]["httpOnly"] is True
    assert pw[1]["expires"] == 1799519127