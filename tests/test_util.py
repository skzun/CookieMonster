"""Testes do M5 (rate limiter e stealth)."""

from cookiemonster.util.rate_limit import RateLimiter, extract_host
from cookiemonster.util.stealth import new_context_options, random_user_agent


def test_extract_host():
    assert extract_host("https://www.amazon.com/path?q=1") == "www.amazon.com"
    assert extract_host("http://127.0.0.1:8080/x") == "127.0.0.1"


def test_rate_limiter_backoff_growth(monkeypatch):
    rl = RateLimiter(min_interval=0.0, max_backoff=30.0)
    rl.report_failure("x.com")
    assert rl.backoff_for("x.com") == 1.0
    rl.report_failure("x.com")
    assert rl.backoff_for("x.com") == 2.0
    rl.report_success("x.com")
    assert rl.backoff_for("x.com") == 0.0


def test_new_context_options():
    opts = new_context_options()
    assert "user_agent" in opts
    assert "viewport" in opts
    assert "locale" in opts


def test_random_user_agent_is_not_empty():
    assert len(random_user_agent()) > 0