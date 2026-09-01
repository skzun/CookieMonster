"""Testes do detector diferencial extendido (console_errors, request_failures, api_anon)."""

from cookiemonster.validate.auth_state import (
    detect_baseline_vs_injected,
    ANONYMOUS, CONFIRMED, LIKELY, UNKNOWN,
)


def test_anon_on_api_401_without_login_redirect():
    base = {"api_anon_status": None}
    inj = {"api_anon_status": 401}
    r = detect_baseline_vs_injected(base, inj, domain="example.com")
    assert r["state"] == ANONYMOUS
    assert r["confidence"] >= 0.7


def test_anon_on_api_403():
    base = {}
    inj = {"api_anon_status": 403}
    r = detect_baseline_vs_injected(base, inj, domain="example.com")
    assert r["state"] == ANONYMOUS


def test_console_errors_reduce_likely_confidence():
    """Com nova logica, so api_user_id = LIKELY (api_only).
    Console errors degradam confianca em 0.25."""
    base = {}
    inj = {
        "api_user_id_present": True,
        "console_errors": [{"message": "TypeError: ..."}],
    }
    r = detect_baseline_vs_injected(base, inj, domain="example.com")
    assert r["state"] == LIKELY
    # Confianca base 0.7 (api_only), degradada em 0.25 = 0.45
    assert r["confidence"] < 0.7
    assert r["confidence"] >= 0.4


def test_console_errors_reduce_full_confirmed_confidence():
    """CONFIRMED com api_authenticated + api_user_id + console_errors
    continua CONFIRMED, mas confianca cai 0.25 (0.9 - 0.25 = 0.65)."""
    base = {"api_authenticated": False, "api_user_id_present": False}
    inj = {
        "api_authenticated": True,
        "api_user_id_present": True,
        "console_errors": [{"message": "TypeError: ..."}],
    }
    r = detect_baseline_vs_injected(base, inj, domain="example.com")
    assert r["state"] == CONFIRMED
    assert r["confidence"] < 0.9
    assert r["confidence"] >= 0.6


def test_request_failures_trigger_unknown_reason():
    base = {"console_errors": [], "request_failures": []}
    inj = {"console_errors": [], "request_failures": [{"url": "x"}]}
    r = detect_baseline_vs_injected(base, inj, domain="example.com")
    # Nenhum sinal positivo -> UNKNOWN
    assert r["state"] == UNKNOWN
    assert "request_failures" in r["unknown_reasons"]


def test_runtime_diff_includes_console_and_request_failures():
    base = {"console_errors": [], "request_failures": []}
    inj = {"console_errors": [{"m": "x"}],
           "request_failures": [{"url": "y"}]}
    r = detect_baseline_vs_injected(base, inj, domain="example.com")
    diff = r["differential"]
    assert "runtime" in diff
    assert diff["runtime"]["console_errors"]["injected"] == 1
    assert diff["runtime"]["request_failures"]["injected"] == 1


def test_login_redirect_outranks_console_errors():
    base = {"console_errors": []}
    inj = {"login_redirect": True, "console_errors": [{"m": "x"}]}
    r = detect_baseline_vs_injected(base, inj, domain="example.com")
    assert r["state"] == ANONYMOUS