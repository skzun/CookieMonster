"""Testes do detector diferencial e AuthProbe."""

from cookiemonster.validate.auth_state import (
    detect_baseline_vs_injected, detect_from_summary,
    CONFIRMED, LIKELY, ANONYMOUS, UNKNOWN, extract_evidence_state,
)
from cookiemonster.inject.auth_probe import AuthEvidence


def test_differential_confirmed_via_api_user_id():
    base = {"api_user_id_present": False, "login_redirect": False}
    inj = {"api_user_id_present": True, "login_redirect": False}
    r = detect_baseline_vs_injected(base, inj, domain="example.com")
    assert r["state"] == CONFIRMED
    assert r["confidence"] >= 0.8


def test_differential_anonymous_on_login_redirect():
    base = {}
    inj = {"login_redirect": True}
    r = detect_baseline_vs_injected(base, inj, domain="example.com")
    assert r["state"] == ANONYMOUS


def test_differential_unknown_when_no_diff():
    base = {"api_user_id_present": False, "ui_markers": []}
    inj = {"api_user_id_present": False, "ui_markers": []}
    r = detect_baseline_vs_injected(base, inj, domain="example.com")
    assert r["state"] == UNKNOWN


def test_differential_likely_via_ui_difference():
    base = {"authenticated_ui": False, "login_redirect": False}
    inj = {"authenticated_ui": True, "login_redirect": False}
    r = detect_baseline_vs_injected(base, inj, domain="example.com")
    assert r["state"] in (LIKELY, CONFIRMED)


def test_detect_from_summary_confirmed_via_strong_marker():
    baseline = {"status_code": 200, "final_url": "https://x/", "text": ""}
    injected = {"status_code": 200, "final_url": "https://x/",
                "text": "Sign Out My Account"}
    r = detect_from_summary(baseline, injected, "example.com")
    assert r["state"] in (CONFIRMED, LIKELY)


def test_detect_from_summary_anonymous_on_redirect_login():
    baseline = {"status_code": 200, "final_url": "https://x/", "text": ""}
    injected = {"status_code": 200, "final_url": "https://x/login",
                "text": ""}
    r = detect_from_summary(baseline, injected, "example.com")
    assert r["state"] == ANONYMOUS


def test_auth_evidence_to_dict():
    ev = AuthEvidence(api_user_id_present=True, body_length=42)
    d = ev.to_dict()
    assert d["api_user_id_present"] is True
    assert d["body_length"] == 42


def test_extract_evidence_state():
    s = extract_evidence_state({"api_authenticated": True,
                                "authenticated_ui": False})
    assert "api:auth" in s
    assert extract_evidence_state({}) == ""
    assert extract_evidence_state(None) == ""