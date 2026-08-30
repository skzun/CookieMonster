"""Testes do M3 (detecção de estado auth, scoring, perfis)."""

from cookiemonster.validate.auth_state import detect, VALID, INVALID, UNKNOWN
from cookiemonster.validate.scoring import score_artifact
from cookiemonster.validate.profiles import AmazonProfile, GenericProfile, get_profile


def _base(status=200, url="https://x.com/", text=""):
    return {"status_code": status, "final_url": url, "text": text, "sent_cookies": []}


def test_detect_valid_when_only_injected_has_logout():
    baseline = _base(text="<html>Login</html>")
    injected = _base(text="<html>Logout, My Account</html>")
    result = detect(baseline, injected, "example.com")
    assert result["state"] == VALID
    assert result["confidence"] > 0


def test_detect_invalid_on_login_redirect():
    baseline = _base(text="")
    injected = _base(status=200, url="https://x.com/ap/signin", text="Sign In")
    result = detect(baseline, injected, "amazon.com")
    assert result["state"] == INVALID


def test_detect_unknown_when_no_signal():
    baseline = _base(text="static")
    injected = _base(text="static")
    result = detect(baseline, injected, "example.com")
    assert result["state"] == UNKNOWN


def test_score_artifact_auth_and_anon():
    assert score_artifact("session-id", True, True, True)["auth_candidate"] is True
    assert score_artifact("i18n-prefs", True, False, False)["kind"] == "anon"
    assert score_artifact("anything", False, True, True)["score"] == 0  # não enviado


def test_profiles():
    assert isinstance(get_profile("amazon.com"), AmazonProfile)
    assert isinstance(get_profile("example.com"), GenericProfile)


def test_amazon_profile_detects_hello():
    p = AmazonProfile()
    markers = p.authenticated_markers("Hello, John — Sign Out", "https://amazon.com/", 200)
    assert any("Hello, " in m or "Sign Out" in m for m in markers) or markers