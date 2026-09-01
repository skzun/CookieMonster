"""Testes do M6.0: AuthContext, AuthDetector, Classification."""

import pytest

from cookiemonster.auth import (
    AuthContext,
    AuthMechanism,
    IdentityProvider,
    SessionType,
    AuthClassification,
    Evidence,
    detect_all,
    detect_idp,
    detect_session_type,
    detect_mechanism,
    detect_protections,
    classify,
    classify_legacy,
)


# --- AuthContext dataclass ---

def test_authcontext_default_values():
    """Construtor vazio tem valores UNKNOWN/INCONCLUSIVE."""
    ctx = AuthContext(target="example.com")
    assert ctx.target == "example.com"
    assert ctx.auth_mechanism == AuthMechanism.UNKNOWN
    assert ctx.identity_provider == IdentityProvider.NONE
    assert ctx.session_type == SessionType.UNKNOWN
    assert ctx.classification == AuthClassification.INCONCLUSIVE
    assert ctx.confidence == 0.0
    assert ctx.reason == ""
    assert ctx.evidence == []
    assert ctx.hints == []
    assert ctx.context_dependencies == []
    assert ctx.bot_challenge_detected is False
    assert ctx.mfa_challenge_detected is False


def test_authcontext_to_from_dict():
    """Serializacao round-trip preserva todos os campos."""
    ctx = AuthContext(
        target="chatgpt.com",
        auth_mechanism=AuthMechanism.OIDC,
        identity_provider=IdentityProvider.GOOGLE,
        session_type=SessionType.JWT_COOKIE,
        classification=AuthClassification.IDP_BOUND,
        confidence=0.85,
        reason="identity_provider_boundary:google",
        hints=["idp_reference", "api_only"],
        context_dependencies=["idp"],
    )
    ctx.add_evidence(Evidence(source="json", type="idp_reference:google",
                              value="google-oauth2", confidence=0.95))
    d = ctx.to_dict()
    assert d["target"] == "chatgpt.com"
    assert d["auth_mechanism"] == "oidc"
    assert d["identity_provider"] == "google"
    ctx2 = AuthContext.from_dict(d)
    assert ctx2.target == ctx.target
    assert ctx2.auth_mechanism == ctx.auth_mechanism
    assert ctx2.identity_provider == ctx.identity_provider
    assert len(ctx2.evidence) == 1
    assert ctx2.evidence[0].type == "idp_reference:google"


def test_evidence_to_from_dict():
    """Evidence round-trip."""
    ev = Evidence(source="dom", type="mfa_challenge", value="/mfa/",
                  confidence=0.9, baseline_seen=False)
    d = ev.to_dict()
    ev2 = Evidence.from_dict(d)
    assert ev2.source == "dom"
    assert ev2.type == "mfa_challenge"
    assert ev2.value == "/mfa/"
    assert ev2.confidence == 0.9
    assert ev2.baseline_seen is False


# --- AuthDetector: IdP ---

def test_detect_google_via_json():
    """Detecta Google via campo idp=google-oauth2 no JSON."""
    obs = {
        "url": "https://chatgpt.com/api/auth/session",
        "body": '{"user": {"email": "x@y.com", "idp": "google-oauth2"}}',
    }
    ctx = AuthContext(target="chatgpt.com")
    detect_idp(obs, ctx)
    assert ctx.identity_provider == IdentityProvider.GOOGLE
    assert any(ev.type == "idp_reference:google" for ev in ctx.evidence)


def test_detect_google_via_domain():
    """Detecta Google via accounts.google.com em URL."""
    obs = {"url": "https://accounts.google.com/o/oauth2/auth?client_id=..."}
    ctx = AuthContext(target="x.com")
    detect_idp(obs, ctx)
    assert ctx.identity_provider == IdentityProvider.GOOGLE


def test_detect_microsoft_via_login_url():
    """Detecta Microsoft via login.microsoftonline.com."""
    obs = {"url": "https://login.microsoftonline.com/common/oauth2/authorize"}
    ctx = AuthContext(target="x.com")
    detect_idp(obs, ctx)
    assert ctx.identity_provider == IdentityProvider.MICROSOFT


def test_detect_github_via_oauth_url():
    """Detecta GitHub via /login/oauth/authorize."""
    obs = {"url": "https://github.com/login/oauth/authorize?client_id=x"}
    ctx = AuthContext(target="x.com")
    detect_idp(obs, ctx)
    assert ctx.identity_provider == IdentityProvider.GITHUB


def test_detect_facebook_via_dialog():
    """Detecta Facebook via /dialog/oauth."""
    obs = {"url": "https://www.facebook.com/v18.0/dialog/oauth"}
    ctx = AuthContext(target="x.com")
    detect_idp(obs, ctx)
    assert ctx.identity_provider == IdentityProvider.FACEBOOK


def test_detect_auth0_via_iss():
    """Detecta Auth0 via iss=https://*.auth0.com/."""
    obs = {"body": '{"iss": "https://acme.auth0.com/"}'}
    ctx = AuthContext(target="x.com")
    detect_idp(obs, ctx)
    assert ctx.identity_provider == IdentityProvider.AUTH0


def test_detect_okta_via_api_authn():
    """Detecta Okta via /api/v1/authn."""
    obs = {"url": "https://acme.okta.com/api/v1/authn"}
    ctx = AuthContext(target="x.com")
    detect_idp(obs, ctx)
    assert ctx.identity_provider == IdentityProvider.OKTA


def test_detect_aws_cognito_via_url():
    """Detecta AWS Cognito via cognito-idp.amazonaws.com."""
    obs = {"url": "https://cognito-idp.us-east-1.amazonaws.com/"}
    ctx = AuthContext(target="x.com")
    detect_idp(obs, ctx)
    assert ctx.identity_provider == IdentityProvider.AWS_COGNITO


def test_detect_apple_via_appleid():
    """Detecta Apple via appleid.apple.com."""
    obs = {"url": "https://appleid.apple.com/auth/authorize"}
    ctx = AuthContext(target="x.com")
    detect_idp(obs, ctx)
    assert ctx.identity_provider == IdentityProvider.APPLE


# --- AuthDetector: SessionType ---

def test_detect_jwt_cookie():
    """Detecta JWT em cookie via prefixo eyJ."""
    obs = {"cookie_names": ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc"]}
    ctx = AuthContext(target="x.com")
    detect_session_type(obs, ctx)
    assert ctx.session_type == SessionType.JWT_COOKIE


def test_detect_server_side_cookie_phpsessid():
    """Detecta cookie de servidor tradicional via PHPSESSID."""
    obs = {"cookie_names": ["PHPSESSID"]}
    ctx = AuthContext(target="x.com")
    detect_session_type(obs, ctx)
    assert ctx.session_type == SessionType.SERVER_SIDE_COOKIE


def test_detect_jwt_local_storage_via_dom():
    """Detecta JWT em localStorage via DOM."""
    obs = {"html": "<script>localStorage.getItem('token')</script>"}
    ctx = AuthContext(target="x.com")
    detect_session_type(obs, ctx)
    assert ctx.session_type == SessionType.JWT_LOCAL_STORAGE


# --- AuthDetector: Mechanism ---

def test_detect_oidc_via_well_known():
    """Detecta OIDC via /.well-known/openid-configuration."""
    obs = {"url": "https://x.com/.well-known/openid-configuration"}
    ctx = AuthContext(target="x.com")
    detect_mechanism(obs, ctx)
    assert ctx.auth_mechanism == AuthMechanism.OIDC


def test_detect_saml_via_url():
    """Detecta SAML via /saml/sso."""
    obs = {"url": "https://x.com/saml/sso?SAMLRequest=..."}
    ctx = AuthContext(target="x.com")
    detect_mechanism(obs, ctx)
    assert ctx.auth_mechanism == AuthMechanism.SAML


def test_detect_oauth_via_authorize():
    """Detecta OAuth via /oauth/authorize."""
    obs = {"url": "https://x.com/oauth/authorize?client_id=y"}
    ctx = AuthContext(target="x.com")
    detect_mechanism(obs, ctx)
    assert ctx.auth_mechanism == AuthMechanism.OAUTH


# --- AuthDetector: Protecoes ---

def test_detect_cloudflare_bot_challenge():
    """Detecta Cloudflare bot challenge via /cdn-cgi/challenge."""
    obs = {"url": "https://x.com/cdn-cgi/challenge-platform/..."}
    ctx = AuthContext(target="x.com")
    detect_protections(obs, ctx)
    assert ctx.bot_challenge_detected is True
    assert any(ev.type == "bot_challenge" for ev in ctx.evidence)


def test_detect_recaptcha():
    """Detecta reCAPTCHA via classe DOM."""
    obs = {"html": '<div class="g-recaptcha" data-sitekey="..."></div>'}
    ctx = AuthContext(target="x.com")
    detect_protections(obs, ctx)
    assert ctx.bot_challenge_detected is True


def test_detect_mfa_challenge_via_url():
    """Detecta MFA via /mfa/ no URL."""
    obs = {"url": "https://x.com/mfa/challenge"}
    ctx = AuthContext(target="x.com")
    detect_protections(obs, ctx)
    assert ctx.mfa_challenge_detected is True


def test_detect_mfa_via_amr_claim():
    """Detecta MFA via amr=[mfa] no JSON."""
    obs = {"body": '{"sub": "user", "amr": ["pwd", "mfa"]}'}
    ctx = AuthContext(target="x.com")
    detect_protections(obs, ctx)
    assert ctx.mfa_challenge_detected is True


# --- AuthDetector: detect_all (pipeline) ---

def test_detect_all_returns_context_with_all_signals():
    """detect_all agrega todos os detectores em um unico AuthContext."""
    obs = {
        "url": "https://acme.auth0.com/authorize",
        "body": '{"user": {"email": "x@y.com", "idp": "auth0"}, "id_token": "eyJ..."}',
        "cookie_names": ["__Secure-auth0.session-token"],
        "html": "<script>...</script>",
    }
    ctx = detect_all(obs, target="acme.com")
    assert ctx.target == "acme.com"
    assert ctx.identity_provider == IdentityProvider.AUTH0
    assert ctx.auth_mechanism in (AuthMechanism.OIDC, AuthMechanism.UNKNOWN)


# --- Classification ---

def test_classify_anonymous_on_login_redirect():
    """login_redirect no inj -> ANONYMOUS."""
    inj = {"login_redirect": True}
    base = {}
    ctx = AuthContext(target="x.com")
    result = classify(inj, base, ctx)
    assert result["state"] == "anonymous"
    assert result["confidence"] >= 0.80
    assert "login_redirect" in result["hints"]


def test_classify_anonymous_on_api_401():
    """api_anon_status=401 no inj sem base -> ANONYMOUS."""
    inj = {"api_anon_status": 401}
    base = {"api_anon_status": None}
    result = classify(inj, base, AuthContext(target="x.com"))
    assert result["state"] == "anonymous"
    assert result["confidence"] >= 0.75


def test_classify_authenticated_when_identity_plus_ui():
    """user_id + authenticated_ui + sem IdP bloqueante -> AUTHENTICATED."""
    inj = {
        "api_user_id_present": True,
        "api_authenticated": True,
        "authenticated_ui": True,
    }
    base = {"api_user_id_present": False, "api_authenticated": False,
            "authenticated_ui": False}
    result = classify(inj, base, AuthContext(target="x.com"))
    assert result["state"] == "authenticated"
    assert result["confidence"] >= 0.85


def test_classify_idp_bound_when_google_no_ui():
    """Google IdP detectado + identity_diff + sem UI -> IDP_BOUND."""
    inj = {
        "api_user_id_present": True,
        "api_user_email_present": True,
        "api_authenticated": True,  # API reconheceu
    }
    base = {
        "api_user_id_present": False,
        "api_user_email_present": False,
        "api_authenticated": False,
    }
    ctx = AuthContext(target="chatgpt.com", identity_provider=IdentityProvider.GOOGLE)
    result = classify(inj, base, ctx)
    assert result["state"] == "idp_bound"
    assert "idp" in result["context_dependencies"]
    assert "idp_reference" in result["hints"]


def test_classify_mfa_blocked_when_mfa_detected():
    """MFA challenge detectado + identity_diff -> MFA_BLOCKED."""
    inj = {
        "api_user_id_present": True,
        "api_authenticated": True,
        "authenticated_ui": True,  # UI ok
    }
    base = {"api_user_id_present": False, "api_authenticated": False,
            "authenticated_ui": False}
    ctx = AuthContext(target="x.com", mfa_challenge_detected=True)
    result = classify(inj, base, ctx)
    assert result["state"] == "mfa_blocked"
    assert "mfa" in result["context_dependencies"]


def test_classify_bot_blocked_when_challenge():
    """Bot challenge detectado -> BOT_BLOCKED."""
    inj = {}
    base = {}
    ctx = AuthContext(target="x.com", bot_challenge_detected=True)
    result = classify(inj, base, ctx)
    assert result["state"] == "bot_blocked"
    assert result["confidence"] >= 0.80


def test_classify_context_bound_when_session_token_no_state():
    """Session token presente mas UI/API nao confirma -> CONTEXT_BOUND."""
    inj = {
        "api_responses_inspected": [
            {"url": "https://x.com/api/auth/session", "status": 200, "content_type": "application/json"}
        ],
    }
    base = {}
    result = classify(inj, base, AuthContext(target="x.com"))
    assert result["state"] == "context_bound"
    assert "cookie_only" in result["context_dependencies"]


def test_classify_inconclusive_when_no_signals():
    """Sem nenhum sinal -> INCONCLUSIVE com reason."""
    result = classify({}, {}, AuthContext(target="x.com"))
    assert result["state"] == "inconclusive"
    assert result["reason"] == "insufficient_evidence"
    assert result["confidence"] <= 0.35


def test_classify_runtime_degraded_reduces_confidence():
    """console_errors no inj reduz confianca em 0.25."""
    inj = {
        "api_user_id_present": True,
        "api_authenticated": True,
        "authenticated_ui": True,
        "console_errors": [{"message": "TypeError"}],
    }
    base = {"api_user_id_present": False, "api_authenticated": False,
            "authenticated_ui": False}
    result = classify(inj, base, AuthContext(target="x.com"))
    assert result["state"] == "authenticated"
    assert result["confidence"] < 0.90
    assert "runtime_degraded" in result["hints"]


def test_classify_legacy_returns_auth_context():
    """classify_legacy retorna dict com state + auth_context."""
    obs = {
        "injected_evidence": {
            "api_user_id_present": True,
            "api_authenticated": True,
            "authenticated_ui": True,
        },
        "baseline_evidence": {
            "api_user_id_present": False,
            "api_authenticated": False,
            "authenticated_ui": False,
        },
        "url": "https://example.com",
    }
    result = classify_legacy(obs["injected_evidence"],
                             obs["baseline_evidence"],
                             "example.com")
    assert result["state"] == "authenticated"
    assert "auth_context" in result
    assert result["auth_context"]["classification"] == "authenticated"
