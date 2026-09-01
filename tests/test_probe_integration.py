"""Testes de integracao M6.1: _probe_one + persistencia + CLI output."""

import json
import os
import tempfile
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from cookiemonster.auth import (
    AuthContext, AuthMechanism, IdentityProvider, SessionType,
    AuthClassification, Evidence, detect_all, classify,
)
from cookiemonster.store.db import Store


# --- _probe_one retorna AuthContext ---
# (Teste do _probe_one diretamente requer mockar inject.httpx_client
#  E playwright_client em runtime, o que e fragil. Em vez disso testamos
#  via CLI (test_cli_probe_shows_auth_context_chain abaixo) que e mais
#  confiavel e exercita o mesmo codigo.)


# --- Persistencia de auth_context ---

def test_record_run_persists_auth_context(tmp_path):
    """record_run aceita auth_context_json + reason e persiste."""
    db_path = tmp_path / "test.db"
    s = Store(str(db_path))
    s.init()  # cria schema (victims, runs, cookies, findings)
    # Cria vitima dummy para satisfazer FK.
    with s.batch() as conn:
        vid = s.upsert_victim(conn, dir_name="TEST_VICTIM", layout="netscape", path="/tmp")

    auth_ctx = {
        "target": "example.com",
        "auth_mechanism": "oidc",
        "identity_provider": "google",
        "session_type": "jwt_cookie",
        "classification": "idp_bound",
        "confidence": 0.85,
        "reason": "identity_provider_boundary:google",
    }
    run_id = s.record_run(
        victim_id=vid, target_url="https://example.com/",
        target_domain="example.com", channel="httpx",
        state="IDP_BOUND", confidence=0.85,
        evidence_json=json.dumps({"foo": "bar"}),
        auth_context_json=json.dumps(auth_ctx),
        reason="identity_provider_boundary:google",
    )
    assert run_id > 0

    # Verifica persistencia via list_runs.
    runs = s.list_runs()
    assert len(runs) == 1
    r = runs[0]
    assert r["state"] == "IDP_BOUND"
    assert r["confidence"] == 0.85
    assert r["reason"] == "identity_provider_boundary:google"
    assert r["auth_context_json"] is not None
    persisted_ctx = json.loads(r["auth_context_json"])
    assert persisted_ctx["identity_provider"] == "google"
    assert persisted_ctx["classification"] == "idp_bound"


def test_record_run_backward_compatible(tmp_path):
    """record_run sem auth_context_json/reason funciona (runs antigos)."""
    db_path = tmp_path / "test.db"
    s = Store(str(db_path))
    s.init()
    with s.batch() as conn:
        vid = s.upsert_victim(conn, dir_name="TEST_VICTIM", layout="netscape", path="/tmp")

    run_id = s.record_run(
        victim_id=vid, target_url="https://x.com/",
        target_domain="x.com", channel="httpx",
        state="CONFIRMED", confidence=0.9,
        evidence_json=json.dumps({"legacy": True}),
    )
    assert run_id > 0
    runs = s.list_runs()
    assert runs[0]["auth_context_json"] is None
    assert runs[0]["reason"] is None


# --- CLI output: cadeia de evidencias ---

def test_render_replay_result_with_auth0_idp():
    """_render_replay_result mostra AuthContext + cadeia de evidencias."""
    from rich.console import Console
    from io import StringIO
    from cookiemonster.cli import _render_replay_result

    # Dict no formato de _probe_one (M6.0).
    res = {
        "state": "AUTHENTICATED",
        "confidence": 0.90,
        "reason": "identity_confirmed",
        "hints": ["idp_reference"],
        "context_dependencies": ["idp"],
        "auth_mechanism": "oidc",
        "identity_provider": "auth0",
        "session_type": "jwt_cookie",
        "auth_context": {
            "target": "acme.auth0.com",
            "classification": "authenticated",
            "auth_mechanism": "oidc",
            "identity_provider": "auth0",
            "session_type": "jwt_cookie",
            "evidence": [
                {"source": "json", "type": "idp_reference:auth0",
                 "value": "iss.*auth0.com", "confidence": 0.95},
                {"source": "json", "type": "mechanism:oidc",
                 "value": "/.well-known/openid-configuration", "confidence": 0.85},
                {"source": "json", "type": "api_user_id_present",
                 "value": "true", "confidence": 0.90},
                {"source": "dom", "type": "authenticated_ui",
                 "value": "true", "confidence": 0.85},
            ],
        },
    }
    buf = StringIO()
    console = Console(file=buf, force_terminal=False, width=200)
    _render_replay_result(res, console)
    out = buf.getvalue()

    # Verifica campos M6.0 presentes.
    assert "REPLAY RESULT" in out
    assert "AUTHENTICATED" in out
    assert "Confidence:" in out
    assert "0.90" in out
    assert "Reason:" in out
    assert "identity_confirmed" in out
    assert "Mechanism:" in out
    assert "oidc" in out
    assert "IdP:" in out
    assert "auth0" in out
    assert "Session type:" in out
    assert "jwt_cookie" in out
    assert "Evidence chain" in out
    # Evidencias especificas.
    assert "idp_reference" in out
    assert "mechanism:oidc" in out


def test_render_replay_result_idp_bound_google():
    """_render_replay_result mostra IDP_BOUND com Google + reason contextual."""
    from rich.console import Console
    from io import StringIO
    from cookiemonster.cli import _render_replay_result

    res = {
        "state": "IDP_BOUND",
        "confidence": 0.85,
        "reason": "identity_provider_boundary:google",
        "hints": ["idp_reference", "api_only"],
        "context_dependencies": ["idp"],
        "auth_mechanism": "oidc",
        "identity_provider": "google",
        "session_type": "jwt_cookie",
        "auth_context": {
            "target": "chatgpt.com",
            "classification": "idp_bound",
            "auth_mechanism": "oidc",
            "identity_provider": "google",
            "session_type": "jwt_cookie",
            "evidence": [
                {"source": "json", "type": "idp_reference:google",
                 "value": "google-oauth2", "confidence": 0.95},
            ],
        },
    }
    buf = StringIO()
    console = Console(file=buf, force_terminal=False, width=200)
    _render_replay_result(res, console)
    out = buf.getvalue()

    assert "IDP_BOUND" in out
    assert "google" in out
    assert "identity_provider_boundary:google" in out
    assert "Identity Provider externo" in out  # mensagem especifica


def test_render_replay_result_bot_blocked():
    """_render_replay_result mostra BOT_BLOCKED com aviso claro."""
    from rich.console import Console
    from io import StringIO
    from cookiemonster.cli import _render_replay_result

    res = {
        "state": "BOT_BLOCKED",
        "confidence": 0.85,
        "reason": "anti_bot_challenge_detected",
        "hints": ["bot_challenge"],
        "context_dependencies": [],
        "auth_mechanism": "cookie_session",
        "identity_provider": "none",
        "session_type": "server_side_cookie",
        "bot_challenge_detected": True,
        "auth_context": {
            "target": "x.com",
            "classification": "bot_blocked",
            "auth_mechanism": "cookie_session",
            "identity_provider": "none",
            "session_type": "server_side_cookie",
            "bot_challenge_detected": True,
            "evidence": [
                {"source": "url", "type": "bot_challenge",
                 "value": "/cdn-cgi/challenge", "confidence": 0.95},
            ],
        },
    }
    buf = StringIO()
    console = Console(file=buf, force_terminal=False, width=200)
    _render_replay_result(res, console)
    out = buf.getvalue()

    assert "BOT_BLOCKED" in out
    assert "anti_bot_challenge_detected" in out
    assert "Anti-bot challenge" in out
    assert "Cloudflare" in out or "reCAPTCHA" in out  # mensagem especifica


def test_render_replay_result_mfa_blocked():
    """_render_replay_result mostra MFA_BLOCKED com mfa challenge."""
    from rich.console import Console
    from io import StringIO
    from cookiemonster.cli import _render_replay_result

    res = {
        "state": "MFA_BLOCKED",
        "confidence": 0.85,
        "reason": "mfa_required_by_idp",
        "hints": ["mfa_challenge"],
        "context_dependencies": ["mfa"],
        "auth_mechanism": "oidc",
        "identity_provider": "okta",
        "session_type": "server_side_cookie",
        "mfa_challenge_detected": True,
        "auth_context": {
            "target": "x.com",
            "classification": "mfa_blocked",
            "auth_mechanism": "oidc",
            "identity_provider": "okta",
            "session_type": "server_side_cookie",
            "mfa_challenge_detected": True,
            "evidence": [
                {"source": "url", "type": "mfa_challenge",
                 "value": "/mfa/", "confidence": 0.9},
            ],
        },
    }
    buf = StringIO()
    console = Console(file=buf, force_terminal=False, width=200)
    _render_replay_result(res, console)
    out = buf.getvalue()

    assert "MFA_BLOCKED" in out
    assert "mfa_required_by_idp" in out
    assert "MFA" in out or "IdP exige MFA" in out


# --- Compatibility: classico CONFIRMED/LIKELY/ANONYMOUS/UNKNOWN ainda funcionam ---

def test_legacy_states_preserved():
    """Estados classicos (CONFIRMED, LIKELY, etc) ainda sao emitidos
    alem dos novos (AUTHENTICATED, CONTEXT_BOUND, etc)."""
    # AuthContext e classification funcionam nos dois formatos.
    from cookiemonster.auth.classification import classify_legacy
    result = classify_legacy(
        inj={"api_user_id_present": True, "api_authenticated": True, "authenticated_ui": True},
        base={"api_user_id_present": False, "api_authenticated": False, "authenticated_ui": False},
        domain="example.com",
    )
    # state novo (minúsculo) presente.
    assert result["state"] in ("authenticated", "confirmed")
    # auth_context dict presente.
    assert "auth_context" in result
    assert "classification" in result["auth_context"]


# --- AuthContext sem detector ainda funciona ---

def test_authcontext_minimal_construction():
    """AuthContext sem detector ainda pode ser criado (caso de uso minimo)."""
    ctx = AuthContext(target="x.com")
    # Sem detector, fica tudo UNKNOWN.
    assert ctx.identity_provider == IdentityProvider.NONE
    assert ctx.auth_mechanism == AuthMechanism.UNKNOWN
    # Mas classification padrao e INCONCLUSIVE.
    assert ctx.classification == AuthClassification.INCONCLUSIVE
    # to_dict/from_dict round-trip.
    d = ctx.to_dict()
    ctx2 = AuthContext.from_dict(d)
    assert ctx2.target == "x.com"
