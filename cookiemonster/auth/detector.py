"""AuthDetector: identifica o contexto de autenticacao de uma aplicacao
via fingerprints passiveis (sem bypass).

Fontes de evidencia:
- DOM: classes, atributos, links para IdPs conhecidos.
- Network: URLs de endpoints OIDC/SAML (/.well-known/openid-configuration,
  /saml/sso, /oauth/authorize, etc).
- JSON: campos como idp, provider, iss em responses de auth.
- Cookie: nomes caracteristicos de cada IdP (ex.: __Secure-next-auth).

Cada fingerprint produz uma Evidence com confidence e source.
A agregacao de todas as evidences forma o AuthContext.

NAO executa nenhum flow OAuth. Apenas detecta.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .context import (
    AuthContext,
    AuthMechanism,
    IdentityProvider,
    SessionType,
    Evidence,
)


# --- Fingerprints por IdP ---

# Cada entrada: (IdP, AuthMechanism, lista de regex/fingerprints aplicaveis).
# Cada fingerprint eh um dict com: kind ("domain"|"url"|"cookie"|"json"|"dom"),
# pattern (regex ou string), confidence (0-1), value_template.
_IDP_FINGERPRINTS: List[Dict[str, Any]] = [
    # --- Google ---
    {
        "idp": IdentityProvider.GOOGLE,
        "mechanism": AuthMechanism.OIDC,
        "fingerprints": [
            {"kind": "domain", "pattern": r"accounts\.google\.com", "confidence": 0.95},
            {"kind": "url", "pattern": r"/o/oauth2/", "confidence": 0.85},
            {"kind": "json", "pattern": r'"idp"\s*:\s*"google-oauth2"', "confidence": 0.95},
            {"kind": "json", "pattern": r'"iss"\s*:\s*"https://accounts\.google\.com"', "confidence": 0.95},
            {"kind": "json", "pattern": r'google-oauth2', "confidence": 0.90},
            {"kind": "cookie", "pattern": r"^G_ENABLED_IDPS$", "confidence": 0.7},
            {"kind": "cookie", "pattern": r"__Secure-next-auth", "confidence": 0.3},  # fraco
        ],
    },
    # --- Microsoft / Entra ID ---
    {
        "idp": IdentityProvider.MICROSOFT,
        "mechanism": AuthMechanism.OIDC,
        "fingerprints": [
            {"kind": "domain", "pattern": r"login\.microsoftonline\.com", "confidence": 0.95},
            {"kind": "domain", "pattern": r"login\.live\.com", "confidence": 0.90},
            {"kind": "url", "pattern": r"/oauth2/authorize", "confidence": 0.6},
            {"kind": "json", "pattern": r'"idp"\s*:\s*"(?:azuread|microsoft|aad)"', "confidence": 0.90},
            {"kind": "json", "pattern": r'"iss"\s*:\s*"https://login\.microsoftonline\.com', "confidence": 0.95},
            {"kind": "json", "pattern": r"azuread|microsoft", "confidence": 0.7},
        ],
    },
    # --- GitHub ---
    {
        "idp": IdentityProvider.GITHUB,
        "mechanism": AuthMechanism.OAUTH,
        "fingerprints": [
            {"kind": "domain", "pattern": r"github\.com/login/oauth", "confidence": 0.95},
            {"kind": "url", "pattern": r"github\.com/login/oauth/authorize", "confidence": 0.95},
            {"kind": "json", "pattern": r'"idp"\s*:\s*"github"', "confidence": 0.90},
            {"kind": "json", "pattern": r'"login"\s*:\s*"(?!.*@)', "confidence": 0.4},  # GitHub user login
            {"kind": "dom", "pattern": r"github-btn|github-login", "confidence": 0.7},
        ],
    },
    # --- Facebook ---
    {
        "idp": IdentityProvider.FACEBOOK,
        "mechanism": AuthMechanism.OAUTH,
        "fingerprints": [
            {"kind": "domain", "pattern": r"facebook\.com/(?:v\d+\.0/)?dialog/oauth", "confidence": 0.95},
            {"kind": "url", "pattern": r"facebook\.com/dialog/oauth", "confidence": 0.95},
            {"kind": "json", "pattern": r'"idp"\s*:\s*"facebook"', "confidence": 0.90},
            {"kind": "json", "pattern": r'"name"\s*:\s*".*"\s*,\s*"id"\s*:\s*"\d+"', "confidence": 0.3},  # fraco
        ],
    },
    # --- Apple ---
    {
        "idp": IdentityProvider.APPLE,
        "mechanism": AuthMechanism.OIDC,
        "fingerprints": [
            {"kind": "domain", "pattern": r"appleid\.apple\.com", "confidence": 0.95},
            {"kind": "url", "pattern": r"/auth/authorize", "confidence": 0.5},
            {"kind": "json", "pattern": r'"idp"\s*:\s*"apple"', "confidence": 0.90},
        ],
    },
    # --- Auth0 ---
    {
        "idp": IdentityProvider.AUTH0,
        "mechanism": AuthMechanism.OIDC,
        "fingerprints": [
            {"kind": "domain", "pattern": r"[\w-]+\.auth0\.com", "confidence": 0.95},
            {"kind": "url", "pattern": r"/authorize\?client_id=", "confidence": 0.7},
            {"kind": "url", "pattern": r"/\.well-known/openid-configuration", "confidence": 0.6},
            {"kind": "json", "pattern": r'"iss"\s*:\s*"https://[\w-]+\.auth0\.com/', "confidence": 0.95},
            {"kind": "json", "pattern": r'"idp"\s*:\s*"auth0"', "confidence": 0.95},
        ],
    },
    # --- Okta ---
    {
        "idp": IdentityProvider.OKTA,
        "mechanism": AuthMechanism.OIDC,
        "fingerprints": [
            {"kind": "domain", "pattern": r"[\w-]+\.okta\.com", "confidence": 0.95},
            {"kind": "domain", "pattern": r"[\w-]+\.oktapreview\.com", "confidence": 0.95},
            {"kind": "url", "pattern": r"/oauth2/default/v1/authorize", "confidence": 0.90},
            {"kind": "url", "pattern": r"/api/v1/authn", "confidence": 0.85},
            {"kind": "json", "pattern": r'"idp"\s*:\s*"okta"', "confidence": 0.95},
        ],
    },
    # --- AWS Cognito ---
    {
        "idp": IdentityProvider.AWS_COGNITO,
        "mechanism": AuthMechanism.OIDC,
        "fingerprints": [
            {"kind": "domain", "pattern": r"cognito-idp\.[\w-]+\.amazonaws\.com", "confidence": 0.95},
            {"kind": "domain", "pattern": r"[\w-]+\.auth\.[\w-]+\.amazoncognito\.com", "confidence": 0.95},
            {"kind": "url", "pattern": r"/oauth2/authorize", "confidence": 0.5},
            {"kind": "json", "pattern": r'"idp"\s*:\s*"(?:cognito|aws-cognito)"', "confidence": 0.90},
        ],
    },
]


# --- Fingerprints de SessionType (cookie, JWT, etc) ---

_SESSION_FINGERPRINTS: List[Dict[str, Any]] = [
    # JWT em cookie
    {
        "session_type": SessionType.JWT_COOKIE,
        "fingerprints": [
            {"kind": "cookie", "pattern": r"^eyJ[A-Za-z0-9_-]+\.eyJ", "confidence": 0.90},
            {"kind": "json", "pattern": r'"token"\s*:\s*"eyJ', "confidence": 0.85},
        ],
    },
    # JWT em localStorage (vuln classico)
    {
        "session_type": SessionType.JWT_LOCAL_STORAGE,
        "fingerprints": [
            {"kind": "dom", "pattern": r"localStorage\.(getItem|setItem)\(['\"]token", "confidence": 0.7},
            {"kind": "json", "pattern": r'"localStorage"\s*:', "confidence": 0.4},
        ],
    },
    # Cookie de servidor tradicional (HttpOnly)
    {
        "session_type": SessionType.SERVER_SIDE_COOKIE,
        "fingerprints": [
            {"kind": "cookie", "pattern": r"^(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|connect\.sid)$", "confidence": 0.85},
            {"kind": "cookie", "pattern": r"^session(-id)?$", "confidence": 0.4},  # generico
        ],
    },
    # Token opaco (server resolve)
    {
        "session_type": SessionType.OPAQUE_TOKEN,
        "fingerprints": [
            {"kind": "cookie", "pattern": r"^[a-f0-9]{32,}$", "confidence": 0.3},  # hex longo
            {"kind": "cookie", "pattern": r"^[A-Za-z0-9_-]{40,}$", "confidence": 0.3},  # base64url longo
        ],
    },
]


# --- Fingerprints de AuthMechanism ---

_MECHANISM_FINGERPRINTS: List[Dict[str, Any]] = [
    {
        "mechanism": AuthMechanism.OIDC,
        "fingerprints": [
            {"kind": "url", "pattern": r"/\.well-known/openid-configuration", "confidence": 0.95},
            {"kind": "url", "pattern": r"/oidc/", "confidence": 0.8},
            {"kind": "json", "pattern": r'"id_token"\s*:', "confidence": 0.85},
        ],
    },
    {
        "mechanism": AuthMechanism.SAML,
        "fingerprints": [
            {"kind": "url", "pattern": r"/saml/sso", "confidence": 0.95},
            {"kind": "url", "pattern": r"/saml/acs", "confidence": 0.95},
            {"kind": "dom", "pattern": r"SAMLResponse", "confidence": 0.95},
        ],
    },
    {
        "mechanism": AuthMechanism.OAUTH,
        "fingerprints": [
            {"kind": "url", "pattern": r"/oauth/authorize", "confidence": 0.85},
            {"kind": "url", "pattern": r"/oauth/token", "confidence": 0.85},
        ],
    },
]


# --- Fingerprints de protecoes ---

_BOT_CHALLENGE_FINGERPRINTS = [
    {"kind": "dom", "pattern": r"cf-challenge|hcaptcha|recaptcha|hcaptcha-captcha|datadome|perimeterx|akamai", "confidence": 0.9},
    {"kind": "url", "pattern": r"/cdn-cgi/challenge", "confidence": 0.95},
    {"kind": "url", "pattern": r"/distil_r_captcha", "confidence": 0.95},
    {"kind": "cookie", "pattern": r"^cf_clearance$", "confidence": 0.4},  # Cloudflare
    {"kind": "json", "pattern": r'"cf-ray"\s*:', "confidence": 0.7},
]

_MFA_FINGERPRINTS = [
    {"kind": "url", "pattern": r"/mfa/|/2fa/|/totp/", "confidence": 0.9},
    {"kind": "dom", "pattern": r"(?:two.factor|twofactor|totp|authenticator.app|webauthn)", "confidence": 0.7},
    {"kind": "json", "pattern": r'"mfa_required"\s*:\s*true', "confidence": 0.95},
    {"kind": "json", "pattern": r'"amr"\s*:\s*\[.*"mfa"', "confidence": 0.9},
]


def _match_fingerprint(fp: Dict[str, Any], text: str) -> Tuple[bool, float]:
    """Testa se um fingerprint casa em um texto. Retorna (match, confidence)."""
    pattern = fp.get("pattern", "")
    if not pattern:
        return False, 0.0
    try:
        if re.search(pattern, text, re.IGNORECASE):
            return True, fp.get("confidence", 0.5)
    except re.error:
        pass
    return False, 0.0


def _extract_text(observation: Dict[str, Any]) -> str:
    """Extrai todo o texto pesquisavel de uma observacao."""
    parts: List[str] = []
    for key in ("url", "final_url", "body", "text", "html", "title"):
        v = observation.get(key)
        if isinstance(v, str):
            parts.append(v)
    for key in ("cookie_names", "json_bodies", "headers", "console_errors", "request_failures"):
        v = observation.get(key)
        if isinstance(v, list):
            parts.extend(str(x) for x in v)
        elif isinstance(v, str):
            parts.append(v)
    return "\n".join(parts)


def detect_idp(observation: Dict[str, Any], ctx: AuthContext) -> List[Evidence]:
    """Detecta Identity Provider a partir de uma observacao (dict com url, body, etc).

    Adiciona Evidence ao ctx e retorna a lista criada.
    """
    text = _extract_text(observation)
    if not text:
        return []

    evidences: List[Evidence] = []
    scores: Dict[IdentityProvider, float] = {}

    for entry in _IDP_FINGERPRINTS:
        idp = entry["idp"]
        for fp in entry["fingerprints"]:
            match, conf = _match_fingerprint(fp, text)
            if match:
                ev = Evidence(
                    source=fp["kind"],
                    type=f"idp_reference:{idp.value}",
                    value=fp["pattern"],
                    confidence=conf,
                    baseline_seen=bool(observation.get("baseline", False)),
                )
                evidences.append(ev)
                scores[idp] = scores.get(idp, 0) + conf

    # IdP com maior score vence.
    if scores:
        best = max(scores, key=lambda k: scores[k])
        ctx.identity_provider = best
        for ev in evidences:
            ctx.add_evidence(ev)
    return evidences


def detect_session_type(observation: Dict[str, Any], ctx: AuthContext) -> List[Evidence]:
    """Detecta SessionType (cookie-only, JWT cookie, JWT localStorage, etc)."""
    text = _extract_text(observation)
    if not text:
        return []

    evidences: List[Evidence] = []
    scores: Dict[SessionType, float] = {}

    for entry in _SESSION_FINGERPRINTS:
        st = entry["session_type"]
        for fp in entry["fingerprints"]:
            match, conf = _match_fingerprint(fp, text)
            if match:
                ev = Evidence(
                    source=fp["kind"],
                    type=f"session_type:{st.value}",
                    value=fp["pattern"],
                    confidence=conf,
                    baseline_seen=bool(observation.get("baseline", False)),
                )
                evidences.append(ev)
                scores[st] = scores.get(st, 0) + conf

    if scores:
        best = max(scores, key=lambda k: scores[k])
        ctx.session_type = best
        for ev in evidences:
            ctx.add_evidence(ev)
    return evidences


def detect_mechanism(observation: Dict[str, Any], ctx: AuthContext) -> List[Evidence]:
    """Detecta AuthMechanism (cookie_session, OIDC, SAML, OAuth)."""
    text = _extract_text(observation)
    if not text:
        return []

    evidences: List[Evidence] = []
    scores: Dict[AuthMechanism, float] = {}

    for entry in _MECHANISM_FINGERPRINTS:
        mech = entry["mechanism"]
        for fp in entry["fingerprints"]:
            match, conf = _match_fingerprint(fp, text)
            if match:
                ev = Evidence(
                    source=fp["kind"],
                    type=f"mechanism:{mech.value}",
                    value=fp["pattern"],
                    confidence=conf,
                    baseline_seen=bool(observation.get("baseline", False)),
                )
                evidences.append(ev)
                scores[mech] = scores.get(mech, 0) + conf

    if scores:
        best = max(scores, key=lambda k: scores[k])
        ctx.auth_mechanism = best
        for ev in evidences:
            ctx.add_evidence(ev)
    return evidences


def detect_protections(observation: Dict[str, Any], ctx: AuthContext) -> List[Evidence]:
    """Detecta protecoes (anti-bot, MFA challenge, session binding)."""
    text = _extract_text(observation)
    if not text:
        return []

    evidences: List[Evidence] = []

    for fp in _BOT_CHALLENGE_FINGERPRINTS:
        match, conf = _match_fingerprint(fp, text)
        if match:
            ev = Evidence(
                source=fp["kind"],
                type="bot_challenge",
                value=fp["pattern"],
                confidence=conf,
                baseline_seen=bool(observation.get("baseline", False)),
            )
            evidences.append(ev)
            ctx.bot_challenge_detected = True

    for fp in _MFA_FINGERPRINTS:
        match, conf = _match_fingerprint(fp, text)
        if match:
            ev = Evidence(
                source=fp["kind"],
                type="mfa_challenge",
                value=fp["pattern"],
                confidence=conf,
                baseline_seen=bool(observation.get("baseline", False)),
            )
            evidences.append(ev)
            ctx.mfa_challenge_detected = True

    for ev in evidences:
        ctx.add_evidence(ev)
    return evidences


def detect_all(observation: Dict[str, Any], target: str) -> AuthContext:
    """Pipeline completo: cria AuthContext, executa todos detectores, retorna."""
    ctx = AuthContext(target=target)
    detect_idp(observation, ctx)
    detect_session_type(observation, ctx)
    detect_mechanism(observation, ctx)
    detect_protections(observation, ctx)
    return ctx
