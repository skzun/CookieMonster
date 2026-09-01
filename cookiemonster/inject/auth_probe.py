"""AuthProbe: extracao estruturada de evidencias de autenticacao.

Combina sinais de:
  - DOM (selectors definidos no profile)
  - Network (responses JSON de endpoints de identidade)
  - Navigation (redirects para /login)

Saida: lista de evidencias com confidence; o detector diferencial usa isso
para comparar baseline vs injetado.
"""

from __future__ import annotations

import json

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional

from playwright.sync_api import Page

from .evidence import PageEvents, parse_json_body


@dataclass
class AuthEvidence:
    api_authenticated: bool = False
    api_user_id_present: bool = False
    api_user_name_present: bool = False
    api_user_email_present: bool = False
    api_authenticated_status: Optional[int] = None
    api_anon_status: Optional[int] = None
    identity_present: bool = False
    authenticated_ui: bool = False
    authenticated_selectors: list = field(default_factory=list)
    api_responses_inspected: list = field(default_factory=list)
    login_redirect: bool = False
    navigation_chain: list = field(default_factory=list)
    ui_markers: list = field(default_factory=list)
    body_length: int = 0
    page_title: str = ""
    local_storage_keys: list = field(default_factory=list)
    session_storage_keys: list = field(default_factory=list)
    console_errors: list = field(default_factory=list)
    request_failures: list = field(default_factory=list)
    # Identity provider detectado em JSON de auth (ex.: "google-oauth2", "github",
    # "auth0", "okta"). Indica que o login foi feito via terceiro, o que pode
    # causar o cenario "api_only" (API reconhece mas UI exige re-autenticacao
    # porque o IdP tem checagem extra de IP/device/fingerprint).
    identity_provider: Optional[str] = None
    # Quando True: o JSON de auth contem `user.id` mas o servidor pode ter
    # bloqueado a renovacao do cookie de UI. Util para o classificador.
    session_token_expiry_hint: Optional[str] = None

    def confidence_components(self) -> Dict[str, float]:
        return {
            "api_authenticated": 0.95 if self.api_authenticated else 0.0,
            "api_user_id": 0.95 if self.api_user_id_present else 0.0,
            "api_user_name": 0.85 if self.api_user_name_present else 0.0,
            "api_user_email": 0.90 if self.api_user_email_present else 0.0,
            "identity_present": 0.7 if self.identity_present else 0.0,
            "authenticated_ui": 0.85 if self.authenticated_ui else 0.0,
            "login_redirect_negative": -0.7 if self.login_redirect else 0.0,
        }

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Paths típicos de identidade (case-insensitive).
DEFAULT_AUTH_ENDPOINTS = (
    "/api/me",
    "/api/user",
    "/api/profile",
    "/api/account",
    "/userinfo",
    "/me",
    "/session",
    "/viewer",
    "/current-user",
    "/v1/me",
    "/v2/me",
    "/v1/user",
    "/whoami",
    "/account/me",
)

# Chaves tipicas de identidade em JSON.
_IDENTITY_KEYS = {
    "id": "api_user_id_present",
    "user_id": "api_user_id_present",
    "userId": "api_user_id_present",
    "uuid": "api_user_id_present",
    "name": "api_user_name_present",
    "displayName": "api_user_name_present",
    "display_name": "api_user_name_present",
    "username": "api_user_name_present",
    "email": "api_user_email_present",
}

# Marcadores JSON booleanos que confirmam autenticacao.
_AUTH_BOOLEAN_KEYS = ("authenticated", "logged_in", "isLoggedIn",
                      "is_authenticated", "signed_in")

# Chaves que indicam o Identity Provider (terceiro que autenticou o user).
_IDP_KEYS = ("idp", "provider", "providerId", "federatedProvider",
             "signInProvider", "authProvider", "iss")
# Chaves que guardam o JWT de acesso. Util para entender por que a API
# reconhece a sessao mesmo se a UI pedir re-login.
_TOKEN_KEYS = ("accessToken", "access_token", "idToken", "id_token")
# Chaves que guardam a data de expiracao da sessao.
_EXPIRY_KEYS = ("expires", "expiresAt", "exp", "expiry", "expires_at")


def _extract_json_identity(data: Any, ev: AuthEvidence, depth: int = 0) -> None:
    """Varre recursivamente o JSON procurando chaves de identidade."""
    if depth > 6:
        return
    if isinstance(data, dict):
        for key, val in data.items():
            kl = key.lower()
            if kl in _IDENTITY_KEYS and val not in (None, "", 0, "0"):
                attr = _IDENTITY_KEYS[key]
                setattr(ev, attr, True)
            if kl in (k.lower() for k in _AUTH_BOOLEAN_KEYS) and val is True:
                ev.api_authenticated = True
            # Detecta IdP (primeiro nivel + no objeto user).
            if kl in [k.lower() for k in _IDP_KEYS] and isinstance(val, str):
                if ev.identity_provider is None:
                    ev.identity_provider = val
            # Detecta tokens (sinaliza que a sessao API estao OK).
            if kl in [k.lower() for k in _TOKEN_KEYS] and isinstance(val, str) and len(val) > 20:
                ev.api_authenticated = True
            # Detecta expiry.
            if kl in [k.lower() for k in _EXPIRY_KEYS] and val is not None:
                if ev.session_token_expiry_hint is None:
                    ev.session_token_expiry_hint = str(val)
            _extract_json_identity(val, ev, depth + 1)
    elif isinstance(data, list):
        for item in data:
            _extract_json_identity(item, ev, depth + 1)


def collect_auth_responses_body(page: Page, events: PageEvents,
                                auth_endpoints: tuple = DEFAULT_AUTH_ENDPOINTS) -> list:
    """Carrega os bodies dos endpoints de identidade."""
    out = []
    for entry in events.responses:
        url_l = entry["url"].lower()
        if any(h in url_l for h in auth_endpoints):
            # match na response pelo objeto do playwright
            for resp in page.context.background_pages + []:
                pass  # no-op
            # Buscar response via URL match (events tem somente metadados; usamos
            # o hook `response` para cachear o body, mas aqui simplificamos
            # usando response.request.url).
            # Como events ja armazena metadados, mantemos apenas o meta
            # (body sera carregado sob demanda no probe). Aqui retornamos meta.
            out.append(entry)
    return out


def probe(page: Page, events: PageEvents,
          auth_endpoints: tuple = DEFAULT_AUTH_ENDPOINTS,
          authenticated_selectors: tuple = (),
          anon_selectors: tuple = (),
          body_selectors: tuple = ()) -> AuthEvidence:
    """Coleta evidencias estruturadas em uma pagina ja carregada."""
    ev = AuthEvidence()

    # 1) Network: bodies de endpoints de identidade.
    auth_responses = []
    for entry in events.responses:
        url_l = entry["url"].lower()
        if any(h in url_l for h in auth_endpoints):
            auth_responses.append(entry)
    ev.api_responses_inspected = [
        {"url": r["url"], "status": r["status"], "content_type": r["content_type"]}
        for r in auth_responses
    ]

    # Parseia os bodies JSON coletados pelo PageEvents (ate 256KB cada).
    # Quando a response 200 traz JSON com chaves de identidade, setamos os
    # campos apropriados (api_user_id_present, api_authenticated, etc.).
    for entry in auth_responses:
        json_data = entry.get("json")
        status = entry.get("status")
        if status == 200 and isinstance(json_data, (dict, list)):
            _extract_json_identity(json_data, ev)
        # 401/403 sem payload = forte sinal anonimo
        elif status in (401, 403):
            ev.api_anon_status = status

    # 2) UI: selectors de autenticado/anonimo (se disponiveis no profile).
    for sel in authenticated_selectors:
        try:
            if page.locator(sel).first.count() > 0:
                ev.authenticated_selectors.append(sel)
        except Exception:
            pass

    # 3) DOM: tentar extrair JSON embutido (<script type="application/json">).
    try:
        for el in page.locator("script[type='application/json'], script#__NEXT_DATA__, script[data-test='initial-state']").all():
            try:
                raw = el.inner_text()
                data = json.loads(raw)
                _extract_json_identity(data, ev)
            except Exception:
                continue
    except Exception:
        pass

    # 4) Console / errors / falhas de request.
    ev.console_errors = [e for e in events.errors[:10]]
    ev.request_failures = events.failed[:10]

    # 5) Navigation: redirect para login.
    for entry in events.responses:
        url_l = entry["url"].lower()
        if entry["status"] in (301, 302, 303, 307, 308):
            ev.navigation_chain.append({
                "url": entry["url"], "status": entry["status"],
            })
            if "/login" in url_l or "/signin" in url_l:
                ev.login_redirect = True

    # 6) Local storage / session storage keys (apenas os nomes).
    try:
        ev.local_storage_keys = list(page.evaluate(
            "() => Object.keys(localStorage)"))[:30]
    except Exception:
        pass
    try:
        ev.session_storage_keys = list(page.evaluate(
            "() => Object.keys(sessionStorage)"))[:30]
    except Exception:
        pass

    # 7) body length / title / markers simples.
    try:
        body_text = page.inner_text("body")
        ev.body_length = len(body_text)
        ev.page_title = page.title()
        body_lower = body_text.lower()
        for marker in ("logout", "sign out", "sign-out", "my account",
                      "minha conta", "dashboard", "profile"):
            if marker in body_lower:
                ev.ui_markers.append(marker)
    except Exception:
        pass

    ev.authenticated_ui = bool(ev.authenticated_selectors) or bool(ev.ui_markers)

    return ev