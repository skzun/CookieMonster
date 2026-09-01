"""AuthContext: dataclass canonico que descreve o contexto de autenticacao
observado apos um replay.

Este modulo faz parte do M6.0 (Replay Adversarial Framework).
Substitui a saida binaria UNKNOWN por inteligencia estruturada:
em vez de dizer "nao sei", descreve O QUE foi observado e POR QUE
o replay nao reproduziu a sessao.

Conceitos:
- AuthMechanism: COMO a aplicacao autentica (cookie, OIDC, SAML, etc).
- IdentityProvider: QUEM forneceu a identidade (Google, Microsoft, etc).
- SessionType: COMO a sessao e mantida (cookie-only, JWT, OAuth token).
- Evidence: cada observacao individual (fingerprint, network, JSON, DOM).
- Classification: estado final inferido da cadeia de evidencias.

Nao implementa bypass. Apenas detecta e classifica.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


# --- Enums canonicos ---

class AuthMechanism(str, Enum):
    """Como a aplicacao autentica o usuario."""
    COOKIE_SESSION = "cookie_session"      # Cookie de sessao tradicional
    OAUTH = "oauth"                        # OAuth 2.0 Authorization Code
    OIDC = "oidc"                          # OpenID Connect (camada sobre OAuth2)
    SAML = "saml"                          # SAML 2.0 SSO
    JWT_BEARER = "jwt_bearer"              # JWT em header Authorization
    API_KEY = "api_key"                    # API key estatica
    UNKNOWN = "unknown"


class IdentityProvider(str, Enum):
    """Quem forneceu a identidade."""
    NONE = "none"
    GOOGLE = "google"                      # Google Sign-In, google-oauth2
    MICROSOFT = "microsoft"                # Microsoft Entra ID (Azure AD)
    GITHUB = "github"                      # GitHub OAuth
    FACEBOOK = "facebook"                  # Facebook Login
    APPLE = "apple"                        # Sign in with Apple
    AUTH0 = "auth0"                        # Auth0 Universal Login
    OKTA = "okta"                          # Okta SSO
    AWS_COGNITO = "aws_cognito"            # AWS Cognito
    CUSTOM = "custom"                      # IdP proprio (nao identificado)
    UNKNOWN = "unknown"


class SessionType(str, Enum):
    """Como a sessao e mantida apos autenticacao."""
    SERVER_SIDE_COOKIE = "server_side_cookie"  # Cookie HttpOnly + session id no backend
    JWT_COOKIE = "jwt_cookie"                  # Cookie com JWT assinado
    JWT_LOCAL_STORAGE = "jwt_local_storage"    # JWT no localStorage (vuln classico)
    JWT_MEMORY = "jwt_memory"                  # JWT em memoria (variavel JS)
    OPAQUE_TOKEN = "opaque_token"              # Token opaco (server resolve)
    UNKNOWN = "unknown"


class AuthClassification(str, Enum):
    """Estado final do replay (substitui CONFIRMED/LIKELY/ANONYMOUS/UNKNOWN)."""
    AUTHENTICATED = "authenticated"         # Sessao reproduzida com sucesso
    CONTEXT_BOUND = "context_bound"         # Sessao requer contexto adicional (IP, device, fingerprint)
    IDP_BOUND = "idp_bound"                # Sessao requer validacao no IdP externo
    MFA_BLOCKED = "mfa_blocked"            # IdP exige MFA; cookie sozinho nao basta
    BOT_BLOCKED = "bot_blocked"            # Anti-bot challenge bloqueou replay
    ANONYMOUS = "anonymous"                 # Servidor rejeitou explicitamente
    INCONCLUSIVE = "inconclusive"           # Evidencia insuficiente (substitui UNKNOWN generico)


# --- Evidence (unidade atomica de observacao) ---

@dataclass
class Evidence:
    """Uma observacao individual que alimenta a classificacao.

    source: onde foi coletado (dom, network, json, console, etc).
    type: tipo do sinal (login_redirect, api_user_id, idp_reference, etc).
    value: o que foi observado (string, lista, ou dict).
    confidence: confianca do sinal (0.0 a 1.0).
    baseline_seen: True se o sinal tambem apareceu no baseline (sem cookies).
    """
    source: str                             # "dom" | "network" | "json" | "cookie" | "console"
    type: str                               # livre: "login_redirect", "idp_reference", etc
    value: Any = None
    confidence: float = 1.0
    baseline_seen: bool = False
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Evidence":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# --- AuthContext (resultado consolidado) ---

@dataclass
class AuthContext:
    """Contexto canonico de autenticacao observado apos replay.

    Substitui o antigo dict {'state': ..., 'confidence': ...} por uma
    estrutura com semantica explicita: COMO a app autentica, COM QUE IdP,
    MANTEVE a sessao COMO, e QUE EVIDENCIAS sustentam a classificacao.
    """
    target: str                             # dominio/URL alvo
    auth_mechanism: AuthMechanism = AuthMechanism.UNKNOWN
    identity_provider: IdentityProvider = IdentityProvider.NONE
    session_type: SessionType = SessionType.UNKNOWN

    classification: AuthClassification = AuthClassification.INCONCLUSIVE
    confidence: float = 0.0
    reason: str = ""                        # razao principal da classificacao

    evidence: List[Evidence] = field(default_factory=list)
    hints: List[str] = field(default_factory=list)  # marcadores secundarios

    # Metadados opcionais
    identity_observed: Optional[Dict[str, Any]] = None  # ex.: {"email": "...", "id": "..."}
    bot_challenge_detected: bool = False
    mfa_challenge_detected: bool = False
    context_dependencies: List[str] = field(default_factory=list)  # ["ip", "device", "fingerprint"]

    def add_evidence(self, ev: Evidence) -> None:
        self.evidence.append(ev)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AuthContext":
        # Re-hidrata enums e Evidence
        d = dict(d)
        if "auth_mechanism" in d:
            d["auth_mechanism"] = AuthMechanism(d["auth_mechanism"])
        if "identity_provider" in d:
            d["identity_provider"] = IdentityProvider(d["identity_provider"])
        if "session_type" in d:
            d["session_type"] = SessionType(d["session_type"])
        if "classification" in d:
            d["classification"] = AuthClassification(d["classification"])
        if "evidence" in d:
            d["evidence"] = [Evidence.from_dict(e) if isinstance(e, dict) else e
                             for e in d["evidence"]]
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    def summary(self) -> str:
        """Linha curta para logs e relatorios."""
        return (f"[{self.classification.value}] "
                f"mech={self.auth_mechanism.value} "
                f"idp={self.identity_provider.value} "
                f"session={self.session_type.value} "
                f"conf={self.confidence:.2f} "
                f"reason={self.reason or '-'}")
