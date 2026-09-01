"""auth: deteccao e classificacao de contexto de autenticacao (M6.0).

Modulos:
- context: dataclasses canonicos (AuthContext, Evidence, enums).
- detector: identifica IdP/OAuth/OIDC via fingerprints passiveis.
- classification: classifica AuthContext em 7 estados estendidos.

M6.0 introduz a cadeia:
  Initial page -> IdP references -> API probes -> Browser state -> Classification

Substitui o UNKNOWN generico por inteligencia estruturada
(INCONCLUSIVE com reason, hints, dependencies).
"""

from .context import (
    AuthContext,
    AuthMechanism,
    IdentityProvider,
    SessionType,
    AuthClassification,
    Evidence,
)
from .detector import (
    detect_all,
    detect_idp,
    detect_session_type,
    detect_mechanism,
    detect_protections,
)
from .classification import classify, classify_legacy

__all__ = [
    "AuthContext",
    "AuthMechanism",
    "IdentityProvider",
    "SessionType",
    "AuthClassification",
    "Evidence",
    "detect_all",
    "detect_idp",
    "detect_session_type",
    "detect_mechanism",
    "detect_protections",
    "classify",
    "classify_legacy",
]
