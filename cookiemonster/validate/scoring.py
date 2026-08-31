"""Score de confianca/risco por artefato de sessao.

Para cada cookie enviado ao alvo, atribui uma classificacao e um score.
Atributos observaveis (HttpOnly, Secure) tem tres estados possiveis:
True, False ou Unknown. Unknown NAO conta como ausencia (defensivo).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from ..domain.selection import classify_name


# Estados de atributo: 1=True, 0=False, -1=Unknown
TRIPLE_TRUE = 1
TRIPLE_FALSE = 0
TRIPLE_UNKNOWN = -1


def _norm(value) -> int:
    """Normaliza entrada para {1, 0, -1}."""
    if value is None:
        return TRIPLE_UNKNOWN
    if isinstance(value, bool):
        return TRIPLE_TRUE if value else TRIPLE_FALSE
    if isinstance(value, int):
        if value == 1:
            return TRIPLE_TRUE
        if value == 0:
            return TRIPLE_FALSE
        if value < 0:
            return TRIPLE_UNKNOWN
    return TRIPLE_UNKNOWN


def score_artifact(name: str, sent: bool,
                   http_only: int | bool | None = None,
                   secure: int | bool | None = None,
                   same_site: str = "unknown") -> Dict:
    """Classifica um cookie e devolve um score de relevancia como artefato auth.

    Atributos desconhecidos (unknown) NAO somam bonus (defensivo: tratar como
    informacao faltante, nao como ausencia).
    """
    kind = classify_name(name)
    base = {"auth": 10, "anon": 1, "other": 4}.get(kind, 4)

    ho = _norm(http_only)
    sec = _norm(secure)

    # Bonus apenas quando temos certeza do estado.
    if ho == TRIPLE_FALSE:
        base += 3  # acessivel via JS confirmado
    if sec == TRIPLE_FALSE:
        base += 2  # transitavel em claro confirmado
    # SameSite=None confirmado permite cross-site -> relevante.
    if isinstance(same_site, str) and same_site.lower() == "none":
        base += 1

    if not sent:
        base = 0  # nao foi transmitido ao alvo => irrelevante

    return {
        "name": name,
        "kind": kind,
        "auth_candidate": kind == "auth",
        "sent": sent,
        "http_only_state": ho,
        "secure_state": sec,
        "same_site": same_site,
        "score": base,
    }


def score_artifacts(cookies_sent: List[str], injected_cookies: List[Dict]) -> List[Dict]:
    """Devolve score para cada cookie injetado (usando os efetivamente enviados)."""
    sent_set = set(cookies_sent)
    result = []
    for c in injected_cookies:
        name = c.get("name", "")
        result.append(score_artifact(
            name=name,
            sent=name in sent_set,
            http_only=c.get("http_only"),
            secure=c.get("secure"),
            same_site=c.get("same_site") or "unknown",
        ))
    result.sort(key=lambda r: r["score"], reverse=True)
    return result

__all__ = ["score_artifact", "score_artifacts", "TRIPLE_TRUE", "TRIPLE_FALSE", "TRIPLE_UNKNOWN"]