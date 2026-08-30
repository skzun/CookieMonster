"""Score de confianca/risco por artefato de sessao.

Para cada cookie enviado ao alvo, atribui uma classificacao e um score.
"""

from __future__ import annotations

from typing import Dict, List

from ..domain.selection import classify_name


def score_artifact(name: str, sent: bool, http_only: bool, secure: bool) -> Dict:
    """Classifica um cookie e devolve um score de relevancia como artefato auth.

    Score base + bonus por atributos.
    """
    kind = classify_name(name)
    base = {"auth": 10, "anon": 1, "other": 4}.get(kind, 4)

    if not http_only:
        base += 3  # acessivel via JS (maior impacto se roubado)
    if not secure:
        base += 2  # transitável em claro
    if not sent:
        base = 0  # nao foi transmitido ao alvo => irrelevante

    return {
        "name": name,
        "kind": kind,
        "auth_candidate": kind == "auth",
        "sent": sent,
        "http_only": http_only,
        "secure": secure,
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
            http_only=bool(c.get("http_only")),
            secure=bool(c.get("secure")),
        ))
    result.sort(key=lambda r: r["score"], reverse=True)
    return result

__all__ = ["score_artifact", "score_artifacts"]