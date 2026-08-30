"""Deteccao de estado autenticado por comparacao baseline x injetado.

O resultado e um dos tres estados: SESSION_VALID, SESSION_INVALID ou UNKNOWN,
acompanhado de evidencias (markers, status, redirects, cookies enviados).
"""

from __future__ import annotations

from typing import Dict, List

from .profiles import SiteProfile, get_profile

VALID = "SESSION_VALID"
INVALID = "SESSION_INVALID"
UNKNOWN = "UNKNOWN"


def detect(baseline: dict, injected: dict, domain: str,
           profile: SiteProfile | None = None) -> Dict:
    """
    Determina o estado da sessao.

    baseline: resumo do replay SEM cookies.
    injected: resumo do replay COM cookies (da vítima).

    Retorna dict com estado, confianca, evidências e sinais.
    """
    profile = profile or get_profile(domain)

    b_status = baseline.get("status_code")
    b_url = baseline.get("final_url") or ""
    b_text = baseline.get("text") or ""
    b_markers = profile.authenticated_markers(b_text, b_url, b_status or 0)

    i_status = injected.get("status_code")
    i_url = injected.get("final_url") or ""
    i_text = injected.get("text") or ""
    i_markers = profile.authenticated_markers(i_text, i_url, i_status or 0)

    evidence = {
        "baseline_status": b_status,
        "injected_status": i_status,
        "baseline_markers": b_markers,
        "injected_markers": i_markers,
        "baseline_url": b_url,
        "injected_url": i_url,
        "cookies_sent": injected.get("sent_cookies", []),
    }

    cov = _coverage(i_markers, b_markers)
    state, confidence = _classify(b_markers, i_markers, b_status, i_status,
                                  profile.strong_auth_markers())

    return {
        "state": state,
        "confidence": confidence,
        "profile": profile.name,
        "evidence": evidence,
    }


def _coverage(injected_markers: List[str], baseline_markers: List[str]) -> List[str]:
    """Markers presentes no injetado mas ausentes no baseline (sinal de sessao)."""
    bset = set(baseline_markers)
    return [m for m in injected_markers if m not in bset]


def _classify(b_markers: List[str], i_markers: List[str],
              b_status, i_status, strong_markers: List[str]) -> tuple:
    """Heurística central de classificacao."""
    strong = set(strong_markers)

    new_signals = _coverage(i_markers, b_markers)

    # Sinais fortes de sessao ativa apenas no injetado.
    strong_positive = [m for m in new_signals if m in strong]
    strong_negative = [m for m in i_markers if m in _STRONG_ANON]

    if strong_positive:
        return VALID, 0.9

    # Redirecionamento para login / nao-autorizado => sessao invalida.
    if strong_negative:
        return INVALID, 0.8

    # Qualquer sinal distintivo novo (menos forte) tende a indicar sessao ativa.
    if new_signals:
        return VALID, 0.6

    # Nenhum sinal distinctivo -> indeterminado (conversar conservador).
    return UNKNOWN, 0.3


# Markers que indicam sessao autenticada (genericos, lowercase).
_STRONG_ANON = {
    "redirect-to-login", "unauthorized",
}

__all__ = ["detect", "VALID", "INVALID", "UNKNOWN"]