"""Detector diferencial baseline x injetado.

Compara evidencias estruturadas (AuthEvidence) em vez de procurar substrings
em texto HTML cru. Resultado:
  - CONFIRMED: identity/api autenticada diferencial forte.
  - LIKELY: mudancas diferenciais moderadas (UI autenticada, etc).
  - ANONYMOUS: sinais de redirecionamento/login no injetado.
  - UNKNOWN: sem diferenca conclusiva.
"""

from __future__ import annotations

import json

from dataclasses import asdict
from typing import Dict, List

from ..inject.auth_probe import AuthEvidence
from .profiles import SiteProfile, get_profile

CONFIRMED = "CONFIRMED"
LIKELY = "LIKELY"
ANONYMOUS = "ANONYMOUS"
UNKNOWN = "UNKNOWN"


def classify(evidence: Dict) -> Dict:
    """Classifica a partir de um dict AuthEvidence (de probe)."""
    return {"state": UNKNOWN, "confidence": 0.3}


def detect_baseline_vs_injected(baseline_evidence: Dict,
                                injected_evidence: Dict,
                                profile: SiteProfile | None = None,
                                domain: str = "") -> Dict:
    """Compara AuthEvidence baseline vs injetado.

    Heurística:
      - ANONYMOUS forte: injetado tem login_redirect + identity ausente.
      - CONFIRMED forte: API autenticada no injetado (200 com id) e nao no baseline.
      - LIKELY: UI autenticada (selectors/markers) diferente entre inj e base.
      - UNKNOWN: sem diferenca conclusiva.
    """
    p = profile or get_profile(domain)

    base = baseline_evidence or {}
    inj = injected_evidence or {}

    base_api = bool(base.get("api_authenticated") or base.get("api_user_id_present"))
    inj_api = bool(inj.get("api_authenticated") or inj.get("api_user_id_present"))
    inj_login = bool(inj.get("login_redirect"))
    inj_ui = bool(inj.get("authenticated_ui"))
    base_ui = bool(base.get("authenticated_ui"))

    # Identity apareceu no injetado mas nao no baseline = CONFIRMED
    identity_diff = (
        (inj.get("api_user_id_present") and not base.get("api_user_id_present"))
        or (inj.get("api_user_name_present") and not base.get("api_user_name_present"))
        or (inj.get("api_user_email_present") and not base.get("api_user_email_present"))
    )

    if inj_login:
        state, conf = ANONYMOUS, 0.85
    elif identity_diff and not inj_login:
        state, conf = CONFIRMED, 0.9
    elif inj_api and not base_api and not inj_login:
        state, conf = CONFIRMED, 0.85
    elif inj_ui and not base_ui and not inj_login:
        state, conf = LIKELY, 0.7
    elif inj.get("ui_markers") and not base.get("ui_markers") and not inj_login:
        state, conf = LIKELY, 0.6
    else:
        state, conf = UNKNOWN, 0.3

    return {
        "state": state,
        "confidence": conf,
        "profile": p.name,
        "baseline": base,
        "injected": inj,
        "differential": _differential(base, inj),
    }


def _differential(base: Dict, inj: Dict) -> Dict:
    diff = {}
    for key in ("api_authenticated", "api_user_id_present",
                "api_user_name_present", "api_user_email_present",
                "authenticated_ui", "login_redirect"):
        if bool(inj.get(key)) != bool(base.get(key)):
            diff[key] = {"baseline": bool(base.get(key)),
                          "injected": bool(inj.get(key))}
    bl = inj.get("body_length", 0) - base.get("body_length", 0)
    if abs(bl) > 100:
        diff["body_length_delta"] = bl
    return diff


def detect_from_summary(baseline: dict, injected: dict, domain: str,
                        profile: SiteProfile | None = None) -> Dict:
    """Detector baseado em markers textuais (compatibilidade httpx).

    Usado quando nao ha AuthProbe (cliente httpx). Heuristica:
      - ANONYMOUS: redirect-login novo no injetado.
      - CONFIRMED: marker forte novo no injetado.
      - LIKELY: marker comum novo.
      - UNKNOWN: sem diferenca.
    """
    p = profile or get_profile(domain)
    b_status = baseline.get("status_code")
    i_status = injected.get("status_code")
    b_url = baseline.get("final_url") or ""
    i_url = injected.get("final_url") or ""
    b_text = baseline.get("text") or ""
    i_text = injected.get("text") or ""
    b_markers = p.authenticated_markers(b_text, b_url, b_status or 0)
    i_markers = p.authenticated_markers(i_text, i_url, i_status or 0)

    bset = set(b_markers)
    new = [m for m in i_markers if m not in bset]
    strong = set(p.strong_auth_markers)

    has_strong_anon = any(m in i_markers for m in
                         ("signin-redirect", "redirect-to-login", "unauthorized"))

    if any(m in new for m in strong) and not has_strong_anon:
        state, conf = CONFIRMED, 0.85
    elif has_strong_anon:
        state, conf = ANONYMOUS, 0.85
    elif new:
        state, conf = LIKELY, 0.6
    else:
        state, conf = UNKNOWN, 0.3

    return {
        "state": state,
        "confidence": conf,
        "profile": p.name,
        "evidence": {
            "status_baseline": b_status,
            "status_injected": i_status,
            "baseline_markers": b_markers,
            "injected_markers": i_markers,
            "new_markers": new,
        },
    }


# Compatibilidade: `detect` historico baseado em summary (httpx).
detect = detect_from_summary


def extract_evidence_state(evidence: Dict) -> str:
    """Helper para o CLI: retorna uma string compacta do estado das evidencias."""
    if not evidence:
        return ""
    parts = []
    if evidence.get("api_authenticated"):
        parts.append("api:auth")
    if evidence.get("api_user_id_present"):
        parts.append("api:user_id")
    if evidence.get("authenticated_ui"):
        parts.append("ui:auth")
    if evidence.get("login_redirect"):
        parts.append("login_redirect")
    return ", ".join(parts) if parts else "no_signals"


__all__ = ["detect_baseline_vs_injected", "detect_from_summary",
           "detect", "extract_evidence_state",
           "CONFIRMED", "LIKELY", "ANONYMOUS", "UNKNOWN"]