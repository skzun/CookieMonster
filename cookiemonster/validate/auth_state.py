"""Deteccao de estado autenticado por comparacao baseline x injetado.

Resultados:
  CONFIRMED  - forte evidencia de replay autenticado.
  LIKELY     - evidencia consistente, mas nao conclusiva.
  ANONYMOUS  - servidor tratou a requisicao como nao-autenticada.
  UNKNOWN    - evidencia insuficiente (CAPTCHA, bot check, inconsistencias).

Evidencia estruturada:
  - baseline_markers / injected_markers
  - redirect_chain (injetado)
  - status_code (baseline / injetado)
  - identity (nome/email/id extraido, quando disponivel)
  - session_binding_indicators (fingerprint, redirects anomалos, etc.)
"""

from __future__ import annotations

import re

from typing import Dict, List, Optional

from .profiles import SiteProfile, get_profile

CONFIRMED = "CONFIRMED"
LIKELY = "LIKELY"
ANONYMOUS = "ANONYMOUS"
UNKNOWN = "UNKNOWN"


# Identidade: sinais fracos que podem sugerir nome/account id/account_email.
# Patterns mais flexiveis (suportam "key":"value" e "key":"..." com escapes).
_IDENTITY_PATTERNS = [
    (re.compile(r'"displayName"\s*:\s*"([^"\\]+)"'), "displayname"),
    (re.compile(r'"accountName"\s*:\s*"([^"\\]+)"'), "accountname"),
    (re.compile(r'"account_name"\s*:\s*"([^"\\]+)"'), "accountname"),
    (re.compile(r'"accountId"\s*:\s*"([^"\\]+)"'), "account_id"),
    (re.compile(r'"account_id"\s*:\s*"([^"\\]+)"'), "account_id"),
    (re.compile(r'"userId"\s*:\s*"([^"\\]+)"'), "user_id"),
    (re.compile(r'"user_id"\s*:\s*"([^"\\]+)"'), "user_id"),
    (re.compile(r'"username"\s*:\s*"([^"\\]+)"'), "username"),
    (re.compile(r'"login"\s*:\s*"([^"\\]+)"'), "login"),
    (re.compile(r'"name"\s*:\s*"([^"\\]+)"'), "name"),
    (re.compile(r'"email"\s*:\s*"([^"\\]+)"'), "email"),
]


def extract_identity(text: str) -> Dict[str, str]:
    """Extrai possiveis sinais de identidade (heuristica simples).

    Suporta varios nomes de chave comuns em JSON embutido. Aceita pares
    chave:valor entre aspas.
    """
    found: Dict[str, str] = {}
    if not text:
        return found
    for pattern, key in _IDENTITY_PATTERNS:
        m = pattern.search(text)
        if m:
            value = m.group(1).strip()
            if 2 <= len(value) <= 64:
                # Chave preferida (displayname -> name).
                key_norm = {"displayname": "name"}.get(key, key)
                found.setdefault(key_norm, value)
    return found


def detect(baseline: dict, injected: dict, domain: str,
           profile: SiteProfile | None = None) -> Dict:
    """
    Determina o estado da sessao a partir do baseline e injetado.

    Retorna:
      {state, confidence, profile, evidence: {baseline_markers, injected_markers,
       redirect_chain, status_baseline, status_injected, identity_baseline,
       identity_injected, session_binding_indicators}}
    """
    profile = profile or get_profile(domain)

    b_status = baseline.get("status_code")
    i_status = injected.get("status_code")
    b_url = baseline.get("final_url") or ""
    i_url = injected.get("final_url") or ""
    b_text = baseline.get("text") or ""
    i_text = injected.get("text") or ""

    b_markers = profile.authenticated_markers(b_text, b_url, b_status or 0)
    i_markers = profile.authenticated_markers(i_text, i_url, i_status or 0)
    b_identity = extract_identity(b_text)
    i_identity = extract_identity(i_text)

    evidence = {
        "status_baseline": b_status,
        "status_injected": i_status,
        "baseline_markers": b_markers,
        "injected_markers": i_markers,
        "baseline_url": b_url,
        "injected_url": i_url,
        "identity_baseline": b_identity,
        "identity_injected": i_identity,
        "redirect_chain": injected.get("redirect_chain", []),
        "cookie_jar": injected.get("cookie_jar", []),
    }

    state, confidence = _classify(
        baseline=baseline, injected=injected,
        b_markers=b_markers, i_markers=i_markers,
        b_identity=b_identity, i_identity=i_identity,
        strong_markers=profile.strong_auth_markers(),
    )
    evidence["session_binding_indicators"] = _binding_indicators(baseline, injected)

    return {
        "state": state,
        "confidence": confidence,
        "profile": profile.name,
        "evidence": evidence,
    }


def _binding_indicators(baseline: dict, injected: dict) -> Dict:
    """Sinaliza divergencias de fingerprint entre baseline e injetado."""
    return {
        "baseline_url": baseline.get("final_url"),
        "injected_url": injected.get("final_url"),
        "final_url_matches_baseline": (
            baseline.get("final_url") == injected.get("final_url")
        ),
    }


def _coverage(injected_markers: List[str], baseline_markers: List[str]) -> List[str]:
    bset = set(baseline_markers)
    return [m for m in injected_markers if m not in bset]


def _classify(baseline: dict, injected: dict,
              b_markers: List[str], i_markers: List[str],
              b_identity: Dict[str, str], i_identity: Dict[str, str],
              strong_markers: List[str]) -> tuple:
    strong = set(strong_markers)

    new_markers = _coverage(i_markers, b_markers)
    new_identity_keys = set(i_identity) - set(b_identity)

    i_url = injected.get("final_url") or ""
    b_url = baseline.get("final_url") or ""

    # ANONYMOUS: redirect explicito para /login/signin OU strong anon.
    has_strong_anon = any(m in i_markers for m in ("signin-redirect", "redirect-to-login", "unauthorized"))

    # CONFIRMED: strong positive (especifico do site) + redirect_chain NAO termina em login.
    if any(m in new_markers for m in strong) and not has_strong_anon:
        return CONFIRMED, 0.9

    # CONFIRMED tambem: identidade NOVA no injetado (nao presente no baseline)
    # e nenhum sinal anonimo. Identity implica sessao.
    if new_identity_keys and not has_strong_anon and i_url != b_url:
        return CONFIRMED, 0.8
    if new_identity_keys and not has_strong_anon:
        return LIKELY, 0.7

    # LIKELY: marcadores novos que nao sao fortes (podem aparecer publicos).
    if new_markers and not has_strong_anon:
        return LIKELY, 0.6

    # ANONYMOUS: sinais fortes negativos.
    if has_strong_anon:
        return ANONYMOUS, 0.8

    # Sem marcadores novos.
    return UNKNOWN, 0.3

__all__ = ["detect", "CONFIRMED", "LIKELY", "ANONYMOUS", "UNKNOWN", "extract_identity"]