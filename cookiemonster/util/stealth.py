"""Opcoes de contexto para o replay de sessao.

Modos:
- STRICT (default): preserva fingerprint do dump (UA, locale, timezone) para nao
  invalidar a sessao por bind de contexto. Se o dump nao trouxer fingerprint,
  usa BROWSER_DEFAULT.
- BROWSER_DEFAULT: navegador padrao neutro (sem randomizacao agressiva).
- RANDOMIZED: randomiza UA/viewport/locale/timezone (util para diagnostico de
  fingerprinting, NAO para validar sessoes).

Decisao P0: o replay de sessao NAO deve randomizar fingerprint por padrao, sob
risco de gerar falso SESSION_INVALID quando o servidor valida IP/UA/etc.
"""

from __future__ import annotations

import random

from typing import Optional

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

USER_AGENTS = [
    DEFAULT_USER_AGENT,
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
    "Gecko/20100101 Firefox/121.0",
]

VIEWPORTS = [
    {"width": 1920, "height": 1080},
    {"width": 1366, "height": 768},
    {"width": 1536, "height": 864},
]

LOCALES = ["en-US", "en-GB", "pt-BR"]
TIMEZONES = ["America/Sao_Paulo", "America/New_York", "Europe/London"]

MODE_STRICT = "strict"
MODE_BROWSER_DEFAULT = "browser_default"
MODE_RANDOMIZED = "randomized"

VALID_MODES = {MODE_STRICT, MODE_BROWSER_DEFAULT, MODE_RANDOMIZED}


def random_user_agent() -> str:
    return random.choice(USER_AGENTS)


def context_options(mode: str = MODE_STRICT,
                    dump_hint: Optional[dict] = None,
                    extra: Optional[dict] = None) -> dict:
    """Gera opcoes de contexto Playwright para o modo escolhido.

    dump_hint (opcional): dict com chaves 'user_agent', 'locale', 'timezone'
    extraidas do navegador de origem (ex.: via dump JSON). Em modo STRICT, usa
    esses valores; se ausentes, cai para BROWSER_DEFAULT.
    """
    if mode not in VALID_MODES:
        raise ValueError(f"modo invalido: {mode}")

    if mode == MODE_STRICT and dump_hint:
        opts = {
            "user_agent": dump_hint.get("user_agent") or DEFAULT_USER_AGENT,
            "viewport": dump_hint.get("viewport") or VIEWPORTS[0],
            "locale": dump_hint.get("locale") or "en-US",
            "timezone_id": dump_hint.get("timezone") or "America/Sao_Paulo",
            "java_script_enabled": True,
        }
    elif mode == MODE_RANDOMIZED:
        opts = {
            "user_agent": random_user_agent(),
            "viewport": random.choice(VIEWPORTS),
            "locale": random.choice(LOCALES),
            "timezone_id": random.choice(TIMEZONES),
            "java_script_enabled": True,
        }
    else:
        # BROWSER_DEFAULT (tambem usado no fallback do STRICT sem hint).
        opts = {
            "user_agent": DEFAULT_USER_AGENT,
            "viewport": VIEWPORTS[0],
            "locale": "en-US",
            "timezone_id": "America/Sao_Paulo",
            "java_script_enabled": True,
        }

    if extra:
        opts.update(extra)
    return opts