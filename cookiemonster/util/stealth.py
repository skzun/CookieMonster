"""Opcoes de stealth para reduzir deteccao de bots.

Fornece rotação de User-Agent e um conjunto de opções para o browser
(headless "new", viewport, locale, timezone), alem de fingerprints leves.
"""

from __future__ import annotations

import random

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
    "Gecko/20100101 Firefox/121.0",
]


def random_user_agent() -> str:
    return random.choice(USER_AGENTS)


VIEWPORTS = [
    {"width": 1920, "height": 1080},
    {"width": 1366, "height": 768},
    {"width": 1536, "height": 864},
]

LOCALES = ["en-US", "en-GB", "pt-BR"]

TIMEZONES = ["America/Sao_Paulo", "America/New_York", "Europe/London"]


def new_context_options(extra: dict | None = None) -> dict:
    """Gera um dicionario de opcoes de contexto "stealth" para Playwright."""
    options = {
        "user_agent": random_user_agent(),
        "viewport": random.choice(VIEWPORTS),
        "locale": random.choice(LOCALES),
        "timezone_id": random.choice(TIMEZONES),
        "java_script_enabled": True,
    }
    if extra:
        options.update(extra)
    return options