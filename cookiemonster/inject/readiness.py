"""Readiness condicional (sem sleep fixo).

Combina sinais de DOM (selectors do profile), responses (endpoints
identitarios) e heuristicas de navegacao. Conclui o mais cedo possivel.
"""

from __future__ import annotations

import time

from typing import Dict, List, Optional

from playwright.sync_api import Page, Response, TimeoutError as PWTimeout

from .evidence import PageEvents


# Seletores genéricos que tipicamente so aparecem para usuarios autenticados em
# muitos sites. NAO confundir com AUTHENTICATED (sera checado depois).
_APP_READY_SELECTORS = [
    "header nav",
    "footer",
    '[data-testid="app-root"]',
    '[id="app"]',
    '[id="root"]',
    "main",
]


def _try_selector(page: Page, selector: str, timeout_ms: int) -> bool:
    try:
        page.locator(selector).first.wait_for(state="visible", timeout=timeout_ms)
        return True
    except PWTimeout:
        return False
    except Exception:
        return False


def _auth_endpoint_seen(events: PageEvents, hints: tuple) -> bool:
    for entry in events.responses:
        url_l = entry["url"].lower()
        if any(h in url_l for h in hints):
            return True
    return False


def wait_for_app_ready(
    page: Page,
    events: Optional[PageEvents] = None,
    auth_endpoint_hints: tuple = (),
    max_wait_ms: int = 8000,
) -> Dict:
    """Aguarda a aplicacao indicar readiness via DOM e/ou network.

    Retorna dict com 'ready', 'reason', 'elapsed_ms', 'observed_selectors'.
    """
    start = time.monotonic()
    deadline = start + max_wait_ms / 1000.0
    observed: List[str] = []

    # Nível 1: navegacao + DOM ready
    while time.monotonic() < deadline:
        for sel in _APP_READY_SELECTORS:
            per = min(800, int((deadline - time.monotonic()) * 1000))
            if per <= 0:
                break
            if _try_selector(page, sel, per):
                observed.append(f"dom:{sel}")
                elapsed = int((time.monotonic() - start) * 1000)
                return {
                    "ready": True,
                    "reason": "dom",
                    "elapsed_ms": elapsed,
                    "observed": observed,
                }

        # Nível 2: endpoint de identidade respondeu.
        if events and auth_endpoint_hints:
            if _auth_endpoint_seen(events, auth_endpoint_hints):
                elapsed = int((time.monotonic() - start) * 1000)
                return {
                    "ready": True,
                    "reason": "auth_endpoint_seen",
                    "elapsed_ms": elapsed,
                    "observed": observed + ["endpoint"],
                }

        # Espera curta antes de re-checar.
        time.sleep(0.1)

    elapsed = int((time.monotonic() - start) * 1000)
    return {
        "ready": False,
        "reason": "timeout",
        "elapsed_ms": elapsed,
        "observed": observed,
    }


def wait_for_response_matching(page: Page, predicate, timeout_ms: int = 8000) -> Optional[Response]:
    """Aguarda uma response que satisfaça o predicate. Retorna a Response ou None."""
    try:
        with page.expect_response(predicate, timeout=timeout_ms) as info:
            pass
        return info.value
    except Exception:
        return None