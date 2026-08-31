"""Cliente de replay com browser real (Playwright).

Canal canonico de validacao: executa JS, negocia TLS real e permite screenshot.
Injeta os cookies via `context.add_cookies` e visita o alvo.
"""

from __future__ import annotations

import json

from pathlib import Path
from typing import List, Optional

from playwright.sync_api import sync_playwright

from ..util.stealth import (
    DEFAULT_USER_AGENT, MODE_STRICT, VALID_MODES, context_options,
)

_SAMESITE_MAP = {
    "strict": "Strict",
    "lax": "Lax",
    "none": "None",
}


def _coerce_http_only(value) -> Optional[bool]:
    """Tri-state: 1/True -> True; 0/False -> False; -1/None -> manter como esta."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if value == 1:
            return True
        if value == 0:
            return False
    return None  # unknown


def _same_site_for_playwright(value: str) -> Optional[str]:
    """Mapeia o sameSite preservado para a forma aceita por Playwright."""
    if not value:
        return None
    v = value.lower()
    return _SAMESITE_MAP.get(v)


def _to_playwright_cookies(cookies: List[dict]):
    """Converte cookies do store para o formato aceito por Playwright.

    Preserva sameSite original (NUNCA inferir de Secure).
    Preserva httpOnly conforme observado; se unknown, omite (Playwright default).
    """
    out = []
    for c in cookies:
        domain = (c.get("domain") or "").lstrip(".")
        pc = {
            "name": c["name"],
            "value": c["value"],
            "domain": domain,
            "path": c.get("path") or "/",
            "secure": bool(c.get("secure")),
        }
        # httpOnly tri-state: aplica somente quando temos certeza.
        ho = _coerce_http_only(c.get("http_only"))
        if ho is not None:
            pc["httpOnly"] = ho

        # sameSite preservado do dump; se "unknown" ou None, omite.
        ss = _same_site_for_playwright(c.get("same_site") or "")
        if ss is not None:
            pc["sameSite"] = ss

        expires = c.get("expires_epoch") or 0
        if expires > 0:
            pc["expires"] = expires

        out.append(pc)
    return out


def replay(url: str, cookies: List[dict], screenshot_path: Optional[Path] = None,
           wait_ms: int = 1500, headless: bool = True,
           extra_headers: Optional[dict] = None,
           mode: str = MODE_STRICT,
           dump_hint: Optional[dict] = None) -> dict:
    """
    Abre `url` com os cookies injetados e retorna um resumo.

    `mode`: STRICT (preserva fingerprint), BROWSER_DEFAULT ou RANDOMIZED.
    `dump_hint`: dict opcional com fingerprint conhecida (UA, viewport, locale).
    """
    if mode not in VALID_MODES:
        mode = MODE_STRICT

    scheme = "http" if url.startswith("http://") else "https"
    host = url.split("://")[-1].split("/")[0].split(":")[0]
    pw_cookies = _to_playwright_cookies(cookies)

    result = {
        "status_code": None,
        "final_url": None,
        "title": None,
        "text": "",
        "sent_cookies": [],
        "cookie_jar": [],
        "redirect_chain": [],
        "screenshot": None,
        "error": None,
    }

    with sync_playwright() as p:
        args = ["--headless=new"] if headless else []
        browser = p.chromium.launch(headless=headless, args=args)
        ctx_opts = context_options(mode=mode, dump_hint=dump_hint)
        if extra_headers and "User-Agent" in extra_headers:
            ctx_opts["user_agent"] = extra_headers["User-Agent"]
        context = browser.new_context(**ctx_opts)
        try:
            for c in pw_cookies:
                try:
                    context.add_cookies([c])
                except Exception:
                    pass

            sent_cookies = []
            page = context.new_page()

            chain: list = []
            page.on("response", lambda resp: chain.append({
                "url": resp.url, "status": resp.status,
            }))

            response = page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_timeout(wait_ms)

            result["status_code"] = response.status if response else None
            result["final_url"] = page.url
            result["title"] = page.title()
            try:
                result["text"] = page.inner_text("body")
            except Exception:
                result["text"] = ""
            result["sent_cookies"] = sent_cookies
            result["redirect_chain"] = chain

            jar = context.cookies(target_host_url(url))
            result["cookie_jar"] = [c["name"] for c in jar]

            if screenshot_path:
                page.screenshot(path=str(screenshot_path), full_page=False)
                result["screenshot"] = str(screenshot_path)
        except Exception as exc:
            result["error"] = str(exc)
        finally:
            browser.close()

    return result


def _capture_request(request, host: str, into: list):
    url_host = (request.url.split("://")[-1].split("/")[0].split(":")[0])
    if url_host == host or url_host.endswith("." + host):
        into.append({"url": request.url, "headers": dict(request.headers)})


def target_host_url(url: str) -> str:
    """Retorna a URL base (scheme://host) de uma URL."""
    scheme = "https" if url.startswith("https://") else "http"
    host = url.split("://")[-1].split("/")[0]
    return f"{scheme}://{host}"


__all__ = ["replay", "DEFAULT_USER_AGENT"]