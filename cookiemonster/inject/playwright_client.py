"""Cliente de replay com browser real (Playwright).

Canal canonico de validacao:
  1. Cria contexto com fingerprint preservada (STRICT).
  2. Anexa PageEvents (request/response/console/error).
  3. goto + wait_for_app_ready (condicional, nao sleep fixo).
  4. probe() extrai evidencias estruturadas (DOM/network/navigation).
  5. Snapshot final + screenshot.

Retorna dict com status_code, final_url, title, redirect_chain, sent_cookies,
cookie_jar, evidence (AuthEvidence), error.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from playwright.sync_api import sync_playwright

from ..util.stealth import (
    DEFAULT_USER_AGENT, MODE_STRICT, VALID_MODES, context_options,
)
from ..validate.profiles import get_profile
from .evidence import PageEvents
from .readiness import wait_for_app_ready
from .auth_probe import probe


_SAMESITE_MAP = {"strict": "Strict", "lax": "Lax", "none": "None"}


def _coerce_http_only(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if value == 1:
            return True
        if value == 0:
            return False
    return None


def _same_site_for_playwright(value: str):
    if not value:
        return None
    v = value.lower()
    return _SAMESITE_MAP.get(v)


def _to_playwright_cookies(cookies: List[dict]):
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
        ho = _coerce_http_only(c.get("http_only"))
        if ho is not None:
            pc["httpOnly"] = ho
        ss = _same_site_for_playwright(c.get("same_site") or "")
        if ss is not None:
            pc["sameSite"] = ss
        expires = c.get("expires_epoch") or 0
        if expires > 0:
            pc["expires"] = expires
        out.append(pc)
    return out


def replay(url: str, cookies: List[dict], screenshot_path: Optional[Path] = None,
           max_wait_ms: int = 8000,
           headless: bool = True,
           extra_headers: Optional[dict] = None,
           mode: str = MODE_STRICT,
           dump_hint: Optional[dict] = None,
           probe_profile=None) -> dict:
    """
    Abre `url` com os cookies injetados, aguarda readiness condicional,
    executa AuthProbe e retorna um resumo estruturado.

    `probe_profile`: SiteProfile opcional (default: get_profile(host)).
    """
    if mode not in VALID_MODES:
        mode = MODE_STRICT

    host = url.split("://")[-1].split("/")[0].split(":")[0]
    pw_cookies = _to_playwright_cookies(cookies)
    profile = probe_profile or get_profile(host)

    result = {
        "status_code": None,
        "final_url": None,
        "title": None,
        "text": "",
        "sent_cookies": [],
        "cookie_jar": [],
        "redirect_chain": [],
        "evidence": {},
        "readiness": {},
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
        events = PageEvents()
        try:
            for c in pw_cookies:
                try:
                    context.add_cookies([c])
                except Exception:
                    pass

            sent_cookies: list = []
            page = context.new_page()
            events.attach(page)
            page.on("request", lambda req: _capture_request(req, host, sent_cookies))

            try:
                response = page.goto(url, wait_until="domcontentloaded", timeout=30000)
                result["status_code"] = response.status if response else None
            except Exception as exc:
                result["error"] = f"goto_failed: {exc}"

            # Readiness condicional (substitui wait_for_timeout fixo).
            readiness = wait_for_app_ready(
                page, events,
                auth_endpoint_hints=profile.identity_endpoints,
                max_wait_ms=max_wait_ms,
            )
            result["readiness"] = readiness

            # AuthProbe estruturado.
            ev = probe(
                page, events,
                auth_endpoints=profile.identity_endpoints,
                authenticated_selectors=profile.authenticated_selectors,
                anon_selectors=profile.anonymous_selectors,
                body_selectors=profile.body_selectors,
            )
            result["evidence"] = ev.to_dict()

            # Snapshot final.
            try:
                result["text"] = page.inner_text("body")
                result["final_url"] = page.url
                result["title"] = page.title()
            except Exception:
                pass

            result["sent_cookies"] = sent_cookies
            try:
                jar = context.cookies(target_host_url(url))
                result["cookie_jar"] = [c["name"] for c in jar]
            except Exception:
                pass

            # Redirect chain (compacto).
            result["redirect_chain"] = [
                {"url": r["url"], "status": r["status"]}
                for r in events.responses
                if r["status"] in (301, 302, 303, 307, 308)
            ]

            if screenshot_path:
                try:
                    page.screenshot(path=str(screenshot_path), full_page=False)
                    result["screenshot"] = str(screenshot_path)
                except Exception as exc:
                    result["screenshot_error"] = str(exc)
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
    scheme = "https" if url.startswith("https://") else "http"
    host = url.split("://")[-1].split("/")[0]
    return f"{scheme}://{host}"


__all__ = ["replay", "DEFAULT_USER_AGENT"]