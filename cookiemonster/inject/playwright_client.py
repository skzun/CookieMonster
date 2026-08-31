"""Cliente de replay com browser real (Playwright).

Canal canonico de validacao: executa JS, negocia TLS real e permite screenshot.
Injeta os cookies via `context.add_cookies` e visita o alvo.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from playwright.sync_api import sync_playwright

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


def _to_playwright_cookies(cookies: List[dict]):
    """Converte cookies do store para o formato aceito por Playwright."""
    out = []
    for c in cookies:
        domain = (c.get("domain") or "").lstrip(".")
        out.append({
            "name": c["name"],
            "value": c["value"],
            "domain": domain,
            "path": c.get("path") or "/",
            "secure": bool(c.get("secure")),
            "httpOnly": bool(c.get("http_only")),
            "sameSite": "None" if not bool(c.get("secure")) else "Lax",
        })
        # Playwright nao aceita "expires": usa "expires" int ou omite (sessao).
        expires = c.get("expires_epoch") or 0
        if expires > 0:
            # expires em segundos; Playwright aceita int.
            out[-1]["expires"] = expires
    return out


def replay(url: str, cookies: List[dict], screenshot_path: Optional[Path] = None,
           wait_ms: int = 1500, headless: bool = True,
           extra_headers: Optional[dict] = None) -> dict:
    """
    Abre `url` com os cookies injetados e retorna um resumo.

    Retorna dict com: status_code, final_url, title, text, sent_cookies,
    screenshot (str|None), error (str|None).
    """
    scheme = "http" if url.startswith("http://") else "https"
    host = url.split("://")[-1].split("/")[0].split(":")[0]
    pw_cookies = _to_playwright_cookies(cookies)

    result = {
        "status_code": None,
        "final_url": None,
        "title": None,
        "text": "",
        "sent_cookies": [],
        "screenshot": None,
        "error": None,
    }

    with sync_playwright() as p:
        args = []
        if headless and not extra_headers:  # stealth padrao: headless=new
            args = ["--headless=new"]
        browser = p.chromium.launch(headless=headless, args=args)

        from ..util.stealth import new_context_options

        ctx_opts = new_context_options()
        if extra_headers and "User-Agent" in extra_headers:
            ctx_opts["user_agent"] = extra_headers["User-Agent"]
        context = browser.new_context(**ctx_opts)
        try:
            for c in pw_cookies:
                try:
                    context.add_cookies([c])
                except Exception:
                    pass  # cookie de outro dominio/atributo invalido e ignorado

            sent_cookies = []
            page = context.new_page()
            page.on("request", lambda req: _capture_request(req, host, sent_cookies))
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

            # O CDP omite o header `Cookie` em request.headers; `context.cookies`
            # é a fonte confiável dos cookies que o browser detém/envia para o host.
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
    # Registra apenas requisicoes ao host alvo (ou subdominios).
    if url_host == host or url_host.endswith("." + host):
        into.append({"url": request.url, "headers": dict(request.headers)})


def target_host_url(url: str) -> str:
    """Retorna a URL base (scheme://host) de uma URL."""
    scheme = "https" if url.startswith("https://") else "http"
    host = url.split("://")[-1].split("/")[0]
    return f"{scheme}://{host}"


__all__ = ["replay", "DEFAULT_USER_AGENT"]