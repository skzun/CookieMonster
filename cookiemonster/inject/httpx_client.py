"""Cliente de replay HTTP rapido (httpx).

Baixa fidelidade: nao executa JS e pode disparar bot detection. Util para alvos
que aceitam `requests` puro, ou como sondagem inicial rapida.
"""

from __future__ import annotations

from typing import Dict, Optional

import httpx

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def cookies_to_header(cookies) -> str:
    """Monta o header `Cookie` a partir de cookies (list/dicts com name/value)."""
    return "; ".join(f"{c['name']}={c['value']}" for c in cookies if c.get("name"))


def get(url: str, cookies, headers: Optional[Dict[str, str]] = None,
        timeout: float = 15.0, follow_redirects: bool = True) -> dict:
    """
    Faz um GET com os cookies injetados.

    Retorna dict com: status_code, final_url, headers, text, history, cookies_set.
    """
    merged = {**DEFAULT_HEADERS, **(headers or {})}
    merged["Cookie"] = cookies_to_header(cookies)

    response = httpx.get(
        url,
        headers=merged,
        timeout=timeout,
        follow_redirects=follow_redirects,
    )
    return {
        "status_code": response.status_code,
        "final_url": str(response.url),
        "headers": dict(response.headers),
        "text": response.text,
        "history": [(str(r.url), r.status_code) for r in response.history],
        "cookies_set": dict(response.cookies.items()),
    }


def post(url: str, cookies, data: Optional[Dict] = None,
         json: Optional[Dict] = None, headers: Optional[Dict[str, str]] = None,
         timeout: float = 15.0, follow_redirects: bool = True) -> dict:
    merged = {**DEFAULT_HEADERS, **(headers or {})}
    merged["Cookie"] = cookies_to_header(cookies)

    response = httpx.post(
        url,
        headers=merged,
        data=data,
        json=json,
        timeout=timeout,
        follow_redirects=follow_redirects,
    )
    return {
        "status_code": response.status_code,
        "final_url": str(response.url),
        "headers": dict(response.headers),
        "text": response.text,
        "history": [(str(r.url), r.status_code) for r in response.history],
        "cookies_set": dict(response.cookies.items()),
    }