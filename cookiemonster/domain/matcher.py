"""Matching de cookies segundo RFC 6265.

Determina, para um alvo (esquema https/http + host + path), quais cookies de um
dump devem ser enviados, respeitando:

- domain match (host-only vs Domain=, sufixo public-suffix)
- path match
- Secure (apenas em https)
- expiracao
- prefixos __Host- / __Secure-
"""

from __future__ import annotations

import re

from datetime import datetime, timezone
from typing import Dict, Iterable, List, Tuple

# Lista minima de sufixos publicos para evitar que cookies de dominio sejam
# aceitos em TLDs "vazios" (ex.: .com, .net). Completa o suficiente para a
# maioria dos alvos testados; pode ser estendida.
_PUBLIC_SUFFIXES = {
    "com", "net", "org", "edu", "gov", "mil", "int",
    "br", "us", "uk", "co.uk", "org.uk", "ac.uk", "gov.uk",
    "io", "co", "ai", "tv", "me", "dev", "app", "xyz", "info", "biz",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "de", "fr", "es", "it", "pt", "ru", "jp", "cn", "in", "au",
    "co.jp", "co.in", "co.za", "co.kr", "com.au", "com.ar", "com.mx",
    "cloud", "amazonaws.com", "github.io", "pages.dev",
}


def now_epoch() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _host_only(domain: str) -> bool:
    return not domain.startswith(".")


def _canonical_domain(domain: str) -> str:
    """Remove o ponto inicial do dominio (flag include-subdomains)."""
    return domain[1:] if domain.startswith(".") else domain


def _is_public_suffix(domain: str) -> bool:
    # Um cookie com Domain=.com ou .co.uk nao pode ser aceito (public suffix).
    # O dominio em si precisa ser exatamente um public suffix para ser rejeitado.
    return domain.lower() in _PUBLIC_SUFFIXES


def domain_match(request_host: str, cookie_domain: str, host_only: bool) -> bool:
    """
    Verifica o domain matching RFC 6265 (secao 5.1.3).

    request_host: host do alvo (sem porta), ex.: "www.amazon.com"
    cookie_domain: dominio do cookie (com ou sem ponto inicial)
    host_only: True se o cookie NAO possui atributo Domain (nao vai ao subdominio)
    """
    request_host = (request_host or "").lower().rstrip(".")
    cookie_domain = _canonical_domain(cookie_domain or "").lower().rstrip(".")

    if not request_host or not cookie_domain:
        return False

    if host_only:
        # Case-insensitive por RFC, mas convencionalmente hosts sao lowercase.
        return request_host == cookie_domain

    # Cookie de dominio: request_host deve ser igual ou subdominio de cookie_domain.
    if request_host == cookie_domain:
        return True
    if request_host.endswith("." + cookie_domain):
        return not _is_public_suffix(cookie_domain)
    return False


def path_match(request_path: str, cookie_path: str) -> bool:
    """
    Verifica o path matching RFC 6265 (secao 5.1.4).

    cookie_path == "/" casa com qualquer request_path.
    Caso contrario, o path do request casa se:
      - eh igual ao cookie_path, ou
      - comeca com cookie_path e o proximo char de boundary e "/".
    """
    request_path = request_path or "/"
    cookie_path = cookie_path or "/"

    if cookie_path == "/":
        return True
    if request_path == cookie_path:
        return True
    if request_path.startswith(cookie_path):
        boundary = request_path[len(cookie_path):]
        if cookie_path.endswith("/"):
            return True
        return boundary.startswith("/")
    return False


def matches(cookie: dict, scheme: str, host: str, path: str,
            current_time: int | None = None) -> bool:
    """
    Verifica se um cookie (linha do store) deve ser enviado ao alvo.

    cookie: dict com chaves domain, host_only, path, secure, expires_epoch.
    """
    scheme = (scheme or "https").lower()
    host = (host or "").lower().rstrip(".")
    path = path or "/"

    # Secure-domo: apenas HTTPS.
    if cookie.get("secure") and scheme != "https":
        return False

    # Expiracao (0 = cookie de sessao, valido ate o fechamento).
    expires = cookie.get("expires_epoch") or 0
    if expires and expires < (current_time if current_time is not None else now_epoch()):
        return False

    if not domain_match(host, cookie.get("domain", ""), bool(cookie.get("host_only", True))):
        return False

    if not path_match(path, cookie.get("path", "/")):
        return False

    return True


def applicable_cookies(cookies: Iterable[dict], scheme: str, host: str, path: str,
                       current_time: int | None = None) -> List[dict]:
    """Filtra uma lista de cookies aplicaveis a um alvo (tambem deduplica por nome)."""
    matched = [c for c in cookies if matches(c, scheme, host, path, current_time)]
    seen: Dict[str, dict] = {}
    for c in matched:
        key = (c.get("name"), c.get("domain"), c.get("path"))
        # Mantem o mais especifico (maior path) em caso de duplicata.
        prev = seen.get(key)
        if prev is None or len(c.get("path", "/")) > len(prev.get("path", "/")):
            seen[key] = c
    return list(seen.values())