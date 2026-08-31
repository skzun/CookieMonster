"""Parser de exports de cookies em JSON (formato de extensao de navegador).

Formato: lista de objetos com chaves como
    domain, expirationDate, hostOnly, httpOnly, name, path, secure,
    session, sameSite, partitioned, value
"""

from __future__ import annotations

import json

from pathlib import Path
from typing import List

from .netscape_parser import ParsedCookie


def _coerce_samesite(raw: object) -> str:
    """Normaliza sameSite para {strict, lax, none, unknown}."""
    if raw is None:
        return "unknown"
    val = str(raw).strip().strip('"').lower()
    if val in ("strict", "lax", "none", "no_restriction"):
        return "none" if val == "no_restriction" else val
    if val.startswith("none") or val.startswith("no_restriction"):
        return "none"
    return "unknown"


def parse_json_file(path: Path) -> List[ParsedCookie]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            data = json.load(handle)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []

    if not isinstance(data, list):
        return []

    cookies: List[ParsedCookie] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        value = item.get("value")
        domain = item.get("domain")
        if name is None or value is None or not domain:
            continue

        host_only = bool(item.get("hostOnly", False))
        domain = str(domain)
        if domain.startswith("."):
            host_only = False

        cookies.append(
            ParsedCookie(
                name=str(name),
                value=str(value),
                domain=domain,
                path=str(item.get("path") or "/"),
                secure=bool(item.get("secure", False)),
                host_only=host_only,
                http_only=1 if bool(item.get("httpOnly", False)) else 0,
                expires_epoch=int(item.get("expirationDate", 0) or 0),
                same_site=_coerce_samesite(item.get("sameSite")),
                partitioned=bool(item.get("partitioned", False)),
            )
        )
    return cookies