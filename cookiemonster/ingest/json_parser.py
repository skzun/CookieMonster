"""Parser de exports de cookies em JSON (formato de extensao de navegador).

Formato: lista de objetos com chaves como
    domain, expirationDate, hostOnly, httpOnly, name, path, secure, session, value
"""

from __future__ import annotations

import json

from pathlib import Path
from typing import List

from .netscape_parser import ParsedCookie


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
                http_only=bool(item.get("httpOnly", False)),
                expires_epoch=int(item.get("expirationDate", 0) or 0),
            )
        )
    return cookies