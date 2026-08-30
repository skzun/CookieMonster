"""Parser do formato Netscape/curl de cookies.

Formato (tab-separado, 7 colunas):
    domain \t include-subdomains \t path \t secure \t expiry \t name \t value

O campo `value` pode conter tab; os 6 primeiros campos são fixos e o restante
é tratado como valor. Comentarios/linhas vazias sao ignorados.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from typing import List, Optional


@dataclass
class ParsedCookie:
    name: str
    value: str
    domain: str
    path: str
    secure: bool
    host_only: bool
    http_only: bool
    expires_epoch: int

    def as_row(self, victim_id: int, browser: str, profile: str, source_file: str) -> tuple:
        return (
            victim_id,
            browser,
            profile,
            self.name,
            self.value,
            self.domain,
            self.path,
            int(self.secure),
            int(self.host_only),
            int(self.http_only),
            self.expires_epoch,
            source_file,
        )


def _is_true(value: str) -> bool:
    return value.strip().lower() == "true"


def _parse_expiry(raw: str) -> int:
    raw = raw.strip().rstrip("lL")
    try:
        return int(float(raw))
    except ValueError:
        return 0


def parse_line(line: str) -> Optional[ParsedCookie]:
    line = line.rstrip("\r\n")
    if not line or line.startswith("#"):
        return None

    parts = line.split("\t")
    if len(parts) < 7:
        # Linha malformada ou conteudo JSON dentro de .txt (detectado no caller).
        return None

    domain, include_sub, path, secure_flag, expiry, name = parts[:6]
    value = "\t".join(parts[6:])

    domain = domain.strip()
    include_sub = _is_true(include_sub)

    return ParsedCookie(
        name=name.strip(),
        value=value,
        domain=domain,
        path=path.strip() or "/",
        secure=_is_true(secure_flag),
        host_only=not include_sub and not domain.startswith("."),
        http_only=False,  # exportacao Netscape nao carrega HttpOnly
        expires_epoch=_parse_expiry(expiry),
    )


def parse_file(path: Path) -> List[ParsedCookie]:
    """Le um arquivo .txt no formato Netscape e retorna os cookies validos."""
    cookies, _ = parse_file_with_stats(path)
    return cookies


def parse_file_with_stats(path: Path) -> tuple[List[ParsedCookie], int]:
    """Le um arquivo .txt Netscape e retorna (cookies, linhas malformadas)."""
    cookies: List[ParsedCookie] = []
    malformed = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            cookie = parse_line(raw)
            if cookie is not None:
                cookies.append(cookie)
            else:
                line = raw.strip()
                if line and not line.startswith("#"):
                    malformed += 1
    return cookies, malformed