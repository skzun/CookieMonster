"""Guardrail de escopo: recusa alvos fora da allowlist local (scope.txt).

Politica fail-safe: se scope.txt nao existe OU esta vazio OU contem somente
comentarios, o alvo e RECUSADO. Use --allow-unsafe-scope para desabilitar.
"""

from __future__ import annotations

from pathlib import Path

DEFAULT_SCOPE_FILE = Path("scope.txt")


def load_scope(path: Path | None = None) -> set:
    scope_file = Path(path) if path else DEFAULT_SCOPE_FILE
    if not scope_file.exists():
        return set()
    allowed = set()
    for line in scope_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        allowed.add(line.lower().rstrip("."))
    return allowed


def allowed(host: str, path: Path | None = None, unsafe: bool = False) -> bool:
    """True se o host esta autorizado.

    Por padrao (fail-safe), recusamos allowlist vazia/inexistente.
    """
    hosts = load_scope(path)
    if not hosts:
        # Falha segura: sem allowlist, tudo e recusado.
        return unsafe
    host = (host or "").lower().rstrip(".")
    return host in hosts or any(host.endswith("." + h) for h in hosts)