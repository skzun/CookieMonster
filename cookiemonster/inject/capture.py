"""Captura de cookies efetivamente enviados ao alvo.

A partir do resumo do replay, determina quais cookies (nomes) do dump foram
realmente transmitidos nas requisicoes ao host alvo.
"""

from __future__ import annotations

from typing import List


def sent_cookie_names(replay_result: dict) -> List[str]:
    """Retorna nomes de cookies enviados (coluna `Cookie`) nas requisicoes capturadas."""
    names = set()
    for req in replay_result.get("sent_cookies", []):
        headers = req.get("headers", {})
        cookie_header = headers.get("cookie") or headers.get("Cookie") or ""
        for pair in cookie_header.split(";"):
            pair = pair.strip()
            if "=" in pair:
                names.add(pair.split("=", 1)[0])
    return sorted(names)


def summarize_sent(replay_result: dict, injected_names: List[str]) -> dict:
    """Compara os nomes injetados com os enviados e devolve um resumo."""
    sent = sent_cookie_names(replay_result)
    sent_set = set(sent)
    injected_set = set(injected_names)
    return {
        "sent": sent,
        "not_sent": sorted(injected_set - sent_set),
        "unexpected": sorted(sent_set - injected_set),
    }