"""Captura de cookies efetivamente enviados ao alvo (deprecated).

.. deprecated::
   Use \`replay_result["cookie_jar"]\` (preenchido por \`playwright_client.replay\`)
   ou \`replay_result["sent_cookies"]\` para acesso direto. Este modulo existe
   apenas para compatibilidade com o codigo legado e sera removido em M+1.

Historico: \`PageEvents\` nao expunha o header \`Cookie\` do CDP (omitido por
design), entao esta funcao combinava duas fontes (header capturado + cookie_jar).
Hoje o \`AuthProbe\` ja popula \`cookie_jar\` no resumo do replay, tornando este
wrapper redundante.
"""

from __future__ import annotations

import warnings

from typing import List


def sent_cookie_names(replay_result: dict) -> List[str]:
    """DEPRECATED: use replay_result['cookie_jar'] diretamente.

    Retorna nomes de cookies enviados ao alvo, combinando header cookie de
    requests + cookie_jar do browser.
    """
    warnings.warn(
        "capture.sent_cookie_names e' deprecated; use replay_result['cookie_jar']",
        DeprecationWarning, stacklevel=2,
    )
    names = set()
    for req in replay_result.get("sent_cookies", []):
        headers = req.get("headers", {})
        cookie_header = headers.get("cookie") or headers.get("Cookie") or ""
        for pair in cookie_header.split(";"):
            pair = pair.strip()
            if "=" in pair:
                names.add(pair.split("=", 1)[0])
    for n in replay_result.get("cookie_jar", []):
        names.add(n)
    return sorted(names)


def summarize_sent(replay_result: dict, injected_names: List[str]) -> dict:
    """DEPRECATED: calcule em cima de replay_result['cookie_jar']."""
    warnings.warn(
        "capture.summarize_sent e' deprecated",
        DeprecationWarning, stacklevel=2,
    )
    sent = sent_cookie_names(replay_result)
    sent_set = set(sent)
    injected_set = set(injected_names)
    return {
        "sent": sent,
        "not_sent": sorted(injected_set - sent_set),
        "unexpected": sorted(sent_set - injected_set),
    }