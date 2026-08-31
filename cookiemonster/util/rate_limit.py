"""Rate limiting e backoff por host.

Estrutura simples e sem status global: cada cliente instancia um RateLimiter e
aguarda o intervalo minimo entre requisicoes ao mesmo host, com backoff
exponencial quando erros/429/503 sao sinalizados.
"""

from __future__ import annotations

import time

from collections import defaultdict


class RateLimiter:
    """Controla intervalo minimo entre requisicoes, por host."""

    def __init__(self, min_interval: float = 1.0, max_backoff: float = 30.0):
        self.min_interval = min_interval
        self.max_backoff = max_backoff
        self._last: dict = {}
        self._backoff: dict = defaultdict(float)

    def wait(self, host: str) -> None:
        """Bloqueia ate o minimo de intervalo para o host ser respeitado."""
        now = time.monotonic()
        last = self._last.get(host, 0.0)
        backoff = self._backoff.get(host, 0.0)
        delay = max(self.min_interval, backoff) - (now - last)
        if delay > 0:
            time.sleep(delay)
        self._last[host] = time.monotonic()

    def report_success(self, host: str) -> None:
        self._backoff[host] = 0.0

    def report_failure(self, host: str) -> None:
        cur = self._backoff.get(host, 0.0)
        self._backoff[host] = min(self.max_backoff, cur * 2 or 1.0)

    def backoff_for(self, host: str) -> float:
        return self._backoff.get(host, 0.0)


def extract_host(url: str) -> str:
    return url.split("://")[-1].split("/")[0].split(":")[0]