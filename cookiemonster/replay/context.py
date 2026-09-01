"""ContextVariant: dataclass que representa UMA variante de replay na matriz.

Cada variante difere das outras em pelo menos um eixo:
- network (default, controlled_alternate): roteamento de rede
- browser (default, preserved): fingerprint do navegador
- cookies (none, artifact): quais cookies sao enviados

A combinacao forma a matriz N x M x K. Cada variant produz um
AuthContext independente que eh comparado pelo DependencyAnalyzer
para inferir o que o replay depende.

NAO IMPLEMENTA bypass. Apenas combina e compara variacoes passiveis.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# --- Eixos da matriz ---

class NetworkContext(str, Enum):
    """Contexto de rede usado no replay."""
    DEFAULT = "default"                         # rede do operador (sem proxy)
    CONTROLLED_ALTERNATE = "controlled_alternate"  # via proxy/SOCKS5 controlado


class BrowserContext(str, Enum):
    """Contexto de navegador (fingerprint) usado no replay."""
    DEFAULT = "default"             # Playwright default fingerprint
    PRESERVED = "preserved"         # tenta preservar fingerprint da vitima


class CookiesContext(str, Enum):
    """Quais cookies sao enviados no replay."""
    NONE = "none"           # sem cookies (baseline)
    ARTIFACT = "artifact"   # cookies da vitima


# --- Variante ---

@dataclass
class ContextVariant:
    """Uma celula da matriz de replay.

    Representa: executar replay com (network, browser, cookies) e
    capturar o AuthContext resultante.
    """
    network: NetworkContext
    browser: BrowserContext
    cookies: CookiesContext
    label: str = ""  # rotulo humano (ex.: "R1: net=default, br=default, ck=artifact")

    def __post_init__(self):
        if not self.label:
            self.label = (f"net={self.network.value},"
                          f"br={self.browser.value},"
                          f"ck={self.cookies.value}")

    @property
    def is_baseline(self) -> bool:
        """Baseline: sem cookies (e rede/browser default)."""
        return (self.cookies == CookiesContext.NONE
                and self.network == NetworkContext.DEFAULT
                and self.browser == BrowserContext.DEFAULT)

    @property
    def is_canonical_replay(self) -> bool:
        """Replay canonico: artifact cookies + default network/browser."""
        return (self.cookies == CookiesContext.ARTIFACT
                and self.network == NetworkContext.DEFAULT
                and self.browser == BrowserContext.DEFAULT)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "network": self.network.value,
            "browser": self.browser.value,
            "cookies": self.cookies.value,
            "label": self.label,
            "is_baseline": self.is_baseline,
            "is_canonical_replay": self.is_canonical_replay,
        }


# --- Matriz canonica ---

# Default: 6 variantes = 1 baseline + 5 replays (todos os pares (network, browser) com artifact).
# Operador pode chamar build_matrix() com subset para reduzir custo.
CANONICAL_VARIANTS: List[ContextVariant] = [
    # Baseline
    ContextVariant(NetworkContext.DEFAULT, BrowserContext.DEFAULT, CookiesContext.NONE,
                   label="B0: baseline"),
    # Canonical replay (1)
    ContextVariant(NetworkContext.DEFAULT, BrowserContext.DEFAULT, CookiesContext.ARTIFACT,
                   label="R1: canonical"),
    # Network variants
    ContextVariant(NetworkContext.CONTROLLED_ALTERNATE, BrowserContext.DEFAULT, CookiesContext.ARTIFACT,
                   label="R2: network_alternate"),
    # Browser variants
    ContextVariant(NetworkContext.DEFAULT, BrowserContext.PRESERVED, CookiesContext.ARTIFACT,
                   label="R3: browser_preserved"),
    # Combined
    ContextVariant(NetworkContext.CONTROLLED_ALTERNATE, BrowserContext.PRESERVED, CookiesContext.ARTIFACT,
                   label="R4: network+browser"),
]


def build_matrix(networks: Optional[List[NetworkContext]] = None,
                 browsers: Optional[List[BrowserContext]] = None,
                 cookies: Optional[List[CookiesContext]] = None,
                 include_baseline: bool = True) -> List[ContextVariant]:
    """Constroi uma matriz de variantes a partir dos eixos.

    Args:
        networks: subset de NetworkContext (default: todos).
        browsers: subset de BrowserContext (default: todos).
        cookies: subset de CookiesContext (default: [NONE, ARTIFACT]).
        include_baseline: se True, sempre inclui a celula baseline
                         (NONE, DEFAULT, DEFAULT).

    Returns:
        Lista de ContextVariant representando cada celula.
    """
    nets = networks or list(NetworkContext)
    brs = browsers or list(BrowserContext)
    cks = cookies or [CookiesContext.NONE, CookiesContext.ARTIFACT]
    variants: List[ContextVariant] = []
    for n in nets:
        for b in brs:
            for c in cks:
                v = ContextVariant(n, b, c)
                if not include_baseline and v.is_baseline:
                    continue
                variants.append(v)
    return variants


@dataclass
class VariantResult:
    """Resultado de executar uma variante: AuthContext + metadados."""
    variant: ContextVariant
    auth_state: str = "ERROR"           # AUTHENTICATED, ANONYMOUS, INCONCLUSIVE, etc
    confidence: float = 0.0
    reason: str = ""
    dependencies: List[str] = field(default_factory=list)
    final_url: str = ""
    error: Optional[str] = None
    duration_sec: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = self.variant.to_dict()
        d.update({
            "auth_state": self.auth_state,
            "confidence": self.confidence,
            "reason": self.reason,
            "dependencies": self.dependencies,
            "final_url": self.final_url,
            "error": self.error,
            "duration_sec": self.duration_sec,
            "timestamp": self.timestamp,
        })
        return d
