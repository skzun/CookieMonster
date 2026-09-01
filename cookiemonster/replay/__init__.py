"""replay: matriz de contexto para identificar dependencias de replay (M6.2).

Modulos:
- context: ContextVariant, ContextVariant result, matriz canonica.
- matrix: ReplayMatrix orchestrator + DependencyAnalyzer.

A matriz combina variacoes passiveis de (network, browser, cookies)
para identificar O QUE o replay depende (cookie-only, network-bound,
device-bound, multi-factor) sem implementar bypass.
"""

from .context import (
    ContextVariant,
    NetworkContext,
    BrowserContext,
    CookiesContext,
    VariantResult,
    build_matrix,
    CANONICAL_VARIANTS,
)
from .matrix import (
    ReplayMatrix,
    analyze_dependencies,
    should_stop,
)

__all__ = [
    "ContextVariant",
    "NetworkContext",
    "BrowserContext",
    "CookiesContext",
    "VariantResult",
    "build_matrix",
    "CANONICAL_VARIANTS",
    "ReplayMatrix",
    "analyze_dependencies",
    "should_stop",
]
