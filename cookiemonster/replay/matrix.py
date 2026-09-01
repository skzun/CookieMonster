"""ReplayMatrix: orquestra a execucao de N variantes de replay e analisa
as dependencias resultantes.

Fluxo:
  1. Operador escolhe um dominio + vitima (1 cookie jar).
  2. ReplayMatrix gera N ContextVariant (matriz).
  3. Para cada variant, executa replay e captura AuthContext (state).
  4. DependencyAnalyzer compara resultados e infere dependencias.

Custo: cada variant com Playwright = 5-15s. 5 variants = ~1min por vitima.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

from .context import (
    ContextVariant, NetworkContext, BrowserContext, CookiesContext,
    VariantResult, build_matrix, CANONICAL_VARIANTS,
)


# --- Stop conditions ---

def should_stop(results: List[VariantResult]) -> Tuple[bool, str]:
    """Decide se a matriz ja tem informacao suficiente para parar.

    Regras (so aplicam apos o baseline + canonical, ou seja, >= 2 results):
    - AUTHENTICATED em alguma variant: para (encontramos sessao).
    - BOT_BLOCKED consistente em todas as >= 2 variants: para (anti-bot bloqueia).
    - ANONYMOUS consistente em todas as >= 2 variants: para (server rejeita).

    NAO para em: INCONCLUSIVE / CONTEXT_BOUND / IDP_BOUND mistos
    (precisamos de mais dados para distinguir dependencias).
    """
    if len(results) < 2:
        return False, ""
    states = [r.auth_state for r in results if r.auth_state != "ERROR"]
    if not states:
        return False, ""
    # Achamos uma sessao.
    if any(s == "AUTHENTICATED" for s in states):
        return True, "authenticated_found"
    # Bot challenge consistente (>= 2 resultados consistentes).
    if all(s == "BOT_BLOCKED" for s in states):
        return True, "bot_blocked_consistent"
    # Server rejeitando todos.
    if all(s == "ANONYMOUS" for s in states):
        return True, "anonymous_consistent"
    return False, ""


# --- DependencyAnalyzer: deduz cookie-only / network-bound / browser-bound ---

def analyze_dependencies(results: List[VariantResult]) -> Dict[str, Any]:
    """Compara os resultados das variantes e infere dependencias.

    Logica:
    - Se a canonical (default+default+artifact) E todos os variants autenticam:
      -> cookie_only (cookies sozinhos bastam).
    - Se canonical autentica mas network_alternate NAO autentica:
      -> network_bound (sessao exige IP/rede da vitima).
    - Se canonical autentica mas browser_preserved NAO autentica:
      -> browser_bound (sessao exige fingerprint do navegador da vitima).
    - Se canonical NAO autentica MAS network_alternate+browser_preserved autentica:
      -> context_dependent (precisa de contexto adicional).
    - Se nenhum autentica:
      -> inconclusive (evidencia insuficiente).

    Retorna dict com: dependencies (lista), summary (string), variant_states (dict).
    """
    # Indexa resultados por (network, browser, cookies).
    by_label: Dict[str, VariantResult] = {r.variant.label: r for r in results}

    canonical = _find_result(results, CookiesContext.ARTIFACT, NetworkContext.DEFAULT, BrowserContext.DEFAULT)
    net_alt = _find_result(results, CookiesContext.ARTIFACT, NetworkContext.CONTROLLED_ALTERNATE, BrowserContext.DEFAULT)
    browser_pres = _find_result(results, CookiesContext.ARTIFACT, NetworkContext.DEFAULT, BrowserContext.PRESERVED)
    combined = _find_result(results, CookiesContext.ARTIFACT, NetworkContext.CONTROLLED_ALTERNATE, BrowserContext.PRESERVED)

    def is_auth(r: Optional[VariantResult]) -> bool:
        return r is not None and r.auth_state == "AUTHENTICATED"

    def state_name(r: Optional[VariantResult]) -> str:
        return r.auth_state if r else "MISSING"

    dependencies: List[str] = []
    variant_states = {
        "canonical": state_name(canonical),
        "network_alternate": state_name(net_alt),
        "browser_preserved": state_name(browser_pres),
        "combined": state_name(combined),
    }

    canonical_auth = is_auth(canonical)

    if not canonical_auth:
        # Tentar inferir o que precisaria mudar.
        if is_auth(combined):
            dependencies.append("context")
            dependencies.append("network")
            dependencies.append("browser")
        elif is_auth(net_alt):
            dependencies.append("network")
        elif is_auth(browser_pres):
            dependencies.append("browser")
        else:
            dependencies.append("inconclusive")
    else:
        # Canonical autenticou. Testar se remover/reduzir contexto quebra.
        if net_alt and not is_auth(net_alt):
            dependencies.append("network")
        if browser_pres and not is_auth(browser_pres):
            dependencies.append("browser")
        if not dependencies:
            dependencies.append("cookie_only")

    # Resumo humano.
    if "cookie_only" in dependencies:
        summary = ("Replay autenticou com cookies em todas as variacoes. "
                   "Sessao nao depende de IP/device especifico.")
    elif "network" in dependencies and "browser" in dependencies:
        summary = ("Replay exige tanto rede quanto fingerprint do navegador "
                   "da vitima. Sessoes de sessao com binagem forte.")
    elif "network" in dependencies:
        summary = ("Replay exige rede da vitima (IP/ASN). "
                   "Cookie replay provavelmente sera bloqueado por anti-bot/IdP "
                   "em outra origem.")
    elif "browser" in dependencies:
        summary = ("Replay exige fingerprint do navegador da vitima. "
                   "Bot detection provavelmente esta ativo.")
    elif "context" in dependencies:
        summary = ("Replay exige contexto adicional (rede + browser) que nao foi "
                   "reproduzido. Provavelmente IdP externo ou anti-bot.")
    else:
        summary = "Evidencia insuficiente para inferir dependencias."

    return {
        "dependencies": dependencies,
        "summary": summary,
        "variant_states": variant_states,
        "canonical_auth": canonical_auth,
    }


def _find_result(results: List[VariantResult], cookies: CookiesContext,
                 network: NetworkContext, browser: BrowserContext) -> Optional[VariantResult]:
    for r in results:
        if (r.variant.cookies == cookies
                and r.variant.network == network
                and r.variant.browser == browser):
            return r
    return None


# --- High-level orchestrator (sem rede - usado em testes) ---

class ReplayMatrix:
    """Orquestrador da matriz. Recebe um callback `executor` que
    recebe ContextVariant e retorna (auth_state, confidence, reason,
    dependencies, final_url, error).

    Nao implementa rede diretamente - delega ao chamador (CLI ou lab).
    """

    def __init__(self, executor, stop_when: Optional[str] = None,
                 max_variants: int = 5):
        self.executor = executor
        self.stop_when = stop_when  # "authenticated" / "bot_blocked" / "anonymous" / None
        self.max_variants = max_variants
        self.results: List[VariantResult] = []

    def run(self, variants: Optional[List[ContextVariant]] = None) -> List[VariantResult]:
        variants = variants or CANONICAL_VARIANTS
        self.results = []
        for v in variants[:self.max_variants]:
            t0 = time.time()
            try:
                out = self.executor(v)
            except Exception as exc:
                out = {
                    "auth_state": "ERROR",
                    "confidence": 0.0,
                    "reason": "executor_exception",
                    "dependencies": [],
                    "final_url": "",
                    "error": str(exc),
                }
            vr = VariantResult(
                variant=v,
                auth_state=out.get("auth_state", "ERROR"),
                confidence=out.get("confidence", 0.0),
                reason=out.get("reason", ""),
                dependencies=out.get("dependencies", []),
                final_url=out.get("final_url", ""),
                error=out.get("error"),
                duration_sec=time.time() - t0,
            )
            self.results.append(vr)
            # Stop condition.
            stop, reason = should_stop(self.results)
            if stop:
                break
        return self.results

    def summary(self) -> Dict[str, Any]:
        """Retorna dict com results + dependency analysis."""
        dep = analyze_dependencies(self.results)
        return {
            "results": [r.to_dict() for r in self.results],
            "dependencies": dep,
            "count": len(self.results),
        }
