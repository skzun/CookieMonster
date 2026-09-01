"""Testes do M6.2: ContextVariant, ReplayMatrix, DependencyAnalyzer."""

from cookiemonster.replay import (
    ContextVariant, NetworkContext, BrowserContext, CookiesContext,
    VariantResult, build_matrix, CANONICAL_VARIANTS,
    ReplayMatrix, analyze_dependencies, should_stop,
)


# --- ContextVariant ---

def test_variant_default_label():
    """Variant tem label humano derivado dos eixos."""
    v = ContextVariant(NetworkContext.DEFAULT, BrowserContext.DEFAULT, CookiesContext.ARTIFACT)
    assert "net=default" in v.label
    assert "br=default" in v.label
    assert "ck=artifact" in v.label


def test_variant_custom_label():
    """Variant aceita label custom."""
    v = ContextVariant(NetworkContext.DEFAULT, BrowserContext.PRESERVED, CookiesContext.ARTIFACT,
                       label="R3: custom")
    assert v.label == "R3: custom"


def test_variant_is_baseline():
    """Baseline = NONE + DEFAULT + DEFAULT."""
    base = ContextVariant(NetworkContext.DEFAULT, BrowserContext.DEFAULT, CookiesContext.NONE)
    assert base.is_baseline is True
    canonical = ContextVariant(NetworkContext.DEFAULT, BrowserContext.DEFAULT, CookiesContext.ARTIFACT)
    assert canonical.is_baseline is False


def test_variant_is_canonical_replay():
    """Canonical = ARTIFACT + DEFAULT + DEFAULT."""
    canonical = ContextVariant(NetworkContext.DEFAULT, BrowserContext.DEFAULT, CookiesContext.ARTIFACT)
    assert canonical.is_canonical_replay is True
    alt_net = ContextVariant(NetworkContext.CONTROLLED_ALTERNATE, BrowserContext.DEFAULT, CookiesContext.ARTIFACT)
    assert alt_net.is_canonical_replay is False


# --- build_matrix ---

def test_build_matrix_default_includes_baseline():
    """Matriz padrao inclui baseline + canonical + variants."""
    variants = build_matrix()
    assert len(variants) >= 4
    # Primeiro: baseline.
    assert variants[0].is_baseline
    # Pelo menos 1 canonical.
    canonicals = [v for v in variants if v.is_canonical_replay]
    assert len(canonicals) >= 1


def test_build_matrix_excludes_baseline_when_requested():
    """--no-baseline remove a celula baseline."""
    variants = build_matrix(include_baseline=False)
    assert not any(v.is_baseline for v in variants)


def test_build_matrix_subset_axes():
    """Operador pode restringir os eixos."""
    variants = build_matrix(
        networks=[NetworkContext.DEFAULT],
        browsers=[BrowserContext.DEFAULT],
        cookies=[CookiesContext.ARTIFACT],
        include_baseline=False,
    )
    assert len(variants) == 1
    assert variants[0].cookies == CookiesContext.ARTIFACT


# --- should_stop ---

def test_should_stop_authenticated():
    """Para quando encontra AUTHENTICATED."""
    results = [
        VariantResult(variant=ContextVariant(NetworkContext.DEFAULT, BrowserContext.DEFAULT,
                                             CookiesContext.NONE),
                      auth_state="INCONCLUSIVE"),
        VariantResult(variant=ContextVariant(NetworkContext.DEFAULT, BrowserContext.DEFAULT,
                                             CookiesContext.ARTIFACT),
                      auth_state="AUTHENTICATED"),
    ]
    stop, why = should_stop(results)
    assert stop is True
    assert why == "authenticated_found"


def test_should_stop_bot_blocked_consistent():
    """Para quando todas variantes dao BOT_BLOCKED."""
    results = [
        VariantResult(variant=ContextVariant(NetworkContext.DEFAULT, BrowserContext.DEFAULT,
                                             CookiesContext.ARTIFACT),
                      auth_state="BOT_BLOCKED"),
        VariantResult(variant=ContextVariant(NetworkContext.CONTROLLED_ALTERNATE,
                                             BrowserContext.DEFAULT, CookiesContext.ARTIFACT),
                      auth_state="BOT_BLOCKED"),
    ]
    stop, why = should_stop(results)
    assert stop is True
    assert why == "bot_blocked_consistent"


def test_should_stop_does_not_stop_mixed_context_bound():
    """NAO para em INCONCLUSIVE/CONTEXT_BOUND mistos."""
    results = [
        VariantResult(variant=ContextVariant(NetworkContext.DEFAULT, BrowserContext.DEFAULT,
                                             CookiesContext.ARTIFACT),
                      auth_state="CONTEXT_BOUND"),
        VariantResult(variant=ContextVariant(NetworkContext.CONTROLLED_ALTERNATE,
                                             BrowserContext.PRESERVED, CookiesContext.ARTIFACT),
                      auth_state="INCONCLUSIVE"),
    ]
    stop, why = should_stop(results)
    assert stop is False


# --- analyze_dependencies ---

def test_analyze_dependencies_cookie_only():
    """Canonical autentica, todas variants tambem -> cookie_only."""
    results = [
        VariantResult(variant=ContextVariant(NetworkContext.DEFAULT, BrowserContext.DEFAULT,
                                             CookiesContext.ARTIFACT),
                      auth_state="AUTHENTICATED"),
        VariantResult(variant=ContextVariant(NetworkContext.CONTROLLED_ALTERNATE,
                                             BrowserContext.DEFAULT, CookiesContext.ARTIFACT),
                      auth_state="AUTHENTICATED"),
        VariantResult(variant=ContextVariant(NetworkContext.DEFAULT, BrowserContext.PRESERVED,
                                             CookiesContext.ARTIFACT),
                      auth_state="AUTHENTICATED"),
        VariantResult(variant=ContextVariant(NetworkContext.CONTROLLED_ALTERNATE,
                                             BrowserContext.PRESERVED, CookiesContext.ARTIFACT),
                      auth_state="AUTHENTICATED"),
    ]
    dep = analyze_dependencies(results)
    assert "cookie_only" in dep["dependencies"]
    assert dep["canonical_auth"] is True


def test_analyze_dependencies_network_bound():
    """Canonical autentica mas network_alternate nao -> network_bound."""
    results = [
        VariantResult(variant=ContextVariant(NetworkContext.DEFAULT, BrowserContext.DEFAULT,
                                             CookiesContext.ARTIFACT),
                      auth_state="AUTHENTICATED"),
        VariantResult(variant=ContextVariant(NetworkContext.CONTROLLED_ALTERNATE,
                                             BrowserContext.DEFAULT, CookiesContext.ARTIFACT),
                      auth_state="ANONYMOUS"),
        VariantResult(variant=ContextVariant(NetworkContext.DEFAULT, BrowserContext.PRESERVED,
                                             CookiesContext.ARTIFACT),
                      auth_state="AUTHENTICATED"),
    ]
    dep = analyze_dependencies(results)
    assert "network" in dep["dependencies"]


def test_analyze_dependencies_browser_bound():
    """Canonical autentica mas browser_preserved nao -> browser_bound."""
    results = [
        VariantResult(variant=ContextVariant(NetworkContext.DEFAULT, BrowserContext.DEFAULT,
                                             CookiesContext.ARTIFACT),
                      auth_state="AUTHENTICATED"),
        VariantResult(variant=ContextVariant(NetworkContext.CONTROLLED_ALTERNATE,
                                             BrowserContext.DEFAULT, CookiesContext.ARTIFACT),
                      auth_state="AUTHENTICATED"),
        VariantResult(variant=ContextVariant(NetworkContext.DEFAULT, BrowserContext.PRESERVED,
                                             CookiesContext.ARTIFACT),
                      auth_state="IDP_BOUND"),
    ]
    dep = analyze_dependencies(results)
    assert "browser" in dep["dependencies"]


def test_analyze_dependencies_context_dependent():
    """Canonical NAO autentica, mas combined sim -> context."""
    results = [
        VariantResult(variant=ContextVariant(NetworkContext.DEFAULT, BrowserContext.DEFAULT,
                                             CookiesContext.ARTIFACT),
                      auth_state="INCONCLUSIVE"),
        VariantResult(variant=ContextVariant(NetworkContext.CONTROLLED_ALTERNATE,
                                             BrowserContext.PRESERVED, CookiesContext.ARTIFACT),
                      auth_state="AUTHENTICATED"),
    ]
    dep = analyze_dependencies(results)
    assert "context" in dep["dependencies"]


def test_analyze_dependencies_inconclusive():
    """Nenhuma autentica -> inconclusive."""
    results = [
        VariantResult(variant=ContextVariant(NetworkContext.DEFAULT, BrowserContext.DEFAULT,
                                             CookiesContext.ARTIFACT),
                      auth_state="INCONCLUSIVE"),
        VariantResult(variant=ContextVariant(NetworkContext.CONTROLLED_ALTERNATE,
                                             BrowserContext.DEFAULT, CookiesContext.ARTIFACT),
                      auth_state="ANONYMOUS"),
    ]
    dep = analyze_dependencies(results)
    assert "inconclusive" in dep["dependencies"]


# --- ReplayMatrix orchestrator ---

def test_replay_matrix_stops_at_authenticated():
    """ReplayMatrix para cedo quando encontra AUTHENTICATED."""
    def fake_executor(variant):
        return {
            "auth_state": "AUTHENTICATED" if variant.cookies == CookiesContext.ARTIFACT else "INCONCLUSIVE",
            "confidence": 0.9,
            "reason": "test",
            "dependencies": [],
            "final_url": "https://x.com/",
        }

    matrix = ReplayMatrix(executor=fake_executor, max_variants=5)
    results = matrix.run()
    # Para no canonical (R1) que autentica, nao executa R2-R4.
    assert any(r.auth_state == "AUTHENTICATED" for r in results)
    # Parou antes de esgotar max_variants.
    assert len(results) < 5


def test_replay_matrix_runs_all_when_no_stop():
    """Sem stop condition, executa todas as variantes."""
    def fake_executor(variant):
        return {
            "auth_state": "INCONCLUSIVE",  # nunca autentica
            "confidence": 0.3,
            "reason": "test",
            "dependencies": [],
            "final_url": "",
        }

    matrix = ReplayMatrix(executor=fake_executor, max_variants=5)
    results = matrix.run()
    assert len(results) == 5  # baseline + 4 replays


def test_replay_matrix_summary_includes_dependencies():
    """summary() retorna results + dependency analysis."""
    def fake_executor(variant):
        return {
            "auth_state": "AUTHENTICATED",
            "confidence": 0.9,
            "reason": "test",
            "dependencies": [],
            "final_url": "",
        }

    matrix = ReplayMatrix(executor=fake_executor, max_variants=5)
    # Forca execucao de todas as 5 variants sem stop.
    matrix.max_variants = 5
    variants = [ContextVariant(NetworkContext.DEFAULT, BrowserContext.DEFAULT, c)
                for c in [CookiesContext.NONE, CookiesContext.ARTIFACT]] + [
        ContextVariant(NetworkContext.CONTROLLED_ALTERNATE, BrowserContext.DEFAULT, CookiesContext.ARTIFACT),
        ContextVariant(NetworkContext.DEFAULT, BrowserContext.PRESERVED, CookiesContext.ARTIFACT),
        ContextVariant(NetworkContext.CONTROLLED_ALTERNATE, BrowserContext.PRESERVED, CookiesContext.ARTIFACT),
    ]
    matrix.results = []
    for v in variants:
        out = fake_executor(v)
        from cookiemonster.replay import VariantResult
        matrix.results.append(VariantResult(
            variant=v, auth_state=out["auth_state"],
            confidence=out["confidence"], reason=out["reason"],
        ))
    s = matrix.summary()
    assert "results" in s
    assert "dependencies" in s
    assert "cookie_only" in s["dependencies"]["dependencies"]


def test_replay_matrix_handles_executor_exception():
    """Executor exception vira VariantResult com auth_state=ERROR."""
    def broken_executor(variant):
        raise RuntimeError("network down")

    matrix = ReplayMatrix(executor=broken_executor, max_variants=2)
    matrix.run()
    assert all(r.auth_state == "ERROR" for r in matrix.results)
    assert all(r.error == "network down" for r in matrix.results)
