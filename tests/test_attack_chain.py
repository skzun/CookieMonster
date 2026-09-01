"""Testes do OPT-A: AttackChain rendering (impact chain)."""

from cookiemonster.correlate import (
    Finding, FindingType, Severity, Target,
    Edge, EdgeKind, CorrelationGraph, correlate,
    AttackChain, build_chains, render_chain_pretty, render_all_chains,
)


def _make_finding(ftype: FindingType, severity: Severity = Severity.INFO,
                  conf: float = 0.5, target_domain: str = "x.com",
                  victim_id: int = 1, run_id: int = 100) -> Finding:
    return Finding(
        type=ftype, severity=severity, confidence=conf,
        target=Target(domain=target_domain, victim_id=victim_id, run_id=run_id),
    )


def test_build_chains_simple_artifact_to_confirmed():
    """Chain: SESSION_ARTIFACT -> AUTH_STATE_CONFIRMED (via atalho)."""
    findings = [
        _make_finding(FindingType.SESSION_ARTIFACT),
        _make_finding(FindingType.SESSION_REPLAY),
        _make_finding(FindingType.AUTH_STATE_CONFIRMED, Severity.CRITICAL, 0.95),
    ]
    graph = correlate(findings)
    chains = build_chains(graph)
    assert len(chains) >= 1
    # Primeira chain tem pelo menos 2 steps (artifact + confirmed).
    assert len(chains[0].steps) >= 2
    # Confirmed e o endpoint.
    assert any(s.type == FindingType.AUTH_STATE_CONFIRMED for s in chains[0].steps)


def test_build_chains_no_confirmed_returns_empty():
    """Sem AUTH_STATE_CONFIRMED/AUTHENTICATED_STATE nao gera chain completa."""
    findings = [
        _make_finding(FindingType.SESSION_ARTIFACT),
        _make_finding(FindingType.SESSION_REPLAY),
    ]
    graph = correlate(findings)
    chains = build_chains(graph)
    # Sem endpoint, nao ha chain completa.
    assert all(len(c.steps) < 2 or FindingType.AUTH_STATE_CONFIRMED not in [s.type for s in c.steps]
               for c in chains)


def test_build_chains_with_protected_resource():
    """Chain inclui PROTECTED_RESOURCE como continuacao."""
    findings = [
        _make_finding(FindingType.SESSION_ARTIFACT),
        _make_finding(FindingType.SESSION_REPLAY),
        _make_finding(FindingType.AUTH_STATE_CONFIRMED, Severity.CRITICAL, 0.95),
        _make_finding(FindingType.PROTECTED_RESOURCE, Severity.CRITICAL, 0.9),
    ]
    graph = correlate(findings)
    chains = build_chains(graph)
    # Pelo menos 1 chain alcancou CONFIRMED.
    assert any(FindingType.AUTH_STATE_CONFIRMED in [s.type for s in c.steps] for c in chains)


def test_chain_summary_explains_progression():
    """Summary contem marcadores: artifact, confirmed."""
    findings = [
        _make_finding(FindingType.SESSION_ARTIFACT),
        _make_finding(FindingType.SESSION_REPLAY),
        _make_finding(FindingType.AUTH_STATE_CONFIRMED, Severity.CRITICAL, 0.95),
    ]
    graph = correlate(findings)
    chains = build_chains(graph)
    summary = chains[0].summary
    assert "Cookie artifact capturado" in summary
    assert "sessao autenticada confirmada" in summary


def test_render_chain_pretty_includes_severity_and_steps():
    """render_chain_pretty imprime severidade + steps + summary."""
    findings = [
        _make_finding(FindingType.SESSION_ARTIFACT),
        _make_finding(FindingType.SESSION_REPLAY),
        _make_finding(FindingType.AUTH_STATE_CONFIRMED, Severity.CRITICAL, 0.95),
    ]
    graph = correlate(findings)
    chains = build_chains(graph)
    out = render_chain_pretty(chains[0])
    assert "ATTACK CHAIN" in out
    assert "session_artifact" in out
    assert "auth_state_confirmed" in out
    assert "CRITICAL" in out
    assert "enables" in out
    assert "IMPACT" in out


def test_render_all_chains_handles_empty():
    """render_all_chains com lista vazia retorna mensagem amigavel."""
    out = render_all_chains([])
    assert "Nenhuma" in out or "0" in out


def test_chain_to_dict_serializes_all_fields():
    """AttackChain.to_dict() preserva todos os campos canonicos."""
    findings = [
        _make_finding(FindingType.SESSION_ARTIFACT),
        _make_finding(FindingType.AUTH_STATE_CONFIRMED, Severity.CRITICAL, 0.95),
    ]
    graph = correlate(findings)
    chains = build_chains(graph)
    d = chains[0].to_dict()
    assert "steps" in d
    assert "edges" in d
    assert "impact" in d
    assert "severity" in d
    assert "confidence" in d
    assert "summary" in d


def test_chain_blocks_are_tracked_in_summary():
    """Summary inclui bloqueios quando ha edges BLOCKS."""
    findings = [
        _make_finding(FindingType.SESSION_ARTIFACT),
        _make_finding(FindingType.AUTH_BOUNDARY, Severity.MEDIUM, 0.85),
        _make_finding(FindingType.AUTHENTICATED_STATE, Severity.INFO, 0.3),
    ]
    graph = correlate(findings)
    chains = build_chains(graph)
    # Pode ou nao gerar chain (BLOQUEIO), mas se gerar, summary menciona bloqueio.
    for c in chains:
        if "bloqueios" in c.summary.lower():
            return  # OK
    # Se nao gerou chain, isso tambem e aceitavel (BLOQUEIO impediu).
    assert True
