"""Testes do M6.3: Finding, CorrelationGraph, correlate, render."""

from cookiemonster.correlate import (
    Finding, Target, Condition, Engine, FindingType, Severity,
    Edge, EdgeKind, Rule, DEFAULT_RULES,
    CorrelationGraph, correlate, find_chains, render_chain,
    render_graph_markdown, make_finding_from_run,
)


# --- Finding ---

def test_finding_default_values():
    """Finding tem id unico + defaults razoaveis."""
    f = Finding()
    assert len(f.id) == 8
    assert f.engine == Engine.VALIDATE
    assert f.type == FindingType.AUTH_STATE_INDETERMINATE
    assert f.severity == Severity.INFO
    assert f.confidence == 0.5
    assert f.evidence == []


def test_finding_to_from_dict():
    """Finding round-trip preserva campos canonicos."""
    f = Finding(
        engine=Engine.AUTH_CONTEXT,
        type=FindingType.AUTH_STATE_CONFIRMED,
        severity=Severity.CRITICAL,
        confidence=0.95,
        target=Target(domain="x.com", run_id=42),
    )
    d = f.to_dict()
    assert d["engine"] == "auth_context"
    assert d["type"] == "auth_state_confirmed"
    assert d["target"]["domain"] == "x.com"
    f2 = Finding.from_dict(d)
    assert f2.engine == Engine.AUTH_CONTEXT
    assert f2.type == FindingType.AUTH_STATE_CONFIRMED
    assert f2.target.run_id == 42


def test_finding_add_evidence_and_conditions():
    """Helpers de evidence/conditions populam corretamente."""
    f = Finding()
    f.add_evidence("cookie_name", "session-id")
    f.add_evidence("confidence", 0.9)
    f.add_precondition("requires", "session_replay")
    f.add_constraint("blocks", "authenticated_state")
    assert len(f.evidence) == 2
    assert f.evidence[0]["key"] == "cookie_name"
    assert f.preconditions[0].kind == "requires"
    assert f.constraints[0].target_type == "authenticated_state"


# --- make_finding_from_run ---

def test_make_finding_from_run_confirmed():
    """Run CONFIRMED gera SESSION_ARTIFACT + SESSION_REPLAYABLE + SESSION_REPLAY + AUTH_STATE_CONFIRMED."""
    run = {
        "id": 100,
        "target_domain": "x.com",
        "target_url": "https://x.com/",
        "victim_id": 5,
        "state": "AUTHENTICATED",
        "confidence": 0.9,
        "reason": "identity_confirmed",
    }
    findings = make_finding_from_run(run)
    types = [f.type for f in findings]
    assert FindingType.SESSION_ARTIFACT in types
    assert FindingType.SESSION_REPLAYABLE in types
    assert FindingType.SESSION_REPLAY in types
    assert FindingType.AUTH_STATE_CONFIRMED in types
    # Todos no mesmo target.
    assert all(f.target.run_id == 100 for f in findings)


def test_make_finding_from_run_anonymous():
    """Run ANONYMOUS gera AUTH_STATE_REJECTED."""
    run = {
        "id": 101,
        "target_domain": "x.com",
        "target_url": "https://x.com/",
        "victim_id": 5,
        "state": "ANONYMOUS",
        "confidence": 0.85,
        "reason": "session_cookie_rejected",
    }
    findings = make_finding_from_run(run)
    types = [f.type for f in findings]
    assert FindingType.AUTH_STATE_REJECTED in types
    assert FindingType.AUTH_STATE_CONFIRMED not in types


def test_make_finding_from_run_idp_bound():
    """Run IDP_BOUND gera AUTH_BOUNDARY (severity=MEDIUM)."""
    run = {
        "id": 102,
        "target_domain": "chatgpt.com",
        "target_url": "https://chatgpt.com/api/auth/session",
        "victim_id": 1939,
        "state": "IDP_BOUND",
        "confidence": 0.85,
        "reason": "identity_provider_boundary:google",
    }
    findings = make_finding_from_run(run)
    auth_bound = [f for f in findings if f.type == FindingType.AUTH_BOUNDARY]
    assert len(auth_bound) == 1
    assert auth_bound[0].severity == Severity.MEDIUM


# --- CorrelationGraph ---

def test_correlate_artifact_enables_replay():
    """Regra: SESSION_ARTIFACT enables SESSION_REPLAY."""
    findings = [
        Finding(type=FindingType.SESSION_ARTIFACT, target=Target(domain="x.com")),
        Finding(type=FindingType.SESSION_REPLAY, target=Target(domain="x.com")),
    ]
    graph = correlate(findings)
    edges = [(e.source_id, e.target_id, e.kind) for e in graph.edges]
    # Deve ter SESSION_ARTIFACT -> SESSION_REPLAY (enables).
    enables = [e for e in edges if e[2] == EdgeKind.ENABLES]
    assert any(
        graph.findings[e[0]].type == FindingType.SESSION_ARTIFACT
        and graph.findings[e[1]].type == FindingType.SESSION_REPLAY
        for e in enables
    )


def test_correlate_auth_boundary_blocks_auth():
    """Regra: AUTH_BOUNDARY blocks AUTHENTICATED_STATE."""
    findings = [
        Finding(type=FindingType.AUTH_BOUNDARY, target=Target(domain="x.com")),
        Finding(type=FindingType.AUTHENTICATED_STATE, target=Target(domain="x.com")),
    ]
    graph = correlate(findings)
    blocks = [e for e in graph.edges if e.kind == EdgeKind.BLOCKS]
    assert any(
        graph.findings[e.source_id].type == FindingType.AUTH_BOUNDARY
        and graph.findings[e.target_id].type == FindingType.AUTHENTICATED_STATE
        for e in blocks
    )


def test_correlate_anti_bot_blocks_replay():
    """Regra: ANTI_BOT_BLOCK blocks SESSION_REPLAY."""
    findings = [
        Finding(type=FindingType.ANTI_BOT_BLOCK, target=Target(domain="x.com")),
        Finding(type=FindingType.SESSION_REPLAY, target=Target(domain="x.com")),
    ]
    graph = correlate(findings)
    blocks = [e for e in graph.edges if e.kind == EdgeKind.BLOCKS]
    assert any(
        graph.findings[e.source_id].type == FindingType.ANTI_BOT_BLOCK
        and graph.findings[e.target_id].type == FindingType.SESSION_REPLAY
        for e in blocks
    )


def test_correlate_separate_targets_no_edges():
    """Findings em targets diferentes nao geram edges."""
    findings = [
        Finding(type=FindingType.SESSION_ARTIFACT, target=Target(domain="x.com", victim_id=1)),
        Finding(type=FindingType.AUTHENTICATED_STATE, target=Target(domain="y.com", victim_id=2)),
    ]
    graph = correlate(findings)
    assert len(graph.edges) == 0


def test_correlate_complex_chain():
    """Cenario: SESSION_ARTIFACT -> SESSION_REPLAY -> CONFIRMED -> RESOURCE."""
    findings = [
        Finding(type=FindingType.SESSION_ARTIFACT, target=Target(domain="x.com", victim_id=1)),
        Finding(type=FindingType.SESSION_REPLAYABLE, target=Target(domain="x.com", victim_id=1)),
        Finding(type=FindingType.SESSION_REPLAY, target=Target(domain="x.com", victim_id=1)),
        Finding(type=FindingType.AUTH_STATE_CONFIRMED, target=Target(domain="x.com", victim_id=1)),
        Finding(type=FindingType.PROTECTED_RESOURCE, target=Target(domain="x.com", victim_id=1)),
    ]
    graph = correlate(findings)
    # Deve ter edges enables: SESSION_REPLAY -> CONFIRMED (with and=SESSION_REPLAY)
    # E CONFIRMED -> PROTECTED_RESOURCE.
    chains = find_chains(graph)
    assert len(chains) >= 1


# --- Render ---

def test_render_chain_simple():
    """render_chain imprime formatacao esperada."""
    graph = CorrelationGraph()
    a = Finding(id="A1", type=FindingType.SESSION_ARTIFACT,
                target=Target(domain="x.com"))
    b = Finding(id="B1", type=FindingType.SESSION_REPLAY,
                target=Target(domain="x.com"))
    graph.add_finding(a)
    graph.add_finding(b)
    graph.add_edge("A1", "B1", EdgeKind.ENABLES, "enables")
    out = render_chain(graph, ["A1", "B1"])
    assert "session_artifact" in out
    assert "session_replay" in out
    assert "@ x.com" in out


def test_render_graph_markdown_includes_chains():
    """render_graph_markdown produz Markdown com secao de chains."""
    findings = [
        Finding(type=FindingType.SESSION_ARTIFACT, target=Target(domain="x.com", victim_id=1)),
        Finding(type=FindingType.AUTH_STATE_CONFIRMED, target=Target(domain="x.com", victim_id=1)),
    ]
    graph = correlate(findings)
    md = render_graph_markdown(graph)
    assert "CorrelationGraph" in md
    assert "Attack Chains" in md
    assert "session_artifact" in md


# --- Default rules ---

def test_default_rules_count():
    """DEFAULT_RULES tem pelo menos 8 regras (M6.3)."""
    assert len(DEFAULT_RULES) >= 8


def test_default_rules_have_valid_types():
    """Todas regras usam FindingType validos."""
    for r in DEFAULT_RULES:
        assert isinstance(r.if_type, FindingType)
        assert isinstance(r.then_type, FindingType)
        for at in r.and_types:
            assert isinstance(at, FindingType)
        assert isinstance(r.then_kind, EdgeKind)
