"""CorrelationGraph: estrutura de grafo + correlator que conecta Findings
via edges (enables, blocks_by, depends_on).

Linguagem de regras YAML (parsed por RuleSet):
  rules:
    - if: SESSION_ARTIFACT
      then: enables SESSION_REPLAY

    - if: SESSION_REPLAY
      and: AUTH_STATE_CONFIRMED
      then: enables AUTHENTICATED_STATE

    - if: AUTH_BOUNDARY
      then: blocks AUTHENTICATED_STATE
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from .finding import Finding, FindingType


# --- Edges ---

class EdgeKind(str, Enum):
    """Tipo de relacao entre dois Findings."""
    ENABLES = "enables"           # source habilita target
    BLOCKS = "blocks"             # source bloqueia target
    REQUIRES = "requires"         # source requer target
    IMPLIES = "implies"           # source implica target


@dataclass
class Edge:
    """Aresta do CorrelationGraph."""
    source_id: str
    target_id: str
    kind: EdgeKind
    label: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"source_id": self.source_id, "target_id": self.target_id,
                "kind": self.kind.value, "label": self.label}


# --- RuleSet (declarativo) ---

@dataclass
class Rule:
    """Regra declarativa do correlator."""
    if_type: FindingType
    and_types: List[FindingType] = field(default_factory=list)
    then_kind: EdgeKind = EdgeKind.ENABLES
    then_type: FindingType = FindingType.AUTHENTICATED_STATE
    label: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"if": self.if_type.value, "and": [t.value for t in self.and_types],
                "then": [self.then_kind.value, self.then_type.value], "label": self.label}


# Regras canonicas (M6.3).
DEFAULT_RULES: List[Rule] = [
    # Cookie artifact habilita replay.
    Rule(if_type=FindingType.SESSION_ARTIFACT,
         then_kind=EdgeKind.ENABLES, then_type=FindingType.SESSION_REPLAY,
         label="cookie enables replay"),

    # Match RFC 6265 habilita replay.
    Rule(if_type=FindingType.SESSION_REPLAYABLE,
         then_kind=EdgeKind.ENABLES, then_type=FindingType.SESSION_REPLAY,
         label="matching enables replay"),

    # Replay habilita estado de auth (condicional: tambem precisa de CONFIRMED).
    Rule(if_type=FindingType.SESSION_REPLAY,
         and_types=[FindingType.AUTH_STATE_CONFIRMED],
         then_kind=EdgeKind.ENABLES, then_type=FindingType.AUTHENTICATED_STATE,
         label="replay+confirmed enables auth"),

    # SESSION_ARTIFACT habilita diretamente AUTH_STATE_CONFIRMED
    # (atalho: em chains curtas sem SESSION_REPLAY explicito).
    Rule(if_type=FindingType.SESSION_ARTIFACT,
         and_types=[FindingType.AUTH_STATE_CONFIRMED],
         then_kind=EdgeKind.ENABLES, then_type=FindingType.AUTH_STATE_CONFIRMED,
         label="artifact+confirmed enables auth"),

    # Estado de auth confirmado habilita recurso protegido.
    Rule(if_type=FindingType.AUTH_STATE_CONFIRMED,
         then_kind=EdgeKind.ENABLES, then_type=FindingType.PROTECTED_RESOURCE,
         label="confirmed enables resource"),

    # Auth Boundary BLOQUEIA estado autenticado.
    Rule(if_type=FindingType.AUTH_BOUNDARY,
         then_kind=EdgeKind.BLOCKS, then_type=FindingType.AUTHENTICATED_STATE,
         label="IdP blocks auth"),

    # MFA BLOCKED BLOQUEIA estado autenticado.
    Rule(if_type=FindingType.MFA_BLOCK,
         then_kind=EdgeKind.BLOCKS, then_type=FindingType.AUTHENTICATED_STATE,
         label="MFA blocks auth"),

    # Anti-bot BLOCKED BLOQUEIA replay.
    Rule(if_type=FindingType.ANTI_BOT_BLOCK,
         then_kind=EdgeKind.BLOCKS, then_type=FindingType.SESSION_REPLAY,
         label="anti-bot blocks replay"),

    # Rejected (ANONYMOUS) BLOQUEIA estado autenticado.
    Rule(if_type=FindingType.AUTH_STATE_REJECTED,
         then_kind=EdgeKind.BLOCKS, then_type=FindingType.AUTHENTICATED_STATE,
         label="rejected blocks auth"),

    # Context bound REQUIRES dependency_inferred.
    Rule(if_type=FindingType.SESSION_CONTEXT_BOUND,
         then_kind=EdgeKind.REQUIRES, then_type=FindingType.DEPENDENCY_INFERRED,
         label="context requires dependency"),
]


# --- CorrelationGraph ---

@dataclass
class CorrelationGraph:
    """Grafo de Findings + Edges."""
    findings: Dict[str, Finding] = field(default_factory=dict)
    edges: List[Edge] = field(default_factory=list)

    def add_finding(self, f: Finding) -> None:
        self.findings[f.id] = f

    def add_edge(self, source_id: str, target_id: str, kind: EdgeKind, label: str = "") -> None:
        self.edges.append(Edge(source_id, target_id, kind, label))

    def findings_by_type(self, ftype: FindingType) -> List[Finding]:
        return [f for f in self.findings.values() if f.type == ftype]

    def edges_from(self, finding_id: str) -> List[Edge]:
        return [e for e in self.edges if e.source_id == finding_id]

    def edges_to(self, finding_id: str) -> List[Edge]:
        return [e for e in self.edges if e.target_id == finding_id]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings.values()],
            "edges": [e.to_dict() for e in self.edges],
        }


# --- Correlator ---

def correlate(findings: List[Finding],
              rules: Optional[List[Rule]] = None) -> CorrelationGraph:
    """Aplica regras e constroi o grafo.

    Para cada combinacao (source, [and_finding], target_type), se source
    e todos os and_finding existem, cria edge.
    """
    rules = rules or DEFAULT_RULES
    graph = CorrelationGraph()
    for f in findings:
        graph.add_finding(f)

    # Indexa por tipo.
    by_type: Dict[FindingType, List[Finding]] = {}
    for f in findings:
        by_type.setdefault(f.type, []).append(f)

    for rule in rules:
        sources = by_type.get(rule.if_type, [])
        for src in sources:
            # Verifica se todos os and_types estao presentes (no mesmo target).
            if rule.and_types:
                if not _and_types_present(rule.and_types, by_type, src):
                    continue
            # Cria edge(s) para todos os targets do tipo then_type.
            targets = by_type.get(rule.then_type, [])
            for tgt in targets:
                if src.id == tgt.id:
                    continue
                graph.add_edge(src.id, tgt.id, rule.then_kind, rule.label)

    return graph


def _and_types_present(and_types: List[FindingType],
                       by_type: Dict[FindingType, List[Finding]],
                       source: Finding) -> bool:
    """Verifica se todos os and_types estao presentes no mesmo target
    (mesmo dominio/URL/vitima)."""
    for at in and_types:
        candidates = by_type.get(at, [])
        if not any(_same_target(f, source) for f in candidates):
            return False
    return True


def _same_target(a: Finding, b: Finding) -> bool:
    """Mesmo target se dominio+url+vid iguais."""
    return (a.target.domain == b.target.domain
            and a.target.victim_id == b.target.victim_id)


# --- Render: cadeia de ataque (chain) ---

def find_chains(graph: CorrelationGraph,
                start_types: Optional[List[FindingType]] = None) -> List[List[str]]:
    """Encontra chains a partir de nodes do tipo `start_types`.

    Chain = sequencia de Findings conectados por edges.
    Retorna lista de chains (cada chain e lista de finding IDs).
    """
    start_types = start_types or [FindingType.SESSION_ARTIFACT]
    chains: List[List[str]] = []
    starts = [f for f in graph.findings.values() if f.type in start_types]
    for start in starts:
        # BFS/DFS simples.
        visited: Set[str] = set()
        chain = _walk_chain(graph, start.id, visited, max_depth=8)
        if chain:
            chains.append(chain)
    return chains


def _walk_chain(graph: CorrelationGraph, fid: str, visited: Set[str],
                max_depth: int) -> List[str]:
    if fid in visited or max_depth <= 0:
        return []
    visited.add(fid)
    chain = [fid]
    out_edges = graph.edges_from(fid)
    for e in out_edges:
        if e.target_id in visited:
            continue
        sub = _walk_chain(graph, e.target_id, visited, max_depth - 1)
        if sub:
            chain.extend(sub)
            break  # primeira chain encontrada
    return chain


def render_chain(graph: CorrelationGraph, chain: List[str],
                 include_evidence: bool = False) -> str:
    """Renderiza uma chain em formato texto/Markdown."""
    if not chain:
        return ""
    lines = []
    for i, fid in enumerate(chain):
        f = graph.findings.get(fid)
        if not f:
            continue
        prefix = "  " * i
        arrow = "->" if i > 0 else " *"
        line = f"{prefix}{arrow} [{f.severity.value.upper()}] {f.type.value} ({f.confidence:.2f})"
        if f.target.domain:
            line += f" @ {f.target.domain}"
        if f.target.run_id:
            line += f" run#{f.target.run_id}"
        lines.append(line)
        if include_evidence and f.evidence:
            for ev in f.evidence[:3]:
                lines.append(f"{prefix}     - {ev.get('key')}: {ev.get('value')}")
    return "\n".join(lines)


def render_graph_markdown(graph: CorrelationGraph,
                          include_evidence: bool = False) -> str:
    """Renderiza o grafo inteiro em Markdown."""
    lines = ["# CorrelationGraph", ""]
    lines.append(f"**Total findings**: {len(graph.findings)}")
    lines.append(f"**Total edges**: {len(graph.edges)}")
    lines.append("")

    # Chains.
    chains = find_chains(graph)
    lines.append("## Attack Chains")
    for i, chain in enumerate(chains, 1):
        lines.append(f"")
        lines.append(f"### Chain #{i}")
        lines.append("```")
        lines.append(render_chain(graph, chain, include_evidence))
        lines.append("```")

    if not chains:
        lines.append("(no chains found)")

    # Edges isolados.
    isolated = [e for e in graph.edges
                if not any(c for c in chains if e.source_id in c and e.target_id in c)]
    if isolated:
        lines.append("")
        lines.append("## Isolated edges")
        for e in isolated:
            src = graph.findings.get(e.source_id)
            tgt = graph.findings.get(e.target_id)
            if not src or not tgt:
                continue
            lines.append(f"- {src.type.value} --[{e.kind.value}]--> {tgt.type.value}: {e.label}")

    return "\n".join(lines)
