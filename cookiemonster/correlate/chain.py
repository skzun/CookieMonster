"""AttackChain: rendering human-readable da cadeia de impacto a partir
do CorrelationGraph.

Diferenca do find_chains() (M6.3): AttackChain produz uma representacao
de "caminho de impacto" com marcadores visuais (seta, bloqueios,
severidade) e summary executivo.

Exemplo de saida:
  ATTACK CHAIN (3 findings, 2 edges)
  ============================================================
  SESSION_ARTIFACT  ──enables──>  SESSION_REPLAY
  [CRITICAL] vid=1939  conf=0.90  @ chatgpt.com
        |
        v
  AUTH_STATE_CONFIRMED  ──enables──>  PROTECTED_RESOURCE
  [CRITICAL] vid=1939  conf=0.95  @ chatgpt.com
  ============================================================
  IMPACT: CRITICAL (0.95) - Sessao autenticada confirmada.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .finding import Finding, FindingType, Severity
from .graph import CorrelationGraph, Edge, EdgeKind


@dataclass
class ChainStep:
    """Um passo da AttackChain (um Finding + edges saindo)."""
    finding: Finding
    outgoing: List[Tuple[Edge, "ChainStep"]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding.id,
            "finding_type": self.finding.type.value,
            "severity": self.finding.severity.value,
            "confidence": self.finding.confidence,
            "outgoing": [
                {"edge": e.to_dict(), "next": s.to_dict()}
                for e, s in self.outgoing
            ],
        }


@dataclass
class AttackChain:
    """Cadeia de impacto linear (lista de steps conectados)."""
    steps: List[Finding] = field(default_factory=list)
    edges: List[Edge] = field(default_factory=list)
    impact: str = ""
    severity: Severity = Severity.INFO
    confidence: float = 0.0
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "steps": [f.to_dict() for f in self.steps],
            "edges": [e.to_dict() for e in self.edges],
            "impact": self.impact,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "summary": self.summary,
        }


# --- Build chain from graph ---

def build_chains(graph: CorrelationGraph) -> List[AttackChain]:
    """Constroi AttackChains a partir do grafo.

    Uma chain comeca em SESSION_ARTIFACT ou SESSION_REPLAY e segue
    edges ENABLES ate um endpoint (AUTH_STATE_CONFIRMED, PROTECTED_RESOURCE).
    Se houver edges BLOCKS, a chain eh marcada com blocked_by.

    Retorna lista de chains (uma por par (domain, victim) tipicamente).
    """
    chains: List[AttackChain] = []
    # Indexa findings por id.
    findings_by_id = {f.id: f for f in graph.findings.values()}

    # Foco: chains que comecam em SESSION_ARTIFACT/SESSION_REPLAYABLE
    # e tem AUTH_STATE_CONFIRMED como endpoint.
    starts = [f for f in graph.findings.values()
              if f.type in (FindingType.SESSION_ARTIFACT, FindingType.SESSION_REPLAYABLE)]

    visited_global: set = set()
    for start in starts:
        for chain in _walk_forward(graph, findings_by_id, start, visited_global):
            chains.append(chain)
    return chains


def _walk_forward(graph: CorrelationGraph, findings_by_id: Dict[str, Finding],
                  start: Finding, visited_global: set) -> List[AttackChain]:
    """DFS a partir de start seguindo edges ENABLES ate endpoint de auth."""
    results: List[AttackChain] = []

    def dfs(current: Finding, path: List[Finding], path_edges: List[Edge],
            blocked: List[str], visited: set) -> None:
        if current.id in visited:
            return
        visited.add(current.id)
        new_path = path + [current]
        # Endpoint: AUTH_STATE_CONFIRMED ou AUTHENTICATED_STATE.
        if current.type in (FindingType.AUTH_STATE_CONFIRMED, FindingType.AUTHENTICATED_STATE):
            chain = AttackChain(
                steps=new_path,
                edges=path_edges,
                severity=current.severity,
                confidence=current.confidence,
                summary=_summarize(new_path, blocked),
            )
            results.append(chain)
            return
        # Continua por edges ENABLES.
        out_edges = [e for e in graph.edges_from(current.id) if e.kind == EdgeKind.ENABLES]
        if not out_edges:
            return
        for e in out_edges:
            nxt = findings_by_id.get(e.target_id)
            if nxt is None:
                continue
            dfs(nxt, new_path, path_edges + [e], blocked, visited.copy())

    # Coleta edges BLOCKS incidentes no path inicial.
    blocked: List[str] = []
    for e in graph.edges:
        if e.kind == EdgeKind.BLOCKS and e.source_id == start.id:
            blocked.append(e.label or "")

    dfs(start, [], [], blocked, set())
    return results


def _summarize(steps: List[Finding], blocked: List[str]) -> str:
    """Gera summary humano da chain."""
    types = [s.type for s in steps]
    parts = []
    if FindingType.SESSION_ARTIFACT in types:
        parts.append("Cookie artifact capturado")
    if FindingType.SESSION_REPLAY in types:
        parts.append("replay executado")
    if FindingType.AUTH_STATE_CONFIRMED in types:
        parts.append("sessao autenticada confirmada")
    if FindingType.PROTECTED_RESOURCE in types:
        parts.append("recurso protegido acessado")
    summary = " -> ".join(parts) if parts else "chain sem eventos relevantes"
    if blocked:
        summary += f" (com bloqueios: {'; '.join(b for b in blocked if b)})"
    return summary


# --- Render ---

def render_chain_pretty(chain: AttackChain, include_evidence: bool = False) -> str:
    """Renderiza uma AttackChain em formato visual."""
    if not chain.steps:
        return "(empty chain)"

    lines = []
    n_findings = len(chain.steps)
    n_edges = len(chain.edges)
    lines.append(f"ATTACK CHAIN ({n_findings} findings, {n_edges} edges)")
    lines.append("=" * 60)

    # Steps com setas ENABLES.
    for i, step in enumerate(chain.steps):
        sev = step.severity.value.upper()
        sev_color = {
            "CRITICAL": "[red][bold]",
            "HIGH": "[red]",
            "MEDIUM": "[yellow]",
            "LOW": "[dim]",
            "INFO": "[dim]",
        }.get(sev, "[dim]")

        # Header do step.
        target_str = f"@{step.target.domain}" if step.target.domain else ""
        run_str = f" run#{step.target.run_id}" if step.target.run_id else ""
        vid_str = f" vid={step.target.victim_id}" if step.target.victim_id else ""
        line = (f"  {sev_color}{sev:8}[/{sev_color[1:].replace('[', '[/', 1) if False else sev_color.replace('[bold]', '').replace('[/bold]', '')}] " if False else
                f"  [{step.severity.value.upper():8}] ")
        # Formato simples sem cor (compat com qualquer Console).
        line = f"  [{step.severity.value.upper():8}] {step.type.value:30} "
        line += f"(conf {step.confidence:.2f}) {target_str}{run_str}{vid_str}"
        lines.append(line)

        # Evidence opcional.
        if include_evidence and step.evidence:
            for ev in step.evidence[:3]:
                key = ev.get("key", "?")
                val = str(ev.get("value", ""))[:50]
                lines.append(f"      |- {key}: {val}")

        # Seta para proximo step.
        if i < n_findings - 1:
            # Procura edge entre step i e step i+1.
            next_step = chain.steps[i + 1]
            edge = next((e for e in chain.edges
                         if e.source_id == step.id and e.target_id == next_step.id), None)
            if edge:
                if edge.kind == EdgeKind.ENABLES:
                    lines.append(f"      |")
                    lines.append(f"      v  --{edge.kind.value}-->")
                elif edge.kind == EdgeKind.BLOCKS:
                    lines.append(f"      |")
                    lines.append(f"      X  --{edge.kind.value}--> ({edge.label or 'blocked'})")
                else:
                    lines.append(f"      |")
                    lines.append(f"      ?  --{edge.kind.value}-->")

    # Summary.
    lines.append("=" * 60)
    sev_color = {
        "critical": "[red][bold]", "high": "[red]", "medium": "[yellow]",
        "low": "[dim]", "info": "[dim]",
    }.get(chain.severity.value, "[dim]")
    close_tag = "[/bold]" if "bold" in sev_color else "[/]"
    lines.append(f"  IMPACT: {sev_color}{chain.severity.value.upper()}{close_tag} "
                 f"({chain.confidence:.2f})")
    lines.append(f"  [dim]{chain.summary}[/dim]")
    return "\n".join(lines)


def render_all_chains(chains: List[AttackChain], include_evidence: bool = False) -> str:
    """Renderiza todas as chains."""
    if not chains:
        return "[dim]Nenhuma attack chain encontrada.[/dim]"
    out = []
    out.append(f"# Attack Chains ({len(chains)})\n")
    for i, chain in enumerate(chains, 1):
        out.append(f"\n## Chain #{i}\n")
        out.append("```")
        out.append(render_chain_pretty(chain, include_evidence))
        out.append("```")
    return "\n".join(out)
