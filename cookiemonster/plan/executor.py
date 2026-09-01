"""AttackPlanExecutor: orquestra phases de um AttackPlan.

Cada phase chama uma funcao CLI interna (probe, probe-all, matrix,
access, correlate) e coleta resultados. Quando uma stop_condition e
atingida, o executor para cedo.

Apos executar, gera um ImpactAssessment baseado nos findings.

NAO IMPLEMENTA bypass. Apenas orquestra.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional

from .plan import (
    AttackPlan, ReplayConfig, Phase, Transport, StopCondition, ImpactSeverity,
)
from ..correlate import (
    make_finding_from_run, correlate, find_chains, render_graph_markdown,
    FindingType, EdgeKind,
)


@dataclass
class PhaseResult:
    """Resultado de executar UMA phase."""
    phase: Phase
    ok: bool = True
    duration_sec: float = 0.0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["phase"] = self.phase.value
        return d


@dataclass
class ImpactAssessment:
    """Avaliacao final do plano (calculada a partir de findings)."""
    severity: ImpactSeverity
    confidence: float
    authenticated: bool
    artifact: bool
    replayable: bool
    blocked_by: List[str] = field(default_factory=list)
    context_dependencies: List[str] = field(default_factory=list)
    target: str = ""
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


# --- Stop conditions ---

def _should_stop(all_findings: List[Dict[str, Any]],
                stop_conditions: List[StopCondition]) -> bool:
    """Verifica se alguma stop_condition foi atingida."""
    types = {f["type"] for f in all_findings}
    if StopCondition.AUTHENTICATED in stop_conditions and "auth_state_confirmed" in types:
        return True
    if StopCondition.BLOCKED in stop_conditions and (
        "anti_bot_block" in types or "mfa_block" in types
    ):
        return True
    if StopCondition.INCONCLUSIVE in stop_conditions and (
        "auth_state_indeterminate" in types and not types.intersection(
            {"auth_state_confirmed", "auth_state_rejected", "auth_boundary",
             "anti_bot_block", "mfa_block", "session_context_bound"}
        )
    ):
        return True
    return False


# --- Impact assessment ---

def assess_impact(target: str,
                  all_findings: List[Dict[str, Any]]) -> ImpactAssessment:
    """Calcula ImpactAssessment a partir de findings agregados."""
    types = {f["type"] for f in all_findings}
    has_artifact = "session_artifact" in types
    has_replayable = "session_replayable" in types
    has_confirmed = "auth_state_confirmed" in types
    has_rejected = "auth_state_rejected" in types
    has_idp_bound = "auth_boundary" in types
    has_mfa_block = "mfa_block" in types
    has_bot_block = "anti_bot_block" in types
    has_context_bound = "session_context_bound" in types

    blocked_by: List[str] = []
    context_dependencies: List[str] = []
    severity = ImpactSeverity.INFO
    confidence = 0.5

    if has_confirmed:
        severity = ImpactSeverity.CRITICAL
        confidence = 0.95
    elif has_bot_block:
        severity = ImpactSeverity.HIGH
        blocked_by.append("anti_bot_challenge")
    elif has_mfa_block:
        severity = ImpactSeverity.HIGH
        blocked_by.append("mfa_required")
    elif has_idp_bound:
        severity = ImpactSeverity.MEDIUM
        context_dependencies.append("idp")
    elif has_context_bound:
        severity = ImpactSeverity.MEDIUM
        context_dependencies.append("context")
    elif has_rejected:
        severity = ImpactSeverity.LOW
        blocked_by.append("server_rejected")
    elif has_artifact and has_replayable:
        severity = ImpactSeverity.INFO

    # Summary.
    if has_confirmed:
        summary = "Sessao autenticada confirmada. Recomenda-se analise manual."
    elif has_bot_block:
        summary = "Replay bloqueado por anti-bot. Requer contexto adicional (proxy residencial, fingerprint preservado)."
    elif has_mfa_block:
        summary = "Replay bloqueado por MFA do IdP. Cookie sozinho nao basta."
    elif has_idp_bound:
        summary = "Sessao depende de validacao no IdP externo (ex.: Google OAuth, Auth0). API reconhece mas UI exige re-login."
    elif has_context_bound:
        summary = "Sessao depende de contexto adicional (IP/ASN, fingerprint). Cookies sozinhos nao bastam."
    elif has_rejected:
        summary = "Servidor rejeitou explicitamente os cookies. Sessao invalida/expirada."
    else:
        summary = "Evidencia insuficiente. Continue investigacao."

    return ImpactAssessment(
        severity=severity,
        confidence=confidence,
        authenticated=has_confirmed,
        artifact=has_artifact,
        replayable=has_replayable,
        blocked_by=blocked_by,
        context_dependencies=context_dependencies,
        target=target,
        summary=summary,
    )


# --- Executor ---

class AttackPlanExecutor:
    """Executa um AttackPlan phase por phase.

    Recebe callbacks injetaveis para cada phase (CLI, lab ou test).
    """

    def __init__(self, plan: AttackPlan,
                 phase_handlers: Optional[Dict[Phase, Callable]] = None):
        self.plan = plan
        self.phase_results: List[PhaseResult] = []
        self.all_findings: List[Dict[str, Any]] = []
        self.phase_handlers = phase_handlers or {}

    def register(self, phase: Phase, handler: Callable[[AttackPlan], PhaseResult]) -> None:
        """Registra handler customizado para uma phase (usado pela CLI)."""
        self.phase_handlers[phase] = handler

    def run(self) -> Dict[str, Any]:
        """Executa todas as phases em ordem, parando em stop_condition."""
        t0 = time.time()
        for phase in self.plan.phases:
            t1 = time.time()
            handler = self.phase_handlers.get(phase, self._default_handler)
            try:
                pr = handler(self.plan)
            except Exception as exc:
                pr = PhaseResult(phase=phase, ok=False, error=str(exc))
            pr.duration_sec = time.time() - t1
            self.phase_results.append(pr)
            self.all_findings.extend(pr.findings)
            # Stop condition.
            if _should_stop(self.all_findings, self.plan.stop_conditions):
                break

        # Impact assessment.
        impact = assess_impact(self.plan.target, self.all_findings)
        return {
            "plan": self.plan.to_dict(),
            "duration_sec": time.time() - t0,
            "phases": [pr.to_dict() for pr in self.phase_results],
            "findings_count": len(self.all_findings),
            "impact": impact.to_dict(),
        }

    def _default_handler(self, plan: AttackPlan) -> PhaseResult:
        """Handler default: simula phase com no-op (testes sem CLI)."""
        return PhaseResult(phase=plan.phases[0] if plan.phases else Phase.DISCOVER,
                           ok=True, findings=[], metadata={"simulated": True})


# --- Render ---

def render_plan_result(result: Dict[str, Any], include_findings: bool = False) -> str:
    """Renderiza resultado do plano em texto formatado."""
    lines = []
    plan = result["plan"]
    impact = result["impact"]

    lines.append(f"# AttackPlan: {plan.get('name') or plan['target']}")
    lines.append(f"")
    lines.append(f"  Target:   {plan['target']}")
    lines.append(f"  Phases:   {' -> '.join(plan['phases'])}")
    lines.append(f"  Stop:     {', '.join(plan['stop_conditions'])}")
    lines.append(f"  Duration: {result['duration_sec']:.1f}s")
    lines.append(f"")

    lines.append(f"## Impact Assessment")
    lines.append(f"")
    sev_color = {
        "critical": "red", "high": "red", "medium": "yellow",
        "low": "dim", "info": "dim",
    }.get(impact["severity"], "dim")
    lines.append(f"  Severity:    [{sev_color}][bold]{impact['severity'].upper()}[/bold][/{sev_color}]")
    lines.append(f"  Confidence:  {impact['confidence']:.2f}")
    lines.append(f"  Authenticated: {impact['authenticated']}")
    if impact["blocked_by"]:
        lines.append(f"  Blocked by:  {', '.join(impact['blocked_by'])}")
    if impact["context_dependencies"]:
        lines.append(f"  Dependencies: {', '.join(impact['context_dependencies'])}")
    lines.append(f"")
    lines.append(f"  [dim]{impact['summary']}[/dim]")
    lines.append(f"")

    lines.append(f"## Phases")
    for pr in result["phases"]:
        ok = "[green]OK[/]" if pr["ok"] else f"[red]FAIL[/] ({pr['error']})"
        lines.append(f"  * {pr['phase']:12} {ok:5} ({pr['duration_sec']:.1f}s, {len(pr['findings'])} findings)")

    return "\n".join(lines)
