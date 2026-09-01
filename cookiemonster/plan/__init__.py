"""plan: orquestracao declarativa de ataque (M7).

Modulos:
- plan: AttackPlan, ReplayConfig, enums (Phase, Transport, etc).
- loader: YAML loader com validacao.
- executor: AttackPlanExecutor que executa phases e gera Impact.
"""

from .plan import (
    AttackPlan, ReplayConfig, Phase, Transport, ContextVariantKind,
    StopCondition, ImpactSeverity,
)
from .loader import (
    load_plan, load_plan_or_default, PlanValidationError,
)
from .executor import (
    AttackPlanExecutor, PhaseResult, ImpactAssessment,
    assess_impact, render_plan_result, _should_stop,
)

__all__ = [
    "AttackPlan", "ReplayConfig", "Phase", "Transport",
    "ContextVariantKind", "StopCondition", "ImpactSeverity",
    "load_plan", "load_plan_or_default", "PlanValidationError",
    "AttackPlanExecutor", "PhaseResult", "ImpactAssessment",
    "assess_impact", "render_plan_result", "_should_stop",
]
