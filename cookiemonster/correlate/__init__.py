"""correlate: grafo de correlacao entre Findings (M6.3).

Modulos:
- finding: Finding dataclass canonico + builder a partir de runs.
- graph: CorrelationGraph + RuleSet + correlator + render.

Permite responder perguntas como:
  "Quais artefatos me levaram ate uma sessao autenticada?"
  "O que esta bloqueando a sessao?"

NAO IMPLEMENTA bypass. Apenas estrutura a informacao forense.
"""

from .finding import (
    Finding, Target, Condition, Engine, FindingType, Severity,
    make_finding_from_run,
)
from .graph import (
    Edge, EdgeKind, Rule, DEFAULT_RULES,
    CorrelationGraph, correlate, find_chains, render_chain,
    render_graph_markdown,
)
from .chain import (
    ChainStep, AttackChain,
    build_chains, render_chain_pretty, render_all_chains,
)
from .rules import (
    load_rules, merge_rules, load_user_rules, render_rules_markdown,
    DEFAULT_RULES_PATH,
)

__all__ = [
    "Finding", "Target", "Condition", "Engine", "FindingType", "Severity",
    "make_finding_from_run",
    "Edge", "EdgeKind", "Rule", "DEFAULT_RULES",
    "CorrelationGraph", "correlate", "find_chains", "render_chain",
    "render_graph_markdown",
    "ChainStep", "AttackChain", "build_chains",
    "render_chain_pretty", "render_all_chains",
    "load_rules", "merge_rules", "load_user_rules", "render_rules_markdown",
    "DEFAULT_RULES_PATH",
]
