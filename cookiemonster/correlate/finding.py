"""Finding: dataclass canonico que representa uma observacao forense
isolada de um run de replay.

O Finding e a unidade fundamental do CorrelationGraph. Cada probe
produz 1 ou mais Findings, e o correlator infere chains entre eles
(quais Findings habilitaram ou bloquearam quais).

NAO IMPLEMENTA bypass. Apenas estrutura a informacao.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Severidade do Finding (operador pode configurar thresholds)."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Engine(str, Enum):
    """Engine que produziu o Finding."""
    INGEST = "ingest"             # Fase M0
    MATCHER = "matcher"           # Fase M1
    INJECT = "inject"             # Fase M2
    VALIDATE = "validate"         # Fase M3
    REPORT = "report"             # Fase M4
    AUTH_CONTEXT = "auth_context" # M6.0
    REPLAY_MATRIX = "replay_matrix"  # M6.2
    CORRELATE = "correlate"       # M6.3


# Tipos canonicos de Finding.
class FindingType(str, Enum):
    """Tipo canonico do Finding (usado em regras de correlacao)."""
    # Artifact (M0/M1)
    SESSION_ARTIFACT = "session_artifact"           # cookie dump capturado
    SESSION_REPLAYABLE = "session_replayable"       # cookies RFC6265-matching OK

    # Auth state (M3/M6.0)
    AUTH_STATE_CONFIRMED = "auth_state_confirmed"   # AUTHENTICATED
    AUTH_STATE_REJECTED = "auth_state_rejected"     # ANONYMOUS
    AUTH_STATE_INDETERMINATE = "auth_state_indeterminate"  # INCONCLUSIVE

    # Context dependency (M6.0/M6.2)
    SESSION_CONTEXT_BOUND = "session_context_bound" # CONTEXT_BOUND
    AUTH_BOUNDARY = "auth_boundary"                 # IDP_BOUND
    MFA_BLOCK = "mfa_block"                         # MFA_BLOCKED
    ANTI_BOT_BLOCK = "anti_bot_block"               # BOT_BLOCKED

    # Replay matrix (M6.2)
    DEPENDENCY_INFERRED = "dependency_inferred"     # cookie_only/network/browser/context

    # Replay chain (M6.3)
    SESSION_REPLAY = "session_replay"               # execucao de replay (canonica)
    AUTHENTICATED_STATE = "authenticated_state"     # estado alcancado
    PROTECTED_RESOURCE = "protected_resource"       # acesso a recurso protegido


@dataclass
class Target:
    """Alvo do Finding: dominios, URL, vitima, run."""
    domain: str = ""
    url: str = ""
    victim_id: Optional[int] = None
    run_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Target":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class Condition:
    """Precondition ou constraint do Finding."""
    kind: str                          # "requires" | "blocks" | "implies"
    target_type: str                   # ex.: "session_replay", "context_dependency"
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Condition":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class Finding:
    """Unidade fundamental de observacao forense.

    Cada probe produz Findings. O correlator conecta-os via edges
    (enables, blocks_by, depends_on).
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    engine: Engine = Engine.VALIDATE
    type: FindingType = FindingType.AUTH_STATE_INDETERMINATE
    severity: Severity = Severity.INFO
    confidence: float = 0.5

    target: Target = field(default_factory=Target)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    preconditions: List[Condition] = field(default_factory=list)
    constraints: List[Condition] = field(default_factory=list)

    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Converte enums para string.
        d["engine"] = self.engine.value
        d["type"] = self.type.value
        d["severity"] = self.severity.value
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Finding":
        d = dict(d)
        if "engine" in d:
            d["engine"] = Engine(d["engine"])
        if "type" in d:
            d["type"] = FindingType(d["type"])
        if "severity" in d:
            d["severity"] = Severity(d["severity"])
        if "target" in d and isinstance(d["target"], dict):
            d["target"] = Target.from_dict(d["target"])
        if "preconditions" in d:
            d["preconditions"] = [Condition.from_dict(c) if isinstance(c, dict) else c
                                  for c in d["preconditions"]]
        if "constraints" in d:
            d["constraints"] = [Condition.from_dict(c) if isinstance(c, dict) else c
                                 for c in d["constraints"]]
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    # Helpers.
    def add_evidence(self, key: str, value: Any) -> None:
        self.evidence.append({"key": key, "value": value})

    def add_precondition(self, kind: str, target_type: str, description: str = "") -> None:
        self.preconditions.append(Condition(kind, target_type, description))

    def add_constraint(self, kind: str, target_type: str, description: str = "") -> None:
        self.constraints.append(Condition(kind, target_type, description))


# --- Builder helpers ---

def make_finding_from_run(run: Dict[str, Any]) -> List[Finding]:
    """Constroi Findings canonicos a partir de um run do store.

    Mapeia state/AuthContext para FindingType canonico.
    """
    findings: List[Finding] = []
    state = (run.get("state") or "").upper()
    if not state or state == "?":
        return findings

    target = Target(
        domain=run.get("target_domain") or "",
        url=run.get("target_url") or "",
        victim_id=run.get("victim_id"),
        run_id=run.get("id"),
    )

    state_to_type = {
        "AUTHENTICATED": (FindingType.AUTH_STATE_CONFIRMED, Severity.CRITICAL),
        "CONFIRMED": (FindingType.AUTH_STATE_CONFIRMED, Severity.CRITICAL),
        "CONTEXT_BOUND": (FindingType.SESSION_CONTEXT_BOUND, Severity.MEDIUM),
        "LIKELY": (FindingType.SESSION_CONTEXT_BOUND, Severity.MEDIUM),
        "IDP_BOUND": (FindingType.AUTH_BOUNDARY, Severity.MEDIUM),
        "MFA_BLOCKED": (FindingType.MFA_BLOCK, Severity.HIGH),
        "BOT_BLOCKED": (FindingType.ANTI_BOT_BLOCK, Severity.HIGH),
        "ANONYMOUS": (FindingType.AUTH_STATE_REJECTED, Severity.LOW),
        "INCONCLUSIVE": (FindingType.AUTH_STATE_INDETERMINATE, Severity.INFO),
        "UNKNOWN": (FindingType.AUTH_STATE_INDETERMINATE, Severity.INFO),
    }
    ftype, severity = state_to_type.get(state, (FindingType.AUTH_STATE_INDETERMINATE, Severity.INFO))

    # SESSION_ARTIFACT: sempre presente se ha run.
    findings.append(Finding(
        engine=Engine.MATCHER,
        type=FindingType.SESSION_ARTIFACT,
        severity=Severity.INFO,
        confidence=1.0,
        target=Target(**{**target.to_dict()}),
        metadata={"variant_label": run.get("variant_label") or ""},
    ))

    # SESSION_REPLAYABLE: cookie dump com match RFC 6265.
    findings.append(Finding(
        engine=Engine.MATCHER,
        type=FindingType.SESSION_REPLAYABLE,
        severity=Severity.INFO,
        confidence=run.get("confidence") or 0.5,
        target=Target(**{**target.to_dict()}),
    ))

    # SESSION_REPLAY: o run em si.
    findings.append(Finding(
        engine=Engine.INJECT,
        type=FindingType.SESSION_REPLAY,
        severity=Severity.INFO,
        confidence=run.get("confidence") or 0.5,
        target=Target(**{**target.to_dict()}),
        evidence=[{"key": "reason", "value": run.get("reason") or ""}],
    ))

    # AUTH_STATE_*: classificacao final.
    f = Finding(
        engine=Engine.AUTH_CONTEXT,
        type=ftype,
        severity=severity,
        confidence=run.get("confidence") or 0.5,
        target=Target(**{**target.to_dict()}),
        evidence=[{"key": "state", "value": state},
                  {"key": "reason", "value": run.get("reason") or ""}],
    )
    # Se CONFIRMED, marca como preconditions AUTHENTICATED_STATE.
    if ftype in (FindingType.AUTH_STATE_CONFIRMED, FindingType.SESSION_CONTEXT_BOUND):
        f.add_evidence("auth_state_reached", state)
    findings.append(f)
    return findings
