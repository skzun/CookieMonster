"""AttackPlan: dataclass canonico para orquestracao declarativa de
ataque reproduzido.

Em vez de chamar `probe`, `probe-all`, `matrix`, `correlate`
separadamente, o operador descreve o PLANO em YAML e o executor
monta a cadeia de comandos.

Estrutura YAML (exemplo):
  target: chatgpt.com
  artifact_source: store.db
  victim: 1939                # opcional; default = melhor vitima
  phases:
    - discover
    - classify
    - replay
    - observe
    - correlate
  replay:
    transports: [http, browser]
    context_variants: [default, controlled_alternate]
    max_wait_ms: 10000
  stop_conditions:
    - authenticated
    - blocked
    - inconclusive

NAO IMPLEMENTA bypass. Apenas orquestra.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class Phase(str, Enum):
    """Fases do AttackPlan (executadas em ordem)."""
    DISCOVER = "discover"   # lista vitimas, conta cookies por dominio
    CLASSIFY = "classify"   # roda probe canonico (1 vitima) e AuthContext
    REPLAY = "replay"       # roda probe-all (N vitimas) + matrix
    OBSERVE = "observe"     # access headed (1 vitima CONFIRMED)
    CORRELATE = "correlate" # gera grafo M6.3 dos runs


class Transport(str, Enum):
    """Transporte de replay."""
    HTTP = "http"
    BROWSER = "browser"


class ContextVariantKind(str, Enum):
    """Variante de contexto (subset de M6.2)."""
    DEFAULT = "default"
    CONTROLLED_ALTERNATE = "controlled_alternate"
    PRESERVED = "preserved"


class StopCondition(str, Enum):
    """Quando parar a execucao."""
    AUTHENTICATED = "authenticated"  # encontrou sessao CONFIRMED
    BLOCKED = "blocked"              # bot/mfa/anonimo consistente
    INCONCLUSIVE = "inconclusive"    # sem dados suficientes


class ImpactSeverity(str, Enum):
    """Severidade final do plano (calculada a partir de findings)."""
    INFO = "info"             # sem acesso confirmado
    LOW = "low"               # rejeitado
    MEDIUM = "medium"         # context/idp bound (sessao parcial)
    HIGH = "high"             # ANTI_BOT/MFA block (protecao forte)
    CRITICAL = "critical"     # AUTHENTICATED real


# --- Sub-dataclasses ---

@dataclass
class ReplayConfig:
    """Configuracao da fase replay."""
    transports: List[Transport] = field(default_factory=lambda: [Transport.HTTP])
    context_variants: List[ContextVariantKind] = field(
        default_factory=lambda: [ContextVariantKind.DEFAULT])
    max_wait_ms: int = 6000
    max_victims: int = 0          # 0 = todas
    workers: int = 3
    stop_when: StopCondition = StopCondition.AUTHENTICATED

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["transports"] = [t.value for t in self.transports]
        d["context_variants"] = [v.value for v in self.context_variants]
        d["stop_when"] = self.stop_when.value
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ReplayConfig":
        d = dict(d)
        d["transports"] = [Transport(t) for t in d.get("transports", ["http"])]
        d["context_variants"] = [ContextVariantKind(v)
                                  for v in d.get("context_variants", ["default"])]
        d["stop_when"] = StopCondition(d.get("stop_when", "authenticated"))
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class AttackPlan:
    """Plano de ataque reproduzido.

    Descreve COMO o operador quer reproduzir a cadeia:
    - target: qual dominio.
    - artifact_source: onde estao os cookies (default: store.db).
    - victim: vitima especifica (None = melhor).
    - phases: lista ordenada de Phase.
    - replay: ReplayConfig com transports e context_variants.
    - stop_conditions: quando parar cedo.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    target: str = ""
    artifact_source: str = "store.db"
    victim: Optional[int] = None
    phases: List[Phase] = field(default_factory=lambda: [
        Phase.DISCOVER, Phase.CLASSIFY, Phase.REPLAY, Phase.OBSERVE, Phase.CORRELATE,
    ])
    replay: ReplayConfig = field(default_factory=ReplayConfig)
    stop_conditions: List[StopCondition] = field(
        default_factory=lambda: [StopCondition.AUTHENTICATED, StopCondition.BLOCKED])
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["phases"] = [p.value for p in self.phases]
        d["stop_conditions"] = [s.value for s in self.stop_conditions]
        d["replay"] = self.replay.to_dict()
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AttackPlan":
        d = dict(d)
        d["phases"] = [Phase(p) for p in d.get("phases", [])]
        d["stop_conditions"] = [StopCondition(s)
                                for s in d.get("stop_conditions", [])]
        d["replay"] = ReplayConfig.from_dict(d.get("replay", {}))
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})
