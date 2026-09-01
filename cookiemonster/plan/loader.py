"""YAML loader para AttackPlan com validacao de schema.

Formatos suportados:
- YAML completo (PyYAML).
- JSON (fallback se PyYAML nao estiver disponivel).
- Dicionario Python (testes).

Erros de schema sao reportados com linha/coluna quando possivel.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .plan import (
    AttackPlan, ReplayConfig, Phase, Transport, ContextVariantKind,
    StopCondition,
)


class PlanValidationError(Exception):
    """Erro de validacao do schema do AttackPlan."""


# --- Schema definition ---

_REQUIRED_TOP_KEYS = {"target", "phases"}
_ALLOWED_TOP_KEYS = {
    "name", "target", "artifact_source", "victim", "phases",
    "replay", "stop_conditions", "metadata",
}
_VALID_PHASES = {p.value for p in Phase}
_VALID_TRANSPORTS = {t.value for t in Transport}
_VALID_CONTEXT_VARIANTS = {v.value for v in ContextVariantKind}
_VALID_STOP_CONDITIONS = {s.value for s in StopCondition}


def _validate(data: Dict[str, Any]) -> List[str]:
    """Valida o dict. Retorna lista de erros (vazia se OK)."""
    errors: List[str] = []
    if not isinstance(data, dict):
        return [f"plan deve ser um dict, recebi {type(data).__name__}"]

    # Top-level keys.
    for key in data:
        if key not in _ALLOWED_TOP_KEYS:
            errors.append(f"chave desconhecida: {key!r}")
    for req in _REQUIRED_TOP_KEYS:
        if req not in data:
            errors.append(f"chave obrigatoria ausente: {req!r}")

    # target.
    if "target" in data and not isinstance(data["target"], str):
        errors.append(f"target deve ser str, recebi {type(data['target']).__name__}")
    elif "target" in data and not data["target"].strip():
        errors.append("target nao pode ser vazio")

    # victim.
    if "victim" in data and data["victim"] is not None:
        if not isinstance(data["victim"], int):
            errors.append(f"victim deve ser int, recebi {type(data['victim']).__name__}")

    # phases.
    if "phases" in data:
        if not isinstance(data["phases"], list):
            errors.append(f"phases deve ser list, recebi {type(data['phases']).__name__}")
        else:
            for i, p in enumerate(data["phases"]):
                if p not in _VALID_PHASES:
                    errors.append(f"phases[{i}] invalido: {p!r}; validos: {sorted(_VALID_PHASES)}")

    # replay.
    if "replay" in data:
        r = data["replay"]
        if not isinstance(r, dict):
            errors.append("replay deve ser dict")
        else:
            if "transports" in r:
                if not isinstance(r["transports"], list):
                    errors.append("replay.transports deve ser list")
                else:
                    for i, t in enumerate(r["transports"]):
                        if t not in _VALID_TRANSPORTS:
                            errors.append(f"replay.transports[{i}] invalido: {t!r}")
            if "context_variants" in r:
                if not isinstance(r["context_variants"], list):
                    errors.append("replay.context_variants deve ser list")
                else:
                    for i, v in enumerate(r["context_variants"]):
                        if v not in _VALID_CONTEXT_VARIANTS:
                            errors.append(f"replay.context_variants[{i}] invalido: {v!r}")
            if "max_wait_ms" in r and not isinstance(r["max_wait_ms"], int):
                errors.append("replay.max_wait_ms deve ser int")
            if "max_victims" in r and not isinstance(r["max_victims"], int):
                errors.append("replay.max_victims deve ser int")
            if "workers" in r and not isinstance(r["workers"], int):
                errors.append("replay.workers deve ser int")
            if "stop_when" in r and r["stop_when"] not in _VALID_STOP_CONDITIONS:
                errors.append(f"replay.stop_when invalido: {r['stop_when']!r}")

    # stop_conditions.
    if "stop_conditions" in data:
        sc = data["stop_conditions"]
        if not isinstance(sc, list):
            errors.append("stop_conditions deve ser list")
        else:
            for i, s in enumerate(sc):
                if s not in _VALID_STOP_CONDITIONS:
                    errors.append(f"stop_conditions[{i}] invalido: {s!r}")

    return errors


def load_plan(source: Union[str, Path, Dict[str, Any]]) -> AttackPlan:
    """Carrega AttackPlan de:
    - dict Python (testes)
    - str YAML
    - Path YAML/JSON
    """
    if isinstance(source, dict):
        data = source
    elif isinstance(source, (str, Path)):
        path = Path(source)
        text = path.read_text(encoding="utf-8")
        # Tenta YAML primeiro.
        try:
            import yaml  # type: ignore
            data = yaml.safe_load(text)
        except ImportError:
            # Fallback JSON.
            import json
            data = json.loads(text)
        except Exception as exc:
            raise PlanValidationError(f"falha ao parsear YAML/JSON: {exc}") from exc
    else:
        raise PlanValidationError(f"tipo nao suportado: {type(source).__name__}")

    if not isinstance(data, dict):
        raise PlanValidationError(f"top-level deve ser dict, recebi {type(data).__name__}")

    errors = _validate(data)
    if errors:
        raise PlanValidationError(
            f"schema invalido ({len(errors)} erros):\n  - "
            + "\n  - ".join(errors)
        )

    return AttackPlan.from_dict(data)


def load_plan_or_default(target: str,
                         artifact_source: str = "store.db",
                         victim: Optional[int] = None) -> AttackPlan:
    """Convenience: cria plan minimo (apenas discover+classify) para um alvo."""
    return AttackPlan(
        name=f"auto-{target}",
        target=target,
        artifact_source=artifact_source,
        victim=victim,
        phases=[Phase.DISCOVER, Phase.CLASSIFY],
    )
