"""Regras YAML customizaveis para o correlator (OPT-C).

O operador pode estender DEFAULT_RULES com regras proprias via:
  ~/.config/cookiemonster/rules.yaml
  ou --rules-file <path>

Formato YAML:
  rules:
    - if: SESSION_ARTIFACT
      then: enables SESSION_REPLAY
      label: custom rule

    - if: AUTH_BOUNDARY
      and: [SESSION_REPLAY]
      then: blocks PROTECTED_RESOURCE
      label: IdP blocks resource access
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .finding import FindingType
from .graph import Rule, DEFAULT_RULES, EdgeKind


DEFAULT_RULES_PATH = Path.home() / ".config" / "cookiemonster" / "rules.yaml"


def _coerce_finding_type(s: str) -> FindingType:
    """Converte string em FindingType (case-insensitive, aceita hyphens)."""
    s_norm = s.strip().lower().replace("-", "_")
    for ft in FindingType:
        if ft.value == s_norm:
            return ft
    raise ValueError(f"FindingType invalido: {s!r}; validos: "
                     f"{[ft.value for ft in FindingType]}")


def _coerce_edge_kind(s: str) -> EdgeKind:
    s_norm = s.strip().lower()
    for ek in EdgeKind:
        if ek.value == s_norm:
            return ek
    raise ValueError(f"EdgeKind invalido: {s!r}; validos: {[ek.value for ek in EdgeKind]}")


def _parse_rule(d: Dict[str, Any]) -> Rule:
    """Parsea uma regra de dict para Rule dataclass."""
    if not isinstance(d, dict):
        raise ValueError(f"regra deve ser dict, recebi {type(d).__name__}")
    if "if" not in d:
        raise ValueError("regra sem 'if' (tipo source)")
    if "then" not in d:
        raise ValueError("regra sem 'then' (acao + target)")

    if_type = _coerce_finding_type(d["if"])
    then_str = d["then"]
    # Formato: "enables SESSION_REPLAY" ou ["enables", "session_replay"].
    if isinstance(then_str, str):
        parts = then_str.strip().split(None, 1)
        if len(parts) != 2:
            raise ValueError(f"regra 'then' invalido: {then_str!r}; "
                             f"esperado 'kind type' (ex: 'enables SESSION_REPLAY')")
        then_kind = _coerce_edge_kind(parts[0])
        then_type = _coerce_finding_type(parts[1])
    elif isinstance(then_str, (list, tuple)) and len(then_str) == 2:
        then_kind = _coerce_edge_kind(then_str[0])
        then_type = _coerce_finding_type(then_str[1])
    else:
        raise ValueError(f"regra 'then' invalido: {then_str!r}")

    and_types = []
    if "and" in d:
        and_val = d["and"]
        if not isinstance(and_val, list):
            raise ValueError("regra 'and' deve ser list")
        and_types = [_coerce_finding_type(t) for t in and_val]

    return Rule(
        if_type=if_type,
        and_types=and_types,
        then_kind=then_kind,
        then_type=then_type,
        label=d.get("label", ""),
    )


def load_rules(source: Union[str, Path, Dict[str, Any], List]) -> List[Rule]:
    """Carrega regras de:
    - dict ({"rules": [...]})
    - list ([Rule, ...])
    - YAML/JSON file
    """
    if isinstance(source, list):
        # Lista pode ser de Rules ou de dicts.
        out = []
        for item in source:
            if isinstance(item, Rule):
                out.append(item)
            elif isinstance(item, dict):
                out.append(_parse_rule(item))
            else:
                raise ValueError(f"item de regra invalido: {type(item).__name__}")
        return out

    if isinstance(source, dict):
        if "rules" in source:
            return load_rules(source["rules"])
        # Dict com uma unica regra.
        return [_parse_rule(source)]

    if isinstance(source, (str, Path)):
        path = Path(source)
        if not path.exists():
            return []
        text = path.read_text(encoding="utf-8")
        # Tenta YAML.
        try:
            import yaml  # type: ignore
            data = yaml.safe_load(text)
        except ImportError:
            import json
            data = json.loads(text)
        return load_rules(data)

    raise ValueError(f"tipo nao suportado: {type(source).__name__}")


def merge_rules(custom: List[Rule], base: Optional[List[Rule]] = None) -> List[Rule]:
    """Combina regras custom com base (default: DEFAULT_RULES).

    Custom rules sao adicionadas APOS as base, entao tem prioridade
    em caso de duplicacao (last-write-wins no correlator).
    """
    base = base if base is not None else DEFAULT_RULES
    return list(base) + list(custom)


def load_user_rules() -> List[Rule]:
    """Carrega ~/.config/cookiemonster/rules.yaml se existir.

    Retorna lista vazia se nao existir (NAO falha).
    """
    if not DEFAULT_RULES_PATH.exists():
        return []
    try:
        return load_rules(DEFAULT_RULES_PATH)
    except Exception:
        return []


def render_rules_markdown(rules: List[Rule]) -> str:
    """Renderiza regras em formato Markdown (para documentacao)."""
    lines = ["# Custom Rules", ""]
    lines.append(f"Total: {len(rules)} rules")
    lines.append("")
    for i, r in enumerate(rules, 1):
        if_str = r.if_type.value
        and_str = " + ".join(t.value for t in r.and_types) if r.and_types else ""
        cond = f"{if_str}" + (f" + {and_str}" if and_str else "")
        then_str = f"{r.then_kind.value} {r.then_type.value}"
        label = f" ({r.label})" if r.label else ""
        lines.append(f"{i}. IF {cond} THEN {then_str}{label}")
    return "\n".join(lines)
