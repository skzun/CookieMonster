"""Testes do OPT-C: regras YAML customizadas para correlator."""

import json
import pytest
from pathlib import Path

from cookiemonster.correlate import (
    Finding, FindingType, Severity, Target,
    Edge, EdgeKind, Rule, DEFAULT_RULES, CorrelationGraph,
    load_rules, merge_rules, load_user_rules, render_rules_markdown,
    DEFAULT_RULES_PATH,
)


def test_load_rules_from_dict_with_rules_key():
    """load_rules aceita {"rules": [...]}."""
    rules = load_rules({
        "rules": [
            {"if": "SESSION_ARTIFACT", "then": "enables SESSION_REPLAY",
             "label": "test rule"},
        ]
    })
    assert len(rules) == 1
    assert rules[0].if_type == FindingType.SESSION_ARTIFACT
    assert rules[0].then_kind == EdgeKind.ENABLES
    assert rules[0].then_type == FindingType.SESSION_REPLAY
    assert rules[0].label == "test rule"


def test_load_rules_from_list_of_dicts():
    """load_rules aceita lista de dicts."""
    rules = load_rules([
        {"if": "AUTH_BOUNDARY", "then": "blocks AUTHENTICATED_STATE"},
    ])
    assert len(rules) == 1
    assert rules[0].if_type == FindingType.AUTH_BOUNDARY
    assert rules[0].then_kind == EdgeKind.BLOCKS


def test_load_rules_from_yaml_file(tmp_path):
    """load_rules carrega de arquivo YAML."""
    yaml_path = tmp_path / "rules.yaml"
    yaml_path.write_text("""
rules:
  - if: SESSION_ARTIFACT
    then: enables SESSION_REPLAY
    label: custom
  - if: AUTH_BOUNDARY
    and: [SESSION_REPLAY]
    then: blocks PROTECTED_RESOURCE
    label: idp blocks resource
""")
    rules = load_rules(yaml_path)
    assert len(rules) == 2
    assert rules[0].if_type == FindingType.SESSION_ARTIFACT
    assert rules[1].and_types == [FindingType.SESSION_REPLAY]


def test_load_rules_invalid_type_raises():
    """Tipo invalido levanta ValueError."""
    with pytest.raises(ValueError):
        load_rules(123)


def test_load_rules_invalid_finding_type_raises():
    """FindingType invalido levanta ValueError."""
    with pytest.raises(ValueError):
        load_rules({"if": "INVALID_TYPE", "then": "enables SESSION_REPLAY"})


def test_load_rules_invalid_edge_kind_raises():
    """EdgeKind invalido levanta ValueError."""
    with pytest.raises(ValueError):
        load_rules({"if": "SESSION_ARTIFACT", "then": "explodes SESSION_REPLAY"})


def test_load_rules_missing_if_raises():
    """Regra sem 'if' levanta erro."""
    with pytest.raises(ValueError):
        load_rules({"then": "enables SESSION_REPLAY"})


def test_load_rules_then_format_must_be_two_parts():
    """then precisa ser 'kind type'."""
    with pytest.raises(ValueError):
        load_rules({"if": "SESSION_ARTIFACT", "then": "enables"})


def test_load_rules_accepts_camelcase():
    """Accepta camelCase (uaOverride)."""
    rules = load_rules({
        "if": "SESSION_ARTIFACT", "then": "enables SESSION_REPLAY",
        "uaOverride": "test",  # camelCase
    })
    assert len(rules) == 1


def test_merge_rules_combines_base_and_custom():
    """merge_rules adiciona custom APOS base (last-write-wins)."""
    custom = [Rule(if_type=FindingType.SESSION_ARTIFACT,
                   then_kind=EdgeKind.ENABLES,
                   then_type=FindingType.SESSION_REPLAY,
                   label="custom")]
    merged = merge_rules(custom)
    # Base tem 10 regras (DEFAULT_RULES), +1 custom = 11.
    assert len(merged) == len(DEFAULT_RULES) + 1
    # Custom e o ultimo.
    assert merged[-1].label == "custom"


def test_merge_rules_with_custom_base():
    """merge_rules aceita base custom (substitui DEFAULT)."""
    base = [Rule(if_type=FindingType.SESSION_ARTIFACT,
                 then_kind=EdgeKind.ENABLES, then_type=FindingType.SESSION_REPLAY)]
    custom = [Rule(if_type=FindingType.AUTH_BOUNDARY,
                   then_kind=EdgeKind.BLOCKS, then_type=FindingType.AUTHENTICATED_STATE)]
    merged = merge_rules(custom, base=base)
    assert len(merged) == 2


def test_load_user_rules_returns_empty_when_file_missing(tmp_path, monkeypatch):
    """load_user_rules retorna [] se ~/.config/... nao existe."""
    # Monkeypatch DEFAULT_RULES_PATH para um caminho inexistente.
    import cookiemonster.correlate.rules as rules_mod
    monkeypatch.setattr(rules_mod, "DEFAULT_RULES_PATH", tmp_path / "nonexistent.yaml")
    result = load_user_rules()
    assert result == []


def test_render_rules_markdown_includes_all_rules():
    """render_rules_markdown produz Markdown legivel."""
    rules = [Rule(if_type=FindingType.SESSION_ARTIFACT,
                  then_kind=EdgeKind.ENABLES,
                  then_type=FindingType.SESSION_REPLAY,
                  label="test rule")]
    md = render_rules_markdown(rules)
    assert "# Custom Rules" in md
    assert "1. IF" in md
    assert "enables session_replay" in md
    assert "test rule" in md


def test_default_rules_path_is_under_config_dir():
    """DEFAULT_RULES_PATH aponta para ~/.config/cookiemonster/."""
    assert "cookiemonster" in str(DEFAULT_RULES_PATH)
    assert ".yaml" in str(DEFAULT_RULES_PATH) or ".yml" in str(DEFAULT_RULES_PATH) or "rules" in str(DEFAULT_RULES_PATH)
