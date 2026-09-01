"""Testes do M7: AttackPlan, loader, executor, impact."""

import pytest
from pathlib import Path

from cookiemonster.plan import (
    AttackPlan, ReplayConfig, Phase, Transport, ContextVariantKind,
    StopCondition, ImpactSeverity,
    load_plan, load_plan_or_default, PlanValidationError,
    AttackPlanExecutor, PhaseResult, ImpactAssessment,
    assess_impact, render_plan_result, _should_stop,
)


# --- AttackPlan ---

def test_attack_plan_default_values():
    """Plan com defaults razoaveis."""
    p = AttackPlan(target="x.com")
    assert p.target == "x.com"
    assert p.artifact_source == "store.db"
    assert p.victim is None
    assert Phase.DISCOVER in p.phases
    assert Phase.CORRELATE in p.phases
    assert p.replay.max_wait_ms == 6000


def test_attack_plan_to_from_dict():
    """Plan round-trip preserva campos canonicos."""
    p = AttackPlan(
        name="test",
        target="x.com",
        victim=42,
        phases=[Phase.DISCOVER, Phase.CLASSIFY],
        stop_conditions=[StopCondition.AUTHENTICATED],
    )
    d = p.to_dict()
    assert d["name"] == "test"
    assert d["victim"] == 42
    assert d["phases"] == ["discover", "classify"]
    assert d["stop_conditions"] == ["authenticated"]
    p2 = AttackPlan.from_dict(d)
    assert p2.target == "x.com"
    assert p2.victim == 42


def test_replay_config_to_from_dict():
    """ReplayConfig round-trip."""
    rc = ReplayConfig(
        transports=[Transport.HTTP, Transport.BROWSER],
        context_variants=[ContextVariantKind.DEFAULT, ContextVariantKind.CONTROLLED_ALTERNATE],
        max_wait_ms=10000,
        max_victims=5,
    )
    d = rc.to_dict()
    assert d["transports"] == ["http", "browser"]
    assert d["context_variants"] == ["default", "controlled_alternate"]
    rc2 = ReplayConfig.from_dict(d)
    assert rc2.transports == [Transport.HTTP, Transport.BROWSER]
    assert rc2.max_wait_ms == 10000


# --- Loader ---

def test_load_plan_from_dict():
    """load_plan aceita dict Python."""
    plan = load_plan({
        "target": "x.com",
        "phases": ["discover", "classify"],
        "replay": {"transports": ["http"]},
    })
    assert plan.target == "x.com"
    assert plan.phases == [Phase.DISCOVER, Phase.CLASSIFY]


def test_load_plan_validates_required_target():
    """Loader rejeita plan sem target."""
    with pytest.raises(PlanValidationError) as exc:
        load_plan({"phases": ["discover"]})
    assert "target" in str(exc.value)


def test_load_plan_validates_phases_values():
    """Loader rejeita phase invalida."""
    with pytest.raises(PlanValidationError) as exc:
        load_plan({"target": "x.com", "phases": ["unknown_phase"]})
    assert "invalido" in str(exc.value)


def test_load_plan_validates_replay_transports():
    """Loader rejeita transport invalido."""
    with pytest.raises(PlanValidationError) as exc:
        load_plan({
            "target": "x.com",
            "phases": ["discover"],
            "replay": {"transports": ["spaceship"]},
        })
    assert "invalido" in str(exc.value)


def test_load_plan_from_yaml_file(tmp_path):
    """load_plan carrega de arquivo YAML."""
    import yaml
    yaml_path = tmp_path / "plan.yaml"
    yaml_path.write_text(yaml.safe_dump({
        "target": "y.com",
        "phases": ["discover", "classify", "replay"],
        "stop_conditions": ["authenticated"],
    }))
    plan = load_plan(yaml_path)
    assert plan.target == "y.com"
    assert Phase.REPLAY in plan.phases
    assert StopCondition.AUTHENTICATED in plan.stop_conditions


def test_load_plan_or_default_creates_minimal():
    """load_plan_or_default gera plan minimo (discover+classify)."""
    plan = load_plan_or_default("z.com", artifact_source="custom.db", victim=99)
    assert plan.target == "z.com"
    assert plan.artifact_source == "custom.db"
    assert plan.victim == 99
    assert plan.phases == [Phase.DISCOVER, Phase.CLASSIFY]


# --- Stop conditions ---

def test_should_stop_authenticated():
    """Para quando auth_state_confirmed esta presente."""
    findings = [{"type": "auth_state_confirmed"}]
    assert _should_stop(findings, [StopCondition.AUTHENTICATED]) is True


def test_should_stop_anti_bot():
    """Para quando anti_bot_block esta presente."""
    findings = [{"type": "anti_bot_block"}]
    assert _should_stop(findings, [StopCondition.BLOCKED]) is True


def test_should_stop_no_match():
    """Nao para se nenhuma condition casa."""
    findings = [{"type": "auth_state_indeterminate"}]
    assert _should_stop(findings, [StopCondition.AUTHENTICATED]) is False


# --- Impact assessment ---

def test_assess_impact_critical_when_confirmed():
    """Sessao confirmada -> CRITICAL."""
    findings = [
        {"type": "session_artifact"},
        {"type": "session_replayable"},
        {"type": "auth_state_confirmed"},
    ]
    impact = assess_impact("x.com", findings)
    assert impact.severity == ImpactSeverity.CRITICAL
    assert impact.authenticated is True
    assert impact.confidence == 0.95


def test_assess_impact_high_for_bot_block():
    """Bot block -> HIGH com blocked_by."""
    findings = [{"type": "anti_bot_block"}]
    impact = assess_impact("x.com", findings)
    assert impact.severity == ImpactSeverity.HIGH
    assert "anti_bot_challenge" in impact.blocked_by


def test_assess_impact_medium_for_idp_bound():
    """IDP bound -> MEDIUM com context_dependencies."""
    findings = [{"type": "auth_boundary"}]
    impact = assess_impact("x.com", findings)
    assert impact.severity == ImpactSeverity.MEDIUM
    assert "idp" in impact.context_dependencies


def test_assess_impact_low_for_rejected():
    """Rejected -> LOW."""
    findings = [{"type": "auth_state_rejected"}]
    impact = assess_impact("x.com", findings)
    assert impact.severity == ImpactSeverity.LOW


# --- Executor ---

def test_executor_runs_all_phases_with_default_handler():
    """Executor roda todas phases e retorna result."""
    plan = AttackPlan(target="x.com", phases=[Phase.DISCOVER, Phase.CLASSIFY])
    executor = AttackPlanExecutor(plan)
    result = executor.run()
    assert len(result["phases"]) == 2
    assert result["findings_count"] == 0
    assert "impact" in result


def test_executor_custom_handler_produces_findings():
    """Handler customizado injeta findings."""
    plan = AttackPlan(target="x.com", phases=[Phase.DISCOVER])

    def my_handler(p):
        return PhaseResult(
            phase=Phase.DISCOVER, ok=True,
            findings=[{"type": "auth_state_confirmed"}],
        )
    executor = AttackPlanExecutor(plan)
    executor.register(Phase.DISCOVER, my_handler)
    result = executor.run()
    assert result["impact"]["authenticated"] is True
    assert result["impact"]["severity"] == "critical"


def test_executor_stops_at_authenticated():
    """Para no AUTHENTICATED mesmo com mais phases na fila."""
    plan = AttackPlan(
        target="x.com",
        phases=[Phase.DISCOVER, Phase.REPLAY, Phase.CORRELATE],
        stop_conditions=[StopCondition.AUTHENTICATED],
    )

    def fake_discover(p):
        return PhaseResult(
            phase=Phase.DISCOVER, ok=True,
            findings=[{"type": "auth_state_confirmed"}],
        )

    def fake_replay(p):
        return PhaseResult(phase=Phase.REPLAY, ok=True, findings=[])

    def fake_correlate(p):
        return PhaseResult(phase=Phase.CORRELATE, ok=True, findings=[])

    executor = AttackPlanExecutor(plan)
    executor.register(Phase.DISCOVER, fake_discover)
    executor.register(Phase.REPLAY, fake_replay)
    executor.register(Phase.CORRELATE, fake_correlate)
    result = executor.run()
    # Para apos DISCOVER (authenticated encontrado).
    assert len(result["phases"]) == 1
    assert result["phases"][0]["phase"] == "discover"


def test_executor_handler_exception_becomes_failed_phase():
    """Exception no handler vira PhaseResult com ok=False."""
    plan = AttackPlan(target="x.com", phases=[Phase.DISCOVER])

    def broken(p):
        raise RuntimeError("network down")

    executor = AttackPlanExecutor(plan)
    executor.register(Phase.DISCOVER, broken)
    result = executor.run()
    assert result["phases"][0]["ok"] is False
    assert "network down" in result["phases"][0]["error"]


# --- Render ---

def test_render_plan_result_includes_severity():
    """render_plan_result inclui severity do impact."""
    plan = AttackPlan(target="x.com")
    executor = AttackPlanExecutor(plan)
    result = executor.run()
    text = render_plan_result(result)
    assert "AttackPlan" in text
    assert "Impact Assessment" in text
    assert "Severity" in text
    assert "Phases" in text
