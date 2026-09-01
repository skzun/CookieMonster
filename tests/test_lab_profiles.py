"""Testes do OPT-D: Lab profiles (A-G) para ambiente controlado."""

import json
import pytest

from cookiemonster.lab import (
    LabProfile, Protection, ExpectedOutcome,
    LAB_PROFILES, list_labs, get_lab,
    export_scenarios_json, render_lab_summary,
)


def test_lab_profiles_count():
    """7 labs canonicos (A-G)."""
    assert len(LAB_PROFILES) == 7
    for key in "ABCDEFG":
        assert key in LAB_PROFILES


def test_lab_a_cookie_only():
    """Lab A: cookie-only, expected AUTHENTICATED."""
    lab = get_lab("A")
    assert lab is not None
    assert lab.protection == Protection.COOKIE_ONLY
    assert lab.expected_outcome == ExpectedOutcome.AUTHENTICATED


def test_lab_b_ip_binding():
    """Lab B: IP binding, expected CONTEXT_BOUND."""
    lab = get_lab("B")
    assert lab.protection == Protection.IP_BINDING
    assert lab.expected_outcome == ExpectedOutcome.CONTEXT_BOUND
    assert lab.matrix_variant == "controlled_alternate"


def test_lab_c_device_binding():
    """Lab C: device binding, expected CONTEXT_BOUND."""
    lab = get_lab("C")
    assert lab.protection == Protection.DEVICE_BINDING
    assert lab.matrix_variant == "preserved"


def test_lab_d_oauth_front_channel():
    """Lab D: OAuth, expected IDP_BOUND."""
    lab = get_lab("D")
    assert lab.protection == Protection.OAUTH_FRONT_CHANNEL
    assert lab.expected_outcome == ExpectedOutcome.IDP_BOUND


def test_lab_e_oauth_mfa():
    """Lab E: OAuth + MFA, expected MFA_BLOCKED."""
    lab = get_lab("E")
    assert lab.protection == Protection.OAUTH_MFA
    assert lab.expected_outcome == ExpectedOutcome.MFA_BLOCKED


def test_lab_f_anti_bot():
    """Lab F: anti-bot, expected BOT_BLOCKED."""
    lab = get_lab("F")
    assert lab.protection == Protection.ANTI_BOT
    assert lab.expected_outcome == ExpectedOutcome.BOT_BLOCKED


def test_lab_g_rotating_session():
    """Lab G: rotating session, expected INCONCLUSIVE."""
    lab = get_lab("G")
    assert lab.protection == Protection.ROTATING_SESSION
    assert lab.expected_outcome == ExpectedOutcome.INCONCLUSIVE


def test_get_lab_case_insensitive():
    """get_lab aceita A ou a."""
    assert get_lab("a") is not None
    assert get_lab("B") is not None


def test_get_lab_invalid_returns_none():
    """Chave inexistente retorna None (NAO falha)."""
    assert get_lab("Z") is None
    assert get_lab("X") is None


def test_list_labs_returns_7_in_order():
    """list_labs retorna 7 labs em ordem alfabetica."""
    labs = list_labs()
    assert len(labs) == 7
    keys = [lab.name[4] for lab in labs]  # "Lab A - ..."
    assert keys == ["A", "B", "C", "D", "E", "F", "G"]


def test_lab_to_from_dict():
    """Round-trip preserva campos canonicos."""
    lab = get_lab("D")
    d = lab.to_dict()
    assert d["protection"] == "oauth_front_channel"
    assert d["expected_outcome"] == "idp_bound"
    lab2 = LabProfile.from_dict(d)
    assert lab2.protection == Protection.OAUTH_FRONT_CHANNEL
    assert lab2.expected_outcome == ExpectedOutcome.IDP_BOUND


def test_export_scenarios_json_is_valid_json():
    """export_scenarios_json retorna JSON valido com 7 labs."""
    js = export_scenarios_json()
    data = json.loads(js)
    assert data["version"] == "1.0"
    assert len(data["labs"]) == 7


def test_render_lab_summary_includes_all_labs():
    """render_lab_summary produz tabela Markdown."""
    md = render_lab_summary()
    assert "Lab Profiles" in md
    for key in "ABCDEFG":
        assert f"| {key} " in md or f"| {key} |" in md
    # Headers.
    assert "Protection" in md
    assert "Expected Outcome" in md


def test_each_lab_has_unique_protection():
    """Cada lab tem protection unica (para diversidade)."""
    protections = [lab.protection for lab in list_labs()]
    assert len(set(protections)) == 7


def test_each_lab_has_at_least_3_distinct_outcomes():
    """Cobertura: pelo menos 3 outcomes distintos em 7 labs."""
    outcomes = [lab.expected_outcome for lab in list_labs()]
    assert len(set(outcomes)) >= 3  # B/C = CONTEXT_BOUND, resto sao distintos
