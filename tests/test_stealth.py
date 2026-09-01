"""Testes do OPT-B: StealthProfile + loaders."""

import json
import pytest
from pathlib import Path

from cookiemonster.stealth import (
    StealthProfile, load_stealth_profile, list_builtin_profiles,
)


def test_stealth_profile_default_values():
    """Profile tem defaults seguros (risco medio, sem nada ativo)."""
    p = StealthProfile(name="test")
    assert p.name == "test"
    assert p.risk == "medium"
    assert p.canvas_noise is False
    assert p.webgl_noise is False
    assert p.font_mask is False
    assert p.init_scripts == []


def test_stealth_profile_to_from_dict():
    """Round-trip preserva campos."""
    p = StealthProfile(
        name="custom",
        description="test profile",
        risk="high",
        canvas_noise=True,
        webgl_noise=True,
        ua_override="Mozilla/5.0 custom",
    )
    d = p.to_dict()
    p2 = StealthProfile.from_dict(d)
    assert p2.name == "custom"
    assert p2.risk == "high"
    assert p2.canvas_noise is True
    assert p2.webgl_noise is True
    assert p2.ua_override == "Mozilla/5.0 custom"


def test_load_stealth_profile_from_dict():
    """load aceita dict Python."""
    p = load_stealth_profile({
        "name": "from_dict",
        "risk": "low",
        "canvas_noise": True,
    })
    assert p.name == "from_dict"
    assert p.canvas_noise is True


def test_load_stealth_profile_from_json(tmp_path):
    """load aceita arquivo JSON."""
    json_path = tmp_path / "stealth.json"
    json_path.write_text(json.dumps({
        "name": "from_json",
        "risk": "low",
        "webgl_noise": True,
    }))
    p = load_stealth_profile(json_path)
    assert p.name == "from_json"
    assert p.webgl_noise is True


def test_to_playwright_init_scripts_includes_noise_when_enabled():
    """canvas_noise=True produz script de noise na lista."""
    p = StealthProfile(name="noise", canvas_noise=True)
    scripts = p.to_playwright_init_scripts()
    assert any("HTMLCanvasElement" in s for s in scripts)


def test_to_playwright_init_scripts_webgl():
    """webgl_noise=True produz script WebGL."""
    p = StealthProfile(name="webgl", webgl_noise=True)
    scripts = p.to_playwright_init_scripts()
    assert any("WebGLRenderingContext" in s for s in scripts)


def test_to_playwright_init_scripts_ua_override():
    """ua_override produz script de override do navigator.userAgent."""
    p = StealthProfile(name="ua", ua_override="Custom UA")
    scripts = p.to_playwright_init_scripts()
    assert any("userAgent" in s and "Custom UA" in s for s in scripts)


def test_to_playwright_init_scripts_minimal_when_nothing_enabled():
    """Sem nada habilitado, scripts fica vazio."""
    p = StealthProfile(name="plain")
    scripts = p.to_playwright_init_scripts()
    assert scripts == []


def test_builtin_profiles_are_loaded():
    """list_builtin_profiles retorna templates opt-in."""
    profiles = list_builtin_profiles()
    assert "lab-canvas-noise" in profiles
    assert "lab-webgl-mask" in profiles
    assert "lab-full-stealth" in profiles
    # Todos marcados como LAB.
    for name, p in profiles.items():
        assert "lab" in p.required_authorization.lower()


def test_builtin_profile_risk_levels():
    """Builtin profiles tem risk apropriado."""
    profiles = list_builtin_profiles()
    assert profiles["lab-canvas-noise"].risk == "low"
    assert profiles["lab-webgl-mask"].risk == "low"
    assert profiles["lab-full-stealth"].risk == "medium"


def test_load_invalid_type_raises():
    """load com tipo invalido levanta erro."""
    with pytest.raises(ValueError):
        load_stealth_profile(123)  # int nao suportado


def test_init_scripts_are_preserved_in_order():
    """init_scripts do usuario sao preservados (vindos antes dos canonicos)."""
    p = StealthProfile(
        name="custom",
        init_scripts=["// custom 1", "// custom 2"],
        canvas_noise=True,
    )
    scripts = p.to_playwright_init_scripts()
    assert scripts[0] == "// custom 1"
    assert scripts[1] == "// custom 2"
    # Canvas noise vem depois.
    assert any("HTMLCanvasElement" in s for s in scripts[2:])
