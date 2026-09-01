"""Testes de integracao do OPT-B: StealthProfile -> Playwright context."""

from unittest.mock import MagicMock, patch
import pytest

from cookiemonster.stealth import (
    StealthProfile, load_stealth_profile, list_builtin_profiles,
)


def test_stealth_profile_init_scripts_contain_canvas_noise():
    """Canvas noise: HTMLCanvasElement.toDataURL monkey-patch."""
    p = StealthProfile(name="noise", canvas_noise=True)
    scripts = p.to_playwright_init_scripts()
    assert any("HTMLCanvasElement.prototype.toDataURL" in s for s in scripts)


def test_stealth_profile_init_scripts_contain_webgl_mask():
    """WebGL mask: UNMASKED_VENDOR/RENDERER_WEBGL substituidos."""
    p = StealthProfile(name="webgl", webgl_noise=True)
    scripts = p.to_playwright_init_scripts()
    assert any("WebGLRenderingContext" in s and "37445" in s for s in scripts)
    assert any("Intel" in s for s in scripts)


def test_stealth_profile_init_scripts_contain_font_mask():
    """Font mask: navigator.fonts stub."""
    p = StealthProfile(name="font", font_mask=True)
    scripts = p.to_playwright_init_scripts()
    assert any("navigator" in s and "fonts" in s for s in scripts)


def test_stealth_profile_combined_all_features():
    """Todos os flags ativados: scripts contem canvas+webgl+font+UA."""
    p = StealthProfile(
        name="all",
        canvas_noise=True,
        webgl_noise=True,
        font_mask=True,
        ua_override="Custom UA",
    )
    scripts = p.to_playwright_init_scripts()
    joined = "\n".join(scripts)
    assert "HTMLCanvasElement" in joined
    assert "WebGLRenderingContext" in joined
    assert "navigator" in joined
    assert "Custom UA" in joined


def test_replay_function_signature_accepts_init_scripts():
    """replay() tem parametro init_scripts na assinatura."""
    import inspect
    from cookiemonster.inject.playwright_client import replay
    sig = inspect.signature(replay)
    assert "init_scripts" in sig.parameters
    # Default None.
    assert sig.parameters["init_scripts"].default is None


def test_replay_calls_add_init_script_when_scripts_provided():
    """replay() chama context.add_init_script() para cada script."""
    from cookiemonster.inject import playwright_client

    fake_cookies = [{"name": "session", "value": "abc", "domain": "x.com",
                     "path": "/", "secure": True, "http_only": True,
                     "expires_epoch": 0, "same_site": "lax"}]
    scripts_to_inject = ["// script 1", "// script 2"]

    with patch("cookiemonster.inject.playwright_client.sync_playwright") as mock_pw:
        mock_browser = MagicMock()
        mock_context = MagicMock()
        mock_browser.new_context.return_value = mock_context
        mock_pw.return_value.__enter__.return_value.chromium.launch.return_value = mock_browser

        # mock para _to_playwright_cookies
        with patch.object(playwright_client, "_to_playwright_cookies",
                          return_value=[{"name": "session", "value": "abc"}]):
            with patch.object(playwright_client, "probe") as mock_probe:
                with patch.object(playwright_client, "context_options",
                                  return_value={}):
                    mock_probe.return_value = {"ready": True, "evidence": {},
                                              "text": "", "cookie_jar": [],
                                              "api_responses_inspected": [],
                                              "console_errors": [],
                                              "request_failures": [],
                                              "redirect_chain": []}
                    playwright_client.replay("https://x.com/", fake_cookies,
                                            init_scripts=scripts_to_inject,
                                            max_wait_ms=1000)

    # Verifica que add_init_script foi chamado para cada script.
    assert mock_context.add_init_script.call_count == 2
    calls = mock_context.add_init_script.call_args_list
    assert calls[0].args[0] == "// script 1"
    assert calls[1].args[0] == "// script 2"


def test_replay_does_not_call_add_init_script_when_no_scripts():
    """replay() NAO chama add_init_script se init_scripts=None ou vazio."""
    from cookiemonster.inject import playwright_client

    fake_cookies = [{"name": "session", "value": "abc", "domain": "x.com",
                     "path": "/", "secure": True, "http_only": True,
                     "expires_epoch": 0, "same_site": "lax"}]

    with patch("cookiemonster.inject.playwright_client.sync_playwright") as mock_pw:
        mock_browser = MagicMock()
        mock_context = MagicMock()
        mock_browser.new_context.return_value = mock_context
        mock_pw.return_value.__enter__.return_value.chromium.launch.return_value = mock_browser

        with patch.object(playwright_client, "_to_playwright_cookies",
                          return_value=[{"name": "session", "value": "abc"}]):
            with patch.object(playwright_client, "probe") as mock_probe:
                with patch.object(playwright_client, "context_options",
                                  return_value={}):
                    mock_probe.return_value = {"ready": True, "evidence": {},
                                              "text": "", "cookie_jar": [],
                                              "api_responses_inspected": [],
                                              "console_errors": [],
                                              "request_failures": [],
                                              "redirect_chain": []}
                    playwright_client.replay("https://x.com/", fake_cookies,
                                            max_wait_ms=1000)

    # add_init_script NAO foi chamado.
    assert mock_context.add_init_script.call_count == 0


def test_stealth_profile_json_round_trip_preserves_flags():
    """StealthProfile -> JSON -> StealthProfile preserva todos os flags."""
    p = StealthProfile(
        name="test",
        canvas_noise=True,
        webgl_noise=True,
        font_mask=True,
        ua_override="custom",
    )
    import json
    js = json.dumps(p.to_dict())
    p2 = StealthProfile.from_dict(json.loads(js))
    assert p2.canvas_noise is True
    assert p2.webgl_noise is True
    assert p2.font_mask is True
    assert p2.ua_override == "custom"


def test_stealth_builtin_lab_full_stealth_produces_all_scripts():
    """lab-full-stealth built-in produz canvas+webgl+font scripts."""
    profiles = list_builtin_profiles()
    full = profiles["lab-full-stealth"]
    scripts = full.to_playwright_init_scripts()
    joined = "\n".join(scripts)
    assert "HTMLCanvasElement" in joined
    assert "WebGLRenderingContext" in joined
    # Font script: usa sintaxe Object.defineProperty(navigator, 'fonts', ...).
    assert "fonts" in joined and "navigator" in joined
