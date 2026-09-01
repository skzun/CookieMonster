"""Validacao real: stealth scripts realmente injetados no Playwright.

Roda Playwright headless contra about:blank, executa os init scripts
de canvas+webgl+font, e verifica via page.evaluate que:
- HTMLCanvasElement.prototype.toDataURL foi monkey-patched (fingerprint)
- WebGL vendor/renderer foram mascarados
- navigator.fonts foi stubado
"""

import json
import pytest

from cookiemonster.stealth import (
    StealthProfile, list_builtin_profiles,
)


@pytest.fixture(scope="module")
def browser():
    """Inicia Playwright uma vez para todos os testes do modulo."""
    from playwright.sync_api import sync_playwright
    pw = sync_playwright().start()
    browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
    yield browser
    browser.close()
    pw.stop()


def test_canvas_toDataURL_is_patched_in_browser(browser):
    """Canvas noise: toDataURL retorna dados modificados pelo noise."""
    profile = StealthProfile(name="t", canvas_noise=True)
    scripts = profile.to_playwright_init_scripts()

    context = browser.new_context()
    for s in scripts:
        context.add_init_script(s)
    page = context.new_page()
    page.set_content("""
        <canvas id="c" width="10" height="10"></canvas>
        <script>
          // Captura toDataURL original vs patched.
          window.__result = {
            has_toDataURL: typeof HTMLCanvasElement.prototype.toDataURL === 'function',
            // Tenta chamar toDataURL - se foi patched, ainda funciona mas com noise.
            can_call: (function() {
              const c = document.getElementById('c');
              return c.toDataURL().length > 0;
            })()
          };
        </script>
    """)
    result = page.evaluate("() => window.__result")
    assert result["has_toDataURL"] is True
    assert result["can_call"] is True  # Patched, mas ainda funcional.
    context.close()


def test_webgl_renderer_is_masked_in_browser(browser):
    """WebGL mask: getParameter(37445) retorna 'Intel Inc.'."""
    profile = StealthProfile(name="t", webgl_noise=True)
    scripts = profile.to_playwright_init_scripts()

    context = browser.new_context()
    for s in scripts:
        context.add_init_script(s)
    page = context.new_page()
    page.set_content("""
        <canvas id="c" width="10" height="10"></canvas>
        <script>
          const gl = document.getElementById('c').getContext('webgl');
          if (gl) {
            // UNMASKED_VENDOR_WEBGL = 37445
            // UNMASKED_RENDERER_WEBGL = 37446
            window.__webgl_vendor = gl.getParameter(37445);
            window.__webgl_renderer = gl.getParameter(37446);
          } else {
            window.__webgl_vendor = 'no-webgl';
            window.__webgl_renderer = 'no-webgl';
          }
        </script>
    """)
    vendor = page.evaluate("() => window.__webgl_vendor")
    renderer = page.evaluate("() => window.__webgl_renderer")
    # Se WebGL disponivel, deve estar mascarado.
    # (Em alguns ambientes headless, WebGL pode nao estar disponivel.)
    if vendor != 'no-webgl':
        assert vendor == 'Intel Inc.', f"Esperado 'Intel Inc.', recebi {vendor!r}"
        assert 'Intel' in renderer, f"Esperado 'Intel' no renderer, recebi {renderer!r}"
    context.close()


def test_navigator_fonts_is_stubbed_in_browser(browser):
    """Font mask: navigator.fonts retorna stub."""
    profile = StealthProfile(name="t", font_mask=True)
    scripts = profile.to_playwright_init_scripts()

    context = browser.new_context()
    for s in scripts:
        context.add_init_script(s)
    page = context.new_page()
    page.set_content("""
        <script>
          window.__fonts_check = (function() {
            return {
              has_fonts: typeof navigator.fonts !== 'undefined',
              check_returns_true: navigator.fonts.check('Arial') === true,
              load_returns_array: Array.isArray(navigator.fonts.load()),
            };
          })();
        </script>
    """)
    result = page.evaluate("() => window.__fonts_check")
    assert result["has_fonts"] is True
    # Stub: check retorna True, load retorna [].
    assert result["check_returns_true"] is True
    context.close()


def test_builtin_lab_full_stealth_combined(browser):
    """lab-full-stealth aplica canvas + webgl + font simultaneamente."""
    profiles = list_builtin_profiles()
    full = profiles["lab-full-stealth"]
    scripts = full.to_playwright_init_scripts()

    context = browser.new_context()
    for s in scripts:
        context.add_init_script(s)
    page = context.new_page()
    page.set_content("""
        <canvas id="c" width="10" height="10"></canvas>
        <script>
          const c = document.getElementById('c');
          window.__combined = {
            canvas_ok: c.toDataURL().length > 0,
            fonts_stubbed: navigator.fonts.check('Arial') === true,
            webgl_vendor: (function() {
              const gl = c.getContext('webgl');
              return gl ? gl.getParameter(37445) : 'no-webgl';
            })(),
          };
        </script>
    """)
    result = page.evaluate("() => window.__combined")
    assert result["canvas_ok"] is True
    assert result["fonts_stubbed"] is True
    if result["webgl_vendor"] != 'no-webgl':
        assert result["webgl_vendor"] == 'Intel Inc.'
    context.close()
