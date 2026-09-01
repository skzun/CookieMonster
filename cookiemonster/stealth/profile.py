"""Stealth/Bypass profile loader (OPT-B).

Arquitetura: profiles sao arquivos YAML opt-in carregados pelo
operador explicitamente. NAO estao no core (defesa em profundidade:
o usuario precisa carregar manualmente, e cada profile declara
claramente o que faz).

Cada profile define:
- name: identificador
- description: o que faz
- risk: "low" | "medium" | "high" (operador deve revisar)
- required_authorization: texto livre que o operador deve preencher
- init_scripts: lista de JavaScript a injetar via context.add_init_script
- header_overrides: dict de headers HTTP customizados
- ua_overrides: User-Agent customizado
- canvas_noise: bool - randomizar canvas fingerprint
- webgl_noise: bool - randomizar WebGL fingerprint
- font_mask: bool - mascarar fontes do sistema

Uso:
  python -m cookiemonster --stealth-profile ~/.config/cookiemonster/stealth/lab.json probe --domain lab.example
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class StealthProfile:
    """Perfil de stealth/bypass carregavel (opt-in)."""
    name: str
    description: str = ""
    risk: str = "medium"  # low | medium | high
    required_authorization: str = ""
    init_scripts: List[str] = field(default_factory=list)
    header_overrides: Dict[str, str] = field(default_factory=dict)
    ua_override: Optional[str] = None
    canvas_noise: bool = False
    webgl_noise: bool = False
    font_mask: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "StealthProfile":
        d = dict(d)
        # Compat: snake_case ou camelCase.
        d["ua_override"] = d.get("ua_override") or d.get("uaOverride")
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    def to_playwright_init_scripts(self) -> List[str]:
        """Combina os init_scripts canonicos (canvas/WebGL/UA)
        com os do profile. Retorna lista de strings JS."""
        scripts = list(self.init_scripts)
        if self.canvas_noise:
            scripts.append(_CANVAS_NOISE_JS)
        if self.webgl_noise:
            scripts.append(_WEBGL_NOISE_JS)
        if self.font_mask:
            scripts.append(_FONT_MASK_JS)
        if self.ua_override:
            scripts.append(f"Object.defineProperty(navigator, 'userAgent', {{get: () => {json.dumps(self.ua_override)}}});")
        return scripts


# JavaScript canonicos (nao maliciousos, apenas randomizacao passiva).
_CANVAS_NOISE_JS = """
// Canvas fingerprint noise (adiciona ruido minimo a toDataURL).
(function() {
  const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function(type) {
    const ctx = this.getContext('2d');
    if (ctx) {
      const imageData = ctx.getImageData(0, 0, this.width, this.height);
      for (let i = 0; i < imageData.data.length; i += 4) {
        imageData.data[i] = imageData.data[i] ^ (Math.random() < 0.5 ? 0 : 1);
      }
      ctx.putImageData(imageData, 0, 0);
    }
    return originalToDataURL.apply(this, arguments);
  };
})();
"""

_WEBGL_NOISE_JS = """
// WebGL renderer noise (mascara GPU vendor/renderer).
(function() {
  const getParameter = WebGLRenderingContext.prototype.getParameter;
  WebGLRenderingContext.prototype.getParameter = function(param) {
    if (param === 37445) return 'Intel Inc.';  // UNMASKED_VENDOR_WEBGL
    if (param === 37446) return 'Intel Iris OpenGL Engine';  // UNMASKED_RENDERER_WEBGL
    return getParameter.apply(this, arguments);
  };
})();
"""

_FONT_MASK_JS = """
// Font enumeration mitigation (substitui fontes detectaveis).
(function() {
  Object.defineProperty(navigator, 'fonts', {
    get: () => ({
      check: () => true,
      load: () => Promise.resolve([]),
      ready: Promise.resolve(),
    }),
  });
})();
"""


# --- Loader ---

def load_stealth_profile(source: "str | Path | dict") -> StealthProfile:
    """Carrega perfil de dict, JSON file ou YAML file."""
    if isinstance(source, dict):
        return StealthProfile.from_dict(source)
    if isinstance(source, (str, Path)):
        path = Path(source)
        text = path.read_text(encoding="utf-8")
        # Tenta JSON primeiro.
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Fallback YAML.
            try:
                import yaml
                data = yaml.safe_load(text)
            except ImportError as exc:
                raise ValueError(
                    f"perfil {path} nao e JSON valido e PyYAML nao esta instalado: {exc}"
                )
        if not isinstance(data, dict):
            raise ValueError(f"perfil {path} deve ser dict, recebi {type(data).__name__}")
        return StealthProfile.from_dict(data)
    raise ValueError(f"tipo nao suportado: {type(source).__name__}")


def list_builtin_profiles() -> Dict[str, StealthProfile]:
    """Retorna profiles built-in (templates opt-in, NAO ativos por default)."""
    return {
        "lab-canvas-noise": StealthProfile(
            name="lab-canvas-noise",
            description="Canvas fingerprint noise (adiciona ruido minimo). "
                        "Para uso em LAB com autorizacao.",
            risk="low",
            required_authorization="lab",
            canvas_noise=True,
        ),
        "lab-webgl-mask": StealthProfile(
            name="lab-webgl-mask",
            description="Mascara WebGL vendor/renderer para evitar fingerprint.",
            risk="low",
            required_authorization="lab",
            webgl_noise=True,
        ),
        "lab-full-stealth": StealthProfile(
            name="lab-full-stealth",
            description="Canvas + WebGL + Font masking. Para LAB de anti-bot.",
            risk="medium",
            required_authorization="lab",
            canvas_noise=True,
            webgl_noise=True,
            font_mask=True,
        ),
    }
