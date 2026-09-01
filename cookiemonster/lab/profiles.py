"""Lab profiles (OPT-D): ambientes propositalmente vulneraveis para
estudar session protection em condicoes controladas.

Cada Lab representa um cenario realista de binding/evasion:
  Lab A: cookie-only session
  Lab B: cookie + IP binding
  Lab C: cookie + device binding
  Lab D: OAuth front-channel (Google-like mock)
  Lab E: OAuth + MFA
  Lab F: anti-bot challenge (Cloudflare-like)
  Lab G: rotating session (server-side rotation por request)

Os Labs NAO sao implementados aqui (serao servidos por um lab target
separado em docs/labs/). Este modulo apenas define os PROFILES
documentando o que cada lab testa, e fornece o lab_scenarios.json
com a configuracao esperada.

Uso:
  python -m cookiemonster probe-all --domain lab.example --allow-unsafe-scope
  # (com lab target rodando em :8080)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class Protection(str, Enum):
    """Tipo de protecao testada em cada Lab."""
    COOKIE_ONLY = "cookie_only"
    IP_BINDING = "ip_binding"
    DEVICE_BINDING = "device_binding"
    OAUTH_FRONT_CHANNEL = "oauth_front_channel"
    OAUTH_MFA = "oauth_mfa"
    ANTI_BOT = "anti_bot"
    ROTATING_SESSION = "rotating_session"


class ExpectedOutcome(str, Enum):
    """O que esperamos ver no CookieMonster para cada Lab."""
    AUTHENTICATED = "authenticated"      # cookies reproduzem a sessao
    CONTEXT_BOUND = "context_bound"       # depende de contexto
    IDP_BOUND = "idp_bound"              # depende de validacao IdP
    MFA_BLOCKED = "mfa_blocked"          # IdP exige MFA
    BOT_BLOCKED = "bot_blocked"          # anti-bot challenge
    INCONCLUSIVE = "inconclusive"         # dados insuficientes


@dataclass
class LabProfile:
    """Perfil de um lab environment."""
    name: str
    description: str
    protection: Protection
    expected_outcome: ExpectedOutcome
    target_url: str = "http://lab.example/"
    notes: str = ""
    matrix_variant: str = "default"  # network/browser context para usar

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["protection"] = self.protection.value
        d["expected_outcome"] = self.expected_outcome.value
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "LabProfile":
        d = dict(d)
        d["protection"] = Protection(d["protection"])
        d["expected_outcome"] = ExpectedOutcome(d["expected_outcome"])
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# --- Os 7 labs canonicos ---

LAB_PROFILES: Dict[str, LabProfile] = {
    "A": LabProfile(
        name="Lab A - cookie only",
        description="Servidor aceita qualquer cookie valido. "
                    "Sem IP/device/anti-bot binding.",
        protection=Protection.COOKIE_ONLY,
        expected_outcome=ExpectedOutcome.AUTHENTICATED,
        notes="Baseline. Replay direto deve AUTHENTICATED em todas as variants.",
    ),
    "B": LabProfile(
        name="Lab B - cookie + IP binding",
        description="Servidor exige IP do login original. Cookie em outro IP rejeita.",
        protection=Protection.IP_BINDING,
        expected_outcome=ExpectedOutcome.CONTEXT_BOUND,
        matrix_variant="controlled_alternate",
        notes="Replicas via SOCKS5 no IP da vitima = AUTHENTICATED. "
              "Replicas de outro IP = ANONYMOUS ou CONTEXT_BOUND.",
    ),
    "C": LabProfile(
        name="Lab C - cookie + device binding",
        description="Servidor exige fingerprint do navegador original.",
        protection=Protection.DEVICE_BINDING,
        expected_outcome=ExpectedOutcome.CONTEXT_BOUND,
        matrix_variant="preserved",
        notes="Replicas com fingerprint preservado = AUTHENTICATED. "
              "Default = CONTEXT_BOUND ou ANONYMOUS.",
    ),
    "D": LabProfile(
        name="Lab D - OAuth front-channel",
        description="Server valida tokens via IdP mock (Google-like). "
                    "Cookie sozinho nao basta; API reconhece, UI exige re-auth.",
        protection=Protection.OAUTH_FRONT_CHANNEL,
        expected_outcome=ExpectedOutcome.IDP_BOUND,
        notes="CookieMonster deve classificar como IDP_BOUND com reason 'identity_provider_boundary:*'.",
    ),
    "E": LabProfile(
        name="Lab E - OAuth + MFA",
        description="IdP exige MFA. Cookie sozinho nao basta.",
        protection=Protection.OAUTH_MFA,
        expected_outcome=ExpectedOutcome.MFA_BLOCKED,
        notes="CookieMonster deve classificar como MFA_BLOCKED com mfa_challenge detectado.",
    ),
    "F": LabProfile(
        name="Lab F - anti-bot challenge",
        description="Server retorna challenge JS (Cloudflare-like) antes de aceitar request.",
        protection=Protection.ANTI_BOT,
        expected_outcome=ExpectedOutcome.BOT_BLOCKED,
        notes="CookieMonster deve classificar como BOT_BLOCKED com bot_challenge detectado.",
    ),
    "G": LabProfile(
        name="Lab G - rotating session",
        description="Server invalida cookie apos N requests (forca re-login).",
        protection=Protection.ROTATING_SESSION,
        expected_outcome=ExpectedOutcome.INCONCLUSIVE,
        notes="CookieMonster deve classificar como INCONCLUSIVE com hint 'session_token'.",
    ),
}


# --- Exports ---

def list_labs() -> List[LabProfile]:
    """Retorna todos os labs em ordem alfabetica."""
    return [LAB_PROFILES[k] for k in sorted(LAB_PROFILES)]


def get_lab(key: str) -> Optional[LabProfile]:
    """Retorna lab por chave ('A'..'G')."""
    return LAB_PROFILES.get(key.upper())


def export_scenarios_json() -> str:
    """Exporta todos os labs como JSON (para lab target separado)."""
    data = {
        "version": "1.0",
        "labs": [lab.to_dict() for lab in list_labs()],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


def render_lab_summary() -> str:
    """Renderiza tabela resumo dos labs."""
    lines = ["# Lab Profiles (A-G)\n"]
    lines.append("Cada lab propositalmente vulneravel a um tipo de "
                 "session protection para validar deteccoes CookieMonster.\n")
    lines.append("| Lab | Protection | Expected Outcome | Notes |")
    lines.append("|-----|------------|------------------|-------|")
    for key in sorted(LAB_PROFILES):
        lab = LAB_PROFILES[key]
        notes = (lab.notes[:60] + "...") if len(lab.notes) > 63 else lab.notes
        lines.append(f"| {key} | {lab.protection.value:25} | "
                     f"{lab.expected_outcome.value:18} | {notes} |")
    return "\n".join(lines)
