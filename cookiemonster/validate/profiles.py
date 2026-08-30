"""Perfis de site para detecção de estado autenticado.

Cada perfil define como detectar, na resposta de um alvo, sinais de sessao
autenticada. O fallback generico cobre sinais comuns a qualquer site.
"""

from __future__ import annotations

from typing import Dict, List


class SiteProfile:
    """Contrato de um perfil: recebe o resumo do replay e devolve evidências."""

    name = "generic"

    def authenticated_markers(self, text: str, url: str, status: int) -> List[str]:
        raise NotImplementedError

    def authenticated_patterns(self) -> List[str]:
        return []


class GenericProfile(SiteProfile):
    """Sinais comuns de sessao autenticada em qualquer site."""

    name = "generic"

    _AUTH_MARKERS = [
        "logout", "sign out", "sign-out", "log out", "sair", "encerrar sessao",
        "my account", "minha conta", "account settings", "conta",
        "dashboard", "painel", "profile", "perfil", "settings", "configuracoes",
    ]
    _AUTH_SUBSTRINGS = [
        "account_name", "user_name", "username", "display_name", "customer_name",
        "\"logged_in\":true", "\"authenticated\":true", "\"isLoggedIn\":true",
        "signed_in", "\"email\"", "\"name\":",
    ]

    def authenticated_markers(self, text: str, url: str, status: int) -> List[str]:
        low = (text or "").lower()
        found = []
        for m in self._AUTH_MARKERS:
            if m in low:
                found.append(m)
        for s in self._AUTH_SUBSTRINGS:
            if s.lower() in low:
                found.append(s)
        if "login" in url.lower() or "signin" in url.lower():
            found.append("redirect-to-login")
        if status == 403 and "login" in low:
            found.append("unauthorized")
        return found


class AmazonProfile(GenericProfile):
    """Sinais especificos da Amazon (markers de conta logada)."""

    name = "amazon"

    _AMAZON_MARKERS = [
        "Hello, ", "Olá, ", "Sign Out", "Sign out", "Your Account",
        "nav-flyout-ya-signin", "nav-link-accountList",
        "session-token", "ubid-main", "x-main",
    ]

    def authenticated_markers(self, text: str, url: str, status: int) -> List[str]:
        found = super().authenticated_markers(text, url, status)
        low = (text or "")
        for m in self._AMAZON_MARKERS:
            if m in low:
                found.append(m)
        # Amazon redireciona para /ap/signin quando nao autenticado.
        if "/ap/signin" in (url or "") or "/ap/signin" in (text or ""):
            found.append("signin-redirect")
        return found


def get_profile(domain: str) -> SiteProfile:
    """Retorna o perfil apropriado para um dominio (com fallback generico)."""
    d = (domain or "").strip().rstrip(".").lower()
    if d == "amazon.com" or d.startswith("amazon."):
        return AmazonProfile()
    return GenericProfile()


PROFILES: Dict[str, SiteProfile] = {
    "generic": GenericProfile(),
    "amazon": AmazonProfile(),
}

__all__ = ["SiteProfile", "GenericProfile", "AmazonProfile", "get_profile", "PROFILES"]