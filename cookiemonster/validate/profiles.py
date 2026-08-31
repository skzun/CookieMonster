"""Perfis de site para deteccao de estado autenticado.

Cada perfil define:
- markers (sinais gerais, baseline vs injetado)
- strong_auth_markers (sinais especificos que so aparecem logados)
- identity_keys (chaves esperadas em JSON com identidade do usuario)
"""

from __future__ import annotations

import re

from typing import Dict, List


class SiteProfile:
    name = "generic"

    def authenticated_markers(self, text: str, url: str, status: int) -> List[str]:
        raise NotImplementedError

    def strong_auth_markers(self) -> List[str]:
        return []

    def identity_keys(self) -> List[str]:
        return ["name", "displayname", "email", "account_id", "user_id", "login"]


class GenericProfile(SiteProfile):
    name = "generic"

    _AUTH_MARKERS = [
        "logout", "log out", "sign out", "sign-out", "sair",
        "my account", "minha conta", "account settings",
        "dashboard", "painel", "profile", "perfil", "settings",
        "\"logged_in\":true", "\"authenticated\":true", "\"isloggedin\":true",
    ]

    def authenticated_markers(self, text: str, url: str, status: int) -> List[str]:
        low = (text or "").lower()
        found = []
        for m in self._AUTH_MARKERS:
            if m in low:
                found.append(m)
        if "login" in (url or "").lower() or "signin" in (url or "").lower():
            found.append("redirect-to-login")
        if status == 403 and "login" in low:
            found.append("unauthorized")
        return found

    def strong_auth_markers(self) -> List[str]:
        return ["logout", "sign out", "sign-out", "my account", "minha conta",
                "\"logged_in\":true", "\"authenticated\":true"]


class AmazonProfile(GenericProfile):
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
        if "/ap/signin" in (url or "") or "/ap/signin" in low:
            found.append("signin-redirect")
        return found

    def strong_auth_markers(self) -> List[str]:
        return ["Sign Out", "nav-flyout-ya-signout", "account-holder-name",
                "nav-flyout-ya-signin"]


class GitHubProfile(GenericProfile):
    """Sinais especificos do GitHub (renderizados via JS)."""

    name = "github"

    _GITHUB_MARKERS = [
        # O DOM do GitHub logado contem:
        # - Botao com label do usuario / avatar (data-octo-click="...").
        # - Links "Your repositories", "Your projects", "Your gists".
        # - cookie logged_in=yes implicito (jsession).
        "Your repositories", "Your projects", "Your gists",
        "Your stars", "Your codespaces",
        "dashboard-feed",  # dashboard do GitHub logado
        "feed-title",  # feed de atividade pessoal
        "feed-item-content",  # itens de feed pessoal
        "user-profile-link",
        "Signed in as",  # texto na sidebar
        "Sign out", "Sign Out",
    ]

    def authenticated_markers(self, text: str, url: str, status: int) -> List[str]:
        found = super().authenticated_markers(text, url, status)
        for m in self._GITHUB_MARKERS:
            if m in (text or ""):
                found.append(m)
        return found

    def strong_auth_markers(self) -> List[str]:
        return ["Your repositories", "Sign out", "Sign Out",
                "Signed in as", "dashboard-feed"]


class SteamProfile(GenericProfile):
    name = "steam"

    _STEAM_MARKERS = [
        "g_steamID", "g_sessionID", "g_access_token", "g_SteamID",
        "PersonalName", "AccountName",
        "youraccount_",  # nomes de classes
        "store_sale_banner",  # renderizado para logado
    ]

    def authenticated_markers(self, text: str, url: str, status: int) -> List[str]:
        found = super().authenticated_markers(text, url, status)
        for m in self._STEAM_MARKERS:
            if m in (text or ""):
                found.append(m)
        return found

    def strong_auth_markers(self) -> List[str]:
        return ["g_steamID", "AccountName"]


class SpotifyProfile(GenericProfile):
    name = "spotify"

    _SPOTIFY_MARKERS = [
        "your-library", "playlist-page", "user-profile",
        "sp-username",  # placeholder de acordo com profile
        "account-settings-link",
        "Sign out", "Sign Out",
    ]

    def authenticated_markers(self, text: str, url: str, status: int) -> List[str]:
        found = super().authenticated_markers(text, url, status)
        for m in self._SPOTIFY_MARKERS:
            if m in (text or ""):
                found.append(m)
        return found

    def strong_auth_markers(self) -> List[str]:
        return ["your-library", "Sign out", "Sign Out"]


class NetflixProfile(GenericProfile):
    name = "netflix"

    _NETFLIX_MARKERS = [
        "ProfileSelector", "BobContext", "activeProfile",
        "Sign out", "Sign Out", "accountMenu",
    ]

    def authenticated_markers(self, text: str, url: str, status: int) -> List[str]:
        found = super().authenticated_markers(text, url, status)
        for m in self._NETFLIX_MARKERS:
            if m in (text or ""):
                found.append(m)
        return found

    def strong_auth_markers(self) -> List[str]:
        return ["BobContext", "activeProfile", "Sign out"]


_REGISTRY: Dict[str, SiteProfile] = {}


def register_profile(domain: str, profile: SiteProfile) -> None:
    _REGISTRY[(domain or "").strip().rstrip(".").lower()] = profile


def get_profile(domain: str) -> SiteProfile:
    d = (domain or "").strip().rstrip(".").lower()
    custom = _REGISTRY.get(d)
    if custom is not None:
        return custom
    if d == "amazon.com" or d.startswith("amazon."):
        return AmazonProfile()
    if d == "github.com" or d.endswith(".github.com") or d == "github.io":
        return GitHubProfile()
    if d == "steamcommunity.com" or d.endswith(".steamcommunity.com"):
        return SteamProfile()
    if d == "spotify.com" or d.endswith(".spotify.com"):
        return SpotifyProfile()
    if d == "netflix.com" or d.endswith(".netflix.com"):
        return NetflixProfile()
    return GenericProfile()


PROFILES: Dict[str, SiteProfile] = {
    "generic": GenericProfile(),
    "amazon": AmazonProfile(),
    "github": GitHubProfile(),
    "steam": SteamProfile(),
    "spotify": SpotifyProfile(),
    "netflix": NetflixProfile(),
}

__all__ = [
    "SiteProfile", "GenericProfile", "AmazonProfile", "GitHubProfile",
    "SteamProfile", "SpotifyProfile", "NetflixProfile",
    "get_profile", "register_profile", "PROFILES",
]