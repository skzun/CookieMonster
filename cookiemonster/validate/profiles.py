"""Perfis de site para deteccao de estado autenticado.

Cada perfil define (via dataclass ClassVar):
- identity_endpoints: hints de URL para respostas JSON de identidade.
- authenticated_selectors: locators Playwright quando logado.
- anonymous_selectors: locators quando deslogado.
- body_selectors: markers textuais no body (fallback).
- login_paths: caminhos URL que indicam redirect para login.
- strong_auth_markers: markers fortes (CONFIRMED).
"""

from __future__ import annotations

import re

from dataclasses import dataclass, field
from typing import ClassVar, Dict, List, Tuple


@dataclass
class SiteProfile:
    name: ClassVar[str] = "generic"
    identity_endpoints: ClassVar[Tuple[str, ...]] = ()
    authenticated_selectors: ClassVar[Tuple[str, ...]] = ()
    anonymous_selectors: ClassVar[Tuple[str, ...]] = ()
    body_selectors: ClassVar[Tuple[str, ...]] = ()
    login_paths: ClassVar[Tuple[str, ...]] = ("/login", "/signin", "/api/signin")
    strong_auth_markers: ClassVar[Tuple[str, ...]] = ()

    def authenticated_markers(self, text: str, url: str, status: int) -> List[str]:
        return []

    def identity_keys(self) -> List[str]:
        return ["name", "displayname", "email", "account_id", "user_id"]


class GenericProfile(SiteProfile):
    name = "generic"

    identity_endpoints = ("/api/me", "/api/user", "/api/profile",
                          "/me", "/session", "/userinfo", "/whoami",
                          "/api/session", "/api/account")

    authenticated_selectors = (
        '[data-testid="user-menu"]',
        '[data-testid="user-avatar"]',
        '[data-testid="account-menu"]',
        'button[aria-label*="account" i]',
        'a[href*="/settings" i][href*="account"]',
        'a[href*="/logout" i]',
    )
    anonymous_selectors = (
        'a[href*="/login" i]',
        'a[href*="/signin" i]',
        'button:has-text("Sign in")',
        'button:has-text("Log in")',
    )
    body_selectors = (
        "logout", "sign out", "sign-out", "my account", "minha conta",
        "dashboard", "profile",
    )
    strong_auth_markers = (
        "logout", "sign out", "sign-out", "my account", "minha conta",
    )

    def authenticated_markers(self, text: str, url: str, status: int) -> List[str]:
        low = (text or "").lower()
        found: List[str] = []
        for m in self.body_selectors:
            if m in low:
                found.append(m)
        if "login" in (url or "").lower() or "signin" in (url or "").lower():
            found.append("redirect-to-login")
        if status == 403 and "login" in low:
            found.append("unauthorized")
        return found


class AmazonProfile(GenericProfile):
    name = "amazon"

    identity_endpoints = ("/auth/api/me", "/api/me", "/user/profile")
    authenticated_selectors = (
        '#nav-link-accountList',
        '#nav-flyout-ya-signout',
        '[data-nav-ref="nav_your_account"]',
    )
    anonymous_selectors = (
        '#nav-flyout-ya-signin',
        'a[href*="/ap/signin"]',
    )
    body_selectors = (
        "Hello, ", "Olá, ", "Sign Out", "Sign out",
        "Your Account", "session-token", "ubid-main", "x-main",
    )
    login_paths = ("/ap/signin",)
    strong_auth_markers = (
        "Sign Out", "Sign out", "nav-flyout-ya-signout",
        "account-holder-name",
    )

    def authenticated_markers(self, text: str, url: str, status: int) -> List[str]:
        found = super().authenticated_markers(text, url, status)
        low = (text or "")
        for m in self.body_selectors:
            if m in low:
                found.append(m)
        if "/ap/signin" in (url or "") or "/ap/signin" in low:
            found.append("signin-redirect")
        return found


class GitHubProfile(GenericProfile):
    name = "github"

    identity_endpoints = ("/api/user", "/api/v3/user", "/api/octocat")
    authenticated_selectors = (
        'img.avatar[alt]',
        '[data-octo-click="avatar_click"]',
        'summary[aria-label*="View profile"]',
        'a[href$="?tab=repositories"]',
        'a[href*="/settings/profile"]',
        'details-menu a[href$="/logout"]',
    )
    anonymous_selectors = (
        'a[href*="/login"]',
        'a[href="/signup"]',
        'form[action="/session"]',
    )
    body_selectors = (
        "Your repositories", "Your projects", "Your gists", "Your stars",
        "Signed in as", "dashboard-feed", "feed-title",
    )
    login_paths = ("/login", "/session")
    strong_auth_markers = (
        "Your repositories", "Your projects", "Signed in as",
    )


class SteamProfile(GenericProfile):
    name = "steam"

    identity_endpoints = ("/profiles/", "/api/IServiceWebAPI/IClus")
    authenticated_selectors = (
        '#account_pulldown',
        'a[href*="steamcommunity.com/id/"]',
        'span.profile_summary',
    )
    anonymous_selectors = (
        'a[href*="/login"]',
        '.loginbtn',
    )
    body_selectors = (
        "g_steamID", "AccountName", "store_sale_banner",
    )
    strong_auth_markers = ("g_steamID", "AccountName")


class SpotifyProfile(GenericProfile):
    name = "spotify"

    identity_endpoints = ("/v1/me", "/api/v1/me", "/user-profile-info")
    authenticated_selectors = (
        '[data-testid="user-widget"]',
        'a[href*="/library"]',
        'a[href*="/search"]',
        'a[href*="/settings"]',
    )
    anonymous_selectors = (
        'button[data-testid="login-button"]',
        'a[href*="/login"]',
    )
    body_selectors = (
        "your-library", "playlist-page", "your-account",
    )
    strong_auth_markers = ("your-library",)


class NetflixProfile(GenericProfile):
    name = "netflix"

    identity_endpoints = ("/api/shakti/v9f9b8b30", "/api/v1/users")
    authenticated_selectors = (
        '[data-uia="header-account"]',
        'div.profile-gate',
    )
    anonymous_selectors = (
        'a[href*="/login"]',
    )
    body_selectors = (
        "BobContext", "activeProfile", "ProfileSelector",
    )
    strong_auth_markers = ("BobContext", "activeProfile")


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