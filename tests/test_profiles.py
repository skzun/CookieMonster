"""Testes dos perfis de site adicionais."""

from cookiemonster.validate.profiles import (
    GitHubProfile, SteamProfile, SpotifyProfile, NetflixProfile,
    GenericProfile, get_profile,
)
from cookiemonster.domain.selection import (
    classify_name, is_auth_candidate,
)


def test_github_strong_auth_markers():
    p = GitHubProfile()
    assert "Your repositories" in list(p.strong_auth_markers)


def test_github_detects_dashboard():
    p = GitHubProfile()
    markers = p.authenticated_markers("dashboard-feed Signed in as user",
                                      "https://github.com/", 200)
    assert "dashboard-feed" in markers or "Signed in as" in markers


def test_steam_strong_auth_markers():
    p = SteamProfile()
    assert "g_steamID" in list(p.strong_auth_markers)


def test_spotify_strong_auth_markers():
    p = SpotifyProfile()
    assert "your-library" in list(p.strong_auth_markers)


def test_netflix_strong_auth_markers():
    p = NetflixProfile()
    assert "BobContext" in list(p.strong_auth_markers)


def test_get_profile_dispatches_to_specific():
    assert isinstance(get_profile("github.com"), GitHubProfile)
    assert isinstance(get_profile("steamcommunity.com"), SteamProfile)
    assert isinstance(get_profile("spotify.com"), SpotifyProfile)
    assert isinstance(get_profile("netflix.com"), NetflixProfile)
    assert isinstance(get_profile("example.com"), GenericProfile)


def test_classify_github_cookies():
    assert is_auth_candidate("logged_in")
    assert is_auth_candidate("_octo")
    assert is_auth_candidate("dotcom_user")
    assert is_auth_candidate("saved_user_sessions")


def test_classify_steam_cookies():
    assert is_auth_candidate("sessionid")
    assert is_auth_candidate("steamLoginSecure")


def test_classify_spotify_cookies():
    assert is_auth_candidate("sp_adid") or is_auth_candidate("sp_t") \
        or classify_name("sp_t") in ("auth", "anon")


def test_classify_anon_still_anon():
    assert classify_name("i18n-prefs") == "anon"
    assert not is_auth_candidate("i18n-prefs")