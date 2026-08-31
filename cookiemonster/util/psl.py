"""Public Suffix List (PSL) com cache local.

A RFC 6265 recomenda rejeitar Domain=.TLD (cookie com Domain igual a um
public suffix). Usamos a lista oficial da publicsuffix.org com cache local.

Fonte: https://publicsuffix.org/list/public_suffix_list.dat
Cache: ~/.cache/cookiemonster/public_suffix_list.dat
"""

from __future__ import annotations

import os

from pathlib import Path

PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
CACHE_DIR = Path(os.path.expanduser("~")) / ".cache" / "cookiemonster"
CACHE_FILE = CACHE_DIR / "public_suffix_list.dat"
MIN_CACHE_AGE_DAYS = 7

# Fallback minimo caso a lista nao esteja disponivel.
_FALLBACK = {
    "com", "net", "org", "edu", "gov", "mil", "int",
    "br", "us", "uk", "co.uk", "org.uk", "ac.uk", "gov.uk",
    "io", "co", "ai", "tv", "me", "dev", "app", "xyz", "info", "biz",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "de", "fr", "es", "it", "pt", "ru", "jp", "cn", "in", "au",
    "co.jp", "co.in", "co.za", "co.kr", "com.au", "com.ar", "com.mx",
    "cloud", "amazonaws.com", "github.io", "pages.dev",
}


def _download_psl() -> bool:
    """Baixa a PSL e armazena no cache. Retorna True em sucesso."""
    try:
        import urllib.request
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(PSL_URL, timeout=10) as resp:
            data = resp.read().decode("utf-8", errors="replace")
        CACHE_FILE.write_text(data, encoding="utf-8")
        return True
    except Exception:
        return False


def _cache_fresh() -> bool:
    if not CACHE_FILE.exists():
        return False
    import time
    age = time.time() - CACHE_FILE.stat().st_mtime
    return age < (MIN_CACHE_AGE_DAYS * 86400)


def _load_psl() -> set:
    if not _cache_fresh():
        _download_psl()
    if CACHE_FILE.exists():
        out = set()
        for line in CACHE_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            out.add(line.lower())
        if out:
            return out
    return set(_FALLBACK)


_PSL_CACHE: set | None = None


def psl() -> set:
    global _PSL_CACHE
    if _PSL_CACHE is None:
        _PSL_CACHE = _load_psl()
    return _PSL_CACHE


def is_public_suffix(domain: str) -> bool:
    """True se o dominio for um public suffix (ex.: 'com', 'co.uk', 'com.br')."""
    return (domain or "").lower() in psl()


def reset_cache() -> None:
    """Limpa cache local (forca re-download no proximo uso)."""
    global _PSL_CACHE
    _PSL_CACHE = None
    if CACHE_FILE.exists():
        CACHE_FILE.unlink()


__all__ = ["is_public_suffix", "reset_cache", "psl"]