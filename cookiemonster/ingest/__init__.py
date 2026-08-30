"""Orquestracao da ingestao de dumps de cookies.

Descobre os arquivos de cookies dentro de cada pasta de vitima (sempre sob uma
pasta de nome `Cookies`, case-insensitive), detecta o formato (Netscape vs JSON)
e persiste no store SQLite de forma idempotente.
"""

from __future__ import annotations

import re

from pathlib import Path
from typing import List, Tuple

from ..store.db import Store
from .json_parser import parse_json_file
from .netscape_parser import parse_file_with_stats

_TRAILING_SALT_RE = re.compile(r"\[[A-Fa-f0-9]{4}\]$")


def collect_cookie_files(victim_dir: Path) -> List[Path]:
    files = []
    for path in victim_dir.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in (".txt", ".json"):
            continue
        parents = path.relative_to(victim_dir).parts[:-1]
        if any(part.lower() == "cookies" for part in parents):
            files.append(path)
    return sorted(files)


def detect_layout(victim_dir: Path) -> str:
    for child in victim_dir.iterdir():
        if child.is_dir() and child.name.lower() == "browser":
            return "Browser/Cookies"
        if child.is_dir() and child.name.lower() == "browsers":
            return "Browsers/Cookies"
    return "Cookies"


def _looks_like_json(path: Path) -> bool:
    if path.suffix.lower() == ".json":
        return True
    # Alguns .txt contem JSON (ex.: "<nome>_json.txt" com "[[{...}]]").
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        head = handle.read(256)
    head = head.lstrip()
    return bool(head) and not head.startswith("#") and head[:1] in "[{"


def parse_cookie_file(path: Path) -> List:
    if _looks_like_json(path):
        return parse_json_file(path), 0, True
    cookies, malformed = parse_file_with_stats(path)
    return cookies, malformed, False


def split_browser_profile(stem: str) -> Tuple[str, str]:
    """Heuristica para extrair (browser, profile) do nome do arquivo."""
    name = stem.strip()
    if name.lower().startswith("cookies_"):
        name = name[len("cookies_"):]

    bracket_profile = re.search(r"\[([^\]]*)\]", name)
    if bracket_profile:
        inner = bracket_profile.group(1)
        name = name[: bracket_profile.start()].rstrip("_")
        browser, base_profile = _split_base(name)
        if re.fullmatch(r"(Default|Profile \d+|\d+)", inner.strip(), re.IGNORECASE):
            return browser, inner.strip()
        return browser, base_profile

    name = _TRAILING_SALT_RE.sub("", name)
    return _split_base(name)


def _split_base(name: str) -> Tuple[str, str]:
    m = re.search(r"_(Profile\s+\d+|Default)$", name, re.IGNORECASE)
    if m:
        return name[: m.start()], m.group(1)
    return name, ""


def ingest_dir(store: Store, source_dir: Path, sample: int = 0,
               resume: bool = False, progress_every: int = 200) -> dict:
    source_dir = Path(source_dir)
    victim_dirs = sorted(p for p in source_dir.iterdir() if p.is_dir())
    if sample:
        victim_dirs = victim_dirs[:sample]

    existing = set() if not resume else store.existing_dir_names()

    stats = {
        "victims": len(victim_dirs),
        "files": 0,
        "cookies": 0,
        "json_files": 0,
        "malformed_lines": 0,
        "skipped": 0,
        "errors": [],
    }

    with store.batch() as conn:
        for index, victim_dir in enumerate(victim_dirs, start=1):
            if resume and victim_dir.name in existing:
                stats["skipped"] += 1
            else:
                try:
                    _ingest_victim(conn, store, victim_dir, stats)
                except Exception as exc:
                    conn.rollback()
                    stats["errors"].append(f"{victim_dir.name}: {exc}")

            if index % progress_every == 0 or index == len(victim_dirs):
                conn.commit()
                print(f"[{index}/{len(victim_dirs)}] cookies={stats['cookies']} "
                      f"arquivos={stats['files']} pulados={stats['skipped']} "
                      f"erros={len(stats['errors'])}", flush=True)

    return stats


def _ingest_victim(conn, store: Store, victim_dir: Path, stats: dict) -> None:
    layout = detect_layout(victim_dir)
    files = collect_cookie_files(victim_dir)
    victim_id = store.upsert_victim(
        conn, victim_dir.name, layout, str(victim_dir), wipe=True
    )
    if victim_id is None:
        stats["errors"].append(f"{victim_dir.name}: erro ao criar registro")
        return

    for file_path in files:
        browser, profile = split_browser_profile(file_path.stem)
        parsed, malformed, is_json = parse_cookie_file(file_path)
        if is_json:
            stats["json_files"] += 1
        stats["malformed_lines"] += malformed
        stats["files"] += 1
        if parsed:
            rows = [c.as_row(victim_id, browser, profile, file_path.name)
                    for c in parsed]
            store.insert_cookies(conn, rows)
            stats["cookies"] += len(rows)

    store.recompute_domains(conn, victim_id)