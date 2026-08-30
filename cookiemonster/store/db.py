"""Acesso ao store SQLite."""

from __future__ import annotations

import sqlite3
import threading

from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


class Store:
    def __init__(self, db_path):
        self.path = str(db_path)
        self._lock = threading.Lock()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def init(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(_SCHEMA_PATH.read_text(encoding="utf-8"))
            conn.commit()
        finally:
            conn.close()

    @contextmanager
    def batch(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = OFF")
            conn.execute("PRAGMA temp_store = MEMORY")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ---- ingest ----

    def upsert_victim(self, conn: sqlite3.Connection, dir_name: str,
                      layout: str, path: str, wipe: bool = False) -> Optional[int]:
        row = conn.execute(
            "SELECT id FROM victims WHERE dir_name = ?", (dir_name,)
        ).fetchone()
        if row is not None:
            if wipe:
                conn.execute("DELETE FROM victims WHERE id = ?", (row["id"],))
            else:
                return row["id"]
        cur = conn.execute(
            "INSERT INTO victims (dir_name, source_layout, path, ingested_at)"
            " VALUES (?, ?, ?, ?)",
            (dir_name, layout, path, datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )
        return cur.lastrowid

    def insert_cookies(self, conn: sqlite3.Connection, rows: list) -> None:
        conn.executemany(
            "INSERT INTO cookies (victim_id, browser, profile, name, value, domain,"
            " path, secure, host_only, http_only, expires_epoch, source_file)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )

    def recompute_domains(self, conn: sqlite3.Connection, victim_id: int) -> None:
        conn.execute("DELETE FROM domains WHERE victim_id = ?", (victim_id,))
        conn.execute(
            "INSERT INTO domains (victim_id, domain, cookie_count, auth_candidates)"
            " SELECT victim_id, domain, COUNT(*), 0"
            " FROM cookies WHERE victim_id = ? GROUP BY domain",
            (victim_id,),
        )

    # ---- consultas ----

    def list_victims(self) -> list:
        conn = self._connect()
        try:
            return conn.execute(
                "SELECT v.id, v.dir_name, v.source_layout,"
                " (SELECT COUNT(*) FROM cookies c WHERE c.victim_id = v.id) AS cookie_count,"
                " (SELECT COUNT(*) FROM domains d WHERE d.victim_id = v.id) AS domain_count"
                " FROM victims v ORDER BY v.id"
            ).fetchall()
        finally:
            conn.close()

    def existing_dir_names(self) -> set:
        conn = self._connect()
        try:
            return {r["dir_name"] for r in conn.execute("SELECT dir_name FROM victims")}
        finally:
            conn.close()

    def count_cookies(self) -> int:
        conn = self._connect()
        try:
            return conn.execute("SELECT COUNT(*) AS n FROM cookies").fetchone()["n"]
        finally:
            conn.close()

    def list_domains(self, victim_id: Optional[int] = None, domain: Optional[str] = None) -> list:
        query = (
            "SELECT d.domain, d.cookie_count, d.auth_candidates, v.id AS victim_id,"
            " v.dir_name FROM domains d JOIN victims v ON v.id = d.victim_id"
        )
        clauses = []
        params = []
        if victim_id is not None:
            clauses.append("d.victim_id = ?")
            params.append(victim_id)
        if domain:
            clauses.append("(d.domain = ? OR d.domain LIKE ?)")
            params.extend([domain, "%." + domain])
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY d.cookie_count DESC LIMIT 500"
        conn = self._connect()
        try:
            return conn.execute(query, params).fetchall()
        finally:
            conn.close()

    def list_cookies(self, victim_id: int, domain: str, limit: int = 100) -> list:
        conn = self._connect()
        try:
            return conn.execute(
                "SELECT name, value, domain, path, secure, host_only, http_only,"
                " expires_epoch, browser, profile, source_file"
                " FROM cookies"
                " WHERE victim_id = ? AND (domain = ? OR domain LIKE ?)"
                " ORDER BY domain, path, name LIMIT ?",
                (victim_id, domain, "%." + domain, limit),
            ).fetchall()
        finally:
            conn.close()