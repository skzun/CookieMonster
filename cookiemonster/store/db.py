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
            self._migrate(conn)
            conn.commit()
        finally:
            conn.close()

    def _migrate(self, conn: sqlite3.Connection) -> None:
        """Migracoes leves/idempotentes para schemas antigos."""
        cols = {r[1] for r in conn.execute("PRAGMA table_info(runs)")}
        if "state" not in cols:
            conn.execute("ALTER TABLE runs ADD COLUMN state TEXT")
        if "confidence" not in cols:
            conn.execute("ALTER TABLE runs ADD COLUMN confidence REAL")

        cookie_cols = {r[1] for r in conn.execute("PRAGMA table_info(cookies)")}
        if "attrs" not in cookie_cols:
            conn.execute("ALTER TABLE cookies ADD COLUMN attrs TEXT NOT NULL DEFAULT '{}'")
        if "same_site" not in cookie_cols:
            conn.execute("ALTER TABLE cookies ADD COLUMN same_site TEXT DEFAULT 'unknown'")
        if "partitioned" not in cookie_cols:
            conn.execute("ALTER TABLE cookies ADD COLUMN partitioned INTEGER DEFAULT 0")
        run_cols = {r[1] for r in conn.execute("PRAGMA table_info(runs)")}
        if "evidence_json" not in run_cols:
            conn.execute("ALTER TABLE runs ADD COLUMN evidence_json TEXT")
        if "auth_context_json" not in run_cols:
            conn.execute("ALTER TABLE runs ADD COLUMN auth_context_json TEXT")
        if "reason" not in run_cols:
            conn.execute("ALTER TABLE runs ADD COLUMN reason TEXT")

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
        # 15 colunas (inclui attrs JSON)
        conn.executemany(
            "INSERT INTO cookies (victim_id, browser, profile, name, value, domain,"
            " path, secure, host_only, http_only, expires_epoch, source_file,"
            " same_site, partitioned, attrs)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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

    def list_runs(self) -> list:
        """Retorna todos os runs com contagens agregadas."""
        conn = self._connect()
        try:
            return conn.execute(
                "SELECT r.id, r.victim_id, v.dir_name, r.target_domain, r.target_url,"
                " r.channel, r.state, r.confidence, r.started, r.finished,"
                " r.evidence_json, r.auth_context_json, r.reason,"
                " (SELECT COUNT(*) FROM findings f WHERE f.run_id = r.id) AS finding_count"
                " FROM runs r JOIN victims v ON v.id = r.victim_id"
                " ORDER BY r.id DESC"
            ).fetchall()
        finally:
            conn.close()

    def findings_for_run(self, run_id: int) -> list:
        conn = self._connect()
        try:
            return conn.execute(
                "SELECT cookie_name, sent_to_target, auth_impact, confidence, notes"
                " FROM findings WHERE run_id = ? ORDER BY confidence DESC",
                (run_id,),
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

    def best_victims_for_domain(self, domain: str, limit: int = 10) -> list:
        """Retorna vítimas com cookies do domínio, ordenadas por potencial de sessao.

        Cada linha: {victim_id, dir_name, auth, total}.
        `auth` = cookies cujo nome e candidato a artefato de autenticacao (heuristica M1).
        """
        from ..domain.selection import is_auth_candidate

        domain = (domain or "").strip().rstrip(".")
        conn = self._connect()
        try:
            # Etapa 1: vítimas candidatas via tabela `domains` (menor que `cookies`).
            cand = conn.execute(
                "SELECT victim_id FROM domains"
                " WHERE domain = ? OR domain = ? OR domain LIKE ?",
                (domain, "." + domain, "%." + domain),
            ).fetchall()
            vids = sorted({r["victim_id"] for r in cand})

            result = []
            for vid in vids:
                names = conn.execute(
                    "SELECT name FROM cookies WHERE victim_id = ?"
                    " AND (domain = ? OR domain = ? OR domain LIKE ?)",
                    (vid, domain, "." + domain, "%." + domain),
                ).fetchall()
                total = len(names)
                auth = len({r["name"] for r in names if is_auth_candidate(r["name"])})
                vrow = conn.execute(
                    "SELECT dir_name FROM victims WHERE id = ?", (vid,)
                ).fetchone()
                result.append({
                    "victim_id": vid,
                    "dir_name": vrow["dir_name"] if vrow else "?",
                    "auth": auth,
                    "total": total,
                })
        finally:
            conn.close()

        result.sort(key=lambda r: (r["auth"], r["total"]), reverse=True)
        return result[:limit]

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

    def update_cookie_value(self, victim_id: int, domain: str, name: str,
                            value: str) -> int:
        """Altera o valor de um cookie (teste de replay de artefato editado).

        Atualiza todas as linhas de mesmo (victim, domain, name). Retorna o numero
        de linhas afetadas.
        """
        conn = self._connect()
        try:
            cur = conn.execute(
                "UPDATE cookies SET value = ?"
                " WHERE victim_id = ? AND name = ?"
                " AND (domain = ? OR domain LIKE ?)",
                (value, victim_id, name, domain, "%." + domain),
            )
            conn.commit()
            return cur.rowcount
        finally:
            conn.close()

    def record_run(self, victim_id: int, target_url: str, target_domain: str,
                   channel: str, state: str | None = None,
                   confidence: float | None = None,
                   evidence_json: str | None = None,
                   auth_context_json: str | None = None,
                   reason: str | None = None) -> int:
        """Registra um `run` e retorna seu id (para inserir findings depois).

        M6.0: aceita auth_context_json (AuthContext serializado) e reason
        (string canonica da classificacao).
        """
        conn = self._connect()
        try:
            cur = conn.execute(
                "INSERT INTO runs (victim_id, target_url, target_domain, channel,"
                " state, confidence, started, finished, evidence_json,"
                " auth_context_json, reason)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (victim_id, target_url, target_domain, channel, state, confidence,
                 datetime.now(timezone.utc).isoformat(timespec="seconds"), None,
                 evidence_json, auth_context_json, reason),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def add_findings(self, run_id: int, findings: list) -> None:
        conn = self._connect()
        try:
            conn.executemany(
                "INSERT INTO findings (run_id, cookie_name, sent_to_target,"
                " auth_impact, confidence, notes)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                findings,
            )
            conn.commit()
        finally:
            conn.close()