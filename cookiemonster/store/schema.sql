"""PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS victims (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    dir_name      TEXT NOT NULL UNIQUE,
    source_layout TEXT NOT NULL,
    path          TEXT NOT NULL,
    ingested_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cookies (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    victim_id     INTEGER NOT NULL REFERENCES victims(id) ON DELETE CASCADE,
    browser       TEXT NOT NULL,
    profile       TEXT NOT NULL DEFAULT '',
    name          TEXT NOT NULL,
    value         TEXT NOT NULL,
    domain        TEXT NOT NULL,
    path          TEXT NOT NULL,
    secure        INTEGER NOT NULL DEFAULT 0,
    host_only     INTEGER NOT NULL DEFAULT 0,
    http_only     INTEGER NOT NULL DEFAULT 0,
    expires_epoch INTEGER NOT NULL DEFAULT 0,
    source_file   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cookies_victim ON cookies(victim_id);
CREATE INDEX IF NOT EXISTS idx_cookies_domain ON cookies(domain, victim_id);
CREATE INDEX IF NOT EXISTS idx_cookies_name   ON cookies(name);

CREATE TABLE IF NOT EXISTS domains (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    victim_id       INTEGER NOT NULL REFERENCES victims(id) ON DELETE CASCADE,
    domain          TEXT NOT NULL,
    cookie_count    INTEGER NOT NULL DEFAULT 0,
    auth_candidates INTEGER NOT NULL DEFAULT 0,
    UNIQUE(victim_id, domain)
);

CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain);

-- Preenchido nas fases M2/M3:
CREATE TABLE IF NOT EXISTS runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    victim_id     INTEGER NOT NULL REFERENCES victims(id) ON DELETE CASCADE,
    target_url    TEXT NOT NULL,
    target_domain TEXT NOT NULL,
    channel       TEXT NOT NULL DEFAULT 'playwright',
    state         TEXT,
    confidence    REAL,
    started       TEXT,
    finished      TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id         INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    cookie_name    TEXT NOT NULL,
    sent_to_target INTEGER NOT NULL DEFAULT 0,
    auth_impact    TEXT,
    confidence     REAL NOT NULL DEFAULT 0,
    notes          TEXT
);