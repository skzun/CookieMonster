# Changelog

## [0.1.0] — 2026-08-30

### M0 — Ingestão
- Parser Netscape/curl (2 layouts de pasta + JSON dentro de `.txt`) e JSON de extensão.
- Store SQLite (`victims`, `cookies`, `domains`, `runs`, `findings`).
- CLI: `ingest`, `victims`, `domains`, `cookies`.
- Ingestão idempotente (`--resume`).

### M1 — Domain mapping
- Matcher RFC 6265 (domain/public-suffix, path, secure, host-only, expiração, prefixos).
- Seleção da melhor vítima (`best`) por heurística de artefato auth.

### M2 — Injeção & edição
- `httpx_client` (replay rápido) e `playwright_client` (replay fiel + screenshot).
- Captura de cookies enviados (`capture.py`, via CDP + `context.cookies`).
- Comando `inject` e `edit`.

### M3 — Validação
- `auth_state.detect` (baseline × injetado → `SESSION_VALID`/`INVALID`/`UNKNOWN`).
- Perfis por site (`generic`, `amazon`) com registry extensível.
- `scoring` de artefatos; persistência em `runs`/`findings`.

### M4 — Relatório
- Saída console (matriz), JSON, Markdown.
- Modo batch (`check-batch`).

### M5 — Endurecimento
- Rate limiter com backoff por host.
- Stealth (rotação de User-Agent, headless=new, viewport/locale/timezone).
- Guardrail de escopo (`scope.txt`).
- Laboratório determinístico (`lab/mock_app.py`) e testes E2E sem rede.
- 38 testes.