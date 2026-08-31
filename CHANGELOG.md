# Changelog

## [0.2.0] — 2026-08-31

### Correcoes criticas (revisao tecnica)
- **sameSite preservado** no parser e no replay (Playwright). Removido mapeamento
  infeliz que atribuia SameSite=None para cookies nao-Secure.
- **HttpOnly tri-state** (True / False / Unknown). Formato Netscape nao traz
  HttpOnly; isso NAO pode ser tratado como ausencia confirmada. Scoring
  triplicou em bonus defensivo: unknown nao soma.
- **Replay profile STRICT por padrao** preservando fingerprint do dump (UA,
  locale, timezone). Substitui randomizacao agressiva que invalidava sessoes
  via bind de contexto.
- **Detector estruturado**: CONFIRMED / LIKELY / ANONYMOUS / UNKNOWN com
  evidencia (markers, identidade extraida, redirect_chain, status).
- **Public Suffix List real** (download + cache local) substitui lista hardcoded.
- **Scope guardrail fail-safe**: scope.txt vazio/inexistente RECUSA alvos.
  Flag --allow-unsafe-scope para desabilitar.
- **Validacao de URL efetiva** (incluindo redirects) contra scope.
- **Identidade como evidencia**: extracao heuristica de nome/email/account_id.

## [0.1.0] — 2026-08-30

### M0 — Ingestao
- Parser Netscape/curl (2 layouts de pasta + JSON dentro de .txt) e JSON de extensao.
- Store SQLite (ictims, cookies, domains, 
uns, indings).
- CLI: ingest, ictims, domains, cookies.
- Ingestao idempotente (--resume).

### M1 — Domain mapping
- Matcher RFC 6265 (domain/public-suffix, path, secure, host-only, expiracao, prefixos).
- Selecao da melhor vitima (est) por heuristica de artefato auth.

### M2 — Injecao & edicao
- httpx_client (replay rapido) e playwright_client (replay fiel + screenshot).
- Captura de cookies enviados (capture.py, via CDP + context.cookies).
- Comando inject e edit.

### M3 — Validacao
- uth_state.detect (baseline x injetado).
- Perfis por site (generic, mazon) com registry extensivel.
- scoring de artefatos; persistencia em 
uns/indings.

### M4 — Relatorio
- Saida console (matriz), JSON, Markdown.
- Modo batch (check-batch).

### M5 — Endurecimento
- Rate limiter com backoff por host.
- Stealth (rotação de User-Agent, headless=new, viewport/locale/timezone).
- Guardrail de escopo (scope.txt).
- Laboratorio deterministico (lab/mock_app.py) e testes E2E sem rede.
- 38 testes.
