# Arquitetura — CookieMonster

Desenho técnico do validador de session hijacking por cookie replay. CLI standalone Windows/Python, sem Docker e sem vínculo com outros projetos.

## Visão geral

```
cookiemonster/
├── cli.py                  # interface Click (entrada única)
├── ingest/
│   ├── netscape_parser.py  # formato tab-separado (2 layouts detectados)
│   └── json_parser.py      # reserva (exports JSON futuros)
├── store/
│   ├── schema.sql          # SQLite
│   └── db.py
├── domain/
│   └── matcher.py          # matching RFC 6265 (domain/path/secure/host-only/expiry)
├── inject/
│   ├── httpx_client.py     # replay rápido (baixa fidelidade)
│   ├── playwright_client.py# replay fiel (browser real, screenshot)
│   └── capture.py          # intercepta quais cookies são enviados ao alvo
├── validate/
│   ├── auth_state.py       # heurística baseline × injetado
│   ├── scoring.py          # score de risco por artefato
│   └── profiles/
│       └── amazon.py       # perfis de site plugáveis (markers por domínio)
├── report/
│   ├── console.py          # rich
│   ├── json_out.py
│   └── markdown_out.py
└── util/ (rate_limit, stealth)
```

## Modelo de dados (SQLite)

- **victims**: `id, dir, source_layout, ingested_at` — uma por pasta `{HASH}_{date}`.
- **cookies**: `victim_id, browser, profile, name, value, domain, path, secure, host_only, expires_epoch, source_file` — indexado por `(domain, victim_id)`.
- **domains**: `domain, victim_id, cookie_count, auth_candidates`.
- **runs**: `id, victim_id, target_url, target_domain, channel, started, finished`.
- **findings**: `run_id, cookie_name, sent_to_target, auth_impact, confidence, notes`.

## Formatos de ingestão

Dumps em formato **Netscape/curl** (tab-separado): `domain \t include-subdomains(TRUE/FALSE) \t path \t secure(TRUE/FALSE) \t expiry(epoch) \t name \t value`.

Dois layouts de diretório detectados no dataset `Cookies/`:

1. `Cookies\{HASH}_{date}\Cookies\{Browser}_{Profile}.txt`
2. `Cookies\{HASH}_{date}\Browser\Cookies\{idx}_{Profile}_{hash}.txt`

O parser deve detectar ambos automaticamente (`source_layout` registrado em `victims`).

## Superfície CLI

```
cookie-monster ingest --dir "D:\CookieMonster\Cookies" --db store.db    # M0
cookie-monster victims --db store.db                                     # M1
cookie-monster domains --db store.db --domain amazon.com                 # M1
cookie-monster cookies  --db store.db --victim <id> --domain amazon.com  # M1
cookie-monster inject   --db store.db --victim <id> --domain amazon.com \
                        --url https://www.amazon.com --channel playwright # M2
cookie-monster edit     --db store.db --victim <id> --cookie session-token --value X # M2
cookie-monster check    --db store.db --victim <id> --domain amazon.com   # M3 → relatório
cookie-monster report   --db store.db --out reports/                      # M4
```

## Decisões técnicas

- **Replay fiel exige browser real**: Amazon e similares usam fingerprint/TLS/bot detection — httpx pode dar falso negativo; **Playwright é o canal canônico** de validação; httpx é modo rápido/bulk.
- **Validação heurística, não certeza**: a ferramenta reporta `SESSION_VALID / SESSION_INVALID / UNKNOWN` + evidência (status, markers, screenshot). Nunca afirma "conta comprometida" sem confirmação.
- **Perfis por site** (`validate/profiles/`): regex de markers de sessão com fallback genérico. Exemplo amazon: presença de "Hello, &lt;nome&gt;", id de conta, parse do JWT `am-token`.
- **Gatekeeping de escopo**: alvo precisa estar na allowlist local (`scope.txt`); recusa por padrão fora dela.
- **Classificação conservadora**: cookies expirados ou evidência insuficiente → `UNKNOWN`, nunca `INVALID`.

## Classes de saída

| Resultado | Significado |
|---|---|
| `SESSION_VALID` | Alvo reconheceu os cookies injetados como sessão autenticada. |
| `SESSION_INVALID` | Alvo tratou como anônimo/expirado (baseline == injetado). |
| `UNKNOWN` | Evidência insuficiente (CAPTCHA, geobloqueio, expirado, bot detection). |