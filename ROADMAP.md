# Roadmap — CookieMonster

Roadmap de integração e desenvolvimento do **CookieMonster**, validador de session hijacking por cookie replay.

**Fluxo central (caso Amazon):**

```
ingest (Cookies/) → seleciona vítima/domínio → resolve cookies aplicáveis →
injeta no browser (Playwright) → captura cookies efetivamente enviados →
detecta estado de autenticação → relatório + screenshot
```

Cada fase abaixo tem **issue no GitHub** vinculada via milestone. Critérios de aceite são objetivos e testáveis sobre o dataset real em `Cookies/` (3.306 pastas de vítima).

---

## Fase M0 — Ingestão (fundação)

**Objetivo:** ler todos os dumps de cookies existentes e normalizar em um SQLite.

**Entregáveis**

- `cookiemonster/ingest/netscape_parser.py` — parser do formato Netscape (tab-separado: `domain, flag, path, secure, expiry, name, value`), cobrindo os **2 layouts** detectados:
  - `Cookies\{HASH}_{date}\Cookies\{Browser}_{Profile}.txt`
  - `Cookies\{HASH}_{date}\Browser\Cookies\{idx}_{Profile}_{hash}.txt`
- `cookiemonster/ingest/json_parser.py` — stub reservado para exports JSON futuros.
- `cookiemonster/store/schema.sql` + `cookiemonster/store/db.py` — SQLite (`victims`, `cookies`, `domains`, `runs`, `findings`).
- `cookiemonster/cli.py` — skeleton Click: `ingest`, `victims`, `domains`, `cookies`, `inject`, `edit`, `check`, `report`.
- `.gitignore` (excluir `store.db`, `reports/`, `.venv/`).

**Critério de aceite**

- [ ] Ingestar as **3.306 pastas** de `Cookies/` sem erro.
- [ ] Contagem de cookies no banco = contagem de linhas válidas nos arquivos.
- [ ] Re-ingest é idempotente (não duplica).
- [ ] `cookie-monster victims` lista as vítimas.

**Issue:** `M0 — Ingestão: parser Netscape (2 layouts) + store SQLite + CLI skeleton`

---

## Fase M1 — Domain mapping

**Objetivo:** identificar a que domínios os cookies pertencem e quais são aplicáveis a um alvo.

**Entregáveis**

- `cookiemonster/domain/matcher.py` — matching RFC 6265:
  - host-only vs `Domain=` (flag include-subdomains).
  - Path matching (`/`, prefix boundaries).
  - `Secure` só em HTTPS.
  - Expiração (epoch vs agora).
  - Prefixos `__Host-` / `__Secure-`.
- Seleção automática da **melhor vítima** para um domínio alvo (vítima com maior conjunto de cookies auth candidatos).

**Critério de aceite**

- [ ] Para `amazon.com`, resolve cookies de `.amazon.com` + `www.amazon.com`.
- [ ] Ignora cookies expirados e `Secure` em requisições HTTP.
- [ ] `cookie-monster domains --domain amazon.com` e `cookie-monster cookies --victim <id> --domain amazon.com` funcionais.

**Issue:** `M1 — Domain mapping: matcher RFC 6265 + seleção de vítima`

---

## Fase M2 — Injeção & edição

**Objetivo:** injetar os cookies capturados em um contexto de requisição e permitir edição dos artefatos.

**Entregáveis**

- `cookiemonster/inject/httpx_client.py` — replay rápido (baixa fidelidade; pode disparar bot detection).
- `cookiemonster/inject/playwright_client.py` — replay fiel: `context.add_cookies()` em browser real (chromium padrão), com screenshot.
- `cookiemonster/inject/capture.py` — interceptação (CDP) para reportar **quais cookies são de fato enviados** ao alvo.
- `cookie-monster edit` — alterar valor de um cookie capturado e reinjetar (teste de replay de valor antigo/fixação).

**Critério de aceite**

- [ ] Injetar dump da Amazon e confirmar via captura que `session-id`, `ubid-main`, `session-token`, `x-main` são transmitidos a `www.amazon.com`.
- [ ] `edit` altera o valor persistido e o replay usa o novo valor.

**Issue:** `M2 — Injeção & edição: httpx + Playwright + captura de envio + edit`

---

## Fase M3 — Validação (núcleo)

**Objetivo:** determinar se o session hijack teve sucesso.

**Entregáveis**

- `cookiemonster/validate/auth_state.py` — comparação **baseline (sem cookies)** × **injetado (com cookies)**:
  - status HTTP, cadeia de redirects, markers de sign-in/sign-out, identidade de conta na resposta.
- `cookiemonster/validate/profiles/` — perfis de site plugáveis por domínio (ex.: `amazon.py`) com markers específicos; fallback genérico.
- `cookiemonster/validate/scoring.py` — score de risco por artefato/confiança.
- Screenshot de evidência via Playwright.

**Critério de aceite**

- [ ] Dump autenticado classificado como `SESSION_VALID`.
- [ ] Dump sem artefatos auth classificado como `SESSION_INVALID`.
- [ ] `UNKNOWN` (nunca `INVALID`) quando não há evidência suficiente (ex.: cookies expirados, geobloqueio).

**Issue:** `M3 — Validação: detecção de estado auth + perfis + scoring + screenshot`

---

## Fase M4 — Relatório

**Objetivo:** consolidar resultados em saídas legíveis e exportáveis.

**Entregáveis**

- `cookiemonster/report/console.py` — saída rich (matriz vítima × domínio, score geral).
- `cookiemonster/report/json_out.py` + `markdown_out.py` — exportação.
- Modo **batch** multi-domínio/multi-vítima.

**Critério de aceite**

- [ ] Relatório reproduzível a partir de `store.db` sem rede.
- [ ] Formato JSON consumível por outras ferramentas.

**Issue:** `M4 — Relatório: console rich + JSON/Markdown + modo batch`

---

## Fase M5 — Endurecimento & docs

**Objetivo:** robustez, stealth, testes determinísticos e documentação final.

**Entregáveis**

- Rate limiting + backoff por vítima/domínio.
- Stealth: rotação de user-agent, `headless=new`, fingerprints.
- Registry de profiles de site.
- `lab/` — mock server em Python puro (sem container) como ground truth determinístico dos checks.
- `tests/` — suíte `pytest` verde.
- README/CHANGELOG/documentação de uso.

**Critério de aceite**

- [ ] Suíte `pytest` verde com cobertura dos módulos M0–M4.
- [ ] `check` em lote com backoff sem derrubar endpoints.
- [ ] Documentação de uso completa.

**Issue:** `M5 — Endurecimento: rate limit, stealth, lab mock, pytest, docs`

---

## Ordem de execução

```
M0 → M1 → M2 → M3 (núcleo do valor) → M4 → M5
```

Fases M0–M2 são pré-requisitos de dados/plumbing. M3 entrega o valor central ("os cookies ainda funcionam?"). M4 consolida evidência. M5 profissionaliza a ferramenta.

## Riscos conhecidos

- CAPTCHA / bot detection: mitigado por Playwright + stealth, sem garantia.
- Cookies expirados no dump → classificar `UNKNOWN`, nunca `INVALID` (evitar falso negativo).
- Geobloqueio/consent (`lc-main`, etc.) pode mascarar sessão.
- Fingerprint de TLS/JA3: httpx pode dar falso negativo → Playwright é o canal canônico.