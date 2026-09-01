# CookieMonster

Framework de **replay adversarial de cookies de sessão** — ferramenta CLI standalone (Windows/Python) que:

1. **Ingere** dumps de cookies capturados (formato Netscape/curl/JSON).
2. **Identifica** os domínios a que os cookies pertencem.
3. **Seleciona** quais cookies são efetivamente solicitados por um domínio alvo (matching RFC 6265).
4. **Injeta** os cookies capturados em um contexto de requisição (HTTP ou browser real via Playwright), com possibilidade de **edição** dos valores.
5. **Valida** se o session hijack teve sucesso — detecta estado de autenticação (baseline × injetado) e gera evidência (screenshot, markers, status).
6. **Detecta** Identity Provider (Google, Microsoft, GitHub, Auth0, Okta) e tipo de proteção (anti-bot, MFA, OAuth front-channel).
7. **Correlaciona** Findings em cadeias de ataque com **Impact assessment**.
8. **Orquestra** via plano YAML declarativo com stop conditions e replay matrix.

> **Exemplo de uso:** quer conferir se os cookies capturados do TikTok ainda são funcionais. Executa o CookieMonster contra `tiktok.com` e ele tenta reproduzir a sessão, reportando se o alvo reconheceu os cookies, qual IdP estava envolvido, e qual contexto é necessário.

## 5 comandos rápidos

```bash
# Pipeline unificado (1 vitima, saida M6.0 com IdP/mechanism/dependencies):
python -m cookiemonster probe --domain tiktok.com --allow-unsafe-scope

# Varrer TODAS as vitimas em paralelo (httpx=rapido, playwright=forte):
python -m cookiemonster probe-all --domain tiktok.com --channel httpx --allow-unsafe-scope

# Matriz de contexto (M6.2) — identifica dependencias:
python -m cookiemonster matrix --domain tiktok.com --max-variants 4 --allow-unsafe-scope

# Correlacionar Findings em grafo + AttackChains (OPT-A):
python -m cookiemonster correlate --domain tiktok.com --limit 5

# Resumo amigavel com diagnostico:
python -m cookiemonster dashboard
```

## Workflow completo

```bash
# Setup
pip install -e .
python -m playwright install chromium

# Edite scope.txt com seus dominios autorizados

# 1) Ingestao
python -m cookiemonster ingest --dir Cookies --db store.db --resume

# 2) Top 5 vitimas para um alvo
python -m cookiemonster best --db store.db --domain tiktok.com --limit 5

# 3) Probe canonico (Playwright + M6.0 AuthContext):
python -m cookiemonster probe --domain tiktok.com --allow-unsafe-scope

# 4) Matriz de replay (identifica dependencias):
python -m cookiemonster matrix --domain tiktok.com --victim 2390 --allow-unsafe-scope

# 5) Correlacao + Attack Chains:
python -m cookiemonster correlate --domain tiktok.com --limit 10

# 6) Plano YAML completo (5 phases):
python -m cookiemonster attack-plan --plan-file docs/examples/attack-plan.example.yaml --allow-unsafe-scope
```

## Saída real (M6.0 AuthContext)

```
[4] REPLAY RESULT (M6.0 AuthContext)
    >>> Classification: IDP_BOUND (ACESSO BLOQUEADO POR IDP)
    >>> Confidence:     0.85
    >>> Reason:         identity_provider_boundary:google
    >>> Mechanism:      oidc
    >>> IdP:            google (login via terceiro)
    >>> Dependencies:   idp (replay pode depender desses contextos)
    >>> Sessao requer validacao no Identity Provider externo.
```

## Aviso de escopo e maturidade

**Assessment de seguranca / red team autorizado**. Use apenas contra:
- Ambientes que voce controla.
- Alvos com **autorizacao explicita por escrito** (bug bounty, pentest contratado, laboratorio).

**Guardrail de escopo:** `scope.txt` deve listar os dominios autorizados. Por padrao (fail-safe), alvos fora do scope sao **RECUSADOS**. Para desabilitar, use `--allow-unsafe-scope` (NAO recomendado).

**O que a ferramenta faz:**
- Detecta 8 IdPs (Google, Microsoft, GitHub, Auth0, Okta, AWS Cognito, Facebook, Apple).
- Classifica em 7 estados (AUTHENTICATED, CONTEXT_BOUND, IDP_BOUND, MFA_BLOCKED, BOT_BLOCKED, ANONYMOUS, INCONCLUSIVE).
- Correlaciona Findings em cadeias de ataque com Impact assessment.
- Orquestra via plano YAML declarativo (5 phases: discover → classify → replay → observe → correlate).

**O que a ferramenta NAO faz:**
- **Nao implementa bypass** de MFA/Cloudflare/anti-bot em producao.
- **Nao afirma conta comprometida** com base apenas em heuristica textual.
- **Nao bypassa IdPs externos** (Google OAuth, Microsoft Entra, etc).

Resultados representam **evidencia estruturada de que o servidor reconheceu os cookies injetados** (ou nao) e o motivo. A decisao de explorar mais eh do operador.

## Stack

Python 3.11+ · `click` · `rich` · `httpx` · `playwright` (Chromium) · `pyyaml` (opcional) · SQLite.

## Estrutura

```
CookieMonster/
├── cookiemonster/
│   ├── auth/        # M6.0 - AuthContext + Detector (8 IdPs) + Classification (7 states)
│   ├── correlate/   # M6.3 - Finding canônico + 9 regras + CorrelationGraph + OPT-A AttackChain
│   ├── domain/      # M1 - RFC 6265 matcher + auth heuristics
│   ├── ingest/      # M0 - parsers Netscape/JSON
│   ├── inject/      # M2 - httpx + Playwright + AuthProbe
│   ├── lab/         # OPT-D - 7 lab profiles A-G (cookie_only, IP binding, etc)
│   ├── plan/        # M7 - AttackPlan YAML + executor + Impact
│   ├── replay/      # M6.2 - ReplayMatrix + DependencyAnalyzer
│   ├── report/      # M4 - JSON/Markdown report
│   ├── stealth/     # OPT-B - StealthProfile opt-in (canvas/WebGL/font)
│   ├── store/       # SQLite persistence
│   ├── util/        # scope, PSL, helpers
│   ├── validate/    # M3 - detector + profiles
│   └── cli.py       # 18 comandos CLI
├── docs/
│   ├── MANUAL.md              # manual completo (17 secoes, M0-M7+OPT)
│   ├── examples/
│   │   └── attack-plan.example.yaml
│   └── labs/
│       └── scenarios.json
├── lab/              # mock server Python puro
├── tests/            # 232 testes pytest
├── reports/          # saida dos relatorios
├── scope.txt         # allowlist
└── pyproject.toml
```

## Links

- [Manual de uso completo (17 secoes)](docs/MANUAL.md) — instala, workflow, M6/M7/OPT, troubleshooting
- [Arquitetura](docs/ARCHITECTURE.md)
- [Exemplo de AttackPlan YAML](docs/examples/attack-plan.example.yaml)
- [Lab profiles A-G (especificacao)](docs/labs/scenarios.json)
- [Issues no GitHub](https://github.com/skzun/CookieMonster/issues)

**Versao**: v1.0 (M0–M7 + OPT-A/B/C/D).
**Testes**: 232 verdes.
**18 comandos CLI** + 13 modulos.
