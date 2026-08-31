# CookieMonster

Validador de **session hijacking por cookie replay** — ferramenta CLI standalone (Windows/Python) que:

1. **Ingere** dumps de cookies capturados (formato Netscape/curl).
2. **Identifica** os domínios a que os cookies pertencem.
3. **Seleciona** quais cookies são efetivamente solicitados por um domínio alvo (matching RFC 6265).
4. **Injeta** os cookies capturados em um contexto de requisição (HTTP ou browser real via Playwright), com possibilidade de **edição** dos valores.
5. **Valida** se o session hijack teve sucesso — detecta estado de autenticação no alvo (baseline × injetado) e gera evidência (screenshot, markers, status).

> **Exemplo de uso:** quer conferir se os cookies capturados da Amazon ainda são funcionais. Executa o CookieMonster contra `amazon.com` e ele tenta reproduzir a sessão, reportando se o alvo reconheceu os cookies como uma sessão autenticada válida.

---

## Aviso de escopo e madurez

Ferramenta de **assessment de seguranca / red team autorizado**. Use apenas contra:
- Ambientes que voce controla.
- Alvos com **autorizacao explicita por escrito** (bug bounty, pentest contratado, laboratorio).

**Guardrail de escopo:** scope.txt deve listar os dominios autorizados. Por padrao (fail-safe), alvos fora do scope sao RECUSADOS. Para desabilitar, use --allow-unsafe-scope (NAO recomendado).

**Madurez tecnica atual (v0.2.0):**
- Arquitetura: base estavel para evolucao.
- Implementacao: replay fiel (Playwright, modo STRICT preserva fingerprint).
- Fidelidade do cookie replay: SameSite preservado, HttpOnly tri-state, fingerprint estavel.
- Deteccao de sessao autenticada: estruturada com CONFIRMED/LIKELY/ANONYMOUS/UNKNOWN.
- Pronto para uso em assessment autorizado: depende de autorizacao + alvará do alvo.
- **NAO declara conta comprometida com base apenas em heuristica textual.**

Resultados representam **evidencia de que o servidor reconheceu os cookies injetados**, nao prova absoluta de hijack. Falsos positivos (SESSIONVALID sem autenticacao) sao tratados conservadoramente (UNKNOWN/LIKELY).

Ferramenta de **assessment de segurança / red team autorizado**. Use apenas contra:

- Ambientes que você controla.
- Alvos com **autorização explícita por escrito** (bug bounty scope, pentest contratado, laboratório).

A ferramenta recusa por padrão alvos fora da allowlist local (`scope.txt`). Cookies aqui presentes são dados de teste/laboratório do próprio usuário.

## Stack

- Python 3.14+ · `requests` · `httpx` · `playwright` (browsers já instalados) · `beautifulsoup4` · `rich` · `click` · SQLite.

## Estrutura

```
CookieMonster/
├── cookiemonster/          # pacote principal (módulos por fase)
├── Cookies/                # dumps de cookies de teste (Netscape, 2 layouts)
├── lab/                    # mock server Python puro p/ testes determinísticos
├── tests/                  # pytest
├── reports/                # saída dos relatórios
├── store.db                # SQLite gerado pelo ingest
├── ROADMAP.md              # roadmap por fases (issues vinculadas)
└── docs/ARCHITECTURE.md    # arquitetura, modelo de dados e CLI
```

## Uso

```bash
# 1. Ingerir os dumps (uma vez; idempotente com --resume)
python -m cookiemonster ingest --dir Cookies --db store.db --resume

# 2. Encontrar as melhores vítimas para um domínio
python -m cookiemonster best --domain amazon.com --limit 5

# 3. Listar cookies aplicáveis (matching RFC 6265)
python -m cookiemonster cookies --victim 4013 --domain amazon.com --scheme https

# 4. Validar o session hijack (baseline × injetado)
python -m cookiemonster check --victim 4013 --domain amazon.com --channel playwright --screenshot reports

# 5. Lote automático das N melhores vítimas
python -m cookiemonster check-batch --domain amazon.com --limit 5 --channel httpx

# 6. Consolidar relatórios (matrix + JSON + Markdown)
python -m cookiemonster report --out reports/
```

Saída do `check`: `SESSION_VALID` (sessão reproduzida), `SESSION_INVALID` (expirada/negada) ou `UNKNOWN` (evidência insuficiente — bot detection, geobloqueio, etc.), com score dos artefatos de autenticação.

## Instalação

```bash
pip install -e ".[inject,dev]"   # ou apenas: pip install -e .
python -m playwright install chromium
```

## Guardrail de escopo

Edite `scope.txt` e liste os domínios autorizados. Fora dele, `check`/`inject` recusam o alvo. `127.0.0.1`/`localhost` já vêm liberados para o lab.

## Roadmap

Estado: **M0–M5 concluídos**. Consulte [ROADMAP.md](ROADMAP.md) e [CHANGELOG.md](CHANGELOG.md).

| Fase | Descrição | Status |
|---|---|---|
| M0 | Ingestão (parser Netscape 2 layouts + store SQLite + CLI) | ✅ |
| M1 | Domain mapping (matcher RFC 6265 + seleção de vítima) | ✅ |
| M2 | Injeção & edição (httpx + Playwright + captura + edit) | ✅ |
| M3 | Validação (auth-state, perfis, scoring, screenshot) | ✅ |
| M4 | Relatório (console + JSON/MD + batch) | ✅ |
| M5 | Endurecimento (rate limit, stealth, lab mock, pytest, docs) | ✅ |