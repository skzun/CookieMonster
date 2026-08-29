# CookieMonster

Validador de **session hijacking por cookie replay** — ferramenta CLI standalone (Windows/Python) que:

1. **Ingere** dumps de cookies capturados (formato Netscape/curl).
2. **Identifica** os domínios a que os cookies pertencem.
3. **Seleciona** quais cookies são efetivamente solicitados por um domínio alvo (matching RFC 6265).
4. **Injeta** os cookies capturados em um contexto de requisição (HTTP ou browser real via Playwright), com possibilidade de **edição** dos valores.
5. **Valida** se o session hijack teve sucesso — detecta estado de autenticação no alvo (baseline × injetado) e gera evidência (screenshot, markers, status).

> **Exemplo de uso:** quer conferir se os cookies capturados da Amazon ainda são funcionais. Executa o CookieMonster contra `amazon.com` e ele tenta reproduzir a sessão, reportando se o alvo reconheceu os cookies como uma sessão autenticada válida.

---

## Aviso de escopo

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

## Roadmap

Estado atual: **em construção (fase M0 em andamento)**. Consulte [ROADMAP.md](ROADMAP.md) para o detalhamento das fases e [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) para o desenho técnico.

| Fase | Descrição | Status |
|---|---|---|
| M0 | Ingestão (parser Netscape 2 layouts + store SQLite + CLI skeleton) | 🔨 em andamento |
| M1 | Domain mapping (matcher RFC 6265 + listagens) | ⏳ |
| M2 | Injeção & edição (httpx + Playwright + captura + edit) | ⏳ |
| M3 | Validação (auth-state, perfis de site, scoring, screenshot) | ⏳ |
| M4 | Relatório (console rich + JSON/MD + batch) | ⏳ |
| M5 | Endurecimento (rate limit, stealth, lab mock, pytest, docs) | ⏳ |