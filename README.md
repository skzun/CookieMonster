# CookieMonster

Validador de **session hijacking por cookie replay** — ferramenta CLI standalone (Windows/Python) que:

1. **Ingere** dumps de cookies capturados (formato Netscape/curl).
2. **Identifica** os domínios a que os cookies pertencem.
3. **Seleciona** quais cookies são efetivamente solicitados por um domínio alvo (matching RFC 6265).
4. **Injeta** os cookies capturados em um contexto de requisição (HTTP ou browser real via Playwright), com possibilidade de **edição** dos valores.
5. **Valida** se o session hijack teve sucesso — detecta estado de autenticação no alvo (baseline × injetado) e gera evidência (screenshot, markers, status).

> **Exemplo de uso:** quer conferir se os cookies capturados da Amazon ainda são funcionais. Executa o CookieMonster contra `amazon.com` e ele tenta reproduzir a sessão, reportando se o alvo reconheceu os cookies como uma sessão autenticada válida.

**Veja o [MANUAL completo](docs/MANUAL.md)** para instalação, workflow detalhado, exemplos práticos, troubleshooting e referência de comandos.

---

## Aviso de escopo e madurez

Ferramenta de **assessment de seguranca / red team autorizado**. Use apenas contra:
- Ambientes que voce controla.
- Alvos com **autorizacao explicita por escrito** (bug bounty, pentest contratado, laboratorio).

**Guardrail de escopo:** `scope.txt` deve listar os dominios autorizados. Por padrao (fail-safe), alvos fora do scope sao **RECUSADOS**. Para desabilitar, use `--allow-unsafe-scope` (NAO recomendado).

**Madurez tecnica atual (v0.2.0):**
- Arquitetura: base estavel para evolucao.
- Implementacao: replay fiel (Playwright, modo STRICT preserva fingerprint).
- Fidelidade do cookie replay: SameSite preservado, HttpOnly tri-state, fingerprint estavel.
- Deteccao de sessao autenticada: estruturada com `CONFIRMED`/`LIKELY`/`ANONYMOUS`/`UNKNOWN`.
- Pronto para uso em assessment autorizado: depende de autorizacao + alvara do alvo.
- **NAO declara conta comprometida com base apenas em heuristica textual.**

Resultados representam **evidencia de que o servidor reconheceu os cookies injetados**, nao prova absoluta de hijack.

## Quickstart (TL;DR)

```bash
# Setup
pip install -e .
python -m playwright install chromium

# Edite scope.txt com seus dominios autorizados

# Pipeline completo
python -m cookiemonster ingest --dir Cookies --db store.db --resume
python -m cookiemonster best --db store.db --domain amazon.com --limit 5
python -m cookiemonster check --db store.db --victim 1456 --domain amazon.com \
    --channel playwright --max-wait-ms 8000
python -m cookiemonster report --db store.db --out reports
```

Saída de exemplo:

```
check vitima=1456 https://amazon.com/ [21 cookies aplicaveis, canal=playwright]

ANONYMOUS (confianca 0.85, perfil amazon)
  sinais injetado: login_redirect
  diferencial: login_redirect: base=False inj=True
```

Para **uso detalhado, exemplos, troubleshooting**, consulte **[docs/MANUAL.md](docs/MANUAL.md)**.

## Stack

Python 3.11+ · `click` · `rich` · `httpx` · `playwright` (Chromium) · `beautifulsoup4` · SQLite.

## Estrutura

```
CookieMonster/
├── cookiemonster/          # pacote principal
│   ├── ingest/             # parser Netscape/JSON + orchestrator
│   ├── store/              # SQLite store
│   ├── domain/             # RFC 6265 matcher + auth heuristics
│   ├── inject/             # httpx + Playwright + AuthProbe (readiness + capture)
│   ├── validate/           # detector diferencial + perfis de site
│   ├── report/             # console + JSON + Markdown (atomic write)
│   └── util/               # PSL, stealth, rate limit, scope guardrail
├── lab/                    # mock server Python puro p/ testes deterministicos
├── tests/                  # 68 testes pytest
├── reports/                # saida dos relatorios
├── ROADMAP.md              # roadmap M0-M5
├── CHANGELOG.md            # historico
├── docs/
│   ├── ARCHITECTURE.md     # arquitetura tecnica
│   └── MANUAL.md           # manual de uso (este)
└── pyproject.toml
```

## Links

- [Manual de uso completo](docs/MANUAL.md)
- [Arquitetura](docs/ARCHITECTURE.md)
- [Roadmap M0-M5](ROADMAP.md)
- [Issues no GitHub](https://github.com/skzun/CookieMonster/issues)