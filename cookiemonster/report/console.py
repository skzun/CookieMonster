"""Renderizacao de relatorio no console (rich)."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

console = Console()


def render_summary(report: dict) -> None:
    summary = report.get("summary", [])
    if not summary:
        console.print("[dim]Nenhum run registrado ainda.[/]")
        return

    table = Table(title="Runs (CookieMonster)")
    table.add_column("ID", justify="right", style="dim")
    table.add_column("Vítima", justify="right")
    table.add_column("Domínio")
    table.add_column("Canal")
    table.add_column("Estado")
    table.add_column("Confiança", justify="right")
    table.add_column("Findings", justify="right")

    for r in summary:
        state = r["state"] or "?"
        color = {"SESSION_VALID": "green", "SESSION_INVALID": "red",
                 "UNKNOWN": "yellow"}.get(state, "")
        conf = r["confidence"]
        conf_s = f"{conf:.2f}" if isinstance(conf, (int, float)) else str(conf or "")
        table.add_row(
            str(r.get("id", "")), str(r["victim_id"]), r["domain"], r["channel"],
            f"[{color}]{state}[/]" if color else state,
            conf_s, str(r["finding_count"]),
        )
    console.print(table)