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

    # Sumario por dominio
    domain_agg = report.get("domain_aggregate") or []
    if domain_agg:
        agg_table = Table(title="Resumo por domínio")
        agg_table.add_column("Domínio")
        agg_table.add_column("Runs", justify="right")
        agg_table.add_column("CONFIRMED", justify="right", style="green")
        agg_table.add_column("LIKELY", justify="right", style="cyan")
        agg_table.add_column("ANONYMOUS", justify="right", style="red")
        agg_table.add_column("UNKNOWN", justify="right", style="yellow")
        for a in sorted(domain_agg, key=lambda r: r["runs"], reverse=True):
            agg_table.add_row(
                a["domain"], str(a["runs"]),
                str(a.get("confirmed", 0)),
                str(a.get("likely", 0)),
                str(a.get("anonymous", 0)),
                str(a.get("unknown", 0)),
            )
        console.print(agg_table)
        console.print()

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
        color = {"CONFIRMED": "green", "LIKELY": "cyan", "ANONYMOUS": "red",
                 "UNKNOWN": "yellow"}.get(state, "")
        conf = r["confidence"]
        conf_s = f"{conf:.2f}" if isinstance(conf, (int, float)) else str(conf or "")
        table.add_row(
            str(r.get("id", "")), str(r["victim_id"]), r["domain"], r["channel"],
            f"[{color}]{state}[/]" if color else state,
            conf_s, str(r["finding_count"]),
        )
    console.print(table)