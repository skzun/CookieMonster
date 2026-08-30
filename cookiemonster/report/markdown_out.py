"""Exportacao de relatorios em Markdown."""

from __future__ import annotations

from pathlib import Path
from typing import Any, List


def _rows_to_table(rows: List[dict], columns: List[str]) -> str:
    if not rows:
        return ""
    header = "| " + " | ".join(columns) + " |"
    sep = "|" + "|".join(["---"] * len(columns)) + "|"
    lines = [header, sep]
    for r in rows:
        cells = [str(r.get(c, "")) for c in columns]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def render(report: dict) -> str:
    lines = [f"# Relatório — CookieMonster", ""]
    lines.append(f"- Gerado: {report.get('generated_at', '')}")
    lines.append(f"- Runs: {report.get('run_count', 0)}")
    lines.append("")

    summary = report.get("summary", [])
    if summary:
        lines.append("## Sumário por run")
        lines.append(_rows_to_table(
            summary,
            ["victim_id", "dir_name", "domain", "channel",
             "state", "confidence", "finding_count"],
        ))

    for run in report.get("runs", []):
        lines.append(f"\n## Run {run.get('id')} — {run.get('domain')}")
        lines.append(f"- Vítima: {run.get('victim_id')} (`{run.get('dir_name', '')}`)")
        lines.append(f"- Estado: **{run.get('state', '?')}** (confiança {run.get('confidence', 0)})")
        lines.append(f"- URL: {run.get('target_url', '')}")
        findings = run.get("findings", [])
        if findings:
            lines.append("")
            lines.append(_rows_to_table(
                findings,
                ["cookie_name", "auth_impact", "sent_to_target", "confidence"],
            ))
    return "\n".join(lines)


def dump(report: dict, path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(report), encoding="utf-8")