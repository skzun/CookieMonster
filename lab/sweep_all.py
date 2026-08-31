"""Sweep paralelo: executa `check` em lote contra a lista de dominios/vitimas.

Uso:
    python lab/sweep_all.py --db store.db --targets _targets.txt --channel httpx --workers 4

Gera relatorio consolidado em reports/sweep_<timestamp>.md
"""
import argparse
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, r"D:\CookieMonster")


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--db", required=True)
    p.add_argument("--targets", required=True, help="arquivo dominio,vid por linha")
    p.add_argument("--channel", choices=("httpx", "playwright"), default="httpx")
    p.add_argument("--max-wait-ms", type=int, default=6000)
    p.add_argument("--workers", type=int, default=4, help="paralelismo")
    p.add_argument("--output", default="reports")
    p.add_argument("--allow-unsafe-scope", action="store_true")
    return p.parse_args()


def read_targets(path):
    pairs = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        dom, vid = line.split(",")
        pairs.append((dom.strip(), int(vid)))
    return pairs


def run_check(db, vid, dom, channel, max_wait_ms, unsafe):
    """Executa `check` em subprocess e retorna (dom, vid, state, conf, error)."""
    import subprocess
    args = [
        "python", "-m", "cookiemonster", "check",
        "--db", db,
        "--victim", str(vid),
        "--domain", dom,
        "--channel", channel,
        "--max-wait-ms", str(max_wait_ms),
    ]
    if unsafe:
        args.append("--allow-unsafe-scope")
    try:
        proc = subprocess.run(args, cwd=r"D:\CookieMonster",
                              capture_output=True, text=True, timeout=180)
        text = proc.stdout + proc.stderr
        state, conf = _parse_check_output(text)
        err = None if proc.returncode == 0 else f"rc={proc.returncode}"
        if state == "?" and proc.returncode != 0:
            err = "check_failed"
        return (dom, vid, state, conf, err)
    except subprocess.TimeoutExpired:
        return (dom, vid, "TIMEOUT", "?", "timeout 180s")
    except Exception as exc:
        return (dom, vid, "ERROR", "?", str(exc))


def _parse_check_output(text: str):
    """Extrai estado e confianca do output do comando check."""
    import re
    # Linhas como: "ANONYMOUS (confianca 0.85, perfil amazon)" ou
    # "CONFIRMED (confianca 0.90, perfil github)"
    m = re.search(r"\b(CONFIRMED|LIKELY|ANONYMOUS|UNKNOWN)\s*\(\s*confian\w+\s*([\d.]+)",
                  text)
    if m:
        return m.group(1), m.group(2)
    # Se o output so tem "Recusado:", retorna RECUSADO.
    if "Recusado:" in text:
        return "RECUSADO", "?"
    return "?", "?"


def main():
    args = parse_args()
    pairs = read_targets(args.targets)
    print(f"Sweep: {len(pairs)} alvos, canal={args.channel}, workers={args.workers}\n")

    start = time.time()
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futs = {
            pool.submit(run_check, args.db, vid, dom, args.channel,
                       args.max_wait_ms, args.allow_unsafe_scope): (dom, vid)
            for dom, vid in pairs
        }
        for i, fut in enumerate(as_completed(futs), 1):
            dom, vid, state, conf, err = fut.result()
            results.append((dom, vid, state, conf, err))
            stamp = (time.time() - start)
            avg = stamp / i
            eta = avg * (len(pairs) - i)
            status = f"{state:11}" + (f" (conf={conf})" if conf != "?" else "")
            err_s = f" ERR={err}" if err else ""
            print(f"[{i}/{len(pairs)}] {stamp:6.0f}s (eta {eta:5.0f}s) {dom:30} vid={vid:>5} {status}{err_s}",
                  flush=True)

    # Sumario por estado
    elapsed = time.time() - start
    print(f"\nConcluido em {elapsed:.0f}s")
    by_state = {}
    for dom, vid, state, conf, err in results:
        by_state.setdefault(state, []).append((dom, vid, conf, err))
    print("\n=== Resumo ===")
    for state in ("CONFIRMED", "LIKELY", "ANONYMOUS", "UNKNOWN"):
        items = by_state.get(state, [])
        print(f"  {state}: {len(items)}")
        for dom, vid, conf, err in items:
            err_s = f"  ERR={err}" if err else ""
            print(f"    {dom:30} vid={vid:>5}  conf={conf}{err_s}")

    # Salva relatorio
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = out_dir / f"sweep_{args.channel}_{ts}.md"
    lines = [
        f"# Sweep — {ts}",
        "",
        f"- Canal: **{args.channel}**",
        f"- Workers: {args.workers}",
        f"- Alvos: {len(pairs)}",
        f"- Tempo total: {elapsed:.0f}s",
        f"- Por alvo: {elapsed / len(pairs):.1f}s",
        "",
        "## Resumo",
        "",
        "| Estado | Count |",
        "|---|---|",
    ]
    for state in ("CONFIRMED", "LIKELY", "ANONYMOUS", "UNKNOWN", "TIMEOUT", "ERROR"):
        items = by_state.get(state, [])
        if items:
            lines.append(f"| {state} | {len(items)} |")
    lines.append("")
    lines.append("## Detalhes")
    lines.append("")
    lines.append("| Dominio | Vítima | Estado | Confiança | Erro |")
    lines.append("|---|---|---|---|---|")
    for dom, vid, state, conf, err in results:
        err_s = err or ""
        lines.append(f"| {dom} | {vid} | {state} | {conf} | {err_s} |")
    lines.append("")
    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nRelatorio salvo em: {report_path}")


if __name__ == "__main__":
    main()