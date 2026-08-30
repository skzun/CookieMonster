"""Construcao do relatorio a partir do store (consolidacao runs + findings)."""

from __future__ import annotations

from datetime import datetime, timezone

from ..store.db import Store


def build_report(store: Store) -> dict:
    runs = store.list_runs()
    runs_data = []
    for r in runs:
        findings = store.findings_for_run(r["id"])
        runs_data.append({
            "id": r["id"],
            "victim_id": r["victim_id"],
            "dir_name": r["dir_name"],
            "domain": r["target_domain"],
            "target_url": r["target_url"],
            "channel": r["channel"],
            "state": r["state"],
            "confidence": r["confidence"],
            "started": r["started"],
            "findings": [
                {
                    "cookie_name": f["cookie_name"],
                    "sent_to_target": f["sent_to_target"],
                    "auth_impact": f["auth_impact"],
                    "confidence": f["confidence"],
                }
                for f in findings
            ],
        })

    summary = [
        {
            "id": r["id"],
            "victim_id": r["victim_id"],
            "dir_name": r["dir_name"],
            "domain": r["target_domain"],
            "channel": r["channel"],
            "state": r["state"],
            "confidence": r["confidence"],
            "finding_count": r["finding_count"],
        }
        for r in runs
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "run_count": len(runs),
        "summary": summary,
        "runs": runs_data,
    }