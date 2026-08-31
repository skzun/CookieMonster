"""Construcao do relatorio a partir do store (consolidacao runs + findings)."""

from __future__ import annotations

import json

from collections import Counter
from datetime import datetime, timezone

from typing import Dict, List

from ..store.db import Store


def build_report(store: Store) -> Dict:
    runs = store.list_runs()
    runs_data: List[dict] = []
    for r in runs:
        findings = store.findings_for_run(r["id"])
        evidence = {}
        if r["evidence_json"]:
            try:
                evidence = json.loads(r["evidence_json"])
            except Exception:
                evidence = {}
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
            "evidence": evidence,
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

    domain_agg: Dict[str, Dict] = {}
    for s in summary:
        d = s["domain"]
        agg = domain_agg.setdefault(d, {
            "domain": d, "runs": 0,
            "confirmed": 0, "likely": 0, "anonymous": 0, "unknown": 0,
            "channels": Counter(),
        })
        agg["runs"] += 1
        agg["channels"][s["channel"]] += 1
        st = (s["state"] or "").lower()
        if st in agg:
            agg[st] += 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "run_count": len(runs),
        "summary": summary,
        "domain_aggregate": list(domain_agg.values()),
        "runs": runs_data,
    }