"""Coletor de eventos de pagina (Playwright).

Captura requests/responses/console/pageerror para analise diferencial.
"""

from __future__ import annotations

import json

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from playwright.sync_api import Page, Response


@dataclass
class PageEvents:
    requests: List[Dict[str, Any]] = field(default_factory=list)
    responses: List[Dict[str, Any]] = field(default_factory=list)
    failed: List[Dict[str, Any]] = field(default_factory=list)
    console: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[Dict[str, Any]] = field(default_factory=list)

    def attach(self, page: Page, capture_bodies: bool = True,
               max_body_size: int = 256_000) -> None:
        page.on("request", self._on_request)
        page.on("response",
                lambda r: self._on_response(r, capture_bodies, max_body_size))
        page.on("requestfailed", self._on_failed)
        page.on("console", self._on_console)
        page.on("pageerror", self._on_error)

    def _on_request(self, req) -> None:
        self.requests.append({"url": req.url, "method": req.method})

    def _on_response(self, resp: Response, capture_bodies: bool,
                     max_body_size: int) -> None:
        try:
            ct = (resp.headers.get("content-type") or "").lower()
        except Exception:
            ct = ""
        entry: Dict[str, Any] = {
            "url": resp.url,
            "status": resp.status,
            "method": resp.request.method,
            "content_type": ct,
            "body": None,
            "json": None,
        }
        # Carrega body sob demanda se for JSON (economia de memoria).
        if capture_bodies and "json" in ct and resp.status == 200:
            try:
                body = resp.body()
                if body:
                    if len(body) > max_body_size:
                        body = body[:max_body_size]
                    entry["body"] = body
                    try:
                        entry["json"] = json.loads(
                            body.decode("utf-8", errors="replace")
                        )
                    except Exception:
                        pass
            except Exception:
                pass
        self.responses.append(entry)

    def _on_failed(self, req) -> None:
        try:
            err = req.failure
        except Exception:
            err = "unknown"
        self.failed.append({"url": req.url, "method": req.method, "error": err})

    def _on_console(self, msg) -> None:
        try:
            self.console.append({"type": msg.type, "text": msg.text[:500]})
        except Exception:
            pass

    def _on_error(self, err) -> None:
        try:
            self.errors.append({"message": str(err)[:500]})
        except Exception:
            pass

    def find_auth_responses(self, hints: tuple) -> List[Dict[str, Any]]:
        """Retorna responses cujos URLs casam com hints (endpoints de identidade)."""
        out = []
        for entry in self.responses:
            url_l = entry["url"].lower()
            if any(h in url_l for h in hints):
                out.append(entry)
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requests": self.requests[-50:],
            "responses": [
                {k: (None if k == "body" else v) for k, v in e.items()}
                for e in self.responses[-50:]
            ],
            "failed": self.failed[-20:],
            "console": self.console[-20:],
            "errors": self.errors[-20:],
        }


def parse_json_body(body: Optional[bytes]) -> Any:
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        return None