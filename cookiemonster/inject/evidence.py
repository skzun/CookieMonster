"""Coletor de eventos de pagina (Playwright).

Captura requests/responses/console/pageerror para analise diferencial. Nao
armazena valores sensiveis por padrao.
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

    def attach(self, page: Page) -> None:
        page.on("request", self._on_request)
        page.on("response", self._on_response)
        page.on("requestfailed", self._on_failed)
        page.on("console", self._on_console)
        page.on("pageerror", self._on_error)

    def _on_request(self, req) -> None:
        self.requests.append({"url": req.url, "method": req.method})

    def _on_response(self, resp: Response) -> None:
        try:
            ct = (resp.headers.get("content-type") or "").lower()
        except Exception:
            ct = ""
        self.responses.append({
            "url": resp.url,
            "status": resp.status,
            "method": resp.request.method,
            "content_type": ct,
            # Cache do body para reuso. Limitamos tamanho para nao estourar memoria.
            "body": None,
        })

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

    def fetch_response_body(self, response: Response, max_size: int = 256_000) -> Optional[bytes]:
        """Carrega body de uma response (limitado). Cacheia em self.responses."""
        url = response.url
        for entry in self.responses:
            if entry["url"] == url and entry["body"] is not None:
                return entry["body"]
        try:
            body = response.body()
        except Exception:
            return None
        if body and len(body) > max_size:
            body = body[:max_size]
        for entry in self.responses:
            if entry["url"] == url:
                entry["body"] = body
        return body

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
            "requests": self.requests[-50:],   # limite p/ serializacao
            "responses": [
                {k: (None if k == "body" else v) for k, v in e.items()}
                for e in self.responses[-50:]
            ],
            "failed": self.failed[-20:],
            "console": self.console[-20:],
            "errors": self.errors[-20:],
        }


def parse_json_body(body: Optional[bytes]) -> Any:
    """Decodifica body JSON; retorna None em falha."""
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        return None