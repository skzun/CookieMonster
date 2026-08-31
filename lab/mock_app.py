"""Servidor HTTP minimalista de laboratório (stdlib, sem container).

Simula uma aplicação com estado de sessão determinístico para testar o `check`
sem rede real. Sem dependências externas.

Regras de sessão (vulnerável de propósito, para validar o detector):
  - Cookie `session` com valor "VALID"  -> autenticado (marker "My Account").
  - Cookie `session` ausente ou diferente -> anônimo (marker "Login").
  - Cookie `session` = "EXPIRED"         -> redirect para /login (session invalida).

Uso:
    python -m lab.mock_app [--port 8080]
"""

from __future__ import annotations

import argparse

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

AUTH_BODY = "<html><body>My Account Logout Dashboard</body></html>"
ANON_BODY = "<html><body>Login Sign In Welcome guest</body></html>"
LOGIN_OK = 200


def _get_cookie(handler: BaseHTTPRequestHandler, name: str) -> str:
    header = handler.headers.get("Cookie", "")
    for pair in header.split(";"):
        pair = pair.strip()
        if "=" in pair and pair.split("=", 1)[0].strip() == name:
            return pair.split("=", 1)[1].strip()
    return ""


def _session(handler: BaseHTTPRequestHandler) -> str:
    return _get_cookie(handler, "session")


class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        session = _session(self)
        path = urlparse(self.path).path

        if session == "EXPIRED":
            # Redireciona para login (sessão inválida).
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
            return

        if session == "VALID":
            body = AUTH_BODY
        else:
            body = ANON_BODY

        if path == "/login":
            body = ANON_BODY

        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass  # silencia logs para testes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), Handler)
    print(f"mock app ouvindo em http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()