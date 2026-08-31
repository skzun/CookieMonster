"""Teste E2E deterministico usando o mock do lab (sem rede real).

Valida o fluxo inject -> detect sobre a aplicação de laboratório.
"""

import threading

from http.server import HTTPServer

import pytest

from lab.mock_app import Handler

from cookiemonster.inject import httpx_client
from cookiemonster.validate.auth_state import detect, VALID, INVALID, UNKNOWN


@pytest.fixture(scope="module")
def server_url():
    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


def _check(url, cookies):
    baseline = httpx_client.get(url, [])
    injected = httpx_client.get(url, cookies)
    return detect(baseline, injected, "127.0.0.1")


def test_valid_session_detected(server_url):
    cookies = [{"name": "session", "value": "VALID", "domain": "127.0.0.1",
                "path": "/", "secure": False, "http_only": True, "expires_epoch": 0}]
    result = _check(server_url + "/", cookies)
    assert result["state"] == VALID


def test_no_cookie_is_anonymous(server_url):
    result = _check(server_url + "/", [])
    # Sem cookies, anonimo: baseline == injetado => nao VALID.
    assert result["state"] in (INVALID, UNKNOWN)


def test_expired_session_invalid(server_url):
    cookies = [{"name": "session", "value": "EXPIRED", "domain": "127.0.0.1",
                "path": "/", "secure": False, "http_only": True, "expires_epoch": 0}]
    result = _check(server_url + "/", cookies)
    assert result["state"] == INVALID