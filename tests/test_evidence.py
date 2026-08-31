"""Testes de carregamento de body JSON via PageEvents."""

from cookiemonster.inject.evidence import PageEvents, parse_json_body


def test_parse_json_body():
    assert parse_json_body(b'{"id": 123}') == {"id": 123}
    assert parse_json_body(b"invalid") is None
    assert parse_json_body(None) is None


def test_response_event_entry_has_json_field():
    e = PageEvents()
    assert isinstance(e.responses, list)
    # Apos attach, response with json content-type deve popular 'json' field
    # (testado em integracao via Playwright). Aqui apenas estrutura.