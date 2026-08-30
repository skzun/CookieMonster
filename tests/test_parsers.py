"""Testes dos parsers de cookies (M0)."""

from pathlib import Path

from cookiemonster.ingest.netscape_parser import parse_line, parse_file
from cookiemonster.ingest.json_parser import parse_json_file


def test_netscape_basic_line():
    line = "accounts.google.com\tFALSE\t/\tTRUE\t1785662434\tOTZ\t8679441_40_40__40_"
    c = parse_line(line)
    assert c is not None
    assert c.name == "OTZ"
    assert c.domain == "accounts.google.com"
    assert c.path == "/"
    assert c.secure is True
    assert c.host_only is True
    assert c.http_only is False
    assert c.expires_epoch == 1785662434


def test_netscape_domain_cookie_and_path():
    line = ".amazon.com\tTRUE\t/some/path\tFALSE\t1817630497\tsession-id\t123-456"
    c = parse_line(line)
    assert c.host_only is False
    assert c.secure is False
    assert c.path == "/some/path"


def test_netscape_expiry_with_suffix():
    line = ".amazon.com\tTRUE\t/\tTRUE\t2082787201l\tsession-id-time\t123"
    c = parse_line(line)
    assert c.expires_epoch == 2082787201


def test_netscape_value_with_tabs():
    line = ".x.com\tTRUE\t/\tFALSE\t0\tv\tpart1\tpart2"
    c = parse_line(line)
    assert c.value == "part1\tpart2"


def test_netscape_ignores_comment_and_empty():
    assert parse_line("# Netscape HTTP Cookie File") is None
    assert parse_line("") is None


def test_netscape_malformed_line():
    assert parse_line("only\tthree\tcols") is None


def test_netscape_file(tmp_path: Path):
    f = tmp_path / "cookies.txt"
    f.write_text(
        "a.com\tFALSE\t/\tTRUE\t1000\tn1\tv1\n"
        "# comment\n"
        "b.com\tTRUE\t/\tFALSE\t2000\tn2\tv2\n"
        "malformed\n",
        encoding="utf-8",
    )
    cookies = parse_file(f)
    assert len(cookies) == 2


def test_json_file(tmp_path: Path):
    f = tmp_path / "cookies.json"
    f.write_text(
        '[{"domain": "accounts.google.com", "expirationDate": 1783869963.0,'
        ' "hostOnly": true, "httpOnly": false, "name": "OTZ", "path": "/",'
        ' "secure": true, "session": false, "value": "8649566"},'
        '{"domain": ".github.com", "expirationDate": 1796850026,'
        ' "hostOnly": false, "httpOnly": true, "name": "logged_in", "path": "/",'
        ' "secure": true, "session": false, "value": "yes"}]',
        encoding="utf-8",
    )
    cookies = parse_json_file(f)
    assert len(cookies) == 2
    assert cookies[0].host_only is True
    assert cookies[0].http_only is False
    assert cookies[1].host_only is False
    assert cookies[1].http_only is True
    assert cookies[1].value == "yes"