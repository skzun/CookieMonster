"""Testes do dump JSON atomico."""

import os

from pathlib import Path

from cookiemonster.report import json_out


def test_dump_atomic_creates_file(tmp_path: Path):
    target = tmp_path / "r.json"
    json_out.dump({"a": 1, "b": [1, 2, 3]}, target)
    assert target.exists()
    # Nao deve sobrar arquivo .tmp
    leftovers = list(tmp_path.glob("*.tmp"))
    assert leftovers == [], f"temporarios restantes: {leftovers}"


def test_dump_overwrites_existing(tmp_path: Path):
    target = tmp_path / "r.json"
    json_out.dump({"old": True}, target)
    json_out.dump({"new": True}, target)
    import json
    assert json.loads(target.read_text()) == {"new": True}


def test_dump_handles_interruption_no_zero_byte(tmp_path: Path):
    """Se o processo for morto, o arquivo final nao pode ser 0 bytes."""
    target = tmp_path / "r.json"
    # Escreve normalmente.
    json_out.dump({"a": 1, "b": 2}, target)
    assert target.stat().st_size > 0
    # O .tmp nao deve existir (foi renomeado).
    assert not target.with_suffix(target.suffix + ".tmp").exists()


def test_dump_creates_parent_dirs(tmp_path: Path):
    target = tmp_path / "deep" / "nested" / "r.json"
    json_out.dump({"a": 1}, target)
    assert target.exists()