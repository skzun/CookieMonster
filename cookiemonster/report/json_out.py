"""Exportacao de relatorios em JSON."""

from __future__ import annotations

import json

import os

from pathlib import Path
from typing import Any


def dump(data: Any, path: Path) -> None:
    """Escreve data como JSON em path com atomicidade (escrita em temp + rename).

    Atomic write garante que `path` nao apareca truncado/zerado se o processo for
    interrompido durante a escrita.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, ensure_ascii=False, indent=2, default=str)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    # Abre em modo 'w' e fecha antes do rename para garantir flush.
    with open(tmp_path, "w", encoding="utf-8") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_path, path)


def dumps(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2, default=str)