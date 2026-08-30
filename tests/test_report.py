"""Testes do M4 (geração de relatórios)."""

from pathlib import Path

from cookiemonster.report import json_out, markdown_out


def test_json_dump(tmp_path: Path):
    path = tmp_path / "r" / "report.json"
    json_out.dump({"a": 1, "b": "x"}, path)
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    assert '"a": 1' in text


def test_markdown_render_table():
    report = {
        "generated_at": "2026-01-01T00:00:00Z",
        "run_count": 1,
        "summary": [
            {"id": 1, "victim_id": 2, "domain": "amazon.com", "channel": "httpx",
             "state": "SESSION_VALID", "confidence": 0.9, "finding_count": 3},
        ],
        "runs": [],
    }
    md = markdown_out.render(report)
    assert "# Relatório — CookieMonster" in md
    assert "SESSION_VALID" in md


def test_markdown_dump(tmp_path: Path):
    path = tmp_path / "report.md"
    markdown_out.dump({"generated_at": "", "run_count": 0, "summary": [], "runs": []}, path)
    assert path.exists()
    assert path.read_text(encoding="utf-8").startswith("# Relatório")