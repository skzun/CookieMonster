"""lab: anti-bot lab profiles (OPT-D).

Modulos:
- profiles: LabProfile + 7 labs canonicos (A-G) + exporters.

NAO IMPLEMENTA bypass. Apenas documenta os cenarios para validacao
controlada em ambiente de laboratorio.
"""

from .profiles import (
    LabProfile, Protection, ExpectedOutcome,
    LAB_PROFILES, list_labs, get_lab,
    export_scenarios_json, render_lab_summary,
)

__all__ = [
    "LabProfile", "Protection", "ExpectedOutcome",
    "LAB_PROFILES", "list_labs", "get_lab",
    "export_scenarios_json", "render_lab_summary",
]
