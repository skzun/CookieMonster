"""stealth: perfil opt-in de bypass/evasion (OPT-B).

Modulos:
- profile: StealthProfile + loaders + built-in templates.

Arquivos YAML/JSON sao carregados explicitamente pelo operador.
NAO ativa nada por padrao.
"""

from .profile import (
    StealthProfile,
    load_stealth_profile,
    list_builtin_profiles,
)

__all__ = [
    "StealthProfile",
    "load_stealth_profile",
    "list_builtin_profiles",
]
