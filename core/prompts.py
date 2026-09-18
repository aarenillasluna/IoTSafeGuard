"""
Carga de prompts por fase desde el directorio prompts/.

Convención:
    prompts/planner.md   → planificador inicial (sin tools)
    prompts/recon.md     → fase de reconocimiento
    prompts/exploit.md   → fase de explotación

El planner usa `.format(goal=...)` por compatibilidad con el flujo previo.
Los prompts de fase se cargan tal cual.
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import Literal

Phase = Literal["recon", "exploit"]

_PROMPTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "prompts",
)


@lru_cache(maxsize=8)
def _read(name: str) -> str:
    path = os.path.join(_PROMPTS_DIR, name)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Prompt no encontrado: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def get_planner_prompt(goal: str) -> str:
    return _read("planner.md").format(goal=goal)


def get_phase_prompt(phase: Phase) -> str:
    if phase not in ("recon", "exploit"):
        raise ValueError(f"phase debe ser 'recon' o 'exploit', no {phase!r}")
    return _read(f"{phase}.md")


def reset_cache() -> None:
    """Útil en tests para forzar relectura del disco."""
    _read.cache_clear()
