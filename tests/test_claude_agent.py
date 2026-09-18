"""
Tests para `core/claude_agent.py` y la detección de proveedor en `run.py`.

No invocan la API real de Anthropic ni AWS — verifican:
  - Cobertura exhaustiva de `_is_claude_model` (todas las regiones Bedrock)
  - Simetría con `_is_bedrock_model`
  - `_supports_thinking` reconoce todos los modelos Claude conocidos
  - `_bedrock_fallback` preserva el prefijo de región
  - `ClaudeConfig` expone los campos que `run.py` rellena, garantizando que
    el contrato de la CLI no se rompe al cambiar de modelo
"""
from __future__ import annotations

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.claude_agent import (
    ClaudeConfig,
    _bedrock_fallback,
    _is_bedrock_model,
    _supports_thinking,
)
from run import _is_claude_model


# ---------------------------------------------------------------------------
# Detección de proveedor — run.py
# ---------------------------------------------------------------------------
class TestProviderDetection:

    @pytest.mark.parametrize("model", [
        "claude-opus-4-7",
        "claude-sonnet-4-6",
        "claude-haiku-4-5-20251001",
        "anthropic.claude-3-5-haiku-20241022-v1:0",
        "us.anthropic.claude-haiku-4-5-20251001-v1:0",
        "eu.anthropic.claude-sonnet-4-6-v1:0",
        "ap.anthropic.claude-opus-4-7-v1:0",
        "au.anthropic.claude-haiku-4-5-v1:0",
        "jp.anthropic.claude-sonnet-4-6-v1:0",
        "global.anthropic.claude-opus-4-7-v1:0",
    ])
    def test_claude_models_detected(self, model):
        assert _is_claude_model(model) is True

    @pytest.mark.parametrize("model", [
        "gpt-4o",
        "llama-3.1-70b",
        "mistral-large",
        "amazon.titan-text-premier-v1:0",
    ])
    def test_non_claude_models_rejected(self, model):
        """`run.py` los rechaza con un mensaje legible en vez de fallar en el SDK."""
        assert _is_claude_model(model) is False

    def test_is_claude_case_insensitive(self):
        assert _is_claude_model("CLAUDE-SONNET-4-6") is True
        assert _is_claude_model("US.ANTHROPIC.CLAUDE-HAIKU") is True


# ---------------------------------------------------------------------------
# Bedrock vs Anthropic directo
# ---------------------------------------------------------------------------
class TestBedrockDetection:

    def setup_method(self):
        # Aislar test del entorno: borrar AWS vars que podrían influir
        self._saved = {}
        for k in ("AWS_BEARER_TOKEN_BEDROCK", "AWS_ACCESS_KEY_ID"):
            if k in os.environ:
                self._saved[k] = os.environ.pop(k)

    def teardown_method(self):
        for k, v in self._saved.items():
            os.environ[k] = v

    def test_bedrock_prefix_triggers_bedrock(self):
        assert _is_bedrock_model("anthropic.claude-3-5-haiku") is True
        assert _is_bedrock_model("us.anthropic.claude-haiku-4-5") is True

    def test_direct_claude_without_aws_env_is_not_bedrock(self):
        assert _is_bedrock_model("claude-sonnet-4-6") is False

    def test_aws_env_overrides_prefix(self, monkeypatch):
        monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "dummy-token")
        # Incluso un modelo "directo" se routea a Bedrock si hay vars AWS:
        # criterio elegido para que usuarios con setup Bedrock no necesiten
        # cambiar el modelo name.
        assert _is_bedrock_model("claude-sonnet-4-6") is True


class TestBedrockFallback:

    def test_us_prefix_preserved(self):
        out = _bedrock_fallback("us.anthropic.claude-opus-4-7-v1:0")
        assert out.startswith("us.anthropic.")
        assert "haiku" in out

    def test_eu_prefix_preserved(self):
        out = _bedrock_fallback("eu.anthropic.claude-sonnet-4-6-v1:0")
        assert out.startswith("eu.anthropic.")

    def test_no_prefix_returns_plain_anthropic(self):
        out = _bedrock_fallback("anthropic.claude-opus-4-7-v1:0")
        assert out.startswith("anthropic.")
        assert not out.startswith("us.")


# ---------------------------------------------------------------------------
# Extended thinking capability
# ---------------------------------------------------------------------------
class TestThinkingCapability:

    @pytest.mark.parametrize("model", [
        "claude-opus-4-7",
        "claude-sonnet-4-6",
        "claude-haiku-4-5-20251001",
        "anthropic.claude-3-5-sonnet-20241022-v2:0",
    ])
    def test_known_thinking_capable(self, model):
        assert _supports_thinking(model) is True

    def test_non_claude_not_thinking_capable(self):
        assert _supports_thinking("gpt-4o") is False
        # Regional prefix sin "anthropic." en raíz no se reconoce — caller
        # debe normalizar antes (el agent solo recibe modelos ya seleccionados).
        assert _supports_thinking("us.anthropic.claude-haiku") is False


# ---------------------------------------------------------------------------
# Contrato del config dataclass — lo que `run.py` rellena tiene que existir
# ---------------------------------------------------------------------------
class TestClaudeConfigContract:

    def test_required_fields_present(self):
        """Los campos que `run.py` construye al invocar `ClaudeConfig(...)`.

        Vive como prueba y no como confianza porque el fallo sería un
        `TypeError` en el arranque de una auditoría real, no en la suite.
        """
        claude_fields = {f for f in ClaudeConfig.__dataclass_fields__}
        required = {"model", "reasoning_model", "max_turns", "wall_clock_seconds",
                    "thinking_budget", "confirm_callback"}
        assert not (required - claude_fields), f"ClaudeConfig falta: {required - claude_fields}"

    def test_confirm_callback_present(self):
        # Necesario para --confirm en CLI
        assert "confirm_callback" in ClaudeConfig.__dataclass_fields__
