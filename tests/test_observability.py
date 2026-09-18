"""
Tests para core/observability.py — Observer Langfuse opcional.

Verifica que:
- Sin Langfuse instalado o sin credenciales: todo es no-op silencioso.
- LANGFUSE_ENABLED=false desactiva manualmente.
- Los context managers nunca rompen el flujo del agente, aunque el SDK falle.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import observability


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Garantiza que cada test parte de un Observer fresco."""
    observability._observer_singleton = None
    yield
    observability._observer_singleton = None


def _clear_lf_env(monkeypatch):
    for k in ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY",
              "LANGFUSE_HOST", "LANGFUSE_ENABLED"):
        monkeypatch.delenv(k, raising=False)


class TestObserverDisabled:

    def test_no_credentials_means_disabled(self, monkeypatch):
        _clear_lf_env(monkeypatch)
        obs = observability.get_observer()
        assert obs.enabled is False

    def test_explicit_false_disables(self, monkeypatch):
        _clear_lf_env(monkeypatch)
        monkeypatch.setenv("LANGFUSE_ENABLED", "false")
        monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk-test")
        monkeypatch.setenv("LANGFUSE_SECRET_KEY", "sk-test")
        obs = observability.get_observer()
        assert obs.enabled is False

    def test_partial_credentials_disables(self, monkeypatch):
        _clear_lf_env(monkeypatch)
        monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk-test")
        # falta secret
        obs = observability.get_observer()
        assert obs.enabled is False


class TestNoopContexts:
    """Cuando Observer está deshabilitado, los context managers funcionan sin romper."""

    def test_trace_yields_handle_with_update(self, monkeypatch):
        _clear_lf_env(monkeypatch)
        obs = observability.get_observer()
        with obs.trace(name="root", input={"x": 1}) as t:
            t.update(output={"ok": True})
        # no exception = test pasa

    def test_generation_yields_handle(self, monkeypatch):
        _clear_lf_env(monkeypatch)
        obs = observability.get_observer()
        with obs.generation(name="gen", model="claude-haiku-4-5") as g:
            g.update(output="hello")

    def test_span_yields_handle(self, monkeypatch):
        _clear_lf_env(monkeypatch)
        obs = observability.get_observer()
        with obs.span(name="tool:x", input={"a": 1}) as s:
            s.update(output={"ok": True})

    def test_nested_contexts_work(self, monkeypatch):
        _clear_lf_env(monkeypatch)
        obs = observability.get_observer()
        with obs.trace(name="root"):
            with obs.generation(name="llm", model="m"):
                with obs.span(name="tool"):
                    pass

    def test_flush_is_safe_when_disabled(self, monkeypatch):
        _clear_lf_env(monkeypatch)
        obs = observability.get_observer()
        obs.flush()  # no exception


class TestSingleton:

    def test_get_observer_is_idempotent(self, monkeypatch):
        _clear_lf_env(monkeypatch)
        a = observability.get_observer()
        b = observability.get_observer()
        assert a is b


class TestEnvTruthy:

    def test_truthy_values(self, monkeypatch):
        for v in ("1", "true", "TRUE", "yes", "on"):
            monkeypatch.setenv("X_TEST", v)
            assert observability._env_truthy("X_TEST") is True

    def test_falsy_values(self, monkeypatch):
        for v in ("0", "false", "no", "off", ""):
            monkeypatch.setenv("X_TEST", v)
            assert observability._env_truthy("X_TEST") is False

    def test_default_when_unset(self, monkeypatch):
        monkeypatch.delenv("X_TEST_UNSET", raising=False)
        assert observability._env_truthy("X_TEST_UNSET", default="true") is True
        assert observability._env_truthy("X_TEST_UNSET", default="false") is False
