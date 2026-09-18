"""
Tests críticos: el Observer NO debe enmascarar excepciones del código envuelto.

Bug histórico: el `@contextmanager` con try/except + yield-en-except corrompía
el generador y reemplazaba la 429 real por `RuntimeError("generator didn't stop
after throw()")`. Esto rompía la lógica de retry de cuota del agente.

Estos tests verifican que excepciones del código yield-eado se propagan tal cual.
"""
from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core import observability
from core.observability import Observer, _NoopHandle


@pytest.fixture(autouse=True)
def _reset():
    observability._observer_singleton = None
    yield
    observability._observer_singleton = None


# ----------------------------------------------------------------- Disabled = noop
class TestDisabledIsNoop:

    def test_disabled_observer_yields_noop(self, monkeypatch):
        for k in ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY",
                  "LANGFUSE_HOST", "LANGFUSE_ENABLED"):
            monkeypatch.delenv(k, raising=False)
        obs = Observer()
        assert obs.enabled is False
        with obs.generation(name="x", model="m") as h:
            assert isinstance(h, _NoopHandle)


# ----------------------------------------------------------------- Propagation
class TestExceptionPropagation:
    """Cuando el código envuelto lanza, el observer debe propagar la excepción
    EXACTA, no una RuntimeError sustituta."""

    def _make_enabled_observer_with_mock_client(self) -> Observer:
        """Construye un Observer enabled con un cliente Langfuse mockeado.

        El mock implementa `start_as_current_observation` como contextmanager
        que yield-ea un MagicMock. Setup nunca falla.
        """
        obs = Observer()
        obs.enabled = True

        class _MockSpan:
            def __init__(self):
                self.update = MagicMock()
                self.end = MagicMock()

        @contextmanager
        def _mock_observation(**kwargs):
            yield _MockSpan()

        client = MagicMock()
        client.start_as_current_observation = _mock_observation
        obs._client = client
        return obs

    def test_user_exception_propagates_unchanged_in_generation(self):
        obs = self._make_enabled_observer_with_mock_client()

        class QuotaExhausted(Exception):
            pass

        # La excepción del usuario debe llegar al caller TAL CUAL
        with pytest.raises(QuotaExhausted, match="429 quota"):
            with obs.generation(name="llm_call", model="claude-haiku-4-5"):
                raise QuotaExhausted("429 quota exceeded for user")

    def test_user_exception_propagates_unchanged_in_trace(self):
        obs = self._make_enabled_observer_with_mock_client()

        class CustomErr(Exception):
            pass

        with pytest.raises(CustomErr, match="boom"):
            with obs.trace(name="root"):
                raise CustomErr("boom")

    def test_user_exception_propagates_unchanged_in_span(self):
        obs = self._make_enabled_observer_with_mock_client()

        class CustomErr(Exception):
            pass

        with pytest.raises(CustomErr, match="tool failed"):
            with obs.span(name="tool:x"):
                raise CustomErr("tool failed")

    def test_keyboardinterrupt_propagates(self):
        """Excepciones que NO heredan de Exception (KeyboardInterrupt) también
        deben propagarse — usamos BaseException en el except."""
        obs = self._make_enabled_observer_with_mock_client()
        with pytest.raises(KeyboardInterrupt):
            with obs.generation(name="x", model="m"):
                raise KeyboardInterrupt()

    def test_no_exception_works_normally(self):
        obs = self._make_enabled_observer_with_mock_client()
        with obs.generation(name="x", model="m") as h:
            assert h is not None
        # Si llegamos aquí sin excepción, el flow normal funciona.

    def test_setup_failure_falls_back_to_noop(self):
        """Si start_as_current_observation lanza durante el setup (raro),
        el observer degrada a noop SIN propagar (no debería romper al usuario)."""
        obs = Observer()
        obs.enabled = True

        @contextmanager
        def _bad_observation(**kwargs):
            raise RuntimeError("Langfuse server unreachable")
            yield  # nunca alcanzado

        client = MagicMock()
        client.start_as_current_observation = _bad_observation
        obs._client = client

        with obs.generation(name="x", model="m") as h:
            # Setup falló → noop yieldeado
            assert isinstance(h, _NoopHandle)
        # No exception propaga — el agente sigue funcionando sin trazas


# ----------------------------------------------------------------- Cleanup en error
class TestCleanupOnError:
    """Cuando el usuario lanza, ctx.__exit__ debe llamarse con la info de la
    excepción (para que Langfuse marque el span como erroneo). Verificamos."""

    def test_exit_called_with_exception_info(self):
        obs = Observer()
        obs.enabled = True

        exit_calls = []

        class _Ctx:
            def __enter__(self):
                return MagicMock()

            def __exit__(self, exc_type, exc_val, exc_tb):
                exit_calls.append((exc_type, exc_val))
                return False  # no suprimir

        client = MagicMock()
        client.start_as_current_observation = lambda **kw: _Ctx()
        obs._client = client

        class MyErr(Exception):
            pass

        with pytest.raises(MyErr):
            with obs.generation(name="x", model="m"):
                raise MyErr("test")

        assert len(exit_calls) == 1
        exc_type, exc_val = exit_calls[0]
        assert exc_type is MyErr
        assert isinstance(exc_val, MyErr)

    def test_exit_called_without_exception_on_success(self):
        obs = Observer()
        obs.enabled = True
        exit_calls = []

        class _Ctx:
            def __enter__(self):
                return MagicMock()

            def __exit__(self, exc_type, exc_val, exc_tb):
                exit_calls.append((exc_type, exc_val))
                return False

        client = MagicMock()
        client.start_as_current_observation = lambda **kw: _Ctx()
        obs._client = client

        with obs.generation(name="x", model="m"):
            pass

        assert exit_calls == [(None, None)]
