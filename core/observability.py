"""
Instrumentación Langfuse opcional para el agent loop.

Si `langfuse` no está instalado o las credenciales no están configuradas,
toda la instrumentación se convierte en no-ops para no romper el flujo.

Variables de entorno:
    LANGFUSE_PUBLIC_KEY    pk-lf-...
    LANGFUSE_SECRET_KEY    sk-lf-...
    LANGFUSE_HOST          https://cloud.langfuse.com  (o tu self-host: http://localhost:3000)
    LANGFUSE_ENABLED       false para desactivar manualmente

Uso:
    obs = get_observer()
    with obs.trace(name="agent_run", input={"goal": goal}) as trace:
        with obs.generation(name="llm_call", model=model, input=contents) as gen:
            resp = client.generate(...)
            gen.update(output=resp)
        with obs.span(name="tool_dispatch", input={"name": tool, "args": args}):
            result = dispatch(...)
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional

from loguru import logger


# ---------------------------------------------------------------------
# Public flag + lazy singleton
# ---------------------------------------------------------------------
_observer_singleton: Optional["Observer"] = None


def _env_truthy(name: str, default: str = "true") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


def get_observer() -> "Observer":
    global _observer_singleton
    if _observer_singleton is None:
        _observer_singleton = Observer()
    return _observer_singleton


# ---------------------------------------------------------------------
# Observer wrapper
# ---------------------------------------------------------------------
class _NoopHandle:
    """Stand-in para spans/generations cuando Langfuse no está disponible."""

    def update(self, **_kwargs: Any) -> None:
        pass

    def end(self, **_kwargs: Any) -> None:
        pass


class Observer:
    """
    Fachada delgada sobre el SDK de Langfuse. Si el SDK no está instalado o
    las credenciales no están presentes, todas las llamadas se vuelven no-ops.
    """

    def __init__(self) -> None:
        self.enabled = False
        self._client = None
        self._reason = ""

        if not _env_truthy("LANGFUSE_ENABLED", default="true"):
            self._reason = "LANGFUSE_ENABLED=false"
            return

        try:
            from langfuse import Langfuse  # type: ignore
        except ImportError:
            self._reason = "paquete `langfuse` no instalado"
            return

        public = os.getenv("LANGFUSE_PUBLIC_KEY", "").strip()
        secret = os.getenv("LANGFUSE_SECRET_KEY", "").strip()
        host = os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com").strip()
        if not public or not secret:
            self._reason = "LANGFUSE_PUBLIC_KEY/LANGFUSE_SECRET_KEY no definidas"
            return

        try:
            self._client = Langfuse(public_key=public, secret_key=secret, host=host)
            self.enabled = True
            logger.info(f"[OBSERVER] Langfuse habilitado → {host}")
        except Exception as e:
            self._reason = f"Langfuse init falló: {e}"
            self._client = None

        if not self.enabled and self._reason:
            logger.debug(f"[OBSERVER] Langfuse desactivado: {self._reason}")

    # -----------------------------------------------------------------
    # Context managers
    # -----------------------------------------------------------------
    # IMPORTANTE: estos context managers NO enmascaran excepciones del código
    # del usuario. Solo "swallow" fallos de SETUP del observer (cuando arrancar
    # la observación falla por config Langfuse rota). Excepciones lanzadas
    # DESDE el código envuelto (ej. un 429 del proveedor) se propagan intactas para
    # que la lógica de retry/fallback del agente las pueda inspeccionar.
    #
    # Bug previo: try/except + yield-en-except hacía que `@contextmanager`
    # corrompiera el generador y reemplazara la excepción real por
    # `RuntimeError("generator didn't stop after throw()")`. La nueva
    # implementación separa los dos casos:
    #
    #   1. Setup falla (raro, config rota)        → log + yield noop
    #   2. Setup OK, código usuario lanza         → propagar tal cual
    @contextmanager
    def trace(self, name: str, input: Optional[Dict[str, Any]] = None,
              metadata: Optional[Dict[str, Any]] = None) -> Iterator[Any]:
        """Trace raíz. Engloba un run completo del agente."""
        if not self.enabled or self._client is None:
            yield _NoopHandle()
            return
        with self._observation_ctx("agent", name, input or {},
                                   metadata or {}) as handle:
            yield handle

    @contextmanager
    def generation(self, name: str, model: str,
                   input: Optional[Any] = None,
                   metadata: Optional[Dict[str, Any]] = None) -> Iterator[Any]:
        """Span tipo `generation` para llamadas LLM."""
        if not self.enabled or self._client is None:
            yield _NoopHandle()
            return
        with self._observation_ctx("generation", name, input,
                                   metadata or {}, model=model) as handle:
            yield handle

    @contextmanager
    def span(self, name: str, input: Optional[Any] = None,
             metadata: Optional[Dict[str, Any]] = None) -> Iterator[Any]:
        """Span genérico (tool dispatch, fase, etc.)."""
        if not self.enabled or self._client is None:
            yield _NoopHandle()
            return
        with self._observation_ctx("tool", name, input,
                                   metadata or {}) as handle:
            yield handle

    # -----------------------------------------------------------------
    # Helper interno
    # -----------------------------------------------------------------
    @contextmanager
    def _observation_ctx(self, as_type: str, name: str,
                         input: Any, metadata: Dict[str, Any],
                         model: Optional[str] = None) -> Iterator[Any]:
        """Wrapper que distingue entre fallo de setup y excepción del código.

        Si `start_as_current_observation` falla (Langfuse roto, red, etc.),
        degradamos a noop SILENCIOSAMENTE — el código del agente no debe
        depender del observer.

        Si setup OK pero el código envuelto lanza, propagamos sin tocar para
        que el caller (ej. agent loop) vea la excepción real.
        """
        kwargs: Dict[str, Any] = {
            "name": name,
            "as_type": as_type,
            "input": input,
            "metadata": metadata,
        }
        if model is not None:
            kwargs["model"] = model

        try:
            ctx = self._client.start_as_current_observation(**kwargs)
            handle = ctx.__enter__()
        except Exception as e:
            # Setup del observer falló → noop, no romper al usuario
            logger.warning(f"[OBSERVER] {as_type} setup failed: {e}")
            yield _NoopHandle()
            return

        # Setup OK. Si el usuario lanza, dejamos que ctx.__exit__ vea la excepción
        # (registrar el fallo en Langfuse) Y la re-lanzamos al caller.
        exc_info: Optional[tuple] = None
        try:
            yield handle
        except BaseException:
            import sys
            exc_info = sys.exc_info()
            raise
        finally:
            try:
                if exc_info is not None:
                    ctx.__exit__(*exc_info)
                else:
                    ctx.__exit__(None, None, None)
            except Exception as exit_err:
                # Errores cerrando el span no deben enmascarar lo que sea que
                # esté pasando con la excepción del usuario.
                logger.debug(f"[OBSERVER] {as_type} exit error: {exit_err}")

    # -----------------------------------------------------------------
    # Flush
    # -----------------------------------------------------------------
    def flush(self) -> None:
        if self.enabled and self._client is not None:
            try:
                self._client.flush()
            except Exception as e:
                logger.debug(f"[OBSERVER] flush error: {e}")
