"""Base común de los agentes ReAct (iter_10).

Materializa la **independencia del proveedor** (OE5) como una jerarquía
explícita: la orquestación, el *tracing* y los *helpers* comunes viven aquí;
cada proveedor solo implementa su **bucle de tool use específico del SDK**
(`_run_inner`) y su planificación (`_plan`). Así, «añadir un proveedor» se
reduce a una subclase que implementa esos dos métodos sobre su SDK, sin
reescribir la lógica común ni tocar el catálogo de herramientas.

No abstrae el bucle SDK a propósito: cada SDK tiene su forma de mensaje y de
*tool calling*, y forzar una abstracción única perjudicaría la legibilidad sin
beneficio real. Lo que SÍ es idéntico —el envoltorio de *tracing* `run()` y la
extracción de metadatos/enlace de reflexión— se comparte aquí.
"""
from __future__ import annotations

import os
from typing import Optional

from loguru import logger


class BaseReActAgent:
    """Comportamiento común a las implementaciones concretas (`ClaudeAgent`).

    Las subclases deben proporcionar:
      - `self.observer` con `.trace(...)` (context manager) y `.flush()`.
      - `self.cfg` con `.model` e `.initial_phase`.
      - `_run_inner(self, goal, root_trace) -> dict`: el bucle ReAct del SDK.
    """

    # Anotaciones para los type-checkers / lectores; las subclases las asignan.
    observer: object
    cfg: object

    def run(self, goal: str) -> dict:
        """Envoltorio común: abre una traza raíz, ejecuta el bucle del proveedor
        y garantiza el *flush* de observabilidad pase lo que pase.

        También garantiza el **informe**. Hasta ahora solo lo producía la ruta
        feliz: `done()` guardaba, y las otra diez formas de terminar —presupuesto
        agotado, reloj, 429 del proveedor, error de API, `end_turn_no_tools`,
        Ctrl+C, el `SIGTERM` del botón «detener» del panel, un apagón— salían
        del bucle sin escribir nada. Dos de las quince ejecuciones de campo del
        2026-08-09 se perdieron enteras así: una tras 274 turnos y 27 minutos de
        trabajo, otra con la identidad ya fijada y 32 CVE candidatos en la mano.

        Que el trabajo hecho sobreviva a la forma de terminar no es una
        comodidad: es lo que hace que una tanda de N réplicas produzca N
        artefactos, y no «N menos las que tuvieron mala suerte».
        """
        self._stamp_session_identity()
        with self.observer.trace(
            name="agent_run",
            input={"goal": goal},
            metadata={"model": self.cfg.model, "initial_phase": self.cfg.initial_phase},
        ) as root_trace:
            try:
                result = self._run_inner(goal, root_trace)
            except BaseException as e:
                # BaseException, no Exception: las paradas externas llegan como
                # `KeyboardInterrupt` (Ctrl+C) o como la excepción que `run.py`
                # levanta desde el manejador de SIGTERM, y ninguna de las dos
                # hereda de `Exception`. Capturarlas es precisamente el caso que
                # más informes perdía.
                self._rescue_report(f"aborted: {type(e).__name__}")
                raise
            finally:
                self.observer.flush()
            self._rescue_report(result.get("finish_reason"), result.get("turns", 0))
            return result

    @staticmethod
    def _publish_turn(turns: int) -> None:
        """Deja el turno en curso en la sesión, si la hay.

        Tolera que no exista: los agentes se conducen también desde pruebas que
        no ligan sesión, y un contador de progreso no puede ser el motivo de que
        el bucle reviente.
        """
        try:
            from core import tools as toolbox
            toolbox.get_session().turns_completed = turns
        except (ImportError, RuntimeError):
            pass

    @staticmethod
    def _rescue_report(finish_reason: Optional[str], turns: int = 0) -> Optional[str]:
        """Guarda el informe si el run acaba sin haberlo guardado.

        No hay nada que decidir sobre el contenido: `_save_report` construye el
        artefacto entero a partir de la SESIÓN (hallazgos, escaneo, identidad),
        no de argumentos del modelo, así que puede llamarse en cualquier momento
        y produce el informe de lo que se sepa hasta ese instante.

        Deliberadamente NO dispara la reflexión: es otra llamada al LLM, tarda, y
        el panel concede cinco segundos entre `SIGTERM` y `SIGKILL`. Ante una
        parada, el artefacto de evidencia va primero.
        """
        from core import tools as toolbox
        try:
            session = toolbox.get_session()
        except (ImportError, RuntimeError):
            return None
        if session.finish_reason is None:
            session.finish_reason = finish_reason
        if turns:
            session.turns_completed = turns
        if getattr(session, "report_saved_path", None) is not None:
            return None  # `done()` o el propio modelo ya lo guardaron
        if not session.findings and not session.scan_cache:
            return None  # el run no llegó a ver nada: un informe vacío es ruido
        try:
            saved = toolbox._save_report({})
            path = saved.get("path")
            logger.warning(
                f"[RESCATE] run terminado por '{finish_reason}' sin llamar a "
                f"done(); informe guardado igualmente en {path}")
            return path
        except Exception as e:
            logger.error(f"[RESCATE] no se pudo guardar el informe: {e}")
            return None

    def _stamp_session_identity(self) -> None:
        """Deja en la sesión qué modelo conduce el run, para el `run_metadata`.

        Lo hacía únicamente `run.py`, de modo que la atribución del informe
        dependía de que el LANZADOR se acordara: cualquier otra vía de entrada
        —conducir el agente programáticamente, un arnés, una prueba— producía
        informes con `model: null`, indistinguibles entre proveedores. La
        atribución debe seguir al agente, que es quien sabe qué modelo es, no a
        quien lo arranca. No sobreescribe lo que ya venga puesto: si `run.py` lo
        fijó con el nombre exacto de la CLI, ese gana.
        """
        try:
            from core import tools as toolbox
            session = toolbox.get_session()
        except (ImportError, RuntimeError):
            return  # sin sesión ligada (tests unitarios del agente)
        model = getattr(self.cfg, "model", None)
        if model and not session.model_name:
            session.model_name = model
        if not session.provider:
            session.provider = self._provider_label()

    def _record_rate_limit_hit(self) -> int:
        """Cuenta un 429 del proveedor y lo publica en la sesión.

        `_quota_retries` mide la RACHA (se pone a cero con cada llamada
        correcta), así que no sirve para informar: en una auditoría real con
        quince 429 el log repetía «(1/6)» quince veces y parecía que el
        presupuesto no se tocaba nunca. El total del run va al `run_metadata`
        porque explica diferencias entre réplicas —una estrangulada recorre
        menos herramientas en el mismo presupuesto de reloj— que de otro modo
        se atribuirían al agente.
        """
        self._quota_hits_total = getattr(self, "_quota_hits_total", 0) + 1
        try:
            from core import tools as toolbox
            toolbox.get_session().provider_rate_limit_hits = self._quota_hits_total
        except (ImportError, RuntimeError):
            pass
        return self._quota_hits_total

    @staticmethod
    def _backoff_seconds(streak: int, provider_hint: Optional[float] = None) -> int:
        """Retroceso exponencial acotado, con la pista del proveedor si la hay.

        Era fijo en 10s y, como la racha se reinicia con cada éxito, nunca
        crecía: quince 429 seguidos a 10s cada uno son 150 s de espera sin que
        el ritmo baje ni una vez.
        """
        delay = min(10 * (2 ** (max(streak, 1) - 1)), 60)
        if provider_hint:
            delay = min(max(int(provider_hint) + 1, delay), 60)
        return delay

    def _provider_label(self) -> str:
        """Etiqueta del proveedor, deducida del nombre del modelo."""
        model = (getattr(self.cfg, "model", "") or "").lower()
        if model.startswith("claude-") or ".anthropic." in model or model.startswith("anthropic."):
            return "Anthropic/Claude"
        return "unknown"

    def _run_inner(self, goal: str, root_trace) -> dict:  # pragma: no cover
        raise NotImplementedError(
            "cada subclase implementa su bucle de tool use específico del SDK")

    @staticmethod
    def _extract_device_metadata(findings: list, scan: dict) -> tuple:
        """Extrae (vendor, model, firmware) priorizando scan_cache.

        Si scan_cache no tiene vendor, delega en el helper consolidado
        `_heuristic_vendor_from_findings` (filtra por confirmed=True y usa
        word boundaries reales — evita el bug histórico de 'LG' dentro de
        'algoritmo').
        """
        from core.tools import _heuristic_vendor_from_findings
        vendor = (
            scan.get("vendor")
            or scan.get("ssdp_manufacturer")
            or scan.get("manufacturer")
            or _heuristic_vendor_from_findings(findings)
        )
        model = (
            scan.get("model")
            or scan.get("ssdp_model")
            or scan.get("ssdp_exact_model")
        )
        firmware = scan.get("firmware") or scan.get("software_version")
        return vendor, model, firmware

    @staticmethod
    def _append_reflection_link_to_latest_report(reflection_md_path: Optional[str]) -> None:
        """Añade un enlace al reflection report al final del MD de ESTE run.

        El reflection se genera DESPUÉS de save_report (el modelo invoca
        save_report → done; el reflection corre post-done). Para que el enlace
        aparezca en el MD del audit report, lo concatenamos al final.
        Idempotente: detecta si ya existe el bloque y no lo duplica.

        El destino es `session.report_saved_path`, no «el MD más reciente de
        reports/». Buscar el más reciente funcionaba solo mientras este run
        hubiera guardado el suyo: cuando no lo hacía —y hasta ahora eso pasaba
        en las diez formas de terminar que no son `done()`— el enlace se pegaba
        al informe del run ANTERIOR, contaminando un artefacto ajeno con la
        reflexión de otra ejecución. En una tanda de réplicas, que es
        precisamente donde importa, el vecino es siempre otra réplica.
        """
        if not reflection_md_path or not os.path.isfile(reflection_md_path):
            return
        try:
            from core import tools as toolbox
            base = toolbox.get_session().report_saved_path
        except (ImportError, RuntimeError):
            return
        if not base:
            logger.debug("[REPORT] sin informe de este run; enlace de reflexión omitido")
            return
        latest = f"{base}.md"
        if not os.path.isfile(latest):
            return
        try:
            with open(latest, "r", encoding="utf-8") as f:
                content = f.read()
            if "🪞 Reflection report" in content:
                return  # ya añadido
            block = (
                "\n\n## 🪞 Reflection report\n\n"
                "Análisis post-run automático con sugerencias de mejora "
                "para próximas auditorías:\n\n"
                f"📄 [`{os.path.basename(reflection_md_path)}`]"
                f"({reflection_md_path})\n"
            )
            with open(latest, "a", encoding="utf-8") as f:
                f.write(block)
            logger.debug(f"[REPORT] reflection link appended to {latest}")
        except OSError:
            pass
