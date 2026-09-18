"""Gestión de auditorías como subprocess + broadcast de stdout vía WebSocket.

Cada audit tiene:
  - `audit_id`         — timestamp con segundo (alineado con report filenames)
  - subprocess         — `./venv/bin/python run.py --target IP --auto`
                         (`--no-policy` solo si el operador lo pide)
  - log file           — `reports/audit_run_<audit_id>.log` (transcript completo)
  - listeners          — set de WebSockets activos a los que se empuja stdout

Diseño:
  * Cada línea de stdout se escribe al log + emite a todos los WS conectados.
  * Multiple clientes pueden conectar al mismo audit_id (broadcast).
  * Late connectors reciben replay del log existente + tail en vivo.
  * Al terminar, se cierra el log con un marker y se emite `event: done` con
    el exit_code y (si existe) el report_id resultante.
"""
from __future__ import annotations

import asyncio
import os
import shlex
import signal
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set

from fastapi import WebSocket
from loguru import logger

from api.services import aggregator

REPO_ROOT = aggregator.REPO_ROOT
RUN_PY = os.path.join(REPO_ROOT, "run.py")
VENV_PYTHON = os.path.join(REPO_ROOT, "venv", "bin", "python")
RUNS_LOG_DIR = os.path.join(REPO_ROOT, "reports")

# Líneas de stdout que se conservan en memoria por auditoría. El transcript
# íntegro vive en el fichero de log; esto es solo lo que se replica a un
# cliente que se conecta tarde.
_MAX_BUFFERED_LINES = 2000


# ── Modos de tanda ─────────────────────────────────────────────────────────
#
# El motor no sabe de modos: sabe de CARRILES. Un carril es una cola FIFO con un
# trabajador que ejecuta de una en una; carriles distintos avanzan en paralelo.
# Un modo, por tanto, no es más que una función que decide en qué carril cae
# cada auditoría, y por eso añadir un modo no toca el planificador.
_CARRIL_UNICO = "__cola_global__"

MODOS_DE_TANDA = {
    # Todo en un carril: una auditoría a la vez pase lo que pase. Es el modo por
    # defecto porque es el que produce réplicas comparables, que es para lo que
    # existe una tanda (§5.10.2).
    "secuencial": (
        "Una auditoría a la vez",
        "Máxima comparabilidad entre réplicas. Es lo que se usó para las "
        "mediciones de varianza de la memoria."),
    # Un carril por IP: los dispositivos avanzan a la vez y las réplicas de cada
    # uno siguen estrictamente en orden. Nunca hay dos runs contra el MISMO
    # aparato, que es la interferencia que sí es física.
    "por_dispositivo": (
        "Un dispositivo en paralelo, réplicas en serie",
        "N veces más rápido con N dispositivos. A cambio, los runs compiten por "
        "la cuota del proveedor LLM, la red y la CPU: si el proveedor limita, "
        "unas réplicas acaban conducidas por el modelo de reserva y dejan de ser "
        "comparables con las demás."),
}


_MARCAS_DE_CREDENCIAL = ("auth_error", "authentication failed",
                         "invalid api key", "api key is valid",
                         "anthropic_api_key no configurada")


def _murio_por_credencial(audit: "Audit") -> bool:
    """¿La ejecución terminó porque el proveedor rechazó la credencial?

    Se mira el propio registro del run —la última línea del bucle declara el
    `finish_reason`— en vez del código de salida, que es 1 para cualquier final
    que no sea `done()` y no distingue una clave caducada de un presupuesto
    agotado. Solo las últimas líneas: el motivo está al final, y el registro
    completo puede pesar cientos de kilobytes.
    """
    if audit.exit_code in (None, 0):
        return False
    try:
        with open(audit.log_path, "r", encoding="utf-8", errors="ignore") as fh:
            cola = fh.readlines()[-40:]
    except OSError:
        return False
    texto = "".join(cola).lower()
    return any(m in texto for m in _MARCAS_DE_CREDENCIAL)


def _vaciar_carril(cola: "asyncio.Queue[Audit]") -> int:
    """Descarta lo que quede en el carril y lo marca como cancelado."""
    n = 0
    while True:
        try:
            pendiente = cola.get_nowait()
        except asyncio.QueueEmpty:
            return n
        pendiente.was_stopped = True
        pendiente.exit_code = -1
        pendiente.finished_at = time.time()
        cola.task_done()
        n += 1


def _carril_para(modo: str, target_ip: str) -> str:
    """Carril que corresponde a una auditoría según el modo de tanda."""
    if modo == "por_dispositivo":
        return f"ip:{target_ip}"
    return _CARRIL_UNICO


def _make_audit_id() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _log_path(audit_id: str) -> str:
    return os.path.join(RUNS_LOG_DIR, f"audit_run_{audit_id}.log")


@dataclass
class Audit:
    audit_id: str
    target_ip: str
    model: Optional[str]
    extra_args: List[str]
    # PolicyEngine activo salvo petición explícita. El dashboard fijaba
    # `--no-policy` en el código, sin alternativa: la interfaz que la memoria
    # presenta como entregable (OM4) desactivaba de forma invisible la capa que
    # OE2 declara cumplida, y `--no-policy` ejecuta con `shell=True`. Ahora es
    # una decisión del operador, se registra en el resumen del audit y queda en
    # el log — el modo investigación existe, pero no puede ser el implícito.
    policy_disabled: bool = False
    process: Optional[asyncio.subprocess.Process] = None
    log_path: str = ""
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    exit_code: Optional[int] = None
    was_stopped: bool = False
    # Réplica i de N sobre el mismo target (cadena secuencial); (1, 1) = run único.
    replica_index: int = 1
    replica_total: int = 1
    listeners: Set[WebSocket] = field(default_factory=set)
    lines_seen: List[str] = field(default_factory=list)
    # Posición en SU carril: 0 = ejecutándose, >0 = esperando turno.
    queue_position: int = 0
    # Carril en el que corre. Con el modo secuencial todas comparten uno; con el
    # modo por dispositivo hay uno por IP. Sale en el resumen para que el panel
    # pueda explicar por qué hay varias en marcha a la vez.
    lane: str = _CARRIL_UNICO
    lines_total: int = 0      # emitidas en total (el buffer está acotado)
    lines_dropped: int = 0    # descartadas del buffer, presentes en el log
    _broadcast_task: Optional[asyncio.Task] = None
    _broadcast_lock: Optional[asyncio.Lock] = None

    def as_summary(self) -> Dict:
        return {
            "audit_id": self.audit_id,
            "target_ip": self.target_ip,
            "model": self.model,
            "extra_args": self.extra_args,
            "policy_disabled": self.policy_disabled,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "exit_code": self.exit_code,
            # `is_running` distingue ahora ejecutándose de esperando turno: con
            # la cola global, una auditoría recién lanzada puede pasar minutos
            # encolada, y mostrarla como «en marcha» hacía pensar que se había
            # colgado.
            "is_running": self.exit_code is None and self.process is not None,
            "is_queued": self.exit_code is None and self.process is None,
            "queue_position": self.queue_position,
            "lane": self.lane,
            "was_stopped": self.was_stopped,
            "replica_index": self.replica_index,
            "replica_total": self.replica_total,
            "log_lines": self.lines_total or len(self.lines_seen),
            "log_lines_buffered": len(self.lines_seen),
            "listeners": len(self.listeners),
        }


class AuditManager:
    def __init__(self) -> None:
        self._audits: Dict[str, Audit] = {}
        self._lock = asyncio.Lock()
        # Carriles de ejecución. Cada uno es una cola FIFO con su propio
        # trabajador, y dentro de un carril se ejecuta UNA auditoría a la vez.
        # El modo de lanzamiento no cambia el motor: solo decide en qué carril
        # cae cada auditoría (ver `_CARRIL_UNICO` y `MODOS_DE_TANDA`).
        self._queues: Dict[str, "asyncio.Queue[Audit]"] = {}
        self._workers: Dict[str, asyncio.Task] = {}

    async def list(self) -> List[Dict]:
        async with self._lock:
            return [a.as_summary() for a in self._audits.values()]

    async def get(self, audit_id: str) -> Optional[Audit]:
        async with self._lock:
            return self._audits.get(audit_id)

    async def stop(self, audit_id: str) -> Optional[Audit]:
        """Detiene una auditoría en curso matando TODO su árbol de procesos
        (run.py + nmap/nc/curl…). SIGTERM y, si no muere a tiempo, SIGKILL.
        El `_drain` recoge la salida y emite el `done`."""
        audit = await self.get(audit_id)
        if audit is None or audit.exit_code is not None:
            return None  # no existe o ya terminó
        if audit.process is None:
            # Todavía en cola: se marca y el trabajador la descartará al llegar
            # su turno. Sin esto, «detener» una auditoría encolada no hacía nada
            # y arrancaba igualmente minutos después.
            audit.was_stopped = True
            logger.info(f"[audit {audit_id}] cancelada antes de arrancar (en cola)")
            await self._broadcast(audit, {
                "type": "stopping", "data": "⏹  Cancelada antes de arrancar."})
            return audit
        proc = audit.process
        audit.was_stopped = True
        await self._broadcast(audit, {
            "type": "stopping", "data": "⏹  Auditoría detenida por el usuario."})
        try:
            pgid = os.getpgid(proc.pid)
        except ProcessLookupError:
            return audit  # ya no existe
        # El margen tras SIGTERM ya no es solo «tiempo para morir»: desde
        # iter_20 `run.py` lo aprovecha para RESCATAR EL INFORME con lo que
        # llevara obtenido. Cinco segundos bastaban para terminar de morir, pero
        # no dejaban holgura para escribir cuatro artefactos y la KB, y un
        # SIGKILL a mitad tira precisamente el trabajo que el rescate existe
        # para salvar. Quince segundos siguen siendo una espera aceptable para
        # quien pulsa «detener», y ya no es una espera vacía.
        for sig, espera in ((signal.SIGTERM, 15), (signal.SIGKILL, 5)):
            try:
                os.killpg(pgid, sig)
            except ProcessLookupError:
                break
            try:
                await asyncio.wait_for(proc.wait(), timeout=espera)
                break  # murió con esta señal
            except asyncio.TimeoutError:
                logger.warning(f"[audit {audit_id}] no murió con {sig.name}, escalando")
        logger.info(f"[audit {audit_id}] detenida por el usuario")
        return audit

    # ------------------------------------------------------------------
    # Carriles: dentro de uno, de una en una; entre carriles, en paralelo
    # ------------------------------------------------------------------
    #
    # Hubo primero concurrencia ENTRE objetivos (secuencial solo dentro de cada
    # uno). El razonamiento era que dos runs contra el MISMO dispositivo se
    # interfieren, mientras que contra dispositivos distintos no. Es cierto en
    # cuanto al objetivo, pero pasa por alto todo lo que los runs comparten aun
    # apuntando a equipos distintos:
    #
    #   · la cuota del proveedor LLM — N runs simultáneos multiplican por N el
    #     ritmo de peticiones, y el bucle degrada al modelo de reserva cuando la
    #     agota, de modo que unas réplicas acaban conducidas por otro modelo;
    #   · el enlace de red y la CPU del anfitrión, con varios `nmap` a la vez;
    #   · la base de conocimiento, que todos leen al arrancar y escriben al
    #     terminar.
    #
    # Ninguna de esas es una interferencia entre objetivos, pero todas rompen la
    # comparabilidad entre réplicas, que es justo lo que el análisis de varianza
    # necesita. Por eso el modo POR DEFECTO sigue siendo el carril único: para un
    # banco de pruebas de una sola máquina, terminar antes no compensa comparar
    # peor.
    #
    # Lo que cambió es que ese criterio dejó de estar cableado. Una tanda de tres
    # aparatos por cinco réplicas son dos horas largas en serie, y hay ocasiones
    # —repetir una tanda, rellenar réplicas que faltan, probar un cambio— en las
    # que la comparabilidad estricta importa menos que acabar hoy. El operador
    # elige el modo y el panel le dice qué está eligiendo; lo que no se admite es
    # que la interfaz prometa una cosa y el motor haga otra, que es exactamente
    # lo que pasaba: el panel anunciaba «hosts en paralelo, réplicas en serie» y
    # nunca llegó a enviar la opción que lo activaba.

    def _ensure_worker(self, carril: str) -> None:
        tarea = self._workers.get(carril)
        if tarea is None or tarea.done():
            self._workers[carril] = asyncio.create_task(self._drain_queue(carril))

    async def _drain_queue(self, carril: str) -> None:
        """Consume un carril de una en una, esperando a que cada run termine."""
        cola = self._queues[carril]
        while True:
            try:
                audit = cola.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                if audit.was_stopped:
                    # Cancelada mientras esperaba su turno.
                    audit.exit_code = -1
                    audit.finished_at = time.time()
                    continue
                await self._spawn(audit)
                if audit._broadcast_task is not None:
                    # Esperar al drenaje —y no solo a que muera el proceso—
                    # garantiza `exit_code` asignado y el informe ya en disco
                    # antes de arrancar el siguiente.
                    await audit._broadcast_task
                if _murio_por_credencial(audit):
                    # Una credencial rechazada no se arregla sola entre
                    # ejecuciones: es configuración, no un fallo transitorio. En
                    # campo, una clave caducada se llevó por delante las CINCO
                    # réplicas de una tanda —cada una arrancó, pidió su primer
                    # turno, recibió 403 y murió en medio segundo— dejando cinco
                    # registros idénticos y ningún dato. Vaciar el carril
                    # convierte cinco fracasos en uno con un motivo legible.
                    descartadas = _vaciar_carril(cola)
                    logger.error(
                        f"[audit {audit.audit_id}] credencial del proveedor "
                        f"rechazada; {descartadas} ejecución(es) pendiente(s) "
                        f"canceladas en este carril")
                    await self._broadcast(audit, {
                        "type": "line",
                        "data": (f"⏹  Credencial del proveedor rechazada. Se cancelan "
                                 f"{descartadas} ejecución(es) pendiente(s): con la misma "
                                 f"clave fallarían igual. Revisa las credenciales del .env."),
                    })
                    return
            except Exception as e:
                logger.exception(f"[audit {audit.audit_id}] error en la cola: {e}")
                audit.exit_code = audit.exit_code if audit.exit_code is not None else -1
                audit.finished_at = time.time()
            finally:
                cola.task_done()

    async def enqueue(self, target_ip: str, *, model: Optional[str] = None,
                      extra_args: Optional[List[str]] = None,
                      replica: tuple = (1, 1),
                      policy_disabled: bool = False,
                      carril: str = _CARRIL_UNICO) -> Audit:
        """Encola una auditoría. Arranca de inmediato si no hay nada por delante.

        `carril` es el único punto donde se materializa el modo de tanda: todas
        las auditorías del mismo carril van estrictamente de una en una, y
        carriles distintos avanzan en paralelo. Con el carril único se obtiene
        la cola global; con el carril por IP, una réplica de cada dispositivo a
        la vez.
        """
        audit = await self._register(target_ip, model=model, extra_args=extra_args,
                                     replica=replica, policy_disabled=policy_disabled)
        cola = self._queues.setdefault(carril, asyncio.Queue())
        tarea = self._workers.get(carril)
        audit.queue_position = cola.qsize() + (
            0 if tarea is None or tarea.done() else 1)
        audit.lane = carril
        await cola.put(audit)
        self._ensure_worker(carril)
        return audit

    async def start_replicas(self, target_ip: str, runs: int, *,
                             model: Optional[str] = None,
                             extra_args: Optional[List[str]] = None,
                             policy_disabled: bool = False,
                             concurrent: bool = False,
                             modo: Optional[str] = None) -> Audit:
        """Encola `runs` auditorías sobre el mismo target y devuelve la primera.

        `modo` elige el carril (ver `MODOS_DE_TANDA`). `concurrent=True` se
        mantiene como alias histórico de `modo="por_dispositivo"`.

        El bug que esto corrige: `concurrent=True` arrancaba **solo la primera
        réplica** de cada objetivo fuera de la cola y mandaba el resto a la cola
        global. Con tres dispositivos por cinco réplicas eso daba tres runs en
        paralelo y luego doce estrictamente en serie — ni una cosa ni la otra, y
        justo lo contrario de lo que el panel prometía por escrito.
        """
        modo = modo or ("por_dispositivo" if concurrent else "secuencial")
        carril = _carril_para(modo, target_ip)
        first: Optional[Audit] = None
        for i in range(1, runs + 1):
            audit = await self.enqueue(
                target_ip, model=model, extra_args=extra_args,
                replica=(i, runs), policy_disabled=policy_disabled, carril=carril)
            if first is None:
                first = audit
        return first  # type: ignore[return-value]

    async def start(self, target_ip: str, *, model: Optional[str] = None,
                    extra_args: Optional[List[str]] = None,
                    replica: tuple = (1, 1),
                    policy_disabled: bool = False) -> Audit:
        """Lanza una auditoría INMEDIATAMENTE, sin pasar por la cola.

        Se conserva para el modo concurrente explícito. El camino normal es
        `enqueue`, que respeta el «una a la vez».
        """
        audit = await self._register(target_ip, model=model, extra_args=extra_args,
                                     replica=replica, policy_disabled=policy_disabled)
        await self._spawn(audit)
        return audit

    async def _register(self, target_ip: str, *, model: Optional[str] = None,
                        extra_args: Optional[List[str]] = None,
                        replica: tuple = (1, 1),
                        policy_disabled: bool = False) -> Audit:
        """Reserva el `audit_id` y crea el registro, sin lanzar nada todavía."""
        # Genera y RESERVA el audit_id bajo lock: dos starts concurrentes en el
        # mismo segundo (caso real: lanzamiento batch desde el dashboard) ya no
        # pueden pisarse. Si el timestamp colisiona, se sufija `_2`, `_3`, …
        # en lugar de dormir 1 s por colisión.
        async with self._lock:
            base = _make_audit_id()
            audit_id, n = base, 2
            while audit_id in self._audits:
                audit_id = f"{base}_{n}"
                n += 1
            audit = Audit(
                audit_id=audit_id,
                target_ip=target_ip,
                model=model,
                extra_args=extra_args or [],
                policy_disabled=policy_disabled,
                log_path=_log_path(audit_id),
                replica_index=replica[0],
                replica_total=replica[1],
            )
            audit._broadcast_lock = asyncio.Lock()
            self._audits[audit_id] = audit
        return audit

    async def _spawn(self, audit: Audit) -> Audit:
        """Arranca el subproceso de una auditoría ya registrada."""
        audit_id, target_ip = audit.audit_id, audit.target_ip
        audit.queue_position = 0
        audit.started_at = time.time()   # el reloj cuenta desde que ARRANCA
        args: List[str] = [
            VENV_PYTHON, RUN_PY,
            "--target", target_ip,
            "--auto",
        ]
        if audit.policy_disabled:
            args.append("--no-policy")
            logger.warning(
                f"[audit {audit_id}] PolicyEngine DESACTIVADO por petición "
                f"explícita — ejecución con shell directo contra {target_ip}"
            )
        if audit.model:
            args += ["--model", audit.model]
        if audit.extra_args:
            args += audit.extra_args

        os.makedirs(RUNS_LOG_DIR, exist_ok=True)

        logger.info(f"[audit {audit_id}] spawn: {shlex.join(args)}")
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                cwd=REPO_ROOT,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,  # combinado para orden cronológico
                # Sesión/grupo de procesos propio: permite matar TODO el árbol
                # (run.py + nmap/nc/curl que lanza) con os.killpg al detener.
                start_new_session=True,
            )
        except Exception:
            async with self._lock:
                self._audits.pop(audit_id, None)
            raise

        audit.process = proc
        audit._broadcast_task = asyncio.create_task(self._drain(audit))
        return audit

    async def _drain(self, audit: Audit) -> None:
        """Lee stdout línea a línea, escribe al log y broadcastea a los WS."""
        assert audit.process is not None
        assert audit.process.stdout is not None
        with open(audit.log_path, "w", encoding="utf-8", buffering=1) as log_f:
            log_f.write(
                f"# audit_id={audit.audit_id} target={audit.target_ip} "
                f"started={datetime.fromtimestamp(audit.started_at).isoformat()}\n"
            )
            try:
                while True:
                    raw = await audit.process.stdout.readline()
                    if not raw:
                        break
                    line = raw.decode("utf-8", errors="replace").rstrip("\n")
                    log_f.write(line + "\n")
                    audit.lines_seen.append(line)
                    audit.lines_total += 1
                    # El buffer en memoria está acotado; el log en disco NO, y
                    # es la fuente completa (`GET /api/audits/{id}/log`). Sin el
                    # tope, una auditoría larga —que son horas y decenas de
                    # miles de líneas, con el volcado de cada respuesta de las
                    # sondas— acumulaba todo el stdout en RAM del backend Y lo
                    # reenviaba entero a cada cliente que se conectara tarde.
                    # Para un panel en vivo, las últimas N líneas es lo útil.
                    if len(audit.lines_seen) > _MAX_BUFFERED_LINES:
                        del audit.lines_seen[:-_MAX_BUFFERED_LINES]
                        audit.lines_dropped = (
                            audit.lines_total - _MAX_BUFFERED_LINES)
                    await self._broadcast(audit, {
                        "type": "line",
                        "data": line,
                        "n": audit.lines_total,
                    })
            except Exception as e:
                logger.exception(f"[audit {audit.audit_id}] drain error: {e}")
                await self._broadcast(audit, {"type": "error", "data": str(e)})

        await audit.process.wait()
        audit.exit_code = audit.process.returncode
        audit.finished_at = time.time()
        elapsed = audit.finished_at - audit.started_at
        logger.info(
            f"[audit {audit.audit_id}] done — exit={audit.exit_code} "
            f"elapsed={elapsed:.1f}s lines={audit.lines_total}"
        )
        # Forzar refresco del aggregator: el nuevo report ya está en disco
        aggregator.invalidate_cache()
        await self._broadcast(audit, {
            "type": "done",
            "exit_code": audit.exit_code,
            "elapsed_seconds": elapsed,
            "total_lines": audit.lines_total,
        })

    async def _broadcast(self, audit: Audit, message: Dict) -> None:
        if not audit.listeners:
            return
        assert audit._broadcast_lock is not None
        async with audit._broadcast_lock:
            dead: Set[WebSocket] = set()
            for ws in audit.listeners:
                try:
                    await ws.send_json(message)
                except Exception:
                    dead.add(ws)
            audit.listeners -= dead

    async def attach(self, audit_id: str, ws: WebSocket) -> Optional[Audit]:
        audit = await self.get(audit_id)
        if not audit:
            return None
        audit.listeners.add(ws)
        # Replay del histórico ya capturado
        # La numeración parte de las líneas ya descartadas del buffer, para que
        # el `n` que ve el cliente sea el número REAL de línea y no reinicie.
        for n, line in enumerate(audit.lines_seen, audit.lines_dropped + 1):
            try:
                await ws.send_json({"type": "line", "data": line, "n": n,
                                    "replay": True})
            except Exception:
                audit.listeners.discard(ws)
                return audit
        if audit.exit_code is not None:
            try:
                await ws.send_json({
                    "type": "done", "exit_code": audit.exit_code,
                    "elapsed_seconds": (audit.finished_at or 0) - audit.started_at,
                    "total_lines": audit.lines_total,
                    "replay": True,
                })
            except Exception:
                audit.listeners.discard(ws)
        return audit

    async def detach(self, audit_id: str, ws: WebSocket) -> None:
        audit = await self.get(audit_id)
        if audit:
            audit.listeners.discard(ws)


_MANAGER: Optional[AuditManager] = None


def get_manager() -> AuditManager:
    global _MANAGER
    if _MANAGER is None:
        _MANAGER = AuditManager()
    return _MANAGER
