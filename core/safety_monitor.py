"""
SafetyMonitor v2: Presupuesto de peticiones, cooldown adaptativo y kill-switch.
Detecta degradación del servicio (latencia alta, errores 500) y detiene operaciones.
"""
import time
import subprocess
import platform
import socket
from collections import deque
from typing import Optional, List, Deque
from colorama import Fore, Style
from loguru import logger

try:
    from pythonping import ping as py_ping
    HAS_PYTHONPING = True
except ImportError:
    HAS_PYTHONPING = False
    py_ping = None


class SafetyMonitorV2:
    """
    Guardián de estabilidad del dispositivo con:
    - Presupuesto de peticiones por minuto (rate limit)
    - Cooldown adaptativo si el target se ralentiza
    - Kill-switch por DOS causas independientes:
        (a) degradación — la latencia media reciente supera el umbral;
        (b) inalcanzabilidad — N sondas de salud consecutivas sin respuesta.

    Las dos causas son necesarias porque miden cosas distintas y la primera
    NO cubre a la segunda: un objetivo que se cae del todo deja de producir
    muestras de latencia, así que la ventana de `is_degraded()` se queda
    congelada con los valores buenos de antes de la caída y el corte nunca
    llega. Es justo el escenario para el que existe esta capa, de modo que
    la muerte del objetivo se cuenta aparte (`record_health_check`).
    """

    def __init__(
        self,
        target_ip: str,
        max_failures: int = 3,
        open_ports: Optional[List[int]] = None,
        requests_per_minute: int = 60,
        latency_threshold_ms: float = 2000.0,
        degradation_window: int = 5,
    ):
        self.target_ip = target_ip
        self.ping_failures = 0
        self.max_failures = max_failures
        self.open_ports = open_ports or []
        self.requests_per_minute = requests_per_minute
        self.latency_threshold_ms = latency_threshold_ms
        self.degradation_window = degradation_window

        self._request_times: Deque[float] = deque(maxlen=requests_per_minute * 2)
        self._latencies: Deque[float] = deque(maxlen=degradation_window)
        self._kill_switch_triggered = False
        self.kill_switch_reason: Optional[str] = None

        system_os = platform.system().lower()
        self.ping_param = "-n" if "windows" in system_os else "-c"

    def _check_icmp(self) -> bool:
        try:
            if HAS_PYTHONPING and py_ping:
                try:
                    result = py_ping(self.target_ip, count=1, timeout=1)
                    if result.success():
                        if result.rtt_avg_ms:
                            self._latencies.append(result.rtt_avg_ms)
                        return True
                except Exception:
                    pass

            cmd = ["ping", self.ping_param, "1", self.target_ip]
            start = time.time()
            rc = subprocess.call(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2
            )
            elapsed = (time.time() - start) * 1000
            if rc == 0:
                self._latencies.append(elapsed)
                return True
            return False
        except Exception as e:
            logger.warning(f"[SAFETY] Ping falló: {e}")
            return False

    def can_check_tcp(self) -> bool:
        """¿Hay algún puerto contra el que intentar el fallback TCP?

        Distinguir «probé por TCP y no contesta» de «no tenía contra qué
        probar» es lo que separa un diagnóstico de una suposición: sin puertos
        conocidos, el silencio de un objetivo que además filtra ICMP no
        significa que esté caído, solo que no hay forma de saberlo.
        """
        return bool(self.open_ports)

    def _check_tcp(self) -> bool:
        """Sondea vitalidad por TCP y MIDE la latencia del connect.

        Es el fallback cuando ICMP está bloqueado (caso real: Amazon Echo y
        muchos IoT con firewall que descartan ping). Sin medir aquí la latencia,
        `_latencies` quedaría vacío y `is_degraded()` sería ciego: el monitor
        sabría que el host *responde* pero no si se está *degradando*. Al
        registrar el tiempo de `connect()` —que también crece cuando la pila de
        red del objetivo se satura— el kill-switch por degradación funciona
        igualmente sin ICMP. Una conexión rechazada (RST) cuenta como host vivo
        pero saludable: el puerto está cerrado, no la pila caída.

        Prueba hasta 3 puertos abiertos: que el primero pase a filtrado (p. ej.
        un servicio que se cae durante la auditoría) no debe declarar muerto a
        un host que sigue respondiendo por los demás.
        """
        if not self.open_ports:
            return False
        for port in self.open_ports[:3]:
            start = time.time()
            try:
                with socket.create_connection((self.target_ip, port), timeout=2):
                    self._latencies.append((time.time() - start) * 1000)
                    return True
            except (socket.timeout, ConnectionRefusedError, OSError):
                continue
        return False

    def consume_budget(self) -> bool:
        """
        Consume una unidad del presupuesto de peticiones/minuto.
        Devuelve False si se excedió el límite (cooldown).
        """
        now = time.time()
        cutoff = now - 60.0
        while self._request_times and self._request_times[0] < cutoff:
            self._request_times.popleft()
        if len(self._request_times) >= self.requests_per_minute:
            logger.warning(
                f"[SAFETY] Presupuesto de {self.requests_per_minute} req/min agotado. Cooldown."
            )
            return False
        self._request_times.append(now)
        return True

    def record_latency(self, latency_ms: float) -> None:
        """Registra latencia para detectar degradación."""
        self._latencies.append(latency_ms)

    def record_health_check(self, alive: bool) -> None:
        """Contabiliza el resultado de una sonda de salud (ICMP o TCP).

        `alive=False` suma un fallo; cualquier respuesta lo devuelve a cero, de
        modo que solo cuentan los fallos CONSECUTIVOS: un paquete perdido
        puntual no debe acercar la auditoría al corte.
        """
        if alive:
            self.ping_failures = 0
        else:
            self.ping_failures += 1

    def is_unreachable(self) -> bool:
        """True si el objetivo lleva `max_failures` sondas seguidas sin responder.

        Complementa a `is_degraded()`, que es ciega ante la caída total: sin
        respuesta no hay muestra de latencia que añadir, así que la media de la
        ventana se queda con los valores previos a la caída y nunca supera el
        umbral. Aquí la señal es la ausencia de respuesta en sí.
        """
        return self.ping_failures >= self.max_failures

    def is_degraded(self) -> bool:
        """True si la latencia media reciente supera el umbral.

        Exige un mínimo de muestras (3, o la ventana si es menor) antes de
        declarar degradación: una única petición lenta —un blip de red puntual—
        no debe bastar para disparar el kill-switch y abortar la auditoría.
        """
        min_samples = min(3, self.degradation_window)
        if len(self._latencies) < min_samples:
            return False
        avg = sum(self._latencies) / len(self._latencies)
        return avg > self.latency_threshold_ms

    def trigger_kill_switch(self, reason: str = "degradation or critical failure") -> None:
        """Activa el kill-switch: detener operaciones.

        `reason` queda en el log y en el aviso al operador: distinguir «el
        objetivo se ha ralentizado» de «el objetivo ha dejado de responder»
        cambia lo que el auditor debe hacer a continuación.
        """
        self._kill_switch_triggered = True
        self.kill_switch_reason = reason
        logger.error(
            f"[SAFETY] KILL-SWITCH activado para {self.target_ip}: {reason}."
        )
        print(
            f"{Fore.RED}[SAFETY] KILL-SWITCH ({reason}): "
            f"Deteniendo operaciones contra {self.target_ip}.{Style.RESET_ALL}"
        )
