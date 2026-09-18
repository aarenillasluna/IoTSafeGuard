"""El kill-switch debe dispararse también cuando el objetivo DEJA DE RESPONDER.

Antes, el `SafetyMonitor` solo cortaba por degradación de latencia, y ese brazo
es estructuralmente ciego a la caída total: un objetivo muerto no produce
muestras nuevas, así que la ventana de `is_degraded()` se queda congelada con
los valores buenos de antes de la caída y la media nunca supera el umbral. Los
campos `ping_failures` / `max_failures` existían pero nadie los escribía ni los
leía: el mecanismo que la memoria (§4.5.2, mecanismo 3) declaraba no existía.

Estas pruebas fijan las dos direcciones: que la caída dispara el corte, y que un
fallo aislado entre respuestas buenas NO lo dispara.
"""
import pytest

import core.tools as toolbox
from core.safety_monitor import SafetyMonitorV2


# ── Contador de fallos consecutivos ─────────────────────────────────────────

def test_consecutive_failures_reach_threshold():
    mon = SafetyMonitorV2(target_ip="10.0.0.5", max_failures=3)
    assert mon.is_unreachable() is False
    for _ in range(3):
        mon.record_health_check(alive=False)
    assert mon.ping_failures == 3
    assert mon.is_unreachable() is True


def test_single_success_resets_the_counter():
    """Un paquete perdido puntual no debe acercar la auditoría al corte."""
    mon = SafetyMonitorV2(target_ip="10.0.0.5", max_failures=3)
    mon.record_health_check(alive=False)
    mon.record_health_check(alive=False)
    mon.record_health_check(alive=True)      # el objetivo vuelve a responder
    assert mon.ping_failures == 0
    mon.record_health_check(alive=False)
    assert mon.is_unreachable() is False


def test_dead_target_is_not_detected_by_degradation_alone():
    """Justifica por qué hace falta el segundo brazo: sin muestras nuevas,
    `is_degraded()` no puede ver la caída."""
    mon = SafetyMonitorV2(target_ip="10.0.0.5", max_failures=3,
                          latency_threshold_ms=2000.0, degradation_window=3)
    # Ventana llena de latencias sanas previas a la caída.
    for _ in range(3):
        mon.record_latency(50.0)
    # El objetivo muere: las sondas fallan y no añaden muestras.
    for _ in range(5):
        mon.record_health_check(alive=False)
    assert mon.is_degraded() is False        # ciego, como se esperaba
    assert mon.is_unreachable() is True      # el brazo nuevo sí lo ve


def test_kill_switch_records_reason():
    mon = SafetyMonitorV2(target_ip="10.0.0.5")
    mon.trigger_kill_switch("target unreachable (3 consecutive probes with no answer)")
    assert mon._kill_switch_triggered is True
    assert "unreachable" in mon.kill_switch_reason


# ── Integración con el health probe de dispatch ─────────────────────────────

@pytest.fixture
def _session_with_safety():
    session = toolbox.AgentSession(target_ip="10.0.0.5")
    session.safety = SafetyMonitorV2(target_ip="10.0.0.5", max_failures=3,
                                     open_ports=[80])
    toolbox.bind_session(session)
    yield session
    toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))


def test_health_probe_trips_kill_switch_when_target_dies(_session_with_safety,
                                                         monkeypatch):
    safety = _session_with_safety.safety
    monkeypatch.setattr(safety, "_check_icmp", lambda: False)
    monkeypatch.setattr(safety, "_check_tcp", lambda: False)

    for _ in range(3):
        toolbox._safety_health_probe()

    assert safety._kill_switch_triggered is True
    assert "unreachable" in safety.kill_switch_reason


def test_health_probe_keeps_running_while_target_answers(_session_with_safety,
                                                         monkeypatch):
    safety = _session_with_safety.safety
    monkeypatch.setattr(safety, "_check_icmp", lambda: True)
    monkeypatch.setattr(safety, "_check_tcp", lambda: False)

    for _ in range(10):
        toolbox._safety_health_probe()

    assert safety._kill_switch_triggered is False
    assert safety.ping_failures == 0


def test_precheck_surfaces_the_reason_to_the_agent(_session_with_safety):
    safety = _session_with_safety.safety
    safety.trigger_kill_switch("target unreachable (3 consecutive probes with no answer)")
    blocked = toolbox._safety_precheck("nmap_scan")
    assert blocked is not None
    assert blocked["error_type"] == "safety_kill_switch"
    # El agente debe poder distinguir «lento» de «caído» para decidir qué hacer.
    assert "unreachable" in blocked["error"]
