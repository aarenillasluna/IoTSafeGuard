"""El kill-switch no puede declarar muerto a un objetivo que solo filtra ICMP.

Regresión detectada en campo, en la tanda de 15 ejecuciones del 2026-08-08: el
*kill-switch* por inalcanzabilidad saltó en **5 de 5** auditorías contra el
Amazon Echo (192.168.1.37), y los propios logs muestran que el dispositivo
seguía contestando inmediatamente después —HTTP 404 en 16 ms, consultas a la
NVD, sondas devolviendo datos—.

La cadena del fallo:

    run.py            attach_safety_monitor(...)   ← sin open_ports: corre ANTES de nmap
                      open_ports = []              ← y nadie los rellenaba después
    _check_tcp()      if not self.open_ports: return False
    health probe      alive = ICMP or TCP = False  ← en TODO equipo que filtre ping
    record_health_check(False) ×3 → kill-switch a mitad de auditoría

El *fallback* TCP se introdujo en iter_10 exactamente para este dispositivo, y
nunca llegó a ejecutarse: era un camino muerto. Mientras la única consecuencia
fue que `is_degraded()` no viera nada, pasó inadvertido; al añadir en iter_19 el
segundo brazo del kill-switch —que sí depende de esa señal— la ceguera silenciosa
se convirtió en un corte en falso.

Dos correcciones, y la segunda es la de fondo: **nunca concluir «muerto» a
partir de una comprobación que no ha llegado a ejecutarse**.
"""
import pytest

import core.tools as toolbox
from core.safety_monitor import SafetyMonitorV2


@pytest.fixture
def session():
    s = toolbox.AgentSession(target_ip="192.168.1.37")
    s.safety = SafetyMonitorV2(target_ip="192.168.1.37", max_failures=3)
    toolbox.bind_session(s)
    yield s
    toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))


# ── 1. Sin puertos conocidos, el silencio es DESCONOCIDO, no muerte ────────

def test_icmp_filtered_without_known_ports_is_not_a_failure(session, monkeypatch):
    """El caso Echo: filtra ping y nmap aún no ha aportado puertos."""
    safety = session.safety
    monkeypatch.setattr(safety, "_check_icmp", lambda: False)
    assert safety.can_check_tcp() is False

    for _ in range(10):
        toolbox._safety_health_probe()

    assert safety.ping_failures == 0, "un diagnóstico imposible no es un fallo"
    assert safety._kill_switch_triggered is False


def test_the_tcp_probe_is_not_even_attempted_without_ports(session, monkeypatch):
    safety = session.safety
    monkeypatch.setattr(safety, "_check_icmp", lambda: False)
    called = {"tcp": 0}
    monkeypatch.setattr(safety, "_check_tcp",
                        lambda: called.__setitem__("tcp", called["tcp"] + 1) or False)
    toolbox._safety_health_probe()
    assert called["tcp"] == 0


# ── 2. Con puertos conocidos, el diagnóstico vuelve a ser posible ──────────

def test_with_ports_a_dead_target_is_still_detected(session, monkeypatch):
    """La corrección no desarma la capa: si hay contra qué probar y tampoco
    responde, el corte debe producirse igual."""
    safety = session.safety
    safety.open_ports = [80, 443]
    monkeypatch.setattr(safety, "_check_icmp", lambda: False)
    monkeypatch.setattr(safety, "_check_tcp", lambda: False)

    for _ in range(3):
        toolbox._safety_health_probe()

    assert safety._kill_switch_triggered is True
    assert "unreachable" in safety.kill_switch_reason


def test_with_ports_a_live_target_is_left_alone(session, monkeypatch):
    safety = session.safety
    safety.open_ports = [80]
    monkeypatch.setattr(safety, "_check_icmp", lambda: False)
    monkeypatch.setattr(safety, "_check_tcp", lambda: True)

    for _ in range(10):
        toolbox._safety_health_probe()

    assert safety.ping_failures == 0
    assert safety._kill_switch_triggered is False


# ── 3. nmap alimenta el fallback: el eslabón que faltaba ──────────────────

def test_nmap_feeds_the_open_ports_to_the_monitor(session):
    assert session.safety.open_ports == []
    toolbox._post_dispatch("nmap_scan", {}, {
        "ports": [
            {"port": 1080, "proto": "tcp", "state": "open", "service": "socks"},
            {"port": 8888, "proto": "tcp", "state": "open", "service": "http"},
            {"port": 69, "proto": "udp", "state": "open", "service": "tftp"},
            {"port": 22, "proto": "tcp", "state": "filtered", "service": "ssh"},
        ],
    })
    # Solo TCP abiertos: por UDP no se puede hacer `connect`, y un puerto
    # filtrado no prueba vitalidad.
    assert session.safety.open_ports == [1080, 8888]
    assert session.safety.can_check_tcp() is True


def test_rescanning_does_not_duplicate_ports(session):
    result = {"ports": [{"port": 80, "proto": "tcp", "state": "open"}]}
    toolbox._post_dispatch("nmap_scan", {}, result)
    toolbox._post_dispatch("nmap_scan", {}, result)
    assert session.safety.open_ports == [80]


def test_a_scan_with_no_tcp_ports_leaves_the_monitor_undiagnosable(session):
    """Coherente con el punto 1: si el equipo solo expone UDP, seguimos sin
    poder distinguir «callado» de «caído», y no se inventa un veredicto."""
    toolbox._post_dispatch("nmap_scan", {}, {
        "ports": [{"port": 5353, "proto": "udp", "state": "open"}],
    })
    assert session.safety.open_ports == []
    assert session.safety.can_check_tcp() is False


# ── 4. Fricciones observadas en campo que costaban turnos ─────────────────

def test_stderr_redirection_is_stripped_not_rejected(monkeypatch):
    """`2>&1` sin shell no redirige nada: llega como operando literal. El modelo
    lo añade por costumbre y la validación de operandos lo rechazaba, perdiendo
    el turno por un fragmento inocuo y además inoperante."""
    seen = {}

    class _FakeExploiter:
        def __init__(self, *a, **k): pass
        def execute_poc(self, cmd, target, **kw):
            seen["cmd"] = cmd
            return {"success": True, "output": "ok", "error_type": "NONE"}

    monkeypatch.setattr("modules.exploiter.ActiveExploiter", _FakeExploiter)
    s = toolbox.AgentSession(target_ip="10.0.0.1")
    s.phase = "exploit"
    toolbox.bind_session(s)
    try:
        toolbox._execute_cmd({"cmd": "nc -zv 10.0.0.1 23 2>&1"})
        assert "2>&1" not in seen["cmd"]
        assert seen["cmd"].strip() == "nc -zv 10.0.0.1 23"
    finally:
        toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))


def test_rejected_binary_points_at_the_dedicated_tool():
    """Un rechazo de política no debe ser un callejón sin salida cuando el
    sistema ya ofrece una sonda para ese protocolo."""
    from modules.exploiter import _dedicated_tool_hint
    assert "probe_tftp" in _dedicated_tool_hint("tftp 192.168.1.1 -c get config.bin")
    assert "probe_coap" in _dedicated_tool_hint("coap-client -m get coap://10.0.0.1")
    assert _dedicated_tool_hint("curl -sk http://10.0.0.1/") is None


def test_the_tool_description_warns_about_useless_pipes():
    """11 de las 18 violaciones de política de la tanda fueron tuberías a
    `head` para truncar una salida que YA venía truncada."""
    toolbox.build_registry()
    desc = toolbox._REGISTRY["execute_command"].description
    assert "head" in desc and "already truncated" in desc.lower()
