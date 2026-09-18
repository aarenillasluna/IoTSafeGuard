"""Herramientas nuevas de iter_18: `probe_tcp` y `audit_status`.

Dos huecos de caso de uso detectados al revisar el catálogo:

  - **`probe_tcp`**: el prompt de recon nombraba Tuya (TCP 6668) y ESPHome
    (TCP 6053) como el caso canónico del dispositivo "mudo" que sí habla el
    protocolo de su fabricante… pero el agente no tenía con qué hablarlos:
    `probe_udp` es UDP y `execute_command` no puede enviar bytes arbitrarios.
  - **`audit_status`**: el agente no podía consultar su propio progreso. Los
    candidatos sin probar solo aparecían en `done()`, es decir cuando ya había
    decidido terminar.
"""
import socket
import threading

import core.tools as toolbox
from modules.iot_probes import _tcp_payload_library, _tuya_frame, probe_tcp_raw


def setup_function():
    toolbox.build_registry()
    toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))


# ------------------------------------------------------------------- probe_tcp

def test_probe_tcp_is_registered_in_recon_only():
    tool = toolbox._REGISTRY["probe_tcp"]
    assert tool.phases == ("recon",)
    assert "port" in (tool.parameters.get("required") or [])


def test_tcp_payload_library_covers_the_tcp_vendor_protocols():
    library = _tcp_payload_library("192.168.1.50")
    assert set(library) == {"tuya", "esphome", "http", "redis"}
    # ESPHome HelloRequest: [preámbulo 0x00, longitud 0, tipo de mensaje 1]
    assert library["esphome"] == bytes([0x00, 0x00, 0x01])
    assert b"GET / HTTP/1.0" in library["http"]


def test_tuya_frame_structure_is_wellformed():
    """Prefijo, comando, longitud y sufijo del protocolo local de Tuya."""
    frame = _tuya_frame()
    assert frame[:4] == bytes.fromhex("000055aa")
    assert frame[-4:] == bytes.fromhex("0000aa55")
    assert int.from_bytes(frame[8:12], "big") == 0x0A       # DP_QUERY
    assert int.from_bytes(frame[12:16], "big") == 8         # payload vacío + CRC + sufijo


def test_probe_tcp_missing_port_is_a_clean_validation_error():
    """Antes, un puerto ausente era un TypeError envuelto en 'tool raised'."""
    result = toolbox.dispatch("probe_tcp", {"ip": "127.0.0.1"})
    assert result["ok"] is False
    assert result["error_type"] == "VALIDATION"


def test_probe_udp_missing_port_is_a_clean_validation_error():
    result = toolbox.dispatch("probe_udp", {"ip": "127.0.0.1"})
    assert result["ok"] is False
    assert result["error_type"] == "VALIDATION"


def test_probe_tcp_unknown_proto_hint_lists_the_library():
    result = probe_tcp_raw("127.0.0.1", port=9, proto_hint="zigbee")
    assert result["ok"] is False
    assert "tuya" in result["error"] and "esphome" in result["error"]


def test_probe_tcp_banner_grab_without_payload():
    """En TCP la payload es OPCIONAL: muchos servicios saludan sin preguntar."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def _greet():
        conn, _ = server.accept()
        conn.sendall(b"Tuya-Local ready\r\n")
        conn.close()

    thread = threading.Thread(target=_greet, daemon=True)
    thread.start()
    try:
        result = probe_tcp_raw("127.0.0.1", port=port, timeout=3)
    finally:
        thread.join(timeout=3)
        server.close()

    assert result["ok"] is True
    assert result["protocol_confirmed"] is True
    assert result["details"]["payload_source"] == "none:banner_grab"
    assert "Tuya-Local ready" in result["details"]["response_ascii"]
    # Descubrimiento, no confirmación: nunca marca vulnerabilidades.
    assert result["vulnerabilities"] == []


def test_probe_tcp_silent_port_is_reachability_not_confirmation():
    """Conexión aceptada y silencio = alcanzabilidad. No puede pasar por servicio
    confirmado (la gobernanza de severidad depende de esa distinción)."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        result = probe_tcp_raw("127.0.0.1", port=port, timeout=1)
    finally:
        server.close()

    assert result["protocol_confirmed"] is False
    assert result["details"]["tcp_connect"] is True
    assert "REACHABILITY" in result["details"]["note"]


def test_probe_tcp_closed_port_reports_refused():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    server.close()  # el puerto queda cerrado
    result = probe_tcp_raw("127.0.0.1", port=port, timeout=1)
    assert result["ok"] is False
    assert result["protocol_confirmed"] is False


# ---------------------------------------------------------------- audit_status

def test_audit_status_is_read_only_and_available_in_both_phases():
    tool = toolbox._REGISTRY["audit_status"]
    assert tool.phases == ("recon", "exploit")
    assert tool.requires_confirmation is False
    # No consume presupuesto de SafetyMonitor: no toca el objetivo.
    assert "audit_status" in toolbox._SAFETY_EXEMPT_TOOLS


def test_audit_status_surfaces_untested_candidates_before_done():
    toolbox.dispatch("record_cve_findings", {"cves": [
        {"id": "CVE-2021-33558", "severity": "HIGH", "description": "Boa path traversal"},
        {"id": "CVE-2017-17215", "severity": "CRITICAL", "description": "Huawei SOAP RCE"},
    ]})
    status = toolbox.dispatch("audit_status", {})
    assert status["ok"] is True
    assert set(status["untested_candidate_cves"]) == {"CVE-2021-33558", "CVE-2017-17215"}
    # `next_actions` se inyecta en el contexto del modelo y va en inglés (§4.4).
    assert any("untested candidate" in hint for hint in status["next_actions"])

    # Probar uno con evidencia real lo saca de la lista de pendientes.
    toolbox.dispatch("record_finding", {
        "cve_id": "CVE-2021-33558", "title": "Boa path traversal",
        "severity": "HIGH", "confirmed": True, "impact": "EXFIL",
        "raw_output": "HTTP/1.1 200 OK\nroot:x:0:0:root:/root:/bin/sh",
        "cmd": "curl -sk http://target/../../etc/passwd",
    })
    status = toolbox.dispatch("audit_status", {})
    assert status["untested_candidate_cves"] == ["CVE-2017-17215"]
    assert status["findings_confirmed"] == 1


def test_audit_status_flags_findings_whose_severity_was_capped():
    """Un confirmado HIGH sin clase de impacto se topa a LOW: el agente debe poder
    verlo EN VIVO, no descubrirlo al leer el informe.

    El ejemplo era `TR069-EXPOSED`, y dejó de servir cuando la reafirmación de
    superficie pasó a ser INFO: ese identificador ejercitaba DOS mecanismos a la
    vez —el tope por impacto y la regla de superficie— y la prueba solo quería
    comprobar el primero. Se usa ahora un identificador que afirma algo más que
    presencia, de modo que el único tope que actúa es el que se está probando.
    """
    toolbox.dispatch("record_finding", {
        "cve_id": "MQTT-BROKER-HIJACK", "title": "Broker MQTT secuestrable",
        "severity": "HIGH", "confirmed": True,   # sin `impact`
        "raw_output": "CONNACK 0x00 recibido del broker en 1883",
    })
    status = toolbox.dispatch("audit_status", {})
    capped = status["severity_capped_findings"]
    assert len(capped) == 1
    assert capped[0]["declared_severity"] == "HIGH"
    assert capped[0]["effective_severity"] == "LOW"
    assert any("effective severity below" in hint for hint in status["next_actions"])


def test_audit_status_reports_pending_probes_and_coverage():
    session = toolbox.get_session()
    session.recommended_probes = ["probe_snmp", "probe_mdns", "probe_coap"]
    session.executed_probes = ["probe_snmp"]
    status = toolbox.dispatch("audit_status", {})
    assert status["coverage_pct"] == 33.3
    assert any("probe_mdns" in hint for hint in status["next_actions"])


def test_done_and_audit_status_agree_on_untested_cves():
    """Una sola definición de "no testeado": si divergen, el aviso de `done` y el
    seguimiento en vivo se contradicen."""
    toolbox.dispatch("record_cve_findings", {"cves": [
        {"id": "CVE-2016-10176", "severity": "HIGH", "description": "Netgear noauth"},
    ]})
    status = toolbox.dispatch("audit_status", {})
    session = toolbox.get_session()
    assert status["untested_candidate_cves"] == toolbox._untested_batch_cves(session)


# ------------------------------------------------ recommend_probes: scan_cache

def test_recommend_probes_plans_probe_tcp_with_resolved_args():
    """El plan entrega el `proto_hint` resuelto: que el agente lo adivine es una
    fuente de varianza entre ejecuciones."""
    plan = toolbox.dispatch("recommend_probes", {"ports": [
        {"port": 6668, "proto": "tcp"}, {"port": 6053, "proto": "tcp"},
    ]})
    by_port = {r["port"]: r for r in plan["recommendations"]}
    assert by_port[6668]["probe"] == "probe_tcp"
    assert by_port[6668]["args"] == {"port": 6668, "proto_hint": "tuya"}
    assert by_port[6053]["args"] == {"port": 6053, "proto_hint": "esphome"}
    # Y cuenta para la cobertura que exige transition_phase.
    assert "probe_tcp" in toolbox.get_session().recommended_probes


def test_recommend_probes_falls_back_to_scan_cache():
    """Sin puertos, devolvía un plan vacío que desactivaba en silencio el control
    de cobertura de `transition_phase`."""
    toolbox.get_session().scan_cache = {
        "ports": [{"port": 161, "proto": "udp", "service": "snmp"},
                  {"port": 23, "proto": "tcp", "service": "telnet"}],
    }
    plan = toolbox.dispatch("recommend_probes", {})
    names = [p["probe"] for p in plan["recommendations"]]
    assert "probe_snmp" in names and "probe_telnet" in names
    assert sorted(plan["input_ports"]) == [23, 161]
    assert toolbox.get_session().recommended_probes
