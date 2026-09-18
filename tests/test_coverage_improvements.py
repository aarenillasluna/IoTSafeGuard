"""
Tests para mejoras de cobertura tras auditoría de la ejecución LG TV:
- recommend_probes(ports) — mapeo puerto→probe
- record_finding dedupe por cve_id
- probe_lg_webos / probe_dial / probe_chromecast

NOTA: el fallback de OUI estático (TestMacVendorFallback) se consolidó en
`test_oui_online_fallback.py` (iter_08).
"""
from __future__ import annotations

import os
import socket
import sys
import threading


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core import tools as toolbox
from modules.iot_probes import probe_chromecast, probe_dial, probe_lg_webos


# ----------------------------------------------------------------- helpers
def _free_tcp_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _HTTPServer:
    """Servidor HTTP minimalista que responde a múltiples conexiones secuenciales
    según un dict {path: response_body_str}."""

    def __init__(self, routes, max_conns=20):
        self.port = _free_tcp_port()
        self.routes = routes
        self.max_conns = max_conns
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.listen(8)
        self._sock.settimeout(8)
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def _run(self):
        for _ in range(self.max_conns):
            try:
                client, _ = self._sock.accept()
            except (socket.timeout, OSError):
                return
            try:
                client.settimeout(2)
                req = b""
                end_at = __import__("time").time() + 1.5
                while __import__("time").time() < end_at and b"\r\n\r\n" not in req:
                    try:
                        chunk = client.recv(2048)
                    except (socket.timeout, OSError):
                        break
                    if not chunk:
                        break
                    req += chunk
                first_line = req.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
                parts = first_line.split(" ")
                path = parts[1] if len(parts) >= 2 else "/"
                # Match exacto, luego prefix
                body = self.routes.get(path)
                if body is None:
                    for k, v in self.routes.items():
                        if path.startswith(k.rstrip("*")) and k.endswith("*"):
                            body = v
                            break
                if body is None:
                    resp = b"HTTP/1.0 404 Not Found\r\n\r\n"
                else:
                    body_b = body.encode("utf-8") if isinstance(body, str) else body
                    resp = (
                        f"HTTP/1.0 200 OK\r\n"
                        f"Content-Type: text/html\r\n"
                        f"Content-Length: {len(body_b)}\r\n\r\n"
                    ).encode("ascii") + body_b
                try:
                    client.sendall(resp)
                except (BrokenPipeError, OSError):
                    pass
            finally:
                try:
                    client.close()
                except OSError:
                    pass
        try:
            self._sock.close()
        except OSError:
            pass


# ----------------------------------------------------------------- recommend_probes
class TestRecommendProbes:

    def setup_method(self):
        toolbox.build_registry()
        toolbox.bind_session(toolbox.AgentSession(target_ip="10.0.0.1"))

    def test_lg_tv_ports_recommend_correctly(self):
        ports = [
            {"port": 1900, "proto": "udp"},
            {"port": 3001, "proto": "tcp"},
            {"port": 5353, "proto": "udp"},
            {"port": 8008, "proto": "tcp"},
            {"port": 8443, "proto": "tcp"},
            {"port": 161, "proto": "udp"},
            {"port": 7000, "proto": "tcp"},
        ]
        r = toolbox.dispatch("recommend_probes", {"ports": ports})
        assert r["ok"] is True
        probes = {rec["probe"] for rec in r["recommendations"]}
        # LG WebOS, Chromecast, UPnP, mDNS, SNMP, RTSP, HTTPS
        assert "probe_lg_webos" in probes
        assert "probe_chromecast" in probes
        assert "probe_upnp_igd" in probes
        assert "probe_mdns" in probes
        assert "probe_snmp" in probes
        assert "probe_rtsp" in probes
        assert "http_interrogate" in probes  # 8443

    def test_industrial_ports(self):
        ports = [
            {"port": 502, "proto": "tcp"},
            {"port": 4840, "proto": "tcp"},
            {"port": 47808, "proto": "udp"},
        ]
        r = toolbox.dispatch("recommend_probes", {"ports": ports})
        probes = {rec["probe"] for rec in r["recommendations"]}
        assert "probe_modbus" in probes
        assert "probe_opcua" in probes
        assert "probe_bacnet" in probes

    def test_int_list_input_works(self):
        r = toolbox.dispatch("recommend_probes", {"ports": [80, 443, 23]})
        probes = {rec["probe"] for rec in r["recommendations"]}
        assert "http_interrogate" in probes
        assert "probe_telnet" in probes

    def test_priority_sorting(self):
        # Ambos prioridad 1 ahora (SSH y Modbus son críticos por igual).
        # Sorted por (priority, port) → 22 antes que 502.
        ports = [{"port": 502, "proto": "tcp"}, {"port": 22, "proto": "tcp"}]
        r = toolbox.dispatch("recommend_probes", {"ports": ports})
        first = r["recommendations"][0]
        # SSH primero por menor puerto a igual prioridad
        assert first["probe"] == "probe_ssh"
        # Y SMTP (priority 3) debe ser ÚLTIMO si lo añadimos
        ports2 = ports + [{"port": 25, "proto": "tcp"}]
        r2 = toolbox.dispatch("recommend_probes", {"ports": ports2})
        # SMTP execute_command priority 3 → último
        assert r2["recommendations"][-1]["port"] == 25

    def test_empty_ports_returns_no_recommendations(self):
        r = toolbox.dispatch("recommend_probes", {"ports": []})
        assert r["recommendations"] == []
        assert r["mandatory_after_nmap"] == []


# ----------------------------------------------------------------- dedupe
class TestRecordFindingDedupe:

    def setup_method(self):
        toolbox.build_registry()
        toolbox.bind_session(toolbox.AgentSession(target_ip="10.0.0.1"))

    def test_first_record_creates_entry(self):
        r = toolbox.dispatch("record_finding", {
            "cve_id": "CVE-2024-1", "title": "T", "severity": "MEDIUM",
            "confirmed": False, "evidence": "first",
        })
        assert r["merged"] is False
        assert r["total_findings"] == 1

    def test_second_with_same_cve_merges(self):
        toolbox.dispatch("record_finding", {
            "cve_id": "CVE-2024-1", "title": "T", "severity": "MEDIUM",
            "confirmed": False, "evidence": "first",
        })
        r = toolbox.dispatch("record_finding", {
            "cve_id": "CVE-2024-1", "title": "T", "severity": "HIGH",
            "confirmed": True, "evidence": "much longer evidence proving exploit works",
        })
        assert r["merged"] is True
        assert r["total_findings"] == 1
        finding = toolbox.get_session().findings[0]
        assert finding["confirmed"] is True
        assert finding["severity"] == "HIGH"
        assert "longer evidence" in finding["evidence"]

    def test_confirmed_true_persists(self):
        toolbox.dispatch("record_finding", {
            "cve_id": "CVE-2024-2", "confirmed": True, "evidence": "exploit success",
            "severity": "HIGH",
        })
        toolbox.dispatch("record_finding", {
            "cve_id": "CVE-2024-2", "confirmed": False,  # intento de "desconfirmar"
            "evidence": "shorter", "severity": "LOW",
        })
        f = toolbox.get_session().findings[0]
        # confirmed=True no se desconfirma
        assert f["confirmed"] is True
        # severidad alta no se rebaja
        assert f["severity"] == "HIGH"

    def test_different_cve_ids_dont_merge(self):
        toolbox.dispatch("record_finding", {
            "cve_id": "CVE-A", "severity": "HIGH", "confirmed": False, "evidence": "a",
        })
        toolbox.dispatch("record_finding", {
            "cve_id": "CVE-B", "severity": "HIGH", "confirmed": False, "evidence": "b",
        })
        assert len(toolbox.get_session().findings) == 2


# NOTA: TestMacVendorFallback se consolidó en `test_oui_online_fallback.py`
# (iter_08), junto al resto de resolución de OUI/vendor.


# ----------------------------------------------------------------- probe_chromecast
class TestProbeChromecast:

    def test_eureka_info_marks_protocol(self):
        eureka_json = (
            '{"build_version":"800768591","cast_build_revision":"1.68.cast_20250829",'
            '"connected":true,"mac_address":"FA:8F:CA:73:7A:3F","name":"Bedroom TV",'
            '"ssid":"MyHomeWifi"}'
        )
        srv = _HTTPServer({
            "/setup/eureka_info": eureka_json,
            "/setup/eureka_info?options=detail": eureka_json,
        }).start()
        result = probe_chromecast("127.0.0.1", port=srv.port, timeout=2)
        assert result["protocol_confirmed"] is True
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "CHROMECAST-INFO-DISCLOSURE" in ids

    def test_no_response_no_vuln(self):
        port = _free_tcp_port()  # nadie escucha
        result = probe_chromecast("127.0.0.1", port=port, timeout=1)
        assert result["protocol_confirmed"] is False


# ----------------------------------------------------------------- probe_dial
class TestProbeDial:

    def test_dd_xml_marks_protocol_and_extracts_metadata(self):
        dd_xml = (
            '<?xml version="1.0"?>'
            '<root xmlns="urn:schemas-upnp-org:device-1-0" xmlns:dial="urn:schemas-dial-multiscreen-org:device-1-0">'
            '<device>'
            '<friendlyName>LG Living Room TV</friendlyName>'
            '<manufacturer>LG Electronics</manufacturer>'
            '<modelName>65QNED826RE</modelName>'
            '</device></root>'
        )
        apps_xml = '<service><state>stopped</state></service>'
        srv = _HTTPServer({
            "/dd.xml": dd_xml,
            "/apps/YouTube": apps_xml,
            "/apps/Netflix": apps_xml,
        }).start()
        result = probe_dial("127.0.0.1", ports=[srv.port], timeout=2)
        assert result["protocol_confirmed"] is True
        assert result["details"]["friendly_name"] == "LG Living Room TV"
        assert result["details"]["model_name"] == "65QNED826RE"
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "DIAL-EXPOSED" in ids
        assert "YouTube" in result["details"]["apps"]


# ----------------------------------------------------------------- probe_lg_webos
class TestProbeLGWebOS:

    def test_no_response_returns_unconfirmed(self):
        port = _free_tcp_port()
        result = probe_lg_webos("127.0.0.1", port=port, alt_port=port + 1, timeout=1)
        assert result["protocol_confirmed"] is False

    def test_rest_endpoint_with_webos_marker_confirms(self):
        srv = _HTTPServer({"/": "<html>WebOS - LG Smart TV control</html>"}).start()
        # El probe intenta WS handshake (fallará) y luego REST. Solo nos importa REST.
        result = probe_lg_webos("127.0.0.1", port=srv.port, alt_port=srv.port,
                                timeout=2)
        assert result["protocol_confirmed"] is True
        ids = [v["id"] for v in result["vulnerabilities"]]
        # Como el server fake no hace WS upgrade, no debería haber CVE confirmado,
        # pero sí marca de exposición LG-WEBOS-EXPOSED
        assert "LG-WEBOS-EXPOSED" in ids
