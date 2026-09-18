"""
Tests de los pulidos finales — auto-register, coverage cap, DIAL Application-URL,
guard wss en execute_command/chain.
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core import tools as toolbox
from core.tools import (
    _auto_register_probe_findings,
    _cache_ws_endpoints_from_result,
    _check_ws_endpoint_guard,
    _compute_coverage_pct,
)
from modules.iot_probes import probe_dial


# ----------------------------------------------------------------- Helpers
def _free_tcp_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _HTTPServerWithHeaders:
    """Servidor HTTP que devuelve headers personalizados (para testar
    `Application-URL` en probe_dial)."""

    def __init__(self, routes):
        """routes: dict {path: (status, headers_dict, body_str)}"""
        self.port = _free_tcp_port()
        self.routes = routes
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.listen(8)
        self._sock.settimeout(8)
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def _run(self):
        for _ in range(15):
            try:
                client, _ = self._sock.accept()
            except (socket.timeout, OSError):
                return
            try:
                client.settimeout(2)
                req = b""
                end_at = time.time() + 1.5
                while time.time() < end_at and b"\r\n\r\n" not in req:
                    try:
                        chunk = client.recv(2048)
                    except (socket.timeout, OSError):
                        break
                    if not chunk:
                        break
                    req += chunk
                first = req.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
                parts = first.split(" ")
                path = parts[1] if len(parts) >= 2 else "/"
                route = self.routes.get(path)
                if route is None:
                    resp = b"HTTP/1.0 404 Not Found\r\n\r\n"
                else:
                    status, headers, body = route
                    body_b = body.encode("utf-8") if isinstance(body, str) else body
                    header_lines = [
                        f"HTTP/1.0 {status} OK",
                        f"Content-Length: {len(body_b)}",
                    ]
                    for k, v in headers.items():
                        header_lines.append(f"{k}: {v}")
                    resp = ("\r\n".join(header_lines) + "\r\n\r\n").encode("ascii") + body_b
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


# ----------------------------------------------------------------- Auto-register
class TestAutoRegisterProbeFindings:

    def setup_method(self):
        toolbox.build_registry()
        toolbox.bind_session(toolbox.AgentSession(target_ip="10.0.0.1"))

    def test_vulnerabilities_array_creates_findings(self):
        result = {
            "ok": True, "ip": "10.0.0.1", "port": 502,
            "vulnerabilities": [
                {"id": "MODBUS-NO-AUTH-FC17", "severity": "HIGH",
                 "description": "Modbus reachable without auth"},
                {"id": "MODBUS-NO-AUTH-READCOILS", "severity": "CRITICAL",
                 "description": "Coils readable"},
            ],
        }
        _auto_register_probe_findings("probe_modbus", {"ip": "10.0.0.1"}, result)
        findings = toolbox.get_session().findings
        ids = {f["cve_id"] for f in findings}
        assert ids == {"MODBUS-NO-AUTH-FC17", "MODBUS-NO-AUTH-READCOILS"}
        for f in findings:
            assert f["confirmed"] is True
        assert "_auto_registered_findings" in result

    def test_no_vulnerabilities_no_findings(self):
        result = {"ok": True, "vulnerabilities": []}
        _auto_register_probe_findings("probe_x", {}, result)
        assert toolbox.get_session().findings == []

    def test_dispatch_auto_registers_via_dial_probe(self):
        """End-to-end: dispatch llamando probe_dial debe auto-registrar
        DIAL-EXPOSED en findings sin que el modelo invoque record_finding."""
        dd_xml = (
            '<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0">'
            '<device><friendlyName>TV</friendlyName>'
            '<modelName>Test</modelName></device></root>'
        )
        srv = _HTTPServerWithHeaders({
            "/dd.xml": (200, {"Application-URL": "http://127.0.0.1:8888/apps/"}, dd_xml),
            "/apps/YouTube": (200, {}, "<service><state>stopped</state></service>"),
        }).start()
        toolbox.dispatch("probe_dial", {"ip": "127.0.0.1", "ports": [srv.port], "timeout": 2})
        findings = toolbox.get_session().findings
        assert any(f["cve_id"] == "DIAL-EXPOSED" for f in findings)

    def test_verification_cmd_promoted_to_cmd_field(self):
        """Contrato actualizado: verification_cmd del probe va al campo `cmd`
        del finding (para reproducción), no a evidence (que ahora captura
        descripción + datos contextuales)."""
        result = {
            "ok": True, "ip": "10.0.0.1", "port": 23,
            "vulnerabilities": [{
                "id": "TELNET-DEFAULT-CRED", "severity": "CRITICAL",
                "description": "Default cred works",
                "verification_cmd": "telnet 10.0.0.1 23",
                "credentials": {"user": "root", "password": "root"},
            }],
        }
        _auto_register_probe_findings("probe_telnet", {}, result)
        f = toolbox.get_session().findings[0]
        # cmd: verification_cmd real shell command
        assert f["cmd"] == "telnet 10.0.0.1 23"
        # evidence: descripción + credenciales (NO el cmd, que ya está en cmd)
        assert "root" in f["evidence"]  # credenciales formateadas


# ----------------------------------------------------------------- Coverage cap
class TestCoveragePctCap:

    def setup_method(self):
        toolbox.build_registry()
        toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))

    def test_cap_at_100_when_executed_exceeds_recommended(self):
        sess = toolbox.get_session()
        sess.recommended_probes = ["probe_a", "probe_b"]
        sess.executed_probes = ["probe_a", "probe_b", "probe_c", "probe_d"]
        # Solo 2/2 recomendadas se ejecutaron → 100%, no 200%
        pct = _compute_coverage_pct(sess)
        assert pct == 100.0

    def test_partial_coverage(self):
        sess = toolbox.get_session()
        sess.recommended_probes = ["probe_a", "probe_b", "probe_c", "probe_d"]
        sess.executed_probes = ["probe_a", "probe_b"]
        pct = _compute_coverage_pct(sess)
        assert pct == 50.0

    def test_no_recommendations_returns_none(self):
        sess = toolbox.get_session()
        pct = _compute_coverage_pct(sess)
        assert pct is None

    def test_transition_phase_returns_capped_pct(self):
        toolbox.dispatch("recommend_probes", {
            "ports": [{"port": 5353, "proto": "udp"}],
        })
        # Ejecutar varios probes adicionales no recomendados
        toolbox.dispatch("probe_mdns", {"ip": "127.0.0.1", "timeout": 1})
        toolbox.dispatch("probe_telnet", {"ip": "127.0.0.1", "timeout": 1,
                                          "try_default_creds": False})
        toolbox.dispatch("probe_ssh", {"ip": "127.0.0.1", "timeout": 1})
        # 1 recom (probe_mdns) + 1 mandatory (mac_vendor_lookup, no ejecutado)
        # 1/2 = 50% de los recomendados se ejecutaron
        r = toolbox.dispatch("transition_phase", {"phase": "exploit", "force": True})
        assert r["coverage_pct"] is not None
        assert 0 <= r["coverage_pct"] <= 100  # capeado


# ----------------------------------------------------------------- DIAL Application-URL
class TestProbeDialApplicationURL:

    def test_application_url_header_is_extracted(self):
        dd_xml = (
            '<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0">'
            '<device><friendlyName>LG TV</friendlyName>'
            '<modelName>QNED826RE</modelName></device></root>'
        )
        # Servidor estático devuelve Application-URL apuntando a SÍ MISMO
        # (mismo puerto en este test, en realidad sería puerto dinámico)
        srv = _HTTPServerWithHeaders({}).start()
        srv.routes["/dd.xml"] = (
            200,
            {"Application-URL": f"http://127.0.0.1:{srv.port}/apps/"},
            dd_xml,
        )
        srv.routes["/apps/YouTube"] = (200, {}, "<service><state>stopped</state></service>")
        srv.routes["/apps/Netflix"] = (200, {}, "<service><state>stopped</state></service>")

        result = probe_dial("127.0.0.1", ports=[srv.port], timeout=2)
        assert result["protocol_confirmed"] is True
        assert "application_url" in result["details"]
        # rstrip('/') aplicado por probe_dial, así que es '/apps' sin barra final
        assert result["details"]["application_url"].endswith("/apps")
        # Apps enumeradas vía Application-URL
        assert "YouTube" in result["details"]["apps"]
        # DIAL-EXPOSED debe mencionar el endpoint dinámico
        vulns = result["vulnerabilities"]
        assert vulns
        assert "DIAL-EXPOSED" == vulns[0]["id"]
        assert "Endpoint dinámico" in vulns[0]["description"]

    def test_dial_without_application_url_falls_back(self):
        dd_xml = (
            '<?xml version="1.0"?><root>'
            '<device><friendlyName>X</friendlyName>'
            '<modelName>Y</modelName></device></root>'
        )
        srv = _HTTPServerWithHeaders({
            "/dd.xml": (200, {}, dd_xml),  # SIN Application-URL header
            "/apps/YouTube": (200, {}, "<service><state>stopped</state></service>"),
        }).start()
        result = probe_dial("127.0.0.1", ports=[srv.port], timeout=2)
        assert result["protocol_confirmed"] is True
        assert result["details"].get("application_url") is None
        # Aún así debería enumerar apps vía /apps en el puerto estático
        assert "YouTube" in result["details"].get("apps", {})


# ----------------------------------------------------------------- Guard wss
class TestExecuteCommandWSGuard:

    def setup_method(self):
        toolbox.build_registry()
        toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))

    def test_curl_to_known_ws_endpoint_blocked(self):
        sess = toolbox.get_session()
        sess.ws_confirmed_endpoints.append(("192.168.1.33", 3001))
        r = toolbox.dispatch("execute_command", {
            "cmd": "curl -sk -X POST https://192.168.1.33:3001/api/v1/service/register",
        })
        assert r["ok"] is False
        assert r["error_type"] == "WS_ENDPOINT_NOT_HTTP"
        assert "execute_websocket" in r.get("_hint", "")
        assert "wss://192.168.1.33:3001" in r["_hint"]

    def test_curl_to_other_endpoint_passes_guard(self):
        """No bloquear curl a endpoints distintos a los WS-confirmed."""
        sess = toolbox.get_session()
        sess.ws_confirmed_endpoints.append(("192.168.1.33", 3001))
        guard = _check_ws_endpoint_guard(
            "curl http://192.168.1.33:8080/something"
        )
        assert guard is None

    def test_check_guard_no_session(self):
        # Sin sesión, no hay guard
        toolbox._SESSION = None
        try:
            assert _check_ws_endpoint_guard("curl http://x:80/") is None
        finally:
            toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))

    def test_chain_with_ws_step_blocked(self):
        sess = toolbox.get_session()
        sess.ws_confirmed_endpoints.append(("10.0.0.5", 3001))
        chain = {
            "steps": [
                {"name": "step1", "cmd": "curl http://10.0.0.5:3001/api"},
                {"name": "step2", "cmd": "curl http://other:80/"},
            ],
        }
        r = toolbox.dispatch("execute_chain", {"chain": chain, "cve_id": "T"})
        assert r["ok"] is False
        assert r["error_type"] == "WS_ENDPOINT_NOT_HTTP"

    def test_cache_ws_endpoint_from_probe_lg_webos_result(self):
        sess = toolbox.get_session()
        result = {
            "ok": True, "ip": "192.168.1.33", "service": "lg_webos",
            "details": {
                "websocket_handshake": {
                    3000: {"upgraded": False, "handshake": "..."},
                    3001: {"upgraded": True, "handshake": "ok"},
                },
            },
        }
        _cache_ws_endpoints_from_result("probe_lg_webos", result)
        assert ("192.168.1.33", 3001) in sess.ws_confirmed_endpoints
        # No upgraded → no se cachea
        assert ("192.168.1.33", 3000) not in sess.ws_confirmed_endpoints
