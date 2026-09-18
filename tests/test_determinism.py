"""
Tests para los fixes deterministas:
- Coverage enforcement en transition_phase
- record_cve_findings batch
- execute_websocket (con server WS local)
- _extract_curl_target
- probe_lg_webos TLS fallback (test del helper)
"""
from __future__ import annotations

import asyncio
import os
import socket
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core import tools as toolbox
from core.tools import _extract_curl_target


def _free_tcp_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ----------------------------------------------------------------- Coverage enforcement
class TestCoverageEnforcement:

    def setup_method(self):
        toolbox.build_registry()
        toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))

    def test_transition_blocked_when_no_probes_executed(self):
        toolbox.dispatch("recommend_probes", {
            "ports": [
                {"port": 1900, "proto": "udp"},
                {"port": 3001, "proto": "tcp"},
                {"port": 5353, "proto": "udp"},
            ],
        })
        r = toolbox.dispatch("transition_phase", {"phase": "exploit"})
        assert r["ok"] is False
        assert r["error_type"] == "COVERAGE_INSUFFICIENT"
        assert r["coverage_pct"] == 0.0
        assert len(r["missing"]) > 0

    def test_transition_allowed_with_60_pct_coverage(self):
        toolbox.dispatch("recommend_probes", {
            "ports": [
                {"port": 5353, "proto": "udp"},
                {"port": 5683, "proto": "udp"},
                {"port": 161, "proto": "udp"},
            ],
        })
        # Ejecutar 2 de 3 probes recomendadas + mac_vendor (mandatory) = ~75%
        for n in ("probe_mdns", "probe_coap"):
            toolbox.dispatch(n, {"ip": "127.0.0.1", "timeout": 1})
        toolbox.dispatch("mac_vendor_lookup", {"mac": "14:7F:67:00:00:00"})
        r = toolbox.dispatch("transition_phase", {"phase": "exploit"})
        assert r["ok"] is True
        assert r["coverage_pct"] >= 60.0

    def test_force_bypasses_coverage_check(self):
        toolbox.dispatch("recommend_probes", {
            "ports": [{"port": 1900, "proto": "udp"}, {"port": 5353, "proto": "udp"}],
        })
        # 0 probes ejecutadas pero force=true
        r = toolbox.dispatch("transition_phase", {"phase": "exploit", "force": True})
        assert r["ok"] is True
        assert r.get("_transition_to") == "exploit"

    def test_no_recommended_probes_no_block(self):
        # Si nunca se llamó recommend_probes, no hay enforcement
        r = toolbox.dispatch("transition_phase", {"phase": "exploit"})
        assert r["ok"] is True


# ----------------------------------------------------------------- record_cve_findings
class TestRecordCVEFindingsBatch:

    def setup_method(self):
        toolbox.build_registry()
        toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))

    def test_batch_register_multiple_cves(self):
        cves = [
            {"id": "CVE-2023-1", "severity": "CRITICAL", "description": "auth bypass"},
            {"id": "CVE-2023-2", "severity": "HIGH", "description": "rce"},
            {"id": "CVE-2023-3", "severity": "MEDIUM", "description": "info leak"},
        ]
        r = toolbox.dispatch("record_cve_findings", {"cves": cves})
        assert r["ok"] is True
        assert sorted(r["registered_new"]) == ["CVE-2023-1", "CVE-2023-2", "CVE-2023-3"]
        assert r["total_findings"] == 3

    def test_invalid_input_returns_validation_error(self):
        r = toolbox.dispatch("record_cve_findings", {"cves": "not a list"})
        assert r["ok"] is False
        assert r["error_type"] == "VALIDATION"

    def test_re_register_merges_via_dedupe(self):
        cves = [{"id": "CVE-X", "severity": "HIGH", "description": "test"}]
        toolbox.dispatch("record_cve_findings", {"cves": cves})
        # Segunda llamada con mismo CVE → merge
        r2 = toolbox.dispatch("record_cve_findings", {"cves": cves})
        assert r2["registered_new"] == []
        assert "CVE-X" in r2["merged_existing"]

    def test_skips_invalid_entries(self):
        cves = [
            {"id": "CVE-Valid", "severity": "HIGH"},
            {},  # vacío
            "string",  # tipo inválido
            {"severity": "HIGH"},  # falta id
        ]
        r = toolbox.dispatch("record_cve_findings", {"cves": cves})
        assert r["registered_new"] == ["CVE-Valid"]


# ----------------------------------------------------------------- _extract_curl_target
class TestExtractCurlTarget:

    @pytest.mark.parametrize("cmd,host,port", [
        ("curl http://192.168.1.1/path", "192.168.1.1", 80),      # puerto implícito
        ("curl https://10.0.0.5/api", "10.0.0.5", 443),           # https → 443
        ("curl http://192.168.0.1:8080/admin", "192.168.0.1", 8080),  # explícito
    ])
    def test_target_extraction(self, cmd, host, port):
        assert _extract_curl_target(cmd) == (host, port)

    def test_with_flags(self):
        cmd = "curl -sk -X POST -H 'Content-Type: application/json' http://1.2.3.4:3001/api/v1"
        host, port = _extract_curl_target(cmd)
        assert host == "1.2.3.4"
        assert port == 3001

    def test_no_url_returns_none(self):
        assert _extract_curl_target("nc -v 1.2.3.4 22") is None


# ----------------------------------------------------------------- execute_websocket
class TestExecuteWebSocket:

    def test_no_server_returns_network_error(self):
        toolbox.build_registry()
        toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))
        port = _free_tcp_port()
        r = toolbox.dispatch("execute_websocket", {
            "url": f"ws://127.0.0.1:{port}/",
            "timeout": 1,
        })
        assert r["ok"] is False
        assert r["error_type"] == "NETWORK"

    def test_missing_url_returns_validation(self):
        toolbox.build_registry()
        toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))
        r = toolbox.dispatch("execute_websocket", {})
        assert r["ok"] is False
        assert "url required" in r["error"]

    def test_real_handshake_with_local_ws_server(self):
        """Levantar un WS server real (websockets lib) y verificar handshake + echo."""
        toolbox.build_registry()
        toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))

        try:
            import websockets.asyncio.server as wss
        except ImportError:
            pytest.skip("websockets lib no disponible")

        port = _free_tcp_port()
        ready = threading.Event()
        stop_event = threading.Event()

        async def echo_handler(ws):
            async for msg in ws:
                await ws.send(f"echo:{msg}")
                break

        async def server_main():
            async with await wss.serve(echo_handler, "127.0.0.1", port):
                ready.set()
                while not stop_event.is_set():
                    await asyncio.sleep(0.1)

        def run_server():
            asyncio.run(server_main())

        t = threading.Thread(target=run_server, daemon=True)
        t.start()
        assert ready.wait(timeout=5), "WS server no arrancó"

        try:
            r = toolbox.dispatch("execute_websocket", {
                "url": f"ws://127.0.0.1:{port}/",
                "payload": "hello",
                "timeout": 3,
                "expect_n_messages": 1,
            })
            assert r["ok"] is True
            assert r["messages_received"] == 1
            assert r["messages"][0] == "echo:hello"
        finally:
            stop_event.set()
            t.join(timeout=2)
