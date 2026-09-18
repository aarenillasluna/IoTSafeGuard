"""
Tests profesionales de los 4 improvements finales:

  1. execute_websocket: auto-detect expect_n_messages para LG WebOS pairing
  2. record_findings_batch_unconfirmed: batch dismiss en una llamada
  3. cve_search: enrichment con PoC templates desde KB local
  4. probe_lg_webos: bypass attempt integrado (Bitdefender CVE-2023-6317)
"""
from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core import tools as toolbox
from core.tools import _enrich_with_pocs
from modules.cve_pocs import (
    CVE_POCS,
    LG_WEBOS_BYPASS_PAYLOAD,
    LG_WEBOS_PAIRING_PERMISSIONS,
    get_poc,
)


def _free_tcp_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ============================================================================
# 1. Auto-detect expect_n_messages
# ============================================================================
class TestWebSocketAutoDetect:
    """Verifica que execute_websocket detecta payload de tipo 'register'
    y default a 2 mensajes esperados (handshake + registered/error)."""

    def setup_method(self):
        toolbox.build_registry()
        toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))

    def test_register_payload_defaults_to_2_messages(self):
        """Payload con type:register debe esperar 2 mensajes por default.
        Verificamos esto inspeccionando el flujo: usamos un servidor WS local
        que envía 2 frames para confirmar que ambos llegan."""
        try:
            import websockets.asyncio.server as wss
        except ImportError:
            pytest.skip("websockets server not available")

        port = _free_tcp_port()
        ready = threading.Event()
        stop = threading.Event()

        async def handler(ws):
            # Espera el frame del cliente
            await ws.recv()
            # Envía DOS mensajes (handshake + registered)
            await ws.send('{"type":"response","payload":{"pairingType":"PROMPT","returnValue":true}}')
            await ws.send('{"type":"registered","payload":{"client-key":"abc-123"}}')

        async def srv():
            async with await wss.serve(handler, "127.0.0.1", port):
                ready.set()
                while not stop.is_set():
                    await asyncio.sleep(0.1)

        t = threading.Thread(target=lambda: asyncio.run(srv()), daemon=True)
        t.start()
        assert ready.wait(timeout=5)

        try:
            # NO especificar expect_n_messages — debe auto-detectar 2
            r = toolbox.dispatch("execute_websocket", {
                "url": f"ws://127.0.0.1:{port}/",
                "payload": '{"type":"register","payload":{}}',
                "timeout": 3,
            })
            assert r["ok"] is True
            assert r["messages_received"] == 2
            assert "client-key" in r["messages"][1]
        finally:
            stop.set()
            t.join(timeout=2)

    def test_non_register_payload_defaults_to_1_message(self):
        """Payload sin type:register usa default 1."""
        try:
            import websockets.asyncio.server as wss
        except ImportError:
            pytest.skip("websockets server not available")

        port = _free_tcp_port()
        ready = threading.Event()
        stop = threading.Event()

        async def handler(ws):
            await ws.recv()
            await ws.send("first")
            await ws.send("second")  # nunca debería leerse

        async def srv():
            async with await wss.serve(handler, "127.0.0.1", port):
                ready.set()
                while not stop.is_set():
                    await asyncio.sleep(0.1)

        t = threading.Thread(target=lambda: asyncio.run(srv()), daemon=True)
        t.start()
        assert ready.wait(timeout=5)

        try:
            r = toolbox.dispatch("execute_websocket", {
                "url": f"ws://127.0.0.1:{port}/",
                "payload": '{"type":"ping"}',
                "timeout": 2,
            })
            assert r["ok"] is True
            assert r["messages_received"] == 1
            assert r["messages"][0] == "first"
        finally:
            stop.set()
            t.join(timeout=2)

    def test_explicit_override_respected(self):
        """expect_n_messages explícito siempre gana sobre auto-detect."""
        try:
            import websockets.asyncio.server as wss
        except ImportError:
            pytest.skip("websockets server not available")

        port = _free_tcp_port()
        ready = threading.Event()
        stop = threading.Event()

        async def handler(ws):
            await ws.recv()
            for i in range(5):
                await ws.send(f"msg-{i}")

        async def srv():
            async with await wss.serve(handler, "127.0.0.1", port):
                ready.set()
                while not stop.is_set():
                    await asyncio.sleep(0.1)

        t = threading.Thread(target=lambda: asyncio.run(srv()), daemon=True)
        t.start()
        assert ready.wait(timeout=5)

        try:
            # Override explícito a 4 — payload register normalmente sería 2
            r = toolbox.dispatch("execute_websocket", {
                "url": f"ws://127.0.0.1:{port}/",
                "payload": '{"type":"register","payload":{}}',
                "expect_n_messages": 4,
                "timeout": 2,
            })
            assert r["messages_received"] == 4
        finally:
            stop.set()
            t.join(timeout=2)


# ============================================================================
# 2. record_findings_batch_unconfirmed
# ============================================================================
class TestBatchUnconfirmed:

    def setup_method(self):
        toolbox.build_registry()
        toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))

    def test_batch_dismiss_creates_findings(self):
        r = toolbox.dispatch("record_findings_batch_unconfirmed", {
            "cve_ids": ["CVE-2023-A", "CVE-2023-B", "CVE-2023-C"],
            "reason": "Depende de CVE-2023-6317 no confirmado",
            "severity": "HIGH",
        })
        assert r["ok"] is True
        assert len(r["created_new"]) == 3
        findings = toolbox.get_session().findings
        assert len(findings) == 3
        for f in findings:
            assert f["confirmed"] is False
            assert f["severity"] == "HIGH"
            assert "no confirmado" in f["evidence"].lower() or "no confirmado" in f["evidence"]

    def test_batch_merges_existing_findings(self):
        # Pre-crear un finding
        toolbox.dispatch("record_finding", {
            "cve_id": "CVE-X", "title": "X", "severity": "MEDIUM",
            "confirmed": False, "evidence": "initial", "cmd": "",
        })
        # Batch lo actualiza
        r = toolbox.dispatch("record_findings_batch_unconfirmed", {
            "cve_ids": ["CVE-X", "CVE-Y"],
            "reason": "razón compartida",
        })
        assert "CVE-X" in r["updated_existing"]
        assert "CVE-Y" in r["created_new"]
        assert r["total_findings"] == 2

    def test_empty_list_returns_validation_error(self):
        r = toolbox.dispatch("record_findings_batch_unconfirmed", {
            "cve_ids": [], "reason": "x",
        })
        assert r["ok"] is False
        assert r["error_type"] == "VALIDATION"

    def test_missing_reason_returns_validation_error(self):
        r = toolbox.dispatch("record_findings_batch_unconfirmed", {
            "cve_ids": ["CVE-A"], "reason": "",
        })
        assert r["ok"] is False
        assert r["error_type"] == "VALIDATION"


# ============================================================================
# 3. PoC Knowledge Base + cve_search enrichment
# ============================================================================
class TestPoCKnowledgeBase:

    def test_kb_has_expected_cves(self):
        ids = CVE_POCS
        # Familia LG WebOS
        for cve in ("CVE-2023-6317", "CVE-2023-6318", "CVE-2023-6319", "CVE-2023-6320"):
            assert cve in ids, f"{cve} ausente en KB"
        # Otros conocidos
        assert "CVE-2017-7921" in ids
        assert "CVE-2014-9222" in ids
        assert "CVE-2017-17215" in ids

    def test_lg_webos_payload_has_required_permissions(self):
        """El payload Bitdefender debe incluir TEST_SECURE y CONTROL_*."""
        perms = LG_WEBOS_PAIRING_PERMISSIONS
        for required in ("TEST_SECURE", "CONTROL_INPUT_TEXT", "WRITE_SETTINGS"):
            assert required in perms

    def test_lg_webos_payload_structure(self):
        p = LG_WEBOS_BYPASS_PAYLOAD
        assert p["type"] == "register"
        assert "manifest" in p["payload"]
        assert "permissions" in p["payload"]["manifest"]
        assert "signed" in p["payload"]["manifest"]

    def test_get_poc_for_known_cve(self):
        poc = get_poc("CVE-2023-6317")
        assert poc is not None
        assert poc["protocol"] == "wss"
        assert poc["default_port"] == 3001
        assert poc["payload"]["type"] == "register"

    def test_get_poc_for_unknown_returns_none(self):
        assert get_poc("CVE-9999-9999") is None

    def test_dependent_cve_marks_dependency(self):
        """CVEs dependientes (6318/19/20) deben marcar `depends_on`."""
        for cve in ("CVE-2023-6318", "CVE-2023-6319", "CVE-2023-6320"):
            poc = get_poc(cve)
            assert poc.get("depends_on") == "CVE-2023-6317"

    def test_cve_search_enriches_with_poc_template(self):
        cves = [
            {"id": "CVE-2023-6317", "severity": "HIGH", "score": 7.2,
             "description": "test"},
            {"id": "CVE-9999-X", "severity": "LOW", "score": 1.0,
             "description": "no en KB"},
        ]
        enriched = _enrich_with_pocs(cves)
        # CVE en KB → enriquecido
        assert enriched[0]["poc_available"] is True
        assert enriched[0]["poc_template"]["protocol"] == "wss"
        assert "payload" in enriched[0]["poc_template"]
        # CVE no en KB → sin enrichment
        assert "poc_available" not in enriched[1]
        assert "poc_template" not in enriched[1]


# ============================================================================
# 4. CVE-2018-10106 / 2015-0150 / 2015-0152: verification_hint + implications
# ============================================================================
# La motivación es empírica: runs sucesivos del agente contra el mismo DIR-815
# confirmaban subconjuntos distintos de estos tres CVEs porque el modelo elegía
# vectores de verificación diferentes cada vez. El KB local ahora documenta la
# receta correcta para los tres y enlaza implícitamente CVE-2015-0150 y
# CVE-2015-0152 como confirmados-por-evidencia-de CVE-2018-10106.

class TestDirCveVerificationHints:

    def test_dir815_parent_cve_has_verification_steps_and_implies(self):
        poc = get_poc("CVE-2018-10106")
        assert poc is not None
        # Vector concreto que se sabe que funciona
        assert poc["query_string"].startswith("a=%0a_POST_SERVICES")
        assert "DEVICE.ACCOUNT" in poc["query_string"]
        # success_indicators incluyen marcadores robustos del XML de respuesta
        si = poc["success_indicators"]
        assert any("DEVICE.ACCOUNT" in s for s in si)
        assert any("admin" in s for s in si)
        # Implicaciones documentadas hacia los CVEs genéricos
        assert set(poc["implies_cves"]) == {"CVE-2015-0150", "CVE-2015-0152"}
        assert len(poc["verification_steps"]) >= 2

    def test_dir815_implied_cves_reference_parent(self):
        for cve_id in ("CVE-2015-0150", "CVE-2015-0152"):
            poc = get_poc(cve_id)
            assert poc is not None, f"{cve_id} ausente del KB"
            assert poc["implied_by"] == "CVE-2018-10106", \
                f"{cve_id} debe declarar implied_by=CVE-2018-10106"
            assert poc["verification_steps"], \
                f"{cve_id} necesita verification_steps explícitos"

    def test_dir815_cleartext_warns_against_inventing_post_services(self):
        """Regresión: el KB debe instruir explícitamente NO inventar otros _POST_SERVICES."""
        poc = get_poc("CVE-2015-0152")
        joined = " ".join(poc["verification_steps"]).lower()
        # El run problemático probó DEVICE.CONFIG; la guía debe atajarlo.
        assert "device.account" in joined
        assert "inventes" in joined or "no inventes" in joined or "no uses" in joined or "device.config" in joined

    def test_dir815_access_bypass_warns_against_login_form_heuristic(self):
        """Regresión: no usar 'la raíz pide login' como verificación negativa."""
        poc = get_poc("CVE-2015-0150")
        joined = " ".join(poc["verification_steps"]).lower()
        assert "login" in joined
        # El paso clave dice explícitamente que mostrar login NO descarta el bypass.

    def test_cve_search_enrichment_exposes_verification_hint(self):
        cves = [
            {"id": "CVE-2018-10106", "severity": "CRITICAL", "score": 9.8,
             "description": "test"},
            {"id": "CVE-2015-0152", "severity": "CRITICAL", "score": 9.8,
             "description": "test"},
        ]
        enriched = _enrich_with_pocs(cves)
        # CVE padre: implies_cves presente, implied_by ausente
        parent = next(c for c in enriched if c["id"] == "CVE-2018-10106")
        assert "verification_hint" in parent
        assert "implies_cves" in parent["verification_hint"]
        assert "implied_by" not in parent["verification_hint"]
        # CVE hijo: implied_by presente, implies_cves ausente
        child = next(c for c in enriched if c["id"] == "CVE-2015-0152")
        assert "verification_hint" in child
        assert child["verification_hint"]["implied_by"] == "CVE-2018-10106"
        assert "implies_cves" not in child["verification_hint"]

    def test_cve_search_response_carries_instruction_when_hinted(self):
        """_cve_search debe añadir un campo `instruction` cuando el KB aporta hints."""
        from core.tools import _cve_search
        from modules import cve_api

        # Forzamos resultado controlado para no depender de la red ni del orden de NVD.
        def fake(self, product, version, nmap_cpe=None):  # noqa: ARG001
            return [
                {"id": "CVE-2018-10106", "severity": "CRITICAL", "score": 9.8,
                 "description": "permission bypass and information disclosure in /htdocs/web/getcfg.php"},
            ]

        from pytest import MonkeyPatch
        mp = MonkeyPatch()
        try:
            mp.setattr(cve_api.NVDCVEClient, "get_cves_for_product", fake)
            result = _cve_search({"keyword": "D-Link DIR-815"})
        finally:
            mp.undo()

        assert result["count"] == 1
        assert "instruction" in result
        assert "verification_hint" in result["instruction"]
        assert "implies_cves" in result["instruction"]


# ============================================================================
# 4. probe_lg_webos bypass integrado
# ============================================================================
class TestLGWebOSBypass:

    def test_attempt_bypass_against_no_server_returns_failed(self):
        from modules.iot_probes import _attempt_lg_webos_bypass
        port = _free_tcp_port()
        result = _attempt_lg_webos_bypass("127.0.0.1", port, "ws", timeout=1.0)
        assert result["attempted"] is True
        assert result["vulnerable"] is False
        assert "handshake failed" in result["diagnosis"]

    def test_attempt_bypass_detects_vulnerable_response(self):
        """Servidor fake que devuelve registered+client-key → marca vulnerable=True."""
        try:
            import websockets.asyncio.server as wss
        except ImportError:
            pytest.skip("websockets server not available")

        port = _free_tcp_port()
        ready = threading.Event()
        stop = threading.Event()

        async def handler(ws):
            await ws.recv()  # consume bypass payload
            # Simula TV vulnerable: devuelve client-key SIN PIN prompt
            await ws.send(json.dumps({
                "type": "registered",
                "id": "register_0",
                "payload": {"client-key": "VULN-LEAKED-KEY-42"},
            }))

        async def srv():
            async with await wss.serve(handler, "127.0.0.1", port):
                ready.set()
                while not stop.is_set():
                    await asyncio.sleep(0.1)

        t = threading.Thread(target=lambda: asyncio.run(srv()), daemon=True)
        t.start()
        assert ready.wait(timeout=5)

        try:
            from modules.iot_probes import _attempt_lg_webos_bypass
            result = _attempt_lg_webos_bypass("127.0.0.1", port, "ws", timeout=3.0)
            assert result["vulnerable"] is True
            assert result["client_key"] == "VULN-LEAKED-KEY-42"
            assert "bypass works" in result["diagnosis"]
        finally:
            stop.set()
            t.join(timeout=2)

    def test_attempt_bypass_detects_patched_response(self):
        """Servidor fake que devuelve PIN prompt → vulnerable=False."""
        try:
            import websockets.asyncio.server as wss
        except ImportError:
            pytest.skip("websockets server not available")

        port = _free_tcp_port()
        ready = threading.Event()
        stop = threading.Event()

        async def handler(ws):
            await ws.recv()
            # Patched TV: pide PIN
            await ws.send(json.dumps({
                "type": "response",
                "payload": {"pairingType": "PROMPT", "returnValue": True},
            }))
            await asyncio.sleep(2)  # no envía registered = patched

        async def srv():
            async with await wss.serve(handler, "127.0.0.1", port):
                ready.set()
                while not stop.is_set():
                    await asyncio.sleep(0.1)

        t = threading.Thread(target=lambda: asyncio.run(srv()), daemon=True)
        t.start()
        assert ready.wait(timeout=5)

        try:
            from modules.iot_probes import _attempt_lg_webos_bypass
            result = _attempt_lg_webos_bypass("127.0.0.1", port, "ws", timeout=2.0)
            assert result["vulnerable"] is False
            assert result["response_seen"] is True
            assert result["client_key"] is None
        finally:
            stop.set()
            t.join(timeout=2)
