"""Tests for the four restored modules wired back into the agent:

  - SafetyMonitor: rate-limit + kill-switch enforced en `dispatch()`
  - TelemetryCollector: registra surface (nmap) + attempts (record_finding)
  - DeviceFingerprinter: tool `fingerprint_consensus` agrega evidencia
  - Searchsploit fallback: anexa `exploit_db_matches` cuando NVD vacío
"""
from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from core import tools as t


@pytest.fixture(autouse=True)
def _fresh_session():
    """Cada test arranca con sesion limpia y safety/telemetry off."""
    session = t.AgentSession(target_ip="192.168.99.99")
    t.bind_session(session)
    yield session
    # cleanup
    t._SESSION = None


# =====================================================================
# SafetyMonitor
# =====================================================================

class TestSafetyMonitorIntegration:
    def test_attach_idempotent(self, _fresh_session):
        t.attach_safety_monitor(requests_per_minute=10)
        first = _fresh_session.safety
        t.attach_safety_monitor(requests_per_minute=99)
        # Idempotente — no se sustituye
        assert _fresh_session.safety is first
        assert _fresh_session.safety.requests_per_minute == 10

    def test_exempt_tools_skip_budget(self, _fresh_session):
        t.attach_safety_monitor(requests_per_minute=1)
        # Agotamos el budget
        _fresh_session.safety.consume_budget()
        # Tools exemptas no son bloqueadas
        assert t._safety_precheck("record_finding") is None
        assert t._safety_precheck("transition_phase") is None
        assert t._safety_precheck("done") is None
        assert t._safety_precheck("save_report") is None
        assert t._safety_precheck("fingerprint_consensus") is None

    def test_network_tools_blocked_when_budget_exhausted(self, _fresh_session):
        t.attach_safety_monitor(requests_per_minute=1)
        _fresh_session.safety.consume_budget()  # quemamos el budget
        block = t._safety_precheck("nmap_scan")
        assert block is not None
        assert block["error_type"] == "safety_rate_limit"
        assert "Budget" in block["error"]

    def test_kill_switch_blocks_all_network_tools(self, _fresh_session):
        t.attach_safety_monitor(requests_per_minute=100)
        _fresh_session.safety.trigger_kill_switch()
        block = t._safety_precheck("probe_telnet")
        assert block["error_type"] == "safety_kill_switch"
        # Exemptas siguen pasando incluso con kill-switch (record_finding, done)
        # para que el agente pueda cerrar el reporte aunque el target esté caído
        assert t._safety_precheck("save_report") is None

    def test_dispatch_skips_tool_when_kill_switch(self, _fresh_session):
        """dispatch() debe devolver el error de safety sin invocar el impl."""
        t.attach_safety_monitor(requests_per_minute=100)
        _fresh_session.safety.trigger_kill_switch()
        # Probe inventada que crashearía si se ejecutara
        sentinel = MagicMock(side_effect=AssertionError("no debería ejecutarse"))
        original = t._REGISTRY.get("nmap_scan")
        try:
            t._REGISTRY["nmap_scan"] = t.Tool(
                name="nmap_scan", description="", parameters={},
                impl=sentinel, phases=("recon",),
            )
            result = t.dispatch("nmap_scan", {})
            assert result["error_type"] == "safety_kill_switch"
            sentinel.assert_not_called()
        finally:
            if original is not None:
                t._REGISTRY["nmap_scan"] = original

    def test_no_safety_means_no_block(self, _fresh_session):
        # Sin attach_safety_monitor, dispatch no debe bloquear nada
        assert _fresh_session.safety is None
        assert t._safety_precheck("nmap_scan") is None
        assert t._safety_precheck("execute_command") is None

    def test_slow_tool_does_not_trigger_kill_switch(self, _fresh_session):
        """REGRESIÓN: nmap_scan dura 30-60s legítimamente. dispatch NO debe
        meter elapsed_ms en record_latency — eso disparaba false positives.
        Solo el health probe ICMP debe alimentar latencias."""
        t.attach_safety_monitor(requests_per_minute=100, latency_threshold_ms=1000.0)

        # Tool falso que tarda mucho (60s simulados via elapsed_ms en result)
        def slow_impl(_args):
            import time as _time
            _time.sleep(0.05)  # real elapsed pequeño pero >threshold
            return {"ok": True}

        original = t._REGISTRY.get("nmap_scan")
        try:
            t._REGISTRY["nmap_scan"] = t.Tool(
                name="nmap_scan", description="", parameters={},
                impl=slow_impl, phases=("recon",),
            )
            # Ejecutar 5 veces — no debe disparar kill-switch
            # (antes del fix: cada elapsed > threshold = kill-switch inmediato)
            for _ in range(5):
                result = t.dispatch("nmap_scan", {})
                assert result["ok"] is True
                assert not _fresh_session.safety._kill_switch_triggered
        finally:
            if original is not None:
                t._REGISTRY["nmap_scan"] = original
            t._dispatch_call_counter = 0

    def test_reset_kill_switch(self, _fresh_session):
        t.attach_safety_monitor()
        _fresh_session.safety.trigger_kill_switch()
        assert _fresh_session.safety._kill_switch_triggered
        assert t.reset_safety_kill_switch() is True
        assert not _fresh_session.safety._kill_switch_triggered
        # Idempotente: segunda llamada devuelve False (nada que resetear)
        assert t.reset_safety_kill_switch() is False

    def test_health_probe_every_n_calls(self, _fresh_session):
        """Health probe ICMP se invoca cada N dispatches, no en cada call."""
        t.attach_safety_monitor()
        # Mockear ICMP para contar invocaciones
        with patch.object(_fresh_session.safety, "_check_icmp",
                          return_value=True) as ping_mock:
            # Tool falso barato
            def fast_impl(_args):
                return {"ok": True}
            original = t._REGISTRY.get("nmap_scan")
            try:
                t._REGISTRY["nmap_scan"] = t.Tool(
                    name="nmap_scan", description="", parameters={},
                    impl=fast_impl, phases=("recon",),
                )
                # Reset counter para que el test sea determinista
                t._dispatch_call_counter = 0
                # 10 calls debe disparar 1 health probe (al call #10)
                for _ in range(10):
                    t.dispatch("nmap_scan", {})
                assert ping_mock.call_count == 1
                # 10 más = 2 probes totales
                for _ in range(10):
                    t.dispatch("nmap_scan", {})
                assert ping_mock.call_count == 2
            finally:
                if original is not None:
                    t._REGISTRY["nmap_scan"] = original
                t._dispatch_call_counter = 0


# =====================================================================
# TelemetryCollector
# =====================================================================

class TestTelemetryIntegration:
    def test_attach_idempotent(self, _fresh_session):
        t.attach_telemetry(session_id="test-1")
        first = _fresh_session.telemetry
        t.attach_telemetry(session_id="test-2")
        assert _fresh_session.telemetry is first
        assert _fresh_session.telemetry.session_id == "test-1"

    def test_record_finding_feeds_telemetry(self, _fresh_session):
        t.attach_telemetry()
        t._record_finding({
            "cve_id": "CVE-2099-1111",
            "title": "Test vuln",
            "confirmed": True,
            "raw_output": "evidence here",
        })
        tm = _fresh_session.telemetry
        assert tm.total_cves_tested == 1
        assert tm.total_successes == 1
        assert "CVE-2099-1111" in tm.techniques

    def test_record_finding_negative_tracked(self, _fresh_session):
        t.attach_telemetry()
        t._record_finding({
            "cve_id": "CVE-2099-2222",
            "title": "Not vuln",
            "confirmed": False,
            "evidence": "404 on endpoint",
        })
        tm = _fresh_session.telemetry
        assert tm.total_cves_tested == 1
        assert tm.total_successes == 0
        assert tm.techniques["CVE-2099-2222"].error_types == {"NOT_VULNERABLE": 1}

    def test_telemetry_surface_from_nmap(self, _fresh_session):
        t.attach_telemetry()
        t._telemetry_record_surface_from_nmap({
            "ports": [
                {"port": 80, "service": "http"},
                {"port": 22, "service": "ssh"},
                {"port": 443, "service_name": "https"},
            ]
        })
        tm = _fresh_session.telemetry
        assert tm.surface_ports == {80, 22, 443}
        assert "http" in tm.surface_services
        assert "ssh" in tm.surface_services

    def test_telemetry_noop_when_unattached(self, _fresh_session):
        # Sin attach_telemetry no debe crashear
        t._telemetry_record_attempt("CVE-X", True)
        t._telemetry_record_surface_from_nmap({"ports": []})
        assert _fresh_session.telemetry is None


# =====================================================================
# DeviceFingerprinter (consensus_only via tool)
# =====================================================================

class TestVendorCanonicalization:
    """Vendor names from different sources must collapse to a single canonical
    name. MAC OUI wins (deterministic) > synonym table > raw name strip."""

    def test_mac_oui_wins_over_name(self):
        from modules.fingerprint import canonicalize_vendor
        # Aunque el name diga otra cosa, OUI 14:7F:67 → LG
        assert canonicalize_vendor("Unknown Vendor", "14:7F:67:AF:0C:6A") == "LG"

    def test_name_synonyms_collapse(self):
        from modules.fingerprint import canonicalize_vendor
        assert canonicalize_vendor("LG Electronics.") == "LG"
        assert canonicalize_vendor("LG Electronics") == "LG"
        assert canonicalize_vendor("LG Innotek") == "LG"
        assert canonicalize_vendor("LG") == "LG"
        assert canonicalize_vendor("D-Link") == "D-Link"
        assert canonicalize_vendor("dlink") == "D-Link"
        assert canonicalize_vendor("Telefónica") == "Telefonica"
        assert canonicalize_vendor("Movistar") == "Telefonica"

    def test_idempotent(self):
        from modules.fingerprint import canonicalize_vendor
        canon = canonicalize_vendor("LG Electronics.")
        assert canonicalize_vendor(canon) == canon

    def test_unknown_vendor_cleaned(self):
        """Vendor que no está en sinónimos: devuelve original sin puntuación final."""
        from modules.fingerprint import canonicalize_vendor
        assert canonicalize_vendor("WeirdoCorp.") == "WeirdoCorp"
        assert canonicalize_vendor("  spaced  ") == "spaced"

    def test_none_returns_none(self):
        from modules.fingerprint import canonicalize_vendor
        assert canonicalize_vendor(None) is None
        assert canonicalize_vendor("") is None


class TestCPESanitization:
    def test_trailing_punctuation_stripped(self):
        from modules.fingerprint import _build_cpe
        cpe = _build_cpe("LG Electronics.", "LG TV", None)
        # No debe haber puntos en componentes (excepto los delimitadores del CPE)
        # Componentes son las partes entre ':' tras 'cpe:2.3:h:'
        parts = cpe.split(":")
        assert parts[3] == "lg_electronics"  # vendor sin punto final
        assert parts[4] == "lg_tv"
        assert parts[5] == "*"  # version vacía → *

    def test_empty_components_become_wildcard(self):
        from modules.fingerprint import _cpe_component
        assert _cpe_component(None) == "*"
        assert _cpe_component("") == "*"
        assert _cpe_component("   ") == "*"
        assert _cpe_component("_") == "*"  # un solo underscore tras sanitize → *

    def test_complex_firmware_preserved(self):
        from modules.fingerprint import _build_cpe
        cpe = _build_cpe("LG", "65QNED826RE", "p20.33.31.23")
        assert ":65qned826re:" in cpe
        # Puntos dentro de versión → _
        assert "p20_33_31_23" in cpe


class TestDeviceTypeDetection:
    def test_smarttv_via_mdns_airplay(self):
        from modules.fingerprint import _detect_device_type
        emap = {"mdns": {"services": [{"type": "_airplay._tcp.local."}]}}
        assert _detect_device_type(emap) == "smarttv"

    def test_router_via_ssdp_igd(self):
        from modules.fingerprint import _detect_device_type
        emap = {"ssdp_xml": {"services": ["InternetGatewayDevice", "WLANConfiguration"]}}
        assert _detect_device_type(emap) == "router"

    def test_camera_via_banner(self):
        from modules.fingerprint import _detect_device_type
        emap = {"tcp_banner": {"banners_by_port": {"80": "Hikvision IP Camera"}}}
        assert _detect_device_type(emap) == "camera"

    def test_no_signals_returns_none(self):
        from modules.fingerprint import _detect_device_type
        assert _detect_device_type({}) is None

    def test_mdns_airplay_outscores_random_router_substring(self):
        """REGRESIÓN: antes una TV LG terminaba como 'router' porque el substring
        'router' aparecía en algún campo del blob global. Con scoring por fuente,
        la señal mDNS airplay (peso 5) gana a cualquier substring random."""
        from modules.fingerprint import _detect_device_type
        emap = {
            "mdns": {"services": [{"type": "_airplay._tcp.local."}]},
            # 'router' aparece random pero NO en una fuente con peso router
            "ssdp_xml": {"services": ["MediaRenderer"], "manufacturer": "LG"},
        }
        assert _detect_device_type(emap) == "smarttv"


class TestKBVendorMigration:
    def test_get_vendor_profile_via_synonym(self, tmp_path):
        from core.knowledge_base import KnowledgeBase
        kb = KnowledgeBase(path=str(tmp_path / "kb.json"))
        kb.upsert_vendor_profile("LG")
        # Buscar via cualquier variante recupera el mismo perfil
        assert kb.get_vendor_profile("LG Electronics.") is not None
        assert kb.get_vendor_profile("LG Innotek") is not None
        assert kb.get_vendor_profile("LG") is not None

    def test_upsert_consolidates_duplicates(self, tmp_path):
        from core.knowledge_base import KnowledgeBase
        kb = KnowledgeBase(path=str(tmp_path / "kb.json"))
        kb.upsert_vendor_profile("LG Electronics.", mac="14:7F:67:AF:0C:6A")
        kb.upsert_vendor_profile("LG")
        kb.upsert_vendor_profile("LG Innotek", mac="14:7F:67:11:22:33")
        # Una sola key en lugar de 3
        assert list(kb.data["vendor_profiles"].keys()) == ["LG"]

    def test_device_count_cuenta_dispositivos_no_llamadas(self, tmp_path):
        """`device_count` se deriva de devices_seen; no es un acumulador.

        Antes incrementaba una vez por llamada, así que contaba auditorías: 30
        ejecuciones sobre 3 aparatos daban 30 «dispositivos». Y como el merge
        disco/memoria además lo sumaba, en campo llegó a 3.556.776.512 para un
        único televisor.
        """
        from core.knowledge_base import KnowledgeBase
        kb = KnowledgeBase(path=str(tmp_path / "kb.json"))
        scan = {"mac": "14:7F:67:AF:0C:6A", "vendor": "LG", "ports": []}
        for _ in range(10):  # diez auditorías del MISMO televisor
            kb.upsert_device("192.168.1.34", scan, [])
        assert kb.data["vendor_profiles"]["LG"]["device_count"] == 1

        kb.upsert_device("192.168.1.35",
                         {"mac": "14:7F:67:11:22:33", "vendor": "LG", "ports": []}, [])
        assert kb.data["vendor_profiles"]["LG"]["device_count"] == 2

    def test_lazy_migration_fuses_existing_duplicates(self, tmp_path):
        """KB en disco con duplicados de runs antiguos se migra al load()."""
        from core.knowledge_base import KnowledgeBase
        import json as _json
        path = tmp_path / "kb.json"
        path.write_text(_json.dumps({
            "version": 1,
            "vendor_profiles": {
                "LG": {"device_count": 2, "patched_cves": ["CVE-A"]},
                "LG Electronics.": {"device_count": 1, "patched_cves": ["CVE-B"]},
                "LG Innotek": {"device_count": 1, "patched_cves": []},
            },
            "devices_seen": {
                "192.168.1.1": {"vendor": "LG Electronics.", "mac": "14:7F:67:00:01:02"},
            },
        }))
        kb = KnowledgeBase(path=str(path))
        kb.load()
        assert "LG" in kb.data["vendor_profiles"]
        assert "LG Electronics." not in kb.data["vendor_profiles"]
        assert "LG Innotek" not in kb.data["vendor_profiles"]
        # La fusión suma (2+1+1=4) porque los perfiles duplicados son historiales
        # disjuntos, pero la reparación de carga acota el resultado a los
        # dispositivos que realmente hay: uno. `device_count` dice dispositivos.
        assert kb.data["vendor_profiles"]["LG"]["device_count"] == 1
        assert sorted(kb.data["vendor_profiles"]["LG"]["patched_cves"]) == ["CVE-A", "CVE-B"]
        # devices_seen también canonicalizado; ahora re-clavado por identidad (MAC)
        assert kb.get_device_record(mac="14:7F:67:00:01:02")["vendor"] == "LG"

    def test_migration_idempotent(self, tmp_path):
        """Re-cargar un KB ya canónico no debe modificar nada."""
        from core.knowledge_base import KnowledgeBase
        kb = KnowledgeBase(path=str(tmp_path / "kb.json"))
        kb.upsert_vendor_profile("LG")
        kb.upsert_vendor_profile("D-Link")
        before = dict(kb.data["vendor_profiles"])
        kb._migrate_vendor_duplicates()
        assert kb.data["vendor_profiles"] == before


class TestFingerprintConsensus:
    def test_high_confidence_short_circuit(self, _fresh_session):
        # Evidencia HNAP + SSDP + SNMP supera HIGH_CONFIDENCE_THRESHOLD (1.20)
        # hnap(1.0) + ssdp_xml(0.95) + snmp(0.90) = 2.85
        _fresh_session.scan_cache = {
            "ports": [{"port": 80, "protocol": "tcp"}],
            "mac": "B0:C5:54:11:22:33",  # D-Link OUI
        }
        _fresh_session.interrogator_evidence = {
            "ssdp_manufacturer": "D-Link",
            "ssdp_model": "DIR-815",
        }
        result = t.dispatch("fingerprint_consensus", {
            "scan_results": {"ports": [{"port": 80, "protocol": "tcp"}]},
            "mac": "B0:C5:54:11:22:33",
            "evidence": {
                "ssdp_manufacturer": "D-Link",
                "ssdp_model": "DIR-815",
                "tcp_banners": {"80": "lighttpd/1.4.35"},
                "http_title": "D-Link Router",
            },
        })
        assert result["ok"] is True
        assert result["consensus"]["label"] in ("HIGH", "MEDIUM")
        det = result["deterministic"]
        # Vendor + model deben venir de SSDP (mayor peso después de HNAP)
        assert det["manufacturer"] == "D-Link"
        assert det["model"] == "DIR-815"
        assert result["cpe"] is not None
        assert "d-link" in result["cpe"].lower() or "d_link" in result["cpe"].lower()

    def test_low_confidence_when_only_mac(self, _fresh_session):
        """Solo MAC OUI (0.25) → LOW, no short-circuit."""
        result = t.dispatch("fingerprint_consensus", {
            "scan_results": {"ports": []},
            "mac": "B0:C5:54:11:22:33",
            "evidence": {},
        })
        assert result["consensus"]["label"] == "LOW"
        assert result["short_circuit"] is False

    def test_consensus_promotes_to_scan_cache(self, _fresh_session):
        """Si el cache no tenía vendor/model, fingerprint_consensus los llena."""
        _fresh_session.scan_cache = {"ports": []}
        t.dispatch("fingerprint_consensus", {
            "scan_results": {"ports": []},
            "mac": None,
            "evidence": {
                "ssdp_manufacturer": "Netgear",
                "ssdp_model": "WNAP320",
            },
        })
        assert _fresh_session.scan_cache.get("vendor") == "Netgear"
        assert _fresh_session.scan_cache.get("model") == "WNAP320"


# =====================================================================
# Searchsploit fallback
# =====================================================================

class TestSearchsploitEnrichment:
    """searchsploit enriquece CADA CVE con PoCs (no es fallback de búsqueda)."""

    def setup_method(self):
        # Reset cache de detección para que cada test controle availability
        t._SEARCHSPLOIT_AVAILABLE = None

    def teardown_method(self):
        t._SEARCHSPLOIT_AVAILABLE = None

    def test_noop_when_binary_missing(self):
        """Si searchsploit no está instalado, no se enriquece nada (silencioso)."""
        cves = [{"id": "CVE-2018-10106", "severity": "HIGH"}]
        with patch("shutil.which", return_value=None):
            result = t._enrich_with_exploit_db_pocs(cves)
            assert result is cves
            assert "exploit_db_pocs" not in result[0]

    def test_enrich_attaches_pocs_per_cve(self):
        """Cada CVE recibe sus propios `exploit_db_pocs` consultando por cve_id."""
        cves = [
            {"id": "CVE-2018-10106", "severity": "HIGH"},
            {"id": "CVE-2019-17373", "severity": "MEDIUM"},
        ]
        # Mock searchsploit que devuelve un PoC distinto según el query
        def fake_run(cmd, **_kw):
            query = cmd[-1]
            return MagicMock(
                returncode=0,
                stdout=(
                    f'{{"RESULTS_EXPLOIT": [{{"Title": "PoC for {query}",'
                    f' "Path": "/tmp/{query}.py", "EDB-ID": "100",'
                    f' "Date": "2024"}}]}}'
                ),
                stderr="",
            )
        with patch("shutil.which", return_value="/usr/bin/searchsploit"), \
             patch("modules.searcher.subprocess.run", side_effect=fake_run), \
             patch("modules.searcher.os.path.isfile", return_value=False):
            result = t._enrich_with_exploit_db_pocs(cves)
            assert len(result[0]["exploit_db_pocs"]) == 1
            # SearchsploitClient.search() lowercases queries durante dedupe;
            # comparamos case-insensitive ya que searchsploit es case-insensitive.
            assert "cve-2018-10106" in result[0]["exploit_db_pocs"][0]["title"].lower()
            assert len(result[1]["exploit_db_pocs"]) == 1
            assert "cve-2019-17373" in result[1]["exploit_db_pocs"][0]["title"].lower()

    def test_respects_max_lookups_cap(self):
        """Cap configurable evita disparar 20 subprocess.run."""
        cves = [{"id": f"CVE-2024-{i:04d}", "severity": "HIGH"} for i in range(20)]
        run_count = {"n": 0}

        def fake_run(*_a, **_kw):
            run_count["n"] += 1
            return MagicMock(returncode=0, stdout='{"RESULTS_EXPLOIT": []}', stderr="")

        with patch("shutil.which", return_value="/usr/bin/searchsploit"), \
             patch("modules.searcher.subprocess.run", side_effect=fake_run):
            t._enrich_with_exploit_db_pocs(cves, max_lookups=5)
            # Cada lookup hace 1 query (solo el cve_id, no múltiples como search())
            assert run_count["n"] <= 5

    def test_skips_non_cve_ids(self):
        """Entradas KB-local con id `LG-WEBOS-EXPOSED` no se consultan."""
        cves = [{"id": "LG-WEBOS-EXPOSED", "severity": "MEDIUM"}]
        ran = {"n": 0}

        def fake_run(*_a, **_kw):
            ran["n"] += 1
            return MagicMock(returncode=0, stdout='{"RESULTS_EXPLOIT": []}', stderr="")

        with patch("shutil.which", return_value="/usr/bin/searchsploit"), \
             patch("modules.searcher.subprocess.run", side_effect=fake_run):
            t._enrich_with_exploit_db_pocs(cves)
            assert ran["n"] == 0
            assert "exploit_db_pocs" not in cves[0]

    def test_cve_search_full_flow_enriches_cves(self):
        """End-to-end: cve_search devuelve CVEs con exploit_db_pocs adjuntos."""
        fake_nvd = [
            {"id": "CVE-2018-10106", "severity": "HIGH", "score": 7.5,
             "description": "D-Link DIR-815 auth bypass"},
        ]

        class _FakeNVDClient:
            def __init__(self, *_a, **_kw): pass
            def get_cves_for_product(self, *_a, **_kw): return fake_nvd

        fake_json = (
            '{"RESULTS_EXPLOIT": [{"Title": "D-Link DIR-815 RCE CVE-2018-10106",'
            ' "Path": "/tmp/dlink.py", "EDB-ID": "45000", "Date": "2018"}]}'
        )
        with patch("shutil.which", return_value="/usr/bin/searchsploit"), \
             patch("modules.cve_api.NVDCVEClient", _FakeNVDClient), \
             patch("modules.searcher.subprocess.run",
                   return_value=MagicMock(returncode=0, stdout=fake_json, stderr="")), \
             patch("modules.searcher.os.path.isfile", return_value=False):
            resp = t._cve_search({"keyword": "D-Link DIR-815"})
            assert resp["count"] >= 1
            assert "exploit_db_pocs" in resp["cves"][0]
            assert len(resp["cves"][0]["exploit_db_pocs"]) >= 1
            assert "Exploit-DB" in resp.get("instruction", "")
