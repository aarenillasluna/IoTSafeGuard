"""
Tests del bucle de auto-mejora — KB persistente + reflection report.

Cubre:
  - KnowledgeBase: load/save atómico, schema versioning, queries, updates.
  - Reflection: JSON parsing tolerante, render markdown, persistencia.
  - Integración: agent loop carga KB al inicio, persiste al final.
  - recommend_probes consume KB context si target/vendor conocidos.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core import tools as toolbox
from core.knowledge_base import (
    KB_SCHEMA_VERSION,
    KnowledgeBase,
    get_kb,
    reset_kb_singleton,
)
from core.reflection import (
    ReflectionReport,
    _extract_json_block,
    _render_markdown,
    apply_reflection_to_kb,
    persist_reflection,
)


@pytest.fixture
def kb_tmp(tmp_path):
    """KB con archivo temporal aislado por test."""
    path = tmp_path / "kb.json"
    kb = KnowledgeBase(path=str(path))
    kb.load()
    yield kb


# ============================================================================
# KnowledgeBase
# ============================================================================
class TestKnowledgeBaseBasics:

    def test_empty_load_creates_default_schema(self, kb_tmp):
        assert kb_tmp.data["version"] == KB_SCHEMA_VERSION
        assert kb_tmp.data["devices_seen"] == {}
        assert kb_tmp.data["vendor_profiles"] == {}
        assert kb_tmp.data["global_stats"]["runs_total"] == 0

    def test_save_and_reload_roundtrip(self, tmp_path):
        path = str(tmp_path / "kb.json")
        kb = KnowledgeBase(path=path)
        kb.load()
        kb.upsert_device("10.0.0.1", {"vendor": "X", "model": "Y"}, [])
        kb.save()
        assert os.path.isfile(path)

        kb2 = KnowledgeBase(path=path)
        kb2.load()
        # devices_seen se clava por identidad; sin MAC la clave es ip:<ip>.
        rec = kb2.get_device_record("10.0.0.1")
        assert rec is not None and rec["vendor"] == "X"

    def test_schema_mismatch_resets_to_empty(self, tmp_path):
        path = str(tmp_path / "kb.json")
        # Escribir KB con version incorrecta
        with open(path, "w") as f:
            json.dump({"version": 999, "devices_seen": {"1.2.3.4": "fake"}}, f)
        kb = KnowledgeBase(path=path)
        kb.load()
        # Como versión no coincide, debe partir vacío
        assert kb.data["devices_seen"] == {}

    def test_corrupted_json_falls_back_to_empty(self, tmp_path):
        path = str(tmp_path / "kb.json")
        with open(path, "w") as f:
            f.write("not valid json {{{")
        kb = KnowledgeBase(path=path)
        kb.load()
        assert kb.data["devices_seen"] == {}

    def test_atomic_save_does_not_leave_partial_files(self, kb_tmp, tmp_path):
        kb_tmp.upsert_device("10.0.0.1", {"vendor": "X"}, [])
        kb_tmp.save()
        # No debe quedar archivo .tmp residual
        leftovers = [f for f in os.listdir(tmp_path) if f.endswith(".tmp")]
        assert leftovers == []


class TestKnowledgeBaseQueries:

    def test_get_device_returns_record(self, kb_tmp):
        kb_tmp.upsert_device("1.2.3.4", {"vendor": "Foo"}, [])
        rec = kb_tmp.get_device_record("1.2.3.4")
        assert rec is not None
        assert rec["vendor"] == "Foo"
        assert rec["audit_count"] == 1

    def test_get_unknown_device_returns_none(self, kb_tmp):
        assert kb_tmp.get_device_record("9.9.9.9") is None

    def test_audit_count_increments(self, kb_tmp):
        # Tres AUDITORÍAS, no tres llamadas: el contador cuenta ejecuciones.
        for i in range(3):
            kb_tmp.upsert_device("1.2.3.4", {"vendor": "X"}, [], run_id=f"run-{i}")
        assert kb_tmp.get_device_record("1.2.3.4")["audit_count"] == 3

    def test_first_seen_preserved_across_audits(self, kb_tmp):
        kb_tmp.upsert_device("1.2.3.4", {"vendor": "X"}, [])
        first_seen = kb_tmp.get_device_record("1.2.3.4")["first_seen"]
        kb_tmp.upsert_device("1.2.3.4", {"vendor": "X"}, [])
        assert kb_tmp.get_device_record("1.2.3.4")["first_seen"] == first_seen


class TestVendorProfile:

    def test_upsert_vendor_creates_profile(self, kb_tmp):
        kb_tmp.upsert_vendor_profile("LG",
                                     ports_seen=[3001, 8008],
                                     useful_probes=["probe_lg_webos"])
        p = kb_tmp.get_vendor_profile("LG")
        assert p is not None
        assert 3001 in p["common_ports"]
        assert "probe_lg_webos" in p["useful_probes"]

    def test_upsert_merges_unique_values(self, kb_tmp):
        kb_tmp.upsert_vendor_profile("LG", ports_seen=[3001, 8008])
        kb_tmp.upsert_vendor_profile("LG", ports_seen=[8008, 7000])  # 8008 duplicate
        p = kb_tmp.get_vendor_profile("LG")
        assert p["common_ports"] == [3001, 8008, 7000]  # sin duplicados

    def test_device_count_no_es_un_contador_de_llamadas(self, kb_tmp):
        """Repetir el upsert del mismo fabricante no inventa dispositivos.

        Incrementar por llamada convertía `device_count` en un contador de
        auditorías, y el merge disco/memoria lo sumaba encima: en campo, 30
        ejecuciones sobre un televisor dieron 3.556.776.512.
        """
        for _ in range(3):
            kb_tmp.upsert_vendor_profile("LG")
        assert kb_tmp.get_vendor_profile("LG")["device_count"] == 1

    def test_upsert_device_auto_creates_vendor_profile(self, kb_tmp):
        """Bug regresión: upsert_device con vendor nuevo debe auto-crear vendor_profile."""
        kb_tmp.upsert_device("1.2.3.4", {
            "vendor": "Netgear",
            "model": "WNR2000v5",
            "ports": [{"port": 80, "proto": "tcp"}, {"port": 22, "proto": "tcp"}],
        }, [])
        profile = kb_tmp.get_vendor_profile("Netgear")
        assert profile is not None, "Vendor profile should be auto-created"
        assert 80 in profile["common_ports"]
        assert 22 in profile["common_ports"]

    def test_upsert_device_known_vendor_no_duplicate_profile(self, kb_tmp):
        """Si vendor_profile ya existe, upsert_device no crea uno nuevo."""
        kb_tmp.upsert_vendor_profile("LG", ports_seen=[3001])
        kb_tmp.upsert_device("1.2.3.4", {"vendor": "LG"}, [])
        kb_tmp.upsert_device("1.2.3.5", {"vendor": "LG"}, [])
        profile = kb_tmp.get_vendor_profile("LG")
        # device_count solo sube por upsert_vendor_profile directo
        assert profile is not None


class TestCVEHistory:

    def test_record_cve_test_creates_history(self, kb_tmp):
        kb_tmp.record_cve_test("CVE-2023-X", confirmed=False, vendor="LG")
        h = kb_tmp.get_cve_history("CVE-2023-X")
        assert h is not None
        assert h["tested_n_times"] == 1
        assert h["confirmed_count"] == 0
        assert "LG" in h["vendors_tested"]

    def test_three_unconfirmed_propagates_to_vendor_patched(self, kb_tmp):
        for _ in range(3):
            kb_tmp.record_cve_test("CVE-X", confirmed=False, vendor="LG")
        # Tras 3 intentos confirmed=False → propagado a vendor.patched_cves
        profile = kb_tmp.get_vendor_profile("LG")
        assert "CVE-X" in profile["patched_cves"]

    def test_one_confirmed_does_not_mark_patched(self, kb_tmp):
        kb_tmp.record_cve_test("CVE-X", confirmed=True, vendor="LG")
        kb_tmp.record_cve_test("CVE-X", confirmed=False, vendor="LG")
        kb_tmp.record_cve_test("CVE-X", confirmed=False, vendor="LG")
        # Como hubo 1 confirmed=True, NO se propaga a patched_cves del vendor
        # (puede que el vendor profile ni exista si nunca tuvo 3 unconfirmed)
        profile = kb_tmp.get_vendor_profile("LG") or {}
        assert "CVE-X" not in profile.get("patched_cves", [])

    def test_is_consistently_patched_threshold(self, kb_tmp):
        kb_tmp.record_cve_test("CVE-X", confirmed=False, vendor="LG")
        kb_tmp.record_cve_test("CVE-X", confirmed=False, vendor="LG")
        # 2 unconfirmed = threshold default
        assert kb_tmp.is_cve_consistently_patched("CVE-X", threshold=2) is True
        assert kb_tmp.is_cve_consistently_patched("CVE-X", threshold=5) is False


class TestKBSingleton:

    def test_get_kb_returns_singleton(self, tmp_path):
        reset_kb_singleton()
        os.environ["KB_PATH"] = str(tmp_path / "kb.json")
        try:
            a = get_kb()
            b = get_kb()
            assert a is b
        finally:
            os.environ.pop("KB_PATH", None)
            reset_kb_singleton()


# ============================================================================
# Reflection
# ============================================================================
class TestJsonExtraction:

    def test_extract_from_clean_json(self):
        parsed = _extract_json_block('{"executive_summary":"ok"}')
        assert parsed["executive_summary"] == "ok"

    def test_extract_from_markdown_fence(self):
        text = 'Analysis:\n```json\n{"executive_summary":"good"}\n```\nDone'
        parsed = _extract_json_block(text)
        assert parsed["executive_summary"] == "good"

    def test_extract_from_text_with_prefix(self):
        text = 'Here is the result: {"executive_summary":"ok","what_failed":[]}'
        parsed = _extract_json_block(text)
        assert parsed["executive_summary"] == "ok"

    def test_no_json_returns_none(self):
        assert _extract_json_block("just text without braces") is None

    def test_malformed_json_returns_none(self):
        assert _extract_json_block("{invalid json here") is None

    def test_truncated_in_string_value_recovers(self):
        """Truncation real observada: response cortado a mitad de string value.

        Caso visto en runs reales: max_output_tokens corta el JSON dejando
        una string sin cerrar y braces pendientes. El parser debe cerrar
        el string + balancear contenedores.
        """
        truncated = (
            '{"executive_summary": "Run completed but with several '
            'issues observed during the recon ph'
        )
        parsed = _extract_json_block(truncated)
        assert parsed is not None
        assert parsed["executive_summary"].startswith("Run completed")

    def test_truncated_inside_array_recovers(self):
        truncated = (
            '{"what_worked": ["nmap detected ports", "probe_dial confirmed", '
            '"third item incomp'
        )
        parsed = _extract_json_block(truncated)
        assert parsed is not None
        assert "what_worked" in parsed
        assert len(parsed["what_worked"]) >= 2

    def test_truncated_with_trailing_comma_recovers(self):
        truncated = '{"a": 1, "b": 2,'
        parsed = _extract_json_block(truncated)
        assert parsed is not None
        assert parsed["a"] == 1
        assert parsed["b"] == 2


class TestReflectionRender:

    def test_render_markdown_includes_all_sections(self):
        report = ReflectionReport(
            raw={
                "executive_summary": "All probes ran",
                "what_worked": ["nmap detected ports", "probe_dial confirmed"],
                "what_failed": ["CVE-X failed validation"],
                "gaps_detected": ["AirPlay not auth-tested"],
                "suggested_improvements": [
                    {"priority": "high", "area": "probes",
                     "description": "add airplay auth"},
                ],
                "new_pocs_to_add": [],
                "kb_updates_proposed": {
                    "patched_cves_to_record": ["CVE-X"],
                },
            },
            target_ip="1.2.3.4",
            timestamp="20260510_120000",
        )
        md = _render_markdown(report)
        assert "Executive Summary" in md
        assert "All probes ran" in md
        assert "What Worked" in md
        assert "nmap detected" in md
        assert "[HIGH]" in md
        assert "CVE-X" in md

    def test_render_skips_empty_sections(self):
        report = ReflectionReport(
            raw={"executive_summary": "ok"},
            target_ip="1.2.3.4",
            timestamp="ts",
        )
        md = _render_markdown(report)
        assert "What Worked" not in md
        assert "Executive Summary" in md


class TestReflectionPersist:

    def test_persist_writes_json_and_md(self, tmp_path):
        report = ReflectionReport(
            raw={"executive_summary": "test"},
            target_ip="1.2.3.4",
            timestamp="20260510_120000",
        )
        persist_reflection(report, reflections_dir=str(tmp_path))
        assert report.json_path is not None
        assert report.md_path is not None
        assert os.path.isfile(report.json_path)
        assert os.path.isfile(report.md_path)
        with open(report.json_path) as f:
            data = json.load(f)
        assert data["executive_summary"] == "test"


class TestApplyReflectionToKB:

    def test_apply_propagates_kb_updates(self, kb_tmp):
        report = ReflectionReport(
            raw={
                "executive_summary": "ok",
                "kb_updates_proposed": {
                    "patched_cves_to_record": ["CVE-Y"],
                    # Nombre real del registro: lo que no existe se descarta,
                    # ver `test_reflection_no_puede_inventar_probes`.
                    "useful_probes_for_vendor": ["probe_snmp"],
                    "fingerprint_markers": ["MARKER1"],
                },
            },
            target_ip="1.2.3.4",
            timestamp="ts",
            json_path="/tmp/test.json",
        )
        apply_reflection_to_kb(report, kb_tmp, vendor="TestVendor")
        profile = kb_tmp.get_vendor_profile("TestVendor")
        assert profile is not None
        assert "CVE-Y" in profile["patched_cves"]
        assert "probe_snmp" in profile["useful_probes"]
        assert "MARKER1" in profile["fingerprint_markers"]
        # Reflection log también actualizado
        assert any(r["path"] == "/tmp/test.json"
                   for r in kb_tmp.data["reflection_log"])

    def test_reflection_no_puede_inventar_probes(self, kb_tmp):
        """El JSON de reflexión es texto libre; la KB solo guarda lo que existe.

        `useful_probes` vuelve al prompt del siguiente run como «probes que
        históricamente funcionaron con este fabricante». En 15 ejecuciones
        reales, 29 de 66 nombres aprendidos no correspondían a ninguna
        herramienta —incluidas frases enteras en español, como
        `"probe_upnp_igd especialmente relevante para CURVE25519"`—, así que la
        KB se dedicaba a realimentar alucinaciones.
        """
        report = ReflectionReport(
            raw={
                "executive_summary": "ok",
                "kb_updates_proposed": {
                    "useful_probes_for_vendor": [
                        "probe_snmp",                       # existe
                        "probe_alexa_api",                  # inventada
                        "probe_ssh con credenciales_askey",  # frase, no nombre
                    ],
                },
            },
            target_ip="1.2.3.4",
            timestamp="ts",
            json_path="/tmp/test.json",
        )
        apply_reflection_to_kb(report, kb_tmp, vendor="TestVendor")
        assert kb_tmp.get_vendor_profile("TestVendor")["useful_probes"] == ["probe_snmp"]

    def test_apply_without_vendor_only_logs_path(self, kb_tmp):
        report = ReflectionReport(
            raw={"executive_summary": "ok",
                 "kb_updates_proposed": {"patched_cves_to_record": ["CVE-Z"]}},
            target_ip="1.2.3.4",
            timestamp="ts",
            json_path="/tmp/x.json",
        )
        apply_reflection_to_kb(report, kb_tmp, vendor=None)
        # Sin vendor, no se aplica nada al perfil
        assert kb_tmp.data["vendor_profiles"] == {}


# ============================================================================
# recommend_probes consume KB context
# ============================================================================
class TestSNMPProbeAcceptsCommunities:
    """Regression test: probe_snmp wrapper tenía bug donde pasaba `communities`
    a una función que no lo aceptaba. Verifica que la firma esté alineada."""

    def test_snmp_probe_function_accepts_communities_kwarg(self):
        from modules.snmp_probe import snmp_probe
        import inspect
        sig = inspect.signature(snmp_probe)
        assert "communities" in sig.parameters

    def test_snmp_probe_dispatch_with_communities_does_not_crash(self):
        toolbox.build_registry()
        toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))
        # IP inalcanzable + timeout corto: solo verificamos que NO crashee
        result = toolbox.dispatch("probe_snmp", {
            "ip": "127.0.0.1",
            "communities": ["public", "private", "admin"],
        })
        # No debe haber error de TypeError ni "raised TypeError"
        assert "raised" not in str(result.get("error", ""))


class TestRecommendProbesKBIntegration:

    def setup_method(self):
        reset_kb_singleton()
        toolbox.build_registry()
        toolbox.bind_session(toolbox.AgentSession(target_ip="1.2.3.4"))

    def teardown_method(self):
        reset_kb_singleton()
        os.environ.pop("KB_PATH", None)

    def test_known_target_adds_kb_context(self, tmp_path):
        # Pre-poblar KB con device + vendor profile
        kb_path = str(tmp_path / "kb.json")
        os.environ["KB_PATH"] = kb_path
        kb = get_kb(reload=True)
        kb.upsert_device("1.2.3.4", {"vendor": "LG", "model": "65X"}, [])
        kb.upsert_vendor_profile("LG",
                                 useful_probes=["probe_lg_webos", "probe_dial"],
                                 patched_cves=["CVE-OLD"])
        kb.save()

        r = toolbox.dispatch("recommend_probes", {
            "ports": [{"port": 3001, "proto": "tcp"}, {"port": 1664, "proto": "tcp"}],
        })
        assert "kb_context" in r
        ctx = r["kb_context"]
        assert ctx["previous_audit"]["vendor"] == "LG"
        assert ctx["vendor_profile"]["vendor"] == "LG"
        # Probes históricamente útiles deben subir a prioridad 0
        for rec in r["recommendations"]:
            if rec["probe"] in ("probe_lg_webos", "probe_dial"):
                assert rec["priority"] == 0
                assert "[KB:" in rec["reason"]

    def test_unknown_target_no_kb_context(self, tmp_path):
        os.environ["KB_PATH"] = str(tmp_path / "kb.json")
        get_kb(reload=True)  # KB vacío
        r = toolbox.dispatch("recommend_probes", {
            "ports": [{"port": 3001, "proto": "tcp"}],
        })
        # Sin KB context si no hay device previo
        assert "kb_context" not in r

    def test_patched_cves_warning_in_instruction(self, tmp_path):
        os.environ["KB_PATH"] = str(tmp_path / "kb.json")
        kb = get_kb(reload=True)
        kb.upsert_device("1.2.3.4", {"vendor": "LG"}, [])
        kb.upsert_vendor_profile("LG", patched_cves=["CVE-2023-6317"])
        kb.save()

        r = toolbox.dispatch("recommend_probes", {
            "ports": [{"port": 3001, "proto": "tcp"}],
        })
        assert "CVE-2023-6317" in r["instruction"]
        assert "patched" in r["instruction"]


class TestSaveReportDeviceIdentityFallback:
    """Regresión: si scan_cache no tiene model/firmware (p. ej. mDNS no devolvió
    nada este run), el reporte debe leer KB.devices_seen como fallback."""

    def setup_method(self):
        reset_kb_singleton()
        toolbox.build_registry()

    def teardown_method(self):
        reset_kb_singleton()
        os.environ.pop("KB_PATH", None)

    def test_device_identity_falls_back_to_kb_when_scan_cache_empty(self, tmp_path):
        # KB tiene model/firmware de run anterior
        kb_path = str(tmp_path / "kb.json")
        os.environ["KB_PATH"] = kb_path
        kb = get_kb(reload=True)
        kb.upsert_device("1.2.3.4", {
            "vendor": "LG",
            "model": "65QNED826RE",
            "firmware": "p20.33.31.23",
        }, [])
        kb.save()

        # Session SIN model/firmware en scan_cache (probe falló este run)
        session = toolbox.AgentSession(target_ip="1.2.3.4")
        session.scan_cache = {"ports": [], "os_match": "Linux"}
        toolbox.bind_session(session)

        out_dir = str(tmp_path / "reports")
        os.makedirs(out_dir, exist_ok=True)
        r = toolbox.dispatch("save_report", {"out_dir": out_dir})
        assert r.get("ok")

        # Leer el HTML generado y comprobar identidad
        html_files = [f for f in os.listdir(out_dir) if f.endswith(".html")]
        assert html_files
        with open(os.path.join(out_dir, html_files[0])) as f:
            html = f.read()
        # Model y firmware vinieron de KB porque scan_cache no los tenía
        assert "65QNED826RE" in html
        assert "p20.33.31.23" in html
        assert "<td>LG</td>" in html

    def test_scan_cache_takes_priority_over_kb(self, tmp_path):
        """Si scan_cache TIENE model fresco, no usar KB stale."""
        kb_path = str(tmp_path / "kb.json")
        os.environ["KB_PATH"] = kb_path
        kb = get_kb(reload=True)
        kb.upsert_device("1.2.3.4", {
            "vendor": "LG", "model": "OLD_MODEL", "firmware": "old_fw",
        }, [])
        kb.save()

        session = toolbox.AgentSession(target_ip="1.2.3.4")
        session.scan_cache = {
            "model": "NEW_MODEL", "firmware": "new_fw",
            "ports": [], "os_match": "Linux",
        }
        toolbox.bind_session(session)

        out_dir = str(tmp_path / "reports")
        os.makedirs(out_dir, exist_ok=True)
        toolbox.dispatch("save_report", {"out_dir": out_dir})

        html_files = [f for f in os.listdir(out_dir) if f.endswith(".html")]
        with open(os.path.join(out_dir, html_files[0])) as f:
            html = f.read()
        assert "NEW_MODEL" in html
        assert "OLD_MODEL" not in html

    def test_report_records_model_and_provider(self, tmp_path):
        """El JSON del informe debe atribuir el run a un modelo/proveedor concreto.

        Regresión: ai_plan llevaba el nombre del proveedor cableado y run_metadata iba vacío,
        haciendo indistinguibles los informes de proveedores distintos (OE3/§5.8).
        """
        kb_path = str(tmp_path / "kb.json")
        os.environ["KB_PATH"] = kb_path
        get_kb(reload=True)

        session = toolbox.AgentSession(target_ip="1.2.3.4")
        session.scan_cache = {"ports": [], "os_match": "Linux"}
        session.model_name = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
        session.provider = "Anthropic/Claude"
        toolbox.bind_session(session)

        out_dir = str(tmp_path / "reports")
        os.makedirs(out_dir, exist_ok=True)
        r = toolbox.dispatch("save_report", {"out_dir": out_dir})
        assert r.get("ok")

        json_files = [f for f in os.listdir(out_dir)
                      if f.endswith(".json") and "_risk" not in f and "_telemetry" not in f]
        assert json_files
        import json as _json
        with open(os.path.join(out_dir, json_files[0])) as f:
            data = _json.load(f)
        entry = data["findings"][0]
        meta = entry.get("run_metadata") or {}
        assert meta.get("model") == "us.anthropic.claude-haiku-4-5-20251001-v1:0"
        assert meta.get("provider") == "Anthropic/Claude"
        assert "hardcoded" not in (entry.get("ai_plan") or "").lower()
        assert "Anthropic/Claude" in (entry.get("ai_plan") or "")
        # Reproducibilidad (OE3): el informe lleva la revisión de código (clave
        # presente; el valor es el hash git o None fuera de un repo).
        assert "code_revision" in meta
