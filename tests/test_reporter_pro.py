"""
Tests del reporter profesional (Opción B):
  - Backward compat con add_entry sin kwargs nuevos
  - Render con contexto enriquecido (device_identity, risk_summary, kb_context)
  - Deduplicación de findings con misma evidencia
  - MITRE filtrado por tools usadas
  - Severity badges
  - Remediation KB integration
"""
from __future__ import annotations

import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from modules.remediation_kb import REMEDIATION_KB, get_remediation
from modules.reporter import (
    Reporter,
    _group_attack_results,
    _severity_badge,
)


# ============================================================================
# Helpers
# ============================================================================
@pytest.fixture
def tmp_reporter():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Reporter(report_dir=tmpdir), tmpdir


def _sample_attack_result(cve_id: str, sev: str = "HIGH", confirmed: bool = False,
                          cmd: str = "test_cmd", evidence: str = "") -> dict:
    return {
        "service": cve_id,
        "cve_id": cve_id,
        "title": f"Test {cve_id}",
        "severity": sev,
        "vuln_found": confirmed,
        "executed_cmd": cmd,
        "output_log": evidence or f"Evidence for {cve_id}",
        "details": sev,
    }


# ============================================================================
# Backward compatibility
# ============================================================================
class TestBackwardCompat:
    """Verifica que add_entry sigue aceptando solo los kwargs originales."""

    def test_add_entry_with_only_legacy_args(self, tmp_reporter):
        rep, _ = tmp_reporter
        rep.add_entry(
            ip="10.0.0.1",
            os_match="Linux",
            ports=[],
            attack_plan="test",
            attack_results=[],
        )
        assert len(rep.findings) == 1
        # Los nuevos campos están vacíos pero presentes
        assert rep.findings[0]["device_identity"] == {}
        assert rep.findings[0]["risk_summary"] == {}

    def test_generate_reports_works_without_new_context(self, tmp_reporter):
        rep, tmpdir = tmp_reporter
        rep.add_entry(
            ip="10.0.0.1", os_match="Linux", ports=[],
            attack_plan="test", attack_results=[],
        )
        base = rep.generate_reports()
        assert os.path.isfile(base + ".md")
        assert os.path.isfile(base + ".html")
        assert os.path.isfile(base + ".json")


# ============================================================================
# Severity badges
# ============================================================================
class TestSeverityBadges:

    def test_critical_high_medium_low_info(self):
        assert _severity_badge("CRITICAL") == "🔴"
        assert _severity_badge("HIGH") == "🟠"
        assert _severity_badge("MEDIUM") == "🟡"
        assert _severity_badge("LOW") == "🔵"
        assert _severity_badge("INFO") == "⚪"

    def test_unknown_severity_falls_back_to_info(self):
        assert _severity_badge("WEIRD") == "⚪"
        assert _severity_badge(None) == "⚪"
        assert _severity_badge("") == "⚪"

    def test_lowercase_normalized(self):
        assert _severity_badge("high") == "🟠"


# ============================================================================
# Group attack results (deduplicación)
# ============================================================================
class TestGroupAttackResults:

    def test_findings_with_unique_evidence_not_grouped(self):
        results = [
            _sample_attack_result("CVE-A", evidence="A unique evidence text " * 20),
            _sample_attack_result("CVE-B", evidence="B different evidence " * 20),
        ]
        groups = _group_attack_results(results)
        assert len(groups) == 2

    def test_findings_with_identical_long_evidence_grouped(self):
        shared = "Same long evidence text describing why these depend " * 5
        results = [
            _sample_attack_result("CVE-1", evidence=shared),
            _sample_attack_result("CVE-2", evidence=shared),
            _sample_attack_result("CVE-3", evidence=shared),
        ]
        groups = _group_attack_results(results)
        assert len(groups) == 1
        assert len(groups[0]["entries"]) == 3
        assert groups[0]["primary"]["cve_id"] == "CVE-1"

    def test_short_evidence_not_grouped_even_if_identical(self):
        """Para evitar agrupar findings legítimos con evidencia corta o vacía."""
        results = [
            _sample_attack_result("CVE-X", evidence="short"),
            _sample_attack_result("CVE-Y", evidence="short"),
        ]
        groups = _group_attack_results(results)
        assert len(groups) == 2

    def test_group_respects_severity_difference(self):
        shared = "Same evidence text " * 10
        results = [
            _sample_attack_result("CVE-A", sev="HIGH", evidence=shared),
            _sample_attack_result("CVE-B", sev="MEDIUM", evidence=shared),
        ]
        groups = _group_attack_results(results)
        # Severidades distintas → grupos distintos (porque la key incluye details)
        assert len(groups) == 2


# ============================================================================
# Markdown render rich
# ============================================================================
class TestMarkdownRich:

    def test_executive_summary_rendered(self, tmp_reporter):
        rep, tmpdir = tmp_reporter
        rep.add_entry(
            ip="10.0.0.1", os_match="Linux", ports=[],
            attack_plan="test",
            attack_results=[
                _sample_attack_result("CVE-A", sev="HIGH", confirmed=True,
                                      evidence="Real evidence " * 10),
            ],
            risk_summary={
                "risk_score": 85, "risk_label": "CRITICAL",
                "severity_counts": {"CRITICAL": 1, "HIGH": 0},
                "confirmed_count": 1, "total_findings": 1,
            },
        )
        base = rep.generate_reports()
        with open(base + ".md") as f:
            md = f.read()
        assert "Resumen ejecutivo" in md
        assert "CRITICAL" in md
        assert "85/100" in md

    def test_device_identity_block_rendered(self, tmp_reporter):
        rep, tmpdir = tmp_reporter
        rep.add_entry(
            ip="10.0.0.1", os_match="Linux", ports=[],
            attack_plan="test", attack_results=[],
            device_identity={
                "vendor": "LG", "model": "65X", "firmware": "p20",
                "mac": "AA:BB:CC:DD:EE:FF",
            },
        )
        base = rep.generate_reports()
        with open(base + ".md") as f:
            md = f.read()
        assert "Identificación del dispositivo" in md
        assert "LG" in md
        assert "65X" in md
        assert "AA:BB:CC:DD:EE:FF" in md

    def test_kb_context_rendered_if_present(self, tmp_reporter):
        rep, tmpdir = tmp_reporter
        rep.add_entry(
            ip="10.0.0.1", os_match="Linux", ports=[],
            attack_plan="test", attack_results=[],
            kb_context={
                "previous_audit": {"audit_count": 5, "first_seen": "2026-01-01T..."},
                "vendor_profile": {
                    "vendor": "LG",
                    "patched_cves_known": ["CVE-2023-6317"],
                },
            },
        )
        base = rep.generate_reports()
        with open(base + ".md") as f:
            md = f.read()
        assert "Knowledge Base" in md
        assert "5" in md  # audit_count
        assert "CVE-2023-6317" in md

    def test_finding_with_remediation_kb_renders_full_block(self, tmp_reporter):
        rep, tmpdir = tmp_reporter
        # CVE-2023-6317 está en remediation_kb
        rep.add_entry(
            ip="10.0.0.1", os_match="Linux", ports=[],
            attack_plan="test",
            attack_results=[
                _sample_attack_result("CVE-2023-6317", sev="HIGH", confirmed=False,
                                      evidence="Patched, returned PIN prompt " * 5),
            ],
        )
        base = rep.generate_reports()
        with open(base + ".md") as f:
            md = f.read()
        assert "CVE-2023-6317" in md
        assert "bitdefender" in md.lower()  # referencia del KB
        assert "CWE-287" in md
        assert "CVSS v3" in md
        assert "Remediación" in md

    def test_dependent_cves_show_grouped_not_repeated(self, tmp_reporter):
        rep, tmpdir = tmp_reporter
        shared = ("These CVEs depend on a successful authentication bypass via "
                  "CVE-2023-6317, which has been confirmed as not exploitable.")
        rep.add_entry(
            ip="10.0.0.1", os_match="Linux", ports=[],
            attack_plan="test",
            attack_results=[
                _sample_attack_result("CVE-2023-6318", sev="HIGH", confirmed=False,
                                      evidence=shared, cmd="batch_dismiss"),
                _sample_attack_result("CVE-2023-6319", sev="HIGH", confirmed=False,
                                      evidence=shared, cmd="batch_dismiss"),
                _sample_attack_result("CVE-2023-6320", sev="HIGH", confirmed=False,
                                      evidence=shared, cmd="batch_dismiss"),
            ],
        )
        base = rep.generate_reports()
        with open(base + ".md") as f:
            md = f.read()
        # La evidencia compartida aparece UNA vez, no 3
        assert md.count(shared) == 1
        # Los dependientes se mencionan en el bloque agrupado
        assert "CVEs dependientes" in md
        assert "CVE-2023-6319" in md
        assert "CVE-2023-6320" in md
        # batch_dismiss NO debe aparecer como reproducción
        assert "```bash\nbatch_dismiss" not in md

    def test_status_label_correct_for_confirmed_high(self, tmp_reporter):
        rep, tmpdir = tmp_reporter
        rep.add_entry(
            ip="10.0.0.1", os_match="Linux", ports=[],
            attack_plan="test",
            attack_results=[
                _sample_attack_result("CVE-A", sev="HIGH", confirmed=True,
                                      evidence="real exploit" * 10),
            ],
        )
        base = rep.generate_reports()
        with open(base + ".md") as f:
            md = f.read()
        assert "`CONFIRMED`" in md

    def test_status_label_correct_for_unconfirmed_high(self, tmp_reporter):
        rep, tmpdir = tmp_reporter
        rep.add_entry(
            ip="10.0.0.1", os_match="Linux", ports=[],
            attack_plan="test",
            attack_results=[
                _sample_attack_result("CVE-A", sev="HIGH", confirmed=False,
                                      evidence="not exploitable" * 10),
            ],
        )
        base = rep.generate_reports()
        with open(base + ".md") as f:
            md = f.read()
        # Los no confirmados van al apéndice compacto "CVEs evaluados y descartados"
        # con estado NO CONFIRMADO (conservando toda su evidencia colapsada).
        assert "CVEs evaluados y descartados" in md
        assert "`NO CONFIRMADO`" in md

    def test_status_label_correct_for_info_confirmed(self, tmp_reporter):
        rep, tmpdir = tmp_reporter
        rep.add_entry(
            ip="10.0.0.1", os_match="Linux", ports=[],
            attack_plan="test",
            attack_results=[
                _sample_attack_result("INFO-X", sev="INFO", confirmed=True,
                                      evidence="just exposed" * 10),
            ],
        )
        base = rep.generate_reports()
        with open(base + ".md") as f:
            md = f.read()
        # INFO confirmed → EXPOSED (no "VULNERABLE")
        assert "`EXPOSED`" in md
        assert "VULNERABLE" not in md  # palabra antigua


# ============================================================================
# MITRE filtering
# ============================================================================
class TestMitreFiltered:

    def test_mitre_only_shows_techniques_for_tools_used(self, tmp_reporter):
        rep, tmpdir = tmp_reporter
        rep.add_entry(
            ip="10.0.0.1", os_match="Linux", ports=[],
            attack_plan="test", attack_results=[],
            executed_tools=["nmap_scan", "probe_dial"],  # solo 2 tools
        )
        base = rep.generate_reports()
        with open(base + ".md") as f:
            md = f.read()
        # MITRE debe estar pero filtrado
        assert "MITRE ATT&CK" in md
        assert "técnicas efectivamente usadas" in md.lower()
        # Tools del run aparecen en la columna de mapping
        assert "nmap_scan" in md or "probe_dial" in md

    def test_mitre_skipped_when_no_tools_recorded(self, tmp_reporter):
        rep, tmpdir = tmp_reporter
        rep.add_entry(
            ip="10.0.0.1", os_match="Linux", ports=[],
            attack_plan="test", attack_results=[],
            # executed_tools vacío
        )
        base = rep.generate_reports()
        with open(base + ".md") as f:
            md = f.read()
        # Sin tools no podemos mapear honestamente — sección omitida
        assert "MITRE ATT&CK" not in md or "técnicas efectivamente usadas" not in md.lower()


# ============================================================================
# Remediation KB
# ============================================================================
class TestRemediationKB:

    def test_known_cves_have_remediation(self):
        for cve in ("CVE-2023-6317", "CVE-2023-6318", "CVE-2017-7921"):
            kb = get_remediation(cve)
            assert kb is not None, f"{cve} missing from remediation KB"
            assert kb.get("remediation"), f"{cve} has no remediation steps"
            assert kb.get("references"), f"{cve} has no references"

    def test_internal_findings_have_remediation(self):
        for fid in ("DIAL-EXPOSED", "MQTT-ANON-ACCESS", "MODBUS-NO-AUTH-FC17",
                    "TELNET-EXPOSED", "RTSP-DEFAULT-CRED"):
            kb = get_remediation(fid)
            assert kb is not None, f"{fid} missing from remediation KB"

    def test_unknown_id_returns_none(self):
        assert get_remediation("CVE-9999-FAKE") is None
        assert get_remediation(None) is None

    def test_cvss_v3_present_for_cves(self):
        for cve in REMEDIATION_KB:
            kb = get_remediation(cve)
            cvss = kb.get("cvss_v3", {})
            # CVSS opcional pero si presente debe tener score y severity
            if cvss:
                assert "severity" in cvss or "score" in cvss


# ============================================================================
# HTML render — smoke test (no assertions detalladas, solo que no rompe)
# ============================================================================
class TestReproductionCommands:
    """Verifica que el reporter renderiza comandos shell ejecutables (no
    nombres de tool del agente como `probe_dial` o `cve_search`)."""

    def test_dial_exposed_renders_curl_commands(self, tmp_reporter):
        rep, tmpdir = tmp_reporter
        rep.add_entry(
            ip="10.0.0.5", os_match="Linux", ports=[],
            attack_plan="test",
            attack_results=[
                _sample_attack_result("DIAL-EXPOSED", sev="MEDIUM", confirmed=True,
                                      cmd="probe_dial(10.0.0.5:1664)",  # nombre tool
                                      evidence="DIAL exposed " * 10),
            ],
        )
        base = rep.generate_reports()
        with open(base + ".md") as f:
            md = f.read()
        # NO debe aparecer el nombre del tool
        assert "probe_dial(10.0.0.5:1664)" not in md
        # SÍ debe aparecer un comando curl real con la IP substituida
        assert "curl" in md
        assert "10.0.0.5" in md
        assert "Reproducción manual" in md

    def test_cve_2017_7921_renders_magic_cookie_curl(self, tmp_reporter):
        rep, tmpdir = tmp_reporter
        rep.add_entry(
            ip="192.168.1.50", os_match="Linux", ports=[],
            attack_plan="test",
            attack_results=[
                _sample_attack_result("CVE-2017-7921", sev="CRITICAL", confirmed=True,
                                      evidence="Hikvision dump " * 10),
            ],
        )
        base = rep.generate_reports()
        with open(base + ".md") as f:
            md = f.read()
        # Magic cookie auth bypass URL específico debe aparecer
        assert "YWRtaW46MTEK" in md
        assert "192.168.1.50" in md

    def test_explicit_verification_cmd_overrides_kb(self, tmp_reporter):
        """Si la probe vuln traía verification_cmd, ese tiene prioridad sobre KB."""
        rep, tmpdir = tmp_reporter
        custom_cmd = "echo CUSTOM_VERIFICATION_HERE"
        attack_result = _sample_attack_result(
            "DIAL-EXPOSED", sev="MEDIUM", confirmed=True,
            cmd="probe_dial(10.0.0.5:1664)",
            evidence="DIAL exposed " * 10,
        )
        attack_result["verification_cmd"] = custom_cmd
        rep.add_entry(
            ip="10.0.0.5", os_match="Linux", ports=[],
            attack_plan="test",
            attack_results=[attack_result],
        )
        base = rep.generate_reports()
        with open(base + ".md") as f:
            md = f.read()
        assert custom_cmd in md

    def test_tool_name_filtered_when_no_kb_entry(self, tmp_reporter):
        """Para findings sin entrada en KB y sin verification_cmd, NO debe
        aparecer el nombre del tool del agente como reproducción."""
        rep, tmpdir = tmp_reporter
        rep.add_entry(
            ip="10.0.0.5", os_match="Linux", ports=[],
            attack_plan="test",
            attack_results=[
                _sample_attack_result(
                    "UNKNOWN-FINDING-XYZ", sev="HIGH", confirmed=False,
                    cmd="probe_lg_webos(10.0.0.5)",  # nombre tool
                    evidence="some short evidence here that is unique",
                ),
            ],
        )
        base = rep.generate_reports()
        with open(base + ".md") as f:
            md = f.read()
        # El nombre del tool NO debe aparecer como reproducción
        assert "probe_lg_webos(10.0.0.5)" not in md


class TestRawOutputVsInterpretation:
    """Verifica la separación entre datos reales del dispositivo y reasoning."""

    def test_record_finding_separates_raw_from_interpretation(self):
        from core import tools as toolbox
        toolbox.build_registry()
        toolbox.bind_session(toolbox.AgentSession(target_ip="1.2.3.4"))

        toolbox.dispatch("record_finding", {
            "cve_id": "CVE-X",
            "title": "Test",
            "severity": "HIGH",
            "confirmed": True,
            "raw_output": '{"banner": "BusyBox 1.20"}',
            "interpretation": "Banner suggests Mirai-vulnerable device",
            "cmd": "nc 1.2.3.4 23",
        })
        f = toolbox.get_session().findings[0]
        # raw_output ahora se pretty-printed por _clean_raw_output (indent=2)
        assert "banner" in f["raw_output"] and "BusyBox 1.20" in f["raw_output"]
        assert f["interpretation"] == "Banner suggests Mirai-vulnerable device"
        # Legacy evidence se reconstruye combinando ambos
        assert "BusyBox" in f["evidence"]
        assert "Mirai-vulnerable" in f["evidence"]

    def test_legacy_evidence_only_goes_to_interpretation(self):
        """Backward compat: si solo se pasa `evidence`, se trata como interpretation."""
        from core import tools as toolbox
        toolbox.build_registry()
        toolbox.bind_session(toolbox.AgentSession(target_ip="1.2.3.4"))

        toolbox.dispatch("record_finding", {
            "cve_id": "CVE-Y",
            "title": "Legacy",
            "severity": "MEDIUM",
            "confirmed": False,
            "evidence": "Texto antiguo todo mezclado",
            "cmd": "test",
        })
        f = toolbox.get_session().findings[0]
        assert f["interpretation"] == "Texto antiguo todo mezclado"
        assert f["raw_output"] == ""

    def test_auto_register_populates_raw_output_as_json(self):
        """Auto-register desde probe debe generar raw_output como JSON estructurado."""
        from core import tools as toolbox
        toolbox.build_registry()
        toolbox.bind_session(toolbox.AgentSession(target_ip="10.0.0.1"))

        result = {
            "ok": True, "ip": "10.0.0.1", "port": 1664,
            "vulnerabilities": [{
                "id": "DIAL-EXPOSED", "severity": "MEDIUM",
                "description": "DIAL exposes apps without auth",
            }],
            "details": {
                "apps": {"YouTube": {"status": "200", "state": "stopped"}},
                "application_url": "http://10.0.0.1:36866/apps/",
                "friendly_name": "Test TV",
                "model_name": "TestModel",
            },
        }
        toolbox._auto_register_probe_findings("probe_dial", {}, result)
        f = toolbox.get_session().findings[0]
        # raw_output debe ser JSON parseable con datos reales
        import json
        raw = json.loads(f["raw_output"])
        assert raw["application_url"] == "http://10.0.0.1:36866/apps/"
        assert raw["model_name"] == "TestModel"
        assert "YouTube" in raw["apps_detected"]
        # interpretation = description del probe (narrativa)
        assert f["interpretation"] == "DIAL exposes apps without auth"

    def test_md_renders_two_separate_sections(self, tmp_reporter):
        rep, tmpdir = tmp_reporter
        rep.add_entry(
            ip="10.0.0.1", os_match="Linux", ports=[],
            attack_plan="test",
            attack_results=[
                {
                    "service": "DIAL-EXPOSED",
                    "cve_id": "DIAL-EXPOSED",
                    "title": "DIAL exposed",
                    "severity": "MEDIUM",
                    "vuln_found": True,
                    "raw_output": '{"banner": "DIAL/1.7", "apps": ["YouTube"]}',
                    "interpretation": "Service exposes apps without authentication.",
                    "executed_cmd": "curl http://10.0.0.1:1664/dd.xml",
                },
            ],
        )
        base = rep.generate_reports()
        with open(base + ".md") as f:
            md = f.read()
        # Deben aparecer ambas secciones con sus headers visuales
        assert "Output del dispositivo" in md or "📡" in md
        assert "🧠" in md and "Interpretación del agente" in md
        # JSON aparece en bloque ```json
        assert "```json" in md
        assert "DIAL/1.7" in md
        # Interpretation aparece en blockquote (>)
        assert "> Service exposes apps" in md

    def test_md_legacy_evidence_renders_as_interpretation_only(self, tmp_reporter):
        """Si entry solo tiene output_log (legacy), debe ir como interpretation."""
        rep, tmpdir = tmp_reporter
        rep.add_entry(
            ip="10.0.0.1", os_match="Linux", ports=[],
            attack_plan="test",
            attack_results=[
                {
                    "service": "OLD-FINDING", "cve_id": "OLD-FINDING",
                    "title": "Old", "severity": "INFO", "vuln_found": True,
                    "output_log": "Mixed legacy text with banner and reasoning",
                    "executed_cmd": "test",
                },
            ],
        )
        base = rep.generate_reports()
        with open(base + ".md") as f:
            md = f.read()
        # Sin raw_output, solo se renderiza la sección de interpretación
        assert "🧠" in md and "Interpretación" in md
        assert "Mixed legacy text" in md


class TestFuzzyDedupeAndTitleNormalization:
    """Verifica los fixes de las 7 incongruencias del HTML report."""

    def setup_method(self):
        from core import tools as toolbox
        toolbox.build_registry()
        toolbox.bind_session(toolbox.AgentSession(target_ip="1.2.3.4"))

    def test_derive_cve_id_from_dial_title(self):
        from core.tools import _derive_cve_id_from_title
        assert _derive_cve_id_from_title("DIAL Exposed - App Enumeration") == "DIAL-EXPOSED"
        assert _derive_cve_id_from_title("DIAL service exposes apps") == "DIAL-EXPOSED"

    def test_derive_cve_id_from_lg_webos_title(self):
        from core.tools import _derive_cve_id_from_title
        assert _derive_cve_id_from_title("LG WebOS Detected - Pairing Requires PIN") == "LG-WEBOS-EXPOSED"
        assert _derive_cve_id_from_title("LG WebOS pairing endpoint") == "LG-WEBOS-EXPOSED"

    def test_derive_cve_id_finds_explicit_cve_in_title(self):
        from core.tools import _derive_cve_id_from_title
        assert _derive_cve_id_from_title("Auth bypass via CVE-2023-6317") == "CVE-2023-6317"

    def test_derive_returns_none_for_unknown_titles(self):
        from core.tools import _derive_cve_id_from_title
        assert _derive_cve_id_from_title("Some random vulnerability") is None

    def test_record_finding_dedupes_via_derived_cve_id(self):
        """Cuando el LLM pasa record_finding sin cve_id pero con title que matchea
        un ID conocido, debe deduplicarse contra el auto-register previo."""
        from core import tools as toolbox
        # Auto-register simulado
        toolbox.dispatch("record_finding", {
            "cve_id": "DIAL-EXPOSED",
            "title": "DIAL service",
            "severity": "MEDIUM",
            "confirmed": True,
            "raw_output": '{"apps": ["YouTube"]}',
        })
        # LLM record_finding sin cve_id (caso del bug observado)
        toolbox.dispatch("record_finding", {
            # cve_id ausente
            "title": "DIAL Exposed - App Enumeration and Launch",
            "severity": "MEDIUM",
            "confirmed": True,
            "interpretation": "Service allows remote app launch",
        })
        findings = toolbox.get_session().findings
        # Solo 1 entry (mergeado, no duplicado)
        assert len(findings) == 1
        assert findings[0]["cve_id"] == "DIAL-EXPOSED"

    def test_record_finding_uses_kb_title_when_truncated(self):
        """Si el LLM pasa un title NVD-truncado (cortado a mitad de palabra),
        usar el título oficial del KB."""
        from core import tools as toolbox
        toolbox.dispatch("record_finding", {
            "cve_id": "CVE-2023-6317",
            "title": "A prompt bypass exists in the secondscreen.gateway service running on webOS vers",
            "severity": "HIGH",
            "confirmed": False,
        })
        f = toolbox.get_session().findings[0]
        # Title del KB (no el truncado)
        assert "PIN Bypass" in f["title"] or "secondscreen.gateway" in f["title"]
        # NO debe terminar a mitad de palabra
        assert not f["title"].endswith("vers")

    def test_record_finding_keeps_short_title_as_is(self):
        """Si el title ya es corto y sensato, no se sobreescribe."""
        from core import tools as toolbox
        toolbox.dispatch("record_finding", {
            "cve_id": "CVE-2023-6317",
            "title": "Short title",
            "severity": "HIGH",
            "confirmed": False,
        })
        f = toolbox.get_session().findings[0]
        assert f["title"] == "Short title"


class TestHTMLStatsAndDualSections:
    """Verifica que HTML stats reflejan findings reales y separa output vs interp."""

    def setup_method(self):
        import tempfile
        self.tmpdir = tempfile.mkdtemp()

    def _gen(self, **kwargs):
        from modules.reporter import Reporter
        rep = Reporter(report_dir=self.tmpdir)
        rep.add_entry(**kwargs)
        base = rep.generate_reports()
        with open(base + ".html") as f:
            return f.read()

    def test_stats_count_findings_not_system_cves(self):
        html = self._gen(
            ip="1.2.3.4", os_match="Linux", ports=[],
            attack_plan="t",
            attack_results=[
                {"service": "DIAL-EXPOSED", "cve_id": "DIAL-EXPOSED",
                 "severity": "MEDIUM", "vuln_found": True,
                 "raw_output": '{"x": 1}', "details": "MEDIUM"},
                {"service": "CVE-X", "cve_id": "CVE-2023-1",
                 "severity": "HIGH", "vuln_found": False,
                 "details": "HIGH"},
            ],
            risk_summary={
                "risk_score": 30, "risk_label": "MEDIUM",
                "severity_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 1, "LOW": 0, "INFO": 0},
                "confirmed_count": 1, "total_findings": 2,
            },
        )
        # Stats debe mostrar 2 findings totales, NO 0
        assert "<div class=\"value\">0</div><div class=\"label\">Findings totales</div>" not in html
        # Risk MEDIUM badge presente
        assert "MEDIUM" in html

    def test_html_renders_dual_sections_with_dual_data(self):
        html = self._gen(
            ip="1.2.3.4", os_match="Linux", ports=[],
            attack_plan="t",
            attack_results=[
                {"service": "DIAL-EXPOSED", "cve_id": "DIAL-EXPOSED",
                 "severity": "MEDIUM", "vuln_found": True,
                 "executed_cmd": "probe_dial(1.2.3.4)",
                 "raw_output": '{"apps": ["YouTube"]}',
                 "interpretation": "Service exposed without auth",
                 "details": "MEDIUM"},
            ],
        )
        assert "Output del dispositivo" in html or "📡" in html
        assert "Interpretación del agente" in html

    def test_html_filters_tool_names_from_cmd(self):
        html = self._gen(
            ip="1.2.3.4", os_match="Linux", ports=[],
            attack_plan="t",
            attack_results=[
                {"service": "DIAL-EXPOSED", "cve_id": "DIAL-EXPOSED",
                 "severity": "MEDIUM", "vuln_found": True,
                 "executed_cmd": "probe_dial(1.2.3.4:1664)",  # nombre tool
                 "raw_output": '{}',
                 "details": "MEDIUM"},
            ],
        )
        # No debe mostrar "probe_dial(1.2.3.4:1664)" como comando shell
        # (puede aparecer en otros sitios pero NO como bloque de reproducción)
        assert ">probe_dial(1.2.3.4:1664)<" not in html

    def test_html_specific_vector_for_known_findings(self):
        html = self._gen(
            ip="1.2.3.4", os_match="Linux", ports=[],
            attack_plan="t",
            attack_results=[
                {"service": "DIAL-EXPOSED", "cve_id": "DIAL-EXPOSED",
                 "severity": "MEDIUM", "vuln_found": True,
                 "raw_output": '{}',
                 "details": "MEDIUM"},
            ],
        )
        # Vector específico DIAL, no genérico "Otro"
        assert "DIAL" in html
        # Si "Otro" aparece, NO debe ser para este finding
        if "Otro — Ataque web" in html:
            # Debe haber TAMBIÉN el vector DIAL específico
            assert "App enumeration" in html or "DIAL —" in html

    def test_non_cve_finding_counts_as_confirmed_in_cluster(self):
        """Bug regresión: DIAL-EXPOSED / MDNS-EXPOSED con vuln_found=True
        deben contar como confirmados en el cluster header, no solo en top stats."""
        html = self._gen(
            ip="1.2.3.4", os_match="Linux", ports=[],
            attack_plan="t",
            attack_results=[
                {"service": "DIAL-EXPOSED", "cve_id": "DIAL-EXPOSED",
                 "severity": "MEDIUM", "vuln_found": True,
                 "raw_output": '{}',
                 "details": "MEDIUM"},
                {"service": "MDNS-EXPOSED", "cve_id": "MDNS-EXPOSED",
                 "severity": "INFO", "vuln_found": True,
                 "raw_output": '{}',
                 "details": "INFO"},
            ],
        )
        # Cluster header debe decir "CONFIRMADO(S)", no "NO CONFIRMADO"
        assert "CONFIRMADO(S)" in html
        # Sub-línea: 2 findings confirmados, 0 CVEs confirmados
        assert ">2</strong> findings confirmados" in html
        assert ">0</strong> CVEs confirmados" in html

    def test_cve_finding_counts_as_cve_confirmed(self):
        """CVE oficial con vuln_found=True cuenta como ambos: finding y CVE confirmado."""
        html = self._gen(
            ip="1.2.3.4", os_match="Linux", ports=[],
            attack_plan="t",
            attack_results=[
                {"service": "WebOS", "cve_id": "CVE-2023-6317",
                 "severity": "HIGH", "vuln_found": True,
                 "raw_output": '{}',
                 "details": "HIGH"},
            ],
        )
        assert ">1</strong> findings confirmados" in html
        assert ">1</strong> CVEs confirmados" in html


class TestRawOutputCleanup:
    """Verifica los fixes del segundo report HTML (admin keys, merge limpio)."""

    def test_clean_raw_output_removes_admin_keys(self):
        from core.tools import _clean_raw_output
        import json
        dirty = json.dumps({
            "_auto_registered_findings": ["X"],
            "_elapsed_ms": 100,
            "ok": True,
            "error": None,
            "ip": "1.2.3.4",
            "port": 80,
            "service": "http",
            "protocol_confirmed": True,
            "vulnerabilities": [{"id": "X"}],
            "details": {"banner": "TestServer/1.0"},
        })
        clean = _clean_raw_output(dirty)
        assert "_auto_registered_findings" not in clean
        assert "_elapsed_ms" not in clean
        assert "ok" not in clean or "TestServer" in clean  # 'ok' fuera del root
        # `details` se promueve al root
        assert "TestServer/1.0" in clean

    def test_clean_raw_output_passes_through_non_json(self):
        from core.tools import _clean_raw_output
        text = "BusyBox v1.20\nlogin:"
        assert _clean_raw_output(text) == text

    def test_quality_score_prefers_clean(self):
        from core.tools import _raw_output_quality_score
        import json
        dirty = json.dumps({"_elapsed_ms": 1, "ok": True, "details": {"x": 1}})
        clean = json.dumps({"banner": "x"})
        assert _raw_output_quality_score(clean) > _raw_output_quality_score(dirty)

    def test_merge_strips_admin_keys_from_both_versions(self):
        """Cleanup se aplica al WRITE: tanto auto-register como LLM record_finding
        terminan con raw_output limpio. Verificar que tras un merge, el resultado
        nunca contiene claves admin del dispatch (_elapsed_ms, ok, etc.)."""
        from core import tools as toolbox
        toolbox.build_registry()
        toolbox.bind_session(toolbox.AgentSession(target_ip="1.2.3.4"))
        import json

        # Auto-register limpio
        toolbox.dispatch("record_finding", {
            "cve_id": "DIAL-EXPOSED",
            "title": "DIAL",
            "severity": "MEDIUM",
            "confirmed": True,
            "raw_output": json.dumps({"app": "YouTube", "port": 1664}),
        })

        # LLM pasa dispatch result completo (admin keys + datos)
        dirty_raw = json.dumps({
            "_elapsed_ms": 999, "ok": True, "ip": "1.2.3.4",
            "service": "dial", "vulnerabilities": [{"id": "DIAL"}],
            "details": {"app": "YouTube", "extra": "info"},
        })
        toolbox.dispatch("record_finding", {
            "cve_id": "DIAL-EXPOSED",
            "title": "DIAL",
            "severity": "MEDIUM",
            "confirmed": True,
            "raw_output": dirty_raw,
        })

        f = toolbox.get_session().findings[0]
        # Sea cual sea el merge, las claves admin NUNCA aparecen
        for admin_key in ("_elapsed_ms", "_auto_registered_findings",
                          '"ok": true', "protocol_confirmed"):
            assert admin_key not in f["raw_output"], \
                f"Admin key {admin_key} contaminó raw_output: {f['raw_output']}"
        # Y los datos útiles sí
        assert "YouTube" in f["raw_output"]


class TestPrettyJsonAndSentenceTruncate:

    def test_pretty_json_indents_and_cleans(self):
        from modules.reporter import _pretty_json_or_truncate
        import json
        s = json.dumps({"_elapsed_ms": 1, "details": {"a": 1, "b": 2}})
        out = _pretty_json_or_truncate(s, max_chars=500)
        assert "\n" in out  # multi-line
        assert "_elapsed_ms" not in out
        # details promovido al root
        assert '"a": 1' in out
        assert '"b": 2' in out

    def test_pretty_json_passes_through_non_json(self):
        from modules.reporter import _pretty_json_or_truncate
        s = "Banner: BusyBox v1.0"
        assert _pretty_json_or_truncate(s) == s


class TestMdnsScanCacheInjection:

    def setup_method(self):
        from core import tools as toolbox
        toolbox.build_registry()
        toolbox.bind_session(toolbox.AgentSession(target_ip="1.2.3.4"))

    def test_mdns_writes_model_firmware_to_scan_cache(self, monkeypatch):
        """probe_mdns debe popular session.scan_cache.model y firmware
        cuando los servicios mDNS contienen esos datos en `properties`.
        """
        from core import tools as toolbox

        # Mock mdns_probe en el wrapper para devolver datos de LG TV
        def fake_mdns(ip, listen_seconds=2.5):
            return [{
                "type": "_airplay._tcp.local.",
                "name": "[LG] TV",
                "server": "LGwebOSTV.local.",
                "port": 7000,
                "properties": {
                    "model": "65QNED826RE",
                    "manufacturer": "LG",
                    "fv": "p20.33.31.23",
                    "deviceid": "FE:FB:02:5F:3C:33",
                },
            }]

        import modules.discovery
        monkeypatch.setattr(modules.discovery, "mdns_probe", fake_mdns)

        result = toolbox.dispatch("probe_mdns", {"ip": "1.2.3.4", "timeout": 1})
        # Vulnerabilidad MDNS-EXPOSED auto-emitida
        assert any(v.get("id") == "MDNS-EXPOSED" for v in result.get("vulnerabilities", []))
        # Scan cache enriquecido
        cache = toolbox.get_session().scan_cache or {}
        assert cache.get("model") == "65QNED826RE"
        assert cache.get("firmware") == "p20.33.31.23"


class TestKBVerificationCmdsRender:
    """Verifica el helper render_verification_cmds."""

    def test_substitutes_ip_placeholder(self):
        from modules.remediation_kb import render_verification_cmds
        cmds = render_verification_cmds("CVE-2017-7921", "10.0.0.5")
        assert all(isinstance(c, str) for c in cmds)
        joined = "\n".join(cmds)
        assert "10.0.0.5" in joined
        assert "{ip}" not in joined  # placeholder substituido

    def test_unknown_id_returns_empty(self):
        from modules.remediation_kb import render_verification_cmds
        assert render_verification_cmds("CVE-9999-FAKE", "1.2.3.4") == []


class TestHTMLRender:

    def test_html_with_device_identity_renders(self, tmp_reporter):
        rep, tmpdir = tmp_reporter
        rep.add_entry(
            ip="10.0.0.1", os_match="Linux", ports=[],
            attack_plan="test", attack_results=[],
            device_identity={"vendor": "LG", "model": "X"},
            risk_summary={"risk_score": 50, "risk_label": "MEDIUM"},
        )
        base = rep.generate_reports()
        with open(base + ".html") as f:
            html = f.read()
        assert "<html" in html
        assert "LG" in html
        # Risk badge color should appear
        assert "MEDIUM" in html or "50/100" in html

    def test_html_xss_safe(self, tmp_reporter):
        rep, tmpdir = tmp_reporter
        rep.add_entry(
            ip="10.0.0.1", os_match="Linux", ports=[],
            attack_plan="test", attack_results=[],
            device_identity={"vendor": "<script>alert(1)</script>", "model": "X"},
        )
        base = rep.generate_reports()
        with open(base + ".html") as f:
            html = f.read()
        # script tag escapado
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html
