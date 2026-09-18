"""
Tests para MITRE ATT&CK mapping, MQTT probing, y Reporter HTML.
"""
import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── MITRE ATT&CK ───
class TestMitreAttack:

    def test_technique_catalog_has_entries(self):
        from core.mitre_attack import TECHNIQUE_CATALOG
        assert len(TECHNIQUE_CATALOG) >= 10

    def test_technique_url_generated(self):
        from core.mitre_attack import TECHNIQUE_CATALOG
        t = TECHNIQUE_CATALOG["T1190"]
        assert "attack.mitre.org" in t.url
        assert "T1190" in t.url

    def test_sub_technique_url(self):
        from core.mitre_attack import TECHNIQUE_CATALOG
        t = TECHNIQUE_CATALOG["T1588.005"]
        assert "T1588/005" in t.url

    def test_get_techniques_for_recon(self):
        from core.mitre_attack import get_techniques_for_node
        techs = get_techniques_for_node("recon")
        assert len(techs) >= 2
        ids = [t.technique_id for t in techs]
        assert "T1595" in ids

    def test_get_techniques_for_exploit(self):
        from core.mitre_attack import get_techniques_for_node
        techs = get_techniques_for_node("exploit")
        ids = [t.technique_id for t in techs]
        assert "T1190" in ids

    def test_get_techniques_unknown_node(self):
        from core.mitre_attack import get_techniques_for_node
        assert get_techniques_for_node("nonexistent") == []

    def test_get_all_no_duplicates(self):
        from core.mitre_attack import get_all_mapped_techniques
        techs = get_all_mapped_techniques()
        ids = [t.technique_id for t in techs]
        assert len(ids) == len(set(ids))

    def test_tactic_summary_structure(self):
        from core.mitre_attack import get_tactic_summary
        summary = get_tactic_summary()
        assert "TA0043" in summary  # Reconnaissance
        assert isinstance(summary["TA0043"]["techniques"], list)
        assert summary["TA0043"]["tactic_name"] == "Reconnaissance"

    def test_build_attack_narrative(self):
        from core.mitre_attack import build_attack_narrative
        narrative = build_attack_narrative(["recon", "exploit"])
        assert len(narrative) == 2
        assert narrative[0]["phase"] == "recon"
        assert len(narrative[0]["techniques"]) >= 2

    def test_narrative_skips_report(self):
        from core.mitre_attack import build_attack_narrative
        narrative = build_attack_narrative(["report"])
        assert len(narrative) == 0  # report has no techniques


# ─── MQTT Probing ───
class TestMQTTProbing:

    def test_detect_mqtt_standard_port(self):
        from modules.mqtt_probes import MQTTProber
        prober = MQTTProber()
        ports = [{"port": 1883, "service_name": "mqtt"}]
        assert prober.detect_mqtt_ports("192.168.1.1", ports) == [1883]

    def test_detect_mqtt_by_service_name(self):
        from modules.mqtt_probes import MQTTProber
        prober = MQTTProber()
        ports = [{"port": 9999, "service_name": "mqtt", "product": ""}]
        assert 9999 in prober.detect_mqtt_ports("192.168.1.1", ports)

    def test_detect_mqtt_by_product(self):
        from modules.mqtt_probes import MQTTProber
        prober = MQTTProber()
        ports = [{"port": 5555, "service_name": "unknown", "product": "Eclipse Mosquitto"}]
        assert 5555 in prober.detect_mqtt_ports("192.168.1.1", ports)

    def test_detect_no_mqtt(self):
        from modules.mqtt_probes import MQTTProber
        prober = MQTTProber()
        ports = [{"port": 80, "service_name": "http", "product": "nginx"}]
        assert prober.detect_mqtt_ports("192.168.1.1", ports) == []

    def test_build_connect_packet(self):
        from modules.mqtt_probes import _build_connect_packet
        pkt = _build_connect_packet("test-client")
        assert pkt[0:1] == b"\x10"  # CONNECT packet type
        assert b"MQTT" in pkt

    def test_build_subscribe_packet(self):
        from modules.mqtt_probes import _build_subscribe_packet
        pkt = _build_subscribe_packet("#")
        assert pkt[0:1] == b"\x82"  # SUBSCRIBE packet type

    def test_build_publish_packet(self):
        from modules.mqtt_probes import _build_publish_packet
        pkt = _build_publish_packet("test/topic", "hello")
        assert pkt[0:1] == b"\x30"  # PUBLISH packet type

    def test_parse_connack_success(self):
        from modules.mqtt_probes import _parse_connack
        # Type=0x20, Length=0x02, session=0x00, return_code=0x00
        result = _parse_connack(b"\x20\x02\x00\x00")
        assert result["connected"] is True

    def test_parse_connack_rejected(self):
        from modules.mqtt_probes import _parse_connack
        result = _parse_connack(b"\x20\x02\x00\x05")  # Not Authorized
        assert result["connected"] is False
        assert result["return_code"] == 5

    def test_probe_all_no_mqtt_ports(self):
        from modules.mqtt_probes import MQTTProber
        prober = MQTTProber()
        result = prober.probe_all("192.168.1.1", [{"port": 80, "service_name": "http"}])
        assert result == []


# ─── Reporter HTML ───
class TestReporterHTML:

    def test_generate_all_formats(self):
        from modules.reporter import Reporter
        with tempfile.TemporaryDirectory() as tmpdir:
            r = Reporter(report_dir=tmpdir)
            r.add_entry(
                ip="192.168.1.1",
                os_match="Linux 4.15",
                ports=[{"port": 80, "service_name": "http", "product": "nginx", "version": "1.18"}],
                attack_plan="Test plan",
                attack_results=[{
                    "service": "CVE-2023-001",
                    "vuln_found": True,
                    "executed_cmd": "curl http://192.168.1.1",
                    "output_log": "200 OK",
                    "details": "",
                }],
                system_cves=[{
                    "id": "CVE-2023-001",
                    "score": 9.8,
                    "severity": "CRITICAL",
                    "description": "Remote code execution",
                }],
            )
            base = r.generate_reports()
            assert os.path.exists(f"{base}.json")
            assert os.path.exists(f"{base}.md")
            assert os.path.exists(f"{base}.html")
            assert os.path.exists(f"{base}_pocs.sh")

    def test_html_contains_chart_js(self):
        from modules.reporter import Reporter
        with tempfile.TemporaryDirectory() as tmpdir:
            r = Reporter(report_dir=tmpdir)
            r.add_entry("10.0.0.1", "Test", [], "", [], [])
            base = r.generate_reports()
            with open(f"{base}.html", "r") as f:
                html = f.read()
            assert "chart.js" in html.lower() or "Chart" in html

    def test_html_contains_mitre(self):
        from modules.reporter import Reporter
        with tempfile.TemporaryDirectory() as tmpdir:
            r = Reporter(report_dir=tmpdir)
            r.add_entry("10.0.0.1", "Test", [], "", [], [])
            base = r.generate_reports(executed_nodes=["recon", "exploit"])
            with open(f"{base}.html", "r") as f:
                html = f.read()
            assert "MITRE" in html
            assert "T1595" in html  # recon technique

    def test_html_escapes_xss(self):
        from modules.reporter import Reporter
        with tempfile.TemporaryDirectory() as tmpdir:
            r = Reporter(report_dir=tmpdir)
            r.add_entry(
                "10.0.0.1", "Test", [],
                "",
                [{"service": "test", "vuln_found": False,
                  "executed_cmd": '<script>alert("xss")</script>',
                  "output_log": "", "details": ""}],
            )
            base = r.generate_reports()
            with open(f"{base}.html", "r") as f:
                html = f.read()
            assert "<script>alert" not in html
            assert "&lt;script&gt;" in html

    def test_mqtt_results_in_html(self):
        from modules.reporter import Reporter
        with tempfile.TemporaryDirectory() as tmpdir:
            r = Reporter(report_dir=tmpdir)
            r.add_entry(
                "10.0.0.1", "Test", [], "", [],
                mqtt_results=[{
                    "ip": "10.0.0.1", "port": 1883,
                    "vulnerabilities": [{
                        "id": "MQTT-ANON-ACCESS",
                        "description": "Anonymous access allowed",
                        "severity": "HIGH",
                        "score": 8.5,
                    }],
                }],
            )
            base = r.generate_reports()
            with open(f"{base}.html", "r") as f:
                html = f.read()
            assert "MQTT" in html
            assert "MQTT-ANON-ACCESS" in html
