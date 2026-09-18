"""Tests for SARIF 2.1.0 export in modules.reporter._build_sarif."""
import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.reporter import (
    Reporter,
    _build_sarif,
    _sarif_level,
    SARIF_VERSION,
    SARIF_SCHEMA,
)


class TestSarifLevel:

    @pytest.mark.parametrize("severity,level", [
        ("CRITICAL", "error"),
        ("HIGH", "error"),
        ("MEDIUM", "warning"),
        ("LOW", "note"),
        # Desconocida o ausente → `note`: nunca se eleva a `error` por defecto,
        # porque SARIF alimenta la anotación en CI y un `error` bloquea builds.
        (None, "note"),
        ("", "note"),
        ("BANANA", "note"),
    ])
    def test_severity_maps_to_sarif_level(self, severity, level):
        assert _sarif_level(severity) == level


class TestBuildSarif:

    def test_empty_findings_valid_shell(self):
        log = _build_sarif([])
        assert log["version"] == SARIF_VERSION
        assert log["$schema"] == SARIF_SCHEMA
        assert log["runs"][0]["tool"]["driver"]["name"] == "IoTSafeGuard-Agent"
        assert log["runs"][0]["results"] == []

    def test_cve_becomes_result(self):
        findings = [{
            "target_ip": "10.0.0.1",
            "system_cves": [
                {"id": "CVE-2024-22651", "description": "RCE in CGI", "severity": "CRITICAL", "score": 9.8}
            ],
            "attack_results": [],
        }]
        log = _build_sarif(findings)
        results = log["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "CVE-2024-22651"
        assert results[0]["level"] == "error"
        rules = log["runs"][0]["tool"]["driver"]["rules"]
        assert any(r["id"] == "CVE-2024-22651" for r in rules)

    def test_attack_confirmed_fail_kind(self):
        findings = [{
            "target_ip": "10.0.0.1",
            "system_cves": [],
            "attack_results": [{
                "service": "PROBE-TELNET-CREDS",
                "vuln_found": True,
                "executed_cmd": "PROBE:telnet_creds 10.0.0.1",
                "output_log": "shell obtained",
                "severity": "CRITICAL",
            }],
        }]
        log = _build_sarif(findings)
        res = log["runs"][0]["results"][0]
        assert res["kind"] == "fail"
        assert res["level"] == "error"
        assert res["properties"]["confirmed"] is True
        assert "CONFIRMED" in res["message"]["text"]

    def test_attack_unconfirmed_pass_kind(self):
        findings = [{
            "target_ip": "10.0.0.1",
            "system_cves": [],
            "attack_results": [{
                "service": "PROBE-MDNS-ENUM",
                "vuln_found": False,
                "executed_cmd": "PROBE:mdns_enum 10.0.0.1",
                "output_log": "",
                "severity": "MEDIUM",
            }],
        }]
        log = _build_sarif(findings)
        res = log["runs"][0]["results"][0]
        assert res["kind"] == "pass"
        assert res["level"] == "warning"

    def test_rules_deduplicated(self):
        findings = [{
            "target_ip": "10.0.0.1",
            "system_cves": [
                {"id": "CVE-X", "description": "d", "severity": "HIGH", "score": 7},
                {"id": "CVE-X", "description": "d", "severity": "HIGH", "score": 7},
            ],
            "attack_results": [],
        }]
        log = _build_sarif(findings)
        rules = log["runs"][0]["tool"]["driver"]["rules"]
        assert len([r for r in rules if r["id"] == "CVE-X"]) == 1
        assert len(log["runs"][0]["results"]) == 2  # Both results present


class TestReporterSarifFile:

    def test_sarif_file_written_and_parseable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            r = Reporter(report_dir=tmpdir)
            r.add_entry(
                "10.0.0.1", "Test",
                [{"port": 80, "service_name": "http", "product": "", "version": ""}],
                "ai plan",
                [{"service": "TEST-1", "vuln_found": False, "executed_cmd": "echo hi",
                  "output_log": "", "severity": "LOW"}],
                system_cves=[{"id": "CVE-9999-1", "description": "x", "severity": "MEDIUM", "score": 5.0}],
            )
            base = r.generate_reports()
            with open(f"{base}.sarif", "r", encoding="utf-8") as fh:
                log = json.load(fh)
            assert log["version"] == "2.1.0"
            assert len(log["runs"][0]["results"]) == 2
