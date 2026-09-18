"""Tests del agregador del dashboard — verifica que parsea correctamente la
estructura real del reporter (`{"findings": [...]}`) y que la identidad de
device se construye por (vendor+model+MAC), nunca por IP.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from api.services import aggregator


SAMPLE_REPORT = {
    "findings": [
        {
            "target_ip": "192.168.1.1",
            "timestamp": "2026-05-17 00:09:02",
            "os_detected": "Linux 2.6.31 - 2.6.35",
            "device_identity": {
                "vendor": "D-Link",
                "model": "DIR-815",
                "firmware": "1.04",
                "mac": "00:DE:FA:1A:01:00",
            },
            "risk_summary": {
                "risk_score": 40,
                "risk_label": "MEDIUM",
                "severity_counts": {"CRITICAL": 3, "HIGH": 0, "MEDIUM": 1, "LOW": 0, "INFO": 1},
                "confirmed_severity_counts": {"CRITICAL": 3, "HIGH": 0, "MEDIUM": 1, "LOW": 0, "INFO": 0},
                "confirmed_count": 4,
                "total_findings": 5,
            },
            "attack_results": [
                {"cve_id": "CVE-2018-10106", "severity": "CRITICAL", "title": "X",
                 "vuln_found": True, "executed_cmd": "curl ...", "raw_output": "evidence",
                 "interpretation": "interp"},
                {"cve_id": "CVE-2015-0150", "severity": "CRITICAL",
                 "vuln_found": True, "executed_cmd": "curl ...", "raw_output": "ev",
                 "interpretation": "interp"},
                {"cve_id": "CVE-2024-22651", "severity": "CRITICAL",
                 "vuln_found": False, "executed_cmd": "curl ...", "raw_output": "404",
                 "interpretation": "endpoint inexistente"},
            ],
            "system_cves": [
                {"id": "CVE-2018-10106", "severity": "CRITICAL", "score": 9.8,
                 "description": "permission bypass in /getcfg.php"},
            ],
            "open_ports": [{"port": 80, "protocol": "tcp"}],
        }
    ]
}

SAMPLE_REPORT_2 = {
    "findings": [
        {
            "target_ip": "192.168.0.1",  # IP DISTINTA, mismo dispositivo físico
            "timestamp": "2026-05-15 14:30:00",
            "os_detected": "Linux 2.6",
            "device_identity": {
                "vendor": "D-Link",
                "model": "DIR-815",
                "firmware": "1.04",
                "mac": "00:DE:FA:1A:01:00",  # mismo MAC
            },
            "risk_summary": {
                "risk_score": 25,
                "risk_label": "LOW",
                "severity_counts": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                "confirmed_severity_counts": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                "confirmed_count": 1,
                "total_findings": 1,
            },
            "attack_results": [
                {"cve_id": "CVE-2018-10106", "severity": "CRITICAL",
                 "vuln_found": True, "executed_cmd": "x", "raw_output": "y",
                 "interpretation": "z"},
            ],
            "system_cves": [],
            "open_ports": [],
        }
    ]
}


@pytest.fixture
def tmp_reports(monkeypatch, tmp_path):
    """Punto monkeypatched: aggregator lee de tmp_path en lugar del REPO_ROOT real."""
    rep_dir = tmp_path / "reports"
    rep_dir.mkdir()
    (rep_dir / "audit_report_20260517_000902.json").write_text(
        json.dumps(SAMPLE_REPORT), encoding="utf-8")
    (rep_dir / "audit_report_20260515_143000.json").write_text(
        json.dumps(SAMPLE_REPORT_2), encoding="utf-8")
    monkeypatch.setattr(aggregator, "REPORTS_DIR", str(rep_dir))
    monkeypatch.setattr(aggregator, "KB_PATH", str(tmp_path / "kb.json"))
    aggregator.invalidate_cache()
    return rep_dir


# ---------------------------------------------------------------------------
# Identidad canónica de device — composite key (vendor+model+MAC)
# ---------------------------------------------------------------------------
class TestDeviceIdentity:

    def test_normalize_mac(self):
        assert aggregator._normalize_mac("00:de:fa:1a:01:00") == "00:DE:FA:1A:01:00"
        assert aggregator._normalize_mac("00-de-fa-1a-01-00") == "00:DE:FA:1A:01:00"
        assert aggregator._normalize_mac("invalid") is None
        assert aggregator._normalize_mac(None) is None

    def test_device_key_composite(self):
        k = aggregator._device_key("D-Link", "DIR-815", "00:DE:FA:1A:01:00")
        assert k == "D-Link|DIR-815|00:DE:FA:1A:01:00"

    def test_device_key_unknown_fallback(self):
        # Sin nada → claves "Unknown|Unknown|" — válido como agrupador degenerado
        k = aggregator._device_key(None, None, None)
        assert k == "Unknown|Unknown|"

    def test_canonical_name_full(self):
        n = aggregator._canonical_name("D-Link", "DIR-815", "00:DE:FA:1A:01:00")
        assert "D-Link" in n and "DIR-815" in n and "00:DE:FA" in n

    def test_canonical_name_no_model(self):
        n = aggregator._canonical_name("Telefonica", None, "74:93:DA:5B:8B:80")
        assert "Telefonica" in n and "device" in n


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------
class TestReports:

    def test_list_reports_extracts_from_findings_array(self, tmp_reports):
        reports = aggregator.list_reports()
        assert len(reports) == 2
        # Más reciente primero
        assert reports[0]["id"] == "20260517_000902"
        assert reports[0]["target_ip"] == "192.168.1.1"
        assert reports[0]["vendor"] == "D-Link"
        assert reports[0]["model"] == "DIR-815"
        assert reports[0]["risk_label"] == "MEDIUM"
        assert reports[0]["risk_score"] == 40

    def test_get_report_returns_raw_with_findings(self, tmp_reports):
        r = aggregator.get_report("20260517_000902")
        assert r is not None
        assert "findings" in r
        assert len(r["findings"]) == 1


# ---------------------------------------------------------------------------
# Devices — clave compuesta, no IP
# ---------------------------------------------------------------------------
class TestDevicesGrouping:

    def test_same_mac_different_ips_groups_as_one_device(self, tmp_reports):
        """Regresión: el MISMO dispositivo (mismo MAC) auditado desde dos IPs
        distintas debe aparecer como UN único device en la lista, con ambas
        IPs en `ips_seen`."""
        devices = aggregator.list_devices()
        assert len(devices) == 1
        d = devices[0]
        assert d["vendor"] == "D-Link"
        assert d["model"] == "DIR-815"
        assert d["runs_count"] == 2
        assert set(d["ips_seen"]) == {"192.168.0.1", "192.168.1.1"}
        # El último seen es el más reciente
        assert d["last_seen"] == "2026-05-17 00:09:02"

    def test_get_device_aggregates_cves_across_runs(self, tmp_reports):
        devices = aggregator.list_devices()
        key = devices[0]["device_key"]
        detail = aggregator.get_device(key)
        assert detail is not None
        assert detail["runs_count"] == 2
        # CVE-2018-10106 aparece en ambos runs, confirmado en ambos
        cve_2018 = next(c for c in detail["cves_seen"] if c["cve_id"] == "CVE-2018-10106")
        assert cve_2018["occurrences"] == 2
        assert cve_2018["confirmed_occurrences"] == 2


# ---------------------------------------------------------------------------
# CVEs — agregación global con confirmed/dismissed
# ---------------------------------------------------------------------------
class TestCves:

    def test_list_cves_aggregates_confirmed_and_total(self, tmp_reports):
        cves = aggregator.list_cves()
        ids = {c["cve_id"] for c in cves}
        assert "CVE-2018-10106" in ids
        assert "CVE-2024-22651" in ids
        c10106 = next(c for c in cves if c["cve_id"] == "CVE-2018-10106")
        assert c10106["total_occurrences"] == 2
        assert c10106["confirmed_occurrences"] == 2
        # NVD score inyectado desde system_cves
        assert c10106["score"] == 9.8
        # Dismissed CVE: total > 0, confirmed = 0
        c22651 = next(c for c in cves if c["cve_id"] == "CVE-2024-22651")
        assert c22651["total_occurrences"] == 1
        assert c22651["confirmed_occurrences"] == 0

    def test_get_cve_returns_per_run_occurrences(self, tmp_reports):
        detail = aggregator.get_cve("CVE-2018-10106")
        assert detail is not None
        assert detail["total_occurrences"] == 2
        assert detail["confirmed_occurrences"] == 2
        # Ordenadas desc por timestamp
        assert detail["occurrences"][0]["timestamp"] >= detail["occurrences"][1]["timestamp"]
        # Cada occurrence linka a su report
        assert all(o["report_id"] for o in detail["occurrences"])

    def test_get_cve_returns_none_for_unknown(self, tmp_reports):
        assert aggregator.get_cve("CVE-9999-XXXX") is None


class TestGlobalStats:

    def test_global_stats_counts(self, tmp_reports):
        s = aggregator.global_stats()
        assert s["runs_total"] == 2
        assert s["devices_total"] == 1  # un solo device físico
        # Tres CVEs distintos vistos: CVE-2018-10106, CVE-2015-0150, CVE-2024-22651
        assert s["cves_total"] == 3
        # CVE-2018-10106 confirmado en ambos runs; CVE-2015-0150 en un run; CVE-2024-22651 nunca
        assert s["cves_confirmed_at_least_once"] == 2
        assert len(s["last_5_runs"]) == 2
