"""Pruebas del harness de baseline (`scripts/baseline_scan.py`).

Protegen la lógica que sostiene la comparación cabeza a cabeza del Capítulo 5:
el mapeo CVSS→severidad y el parseo del XML de Nmap a findings con la semántica
correcta (candidatos `confirmed=False`, NSE `State: VULNERABLE` → `confirmed=True`),
de modo que el `risk_score` se calcule con la MISMA función que para el agente.
"""
import importlib.util
import os

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SPEC = importlib.util.spec_from_file_location(
    "baseline_scan", os.path.join(_ROOT, "scripts", "baseline_scan.py")
)
baseline = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(baseline)

from core.tools import compute_risk_score


SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
<host>
<status state="up"/>
<address addr="172.30.0.10" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="8080">
<state state="open"/>
<service name="http" product="Boa httpd" version="0.94.13"/>
<script id="vulners" output="
  cpe:/a:boa:boa:0.94.13:
      CVE-2021-33558   7.5   https://vulners.com/cve/CVE-2021-33558
      CVE-2017-9833    9.8   https://vulners.com/cve/CVE-2017-9833
"/>
</port>
<port protocol="tcp" portid="80">
<state state="open"/>
<service name="http" product="RomPager" version="4.07"/>
<script id="http-vuln-misfortune-cookie" output="
  VULNERABLE:
  State: VULNERABLE
  IDs:  CVE:CVE-2014-9222
"/>
</port>
<port protocol="tcp" portid="23">
<state state="open"/>
<service name="telnet"/>
<script id="telnet-encryption" output="Telnet server does not support encryption"/>
</port>
</ports>
</host>
</nmaprun>
"""


@pytest.mark.parametrize("score,expected", [
    (9.8, "CRITICAL"), (9.0, "CRITICAL"),
    (8.9, "HIGH"), (7.0, "HIGH"),
    (6.9, "MEDIUM"), (4.0, "MEDIUM"),
    (3.9, "LOW"), (0.1, "LOW"),
    (0.0, "INFO"),
])
def test_cvss_to_severity(score, expected):
    assert baseline.cvss_to_severity(score) == expected


def _parse(tmp_path):
    xml = tmp_path / "sample.xml"
    xml.write_text(SAMPLE_XML)
    return baseline.parse_nmap_xml(str(xml))


def test_parse_counts_candidates_and_confirmed(tmp_path):
    findings, ports, _os = _parse(tmp_path)
    # 2 candidatos vulners + 1 NSE VULNERABLE; el script informativo no cuenta.
    candidates = [f for f in findings if not f["confirmed"]]
    confirmed = [f for f in findings if f["confirmed"]]
    assert len(candidates) == 2
    assert len(confirmed) == 1
    # Puertos abiertos detectados (8080, 80, 23).
    assert len(ports) == 3


def test_vulners_are_unconfirmed(tmp_path):
    findings, _ports, _os = _parse(tmp_path)
    vulners = [f for f in findings if f.get("cve_id") in ("CVE-2021-33558", "CVE-2017-9833")]
    assert vulners and all(f["confirmed"] is False for f in vulners)
    assert all(f["vuln_found"] is False for f in vulners)


def test_nse_vulnerable_is_confirmed(tmp_path):
    findings, _ports, _os = _parse(tmp_path)
    mc = [f for f in findings if f.get("cve_id") == "CVE-2014-9222"]
    assert mc and mc[0]["confirmed"] is True and mc[0]["vuln_found"] is True


def test_scanner_score_is_negligible_despite_critical_candidate(tmp_path):
    """Tesis del trabajo, en número: aunque haya un candidato CRITICAL (9.8),
    el escáner confirma 1 sin clase de impacto → effective_severity lo topa a
    LOW → el risk score (mismo cálculo que el agente) queda NEGLIGIBLE."""
    findings, _ports, _os = _parse(tmp_path)
    risk = compute_risk_score(findings)
    assert risk["risk_label"] == "NEGLIGIBLE"
    assert risk["risk_score"] < 10
