"""Pruebas del harness de varianza (`scripts/variance_harness.py`)."""
import importlib.util, os
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_S = importlib.util.spec_from_file_location("variance_harness",
        os.path.join(_ROOT, "scripts", "variance_harness.py"))
vh = importlib.util.module_from_spec(_S); _S.loader.exec_module(vh)


def test_confirmed_id_excludes_info_and_unconfirmed():
    # Con evidencia: el harness exige lo mismo que el registro del agente, de
    # modo que un hallazgo sin ningún campo de evidencia no cuenta ni aquí.
    ev = {"raw_output": "220 vsFTPd 2.3.4"}
    assert vh._confirmed_id({**ev, "vuln_found": True, "severity": "HIGH", "cve_id": "CVE-1"}) == "CVE-1"
    assert vh._confirmed_id({**ev, "vuln_found": True, "severity": "INFO", "cve_id": "X"}) is None
    assert vh._confirmed_id({**ev, "vuln_found": False, "severity": "HIGH", "cve_id": "X"}) is None
    # sin cve_id → título normalizado
    assert vh._confirmed_id({**ev, "vuln_found": True, "severity": "LOW",
                             "title": "Telnet Open"}) == "telnet open"


def test_confirmed_id_descarta_el_cascaron_sin_evidencia():
    assert vh._confirmed_id({"vuln_found": True, "severity": "CRITICAL",
                             "cve_id": "WEAK-CREDENTIALS"}) is None


def test_identity_prefers_mac():
    e = {"device_identity": {"mac": "aa:bb", "vendor": "LG", "model": "X"}, "target_ip": "1.2.3.4"}
    key, label = vh._identity_key(e)
    assert key == "AA:BB" and "LG" in label
    e2 = {"device_identity": {}, "target_ip": "1.2.3.4"}
    assert vh._identity_key(e2)[0] == "ip:1.2.3.4"


def test_jaccard():
    assert vh._jaccard({"a", "b"}, {"a", "b"}) == 1.0
    assert vh._jaccard({"a"}, {"b"}) == 0.0
    assert vh._jaccard(set(), set()) == 1.0
    assert vh._jaccard({"a", "b"}, {"b", "c"}) == 1 / 3


def test_analyze_group_stability():
    runs = [
        {"confirmed_set": {"A", "B", "C"}, "confirmed_count": 3, "risk_label": "CRITICAL", "has_set": True},
        {"confirmed_set": {"A", "B"}, "confirmed_count": 2, "risk_label": "CRITICAL", "has_set": True},
        {"confirmed_set": {"A", "B", "D"}, "confirmed_count": 3, "risk_label": "CRITICAL", "has_set": True},
    ]
    r = vh.analyze_group(runs)
    assert r["n_runs"] == 3
    assert r["risk_label_mode"] == "CRITICAL"
    assert r["stable_core"] == ["A", "B"]   # presentes en las 3
    # union = {A,B,C,D}=4 ; inter={A,B}=2 → 0.5
    assert r["stability_index"] == 0.5
    assert r["count_min"] == 2 and r["count_max"] == 3
