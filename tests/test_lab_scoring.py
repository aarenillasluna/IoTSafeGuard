"""Harness de precision/recall/F1 sobre el lab (iter_10): puntúa un informe contra
`lab/ground_truth.yml`. TP/FN por vector plantado; FP por confirmado espurio.
"""
import importlib.util
import os


_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "lab_scoring", os.path.join(_ROOT, "scripts", "lab_scoring.py"))
lab_scoring = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lab_scoring)


GT = {
    "target": "172.30.0.10",
    "vectors": [
        {"id": "telnet", "match": ["TELNET-DEFAULT", "TELNET-EXPOSED"]},
        {"id": "modbus", "match": ["MODBUS-NO-AUTH"]},
        {"id": "rtsp", "match": ["RTSP-NO-AUTH"]},
    ],
}


def _report(*confirmed):
    """confirmed: tuplas (id, severity)."""
    return {"findings": [{"attack_results": [
        {"attack_type": cid, "severity": sev, "vuln_found": True}
        for cid, sev in confirmed
    ]}]}


def test_perfect_detection():
    rep = _report(("TELNET-DEFAULT-CRED", "CRITICAL"),
                  ("MODBUS-NO-AUTH-FC17", "HIGH"),
                  ("RTSP-NO-AUTH-STREAM", "HIGH"))
    s = lab_scoring.score(rep, GT)
    assert s["TP"] == 3 and s["FN"] == 0 and s["FP"] == 0
    assert s["precision"] == 1.0 and s["recall"] == 1.0 and s["f1"] == 1.0


def test_missed_vector_is_fn():
    rep = _report(("TELNET-DEFAULT-CRED", "CRITICAL"),
                  ("MODBUS-NO-AUTH-FC17", "HIGH"))
    s = lab_scoring.score(rep, GT)
    assert s["TP"] == 2 and s["FN"] == 1 and s["FP"] == 0
    assert "rtsp" in s["missed"]
    assert round(s["recall"], 3) == round(2 / 3, 3)


def test_spurious_confirmed_is_fp():
    rep = _report(("TELNET-DEFAULT-CRED", "CRITICAL"),
                  ("SOMETHING-NOT-PLANTED", "HIGH"))
    s = lab_scoring.score(rep, GT)
    assert s["TP"] == 1 and s["FP"] == 1
    assert s["precision"] == 0.5
    assert "SOMETHING-NOT-PLANTED" in s["spurious_signatures"]


def test_info_findings_do_not_count():
    # Un INFO confirmado no es vulnerabilidad → ni TP ni FP.
    rep = _report(("TELNET-DEFAULT-CRED", "CRITICAL"),
                  ("ADMIN-PANEL-STUB", "INFO"))
    s = lab_scoring.score(rep, GT)
    assert s["FP"] == 0
    assert s["TP"] == 1


def test_multiple_signals_same_vector_count_once():
    # Tres señales del mismo vector telnet = UNA detección, no tres TP.
    rep = _report(("TELNET-DEFAULT-CRED", "CRITICAL"),
                  ("TELNET-EXPOSED", "MEDIUM"))
    s = lab_scoring.score(rep, GT)
    assert s["TP"] == 1            # un solo vector telnet detectado
    assert s["FP"] == 0           # la 2ª señal no es FP (mismo vector)


def test_empty_report_all_missed():
    s = lab_scoring.score({"findings": []}, GT)
    assert s["TP"] == 0 and s["FN"] == 3
    assert s["precision"] == 0.0 and s["recall"] == 0.0 and s["f1"] == 0.0


def test_real_ground_truth_loads():
    gt = lab_scoring.load_ground_truth()
    assert gt["target"] == "172.30.0.10"
    assert len(gt["vectors"]) == 8
