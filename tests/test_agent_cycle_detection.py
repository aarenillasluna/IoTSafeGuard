"""El detector de bucles debe ver también los CICLOS, no solo la repetición.

`RepetitionDetector` comparaba cada llamada con la inmediatamente anterior, así
que solo cazaba A-A-A. La patología más común de un agente LLM es la otra:
A-B-A-B-A-B, alternar entre dos herramientas creyendo que «prueba otra cosa».
Ese caso era invisible —se acumulaba `history` y no se miraba nunca— y podía
agotar el presupuesto de turnos sin que ninguna guarda interviniera.

Las pruebas fijan también el límite contrario: un barrido legítimo de sondas
distintas, o un ida y vuelta puntual, NO deben disparar la guarda.
"""
from core.agent_guards import RepetitionDetector, build_repetition_warning


def _run(det: RepetitionDetector, sequence) -> list:
    return [det.observe(name, {"ip": "10.0.0.1"}) for name in sequence]


# ── Repetición inmediata (comportamiento previo, intacto) ──────────────────

def test_immediate_repetition_still_detected():
    det = RepetitionDetector(threshold=3)
    fired = _run(det, ["nmap_scan", "nmap_scan", "nmap_scan"])
    assert fired == [False, False, True]
    assert det.last_reason == "repetition"


def test_different_args_are_not_a_repetition():
    det = RepetitionDetector(threshold=3)
    assert det.observe("probe_tcp", {"port": 80}) is False
    assert det.observe("probe_tcp", {"port": 81}) is False
    assert det.observe("probe_tcp", {"port": 82}) is False


# ── Ciclos ─────────────────────────────────────────────────────────────────

def test_two_call_cycle_is_detected():
    """A-B-A-B-A-B: el agente alterna sin avanzar."""
    det = RepetitionDetector(threshold=3)
    fired = _run(det, ["cve_search", "http_interrogate"] * 3)
    assert fired[-1] is True
    assert det.last_reason == "cycle"
    assert det.cycle_length == 2


def test_three_call_cycle_is_detected():
    det = RepetitionDetector(threshold=3)
    fired = _run(det, ["nmap_scan", "probe_ssh", "cve_search"] * 3)
    assert fired[-1] is True
    assert det.cycle_length == 3


def test_one_round_trip_is_not_a_cycle():
    """Sondear, registrar y volver a sondear es trabajo normal, no un bucle."""
    det = RepetitionDetector(threshold=3)
    fired = _run(det, ["probe_ssh", "record_finding", "probe_ssh", "record_finding"])
    assert not any(fired)


def test_a_legitimate_probe_sweep_does_not_fire():
    det = RepetitionDetector(threshold=3)
    fired = _run(det, ["probe_ssh", "probe_ftp", "probe_telnet", "probe_mdns",
                       "probe_snmp", "probe_coap", "probe_rtsp", "probe_smb"])
    assert not any(fired)


def test_reset_clears_history_across_phases():
    """Tras cambiar de fase el catálogo es otro: el historial previo no forma
    un ciclo con el nuevo, y conservarlo generaba avisos falsos."""
    det = RepetitionDetector(threshold=3)
    _run(det, ["cve_search", "http_interrogate"] * 2)
    det.reset()
    assert det.history == []
    fired = _run(det, ["cve_search", "http_interrogate"])
    assert not any(fired)


# ── El aviso explica la patología correcta ─────────────────────────────────

def test_cycle_warning_names_the_real_problem():
    """El aviso va al contexto del modelo, en inglés (§4.4). Lo que se fija es
    que nombre la patología correcta: no «repites», sino «alternas»."""
    msg = build_repetition_warning("cve_search", {}, 1, reason="cycle",
                                   cycle_length=2)
    assert "LOOP" in msg
    assert "Alternating between two tools is NOT changing strategy" in msg
    assert "audit_status" in msg


def test_repetition_warning_is_distinct_from_the_cycle_one():
    msg = build_repetition_warning("nmap_scan", {}, 3)
    assert "3 times in a row" in msg
    assert "LOOP" not in msg
