"""Un hallazgo debe poder corregirse a la baja, no solo agravarse.

El merge de `record_finding` era un trinquete: `confirmed`, `severity` e
`impact` solo subían. En un sistema cuya tesis es que manda la evidencia, eso
deja una asimetría difícil de defender —la evidencia podía agravar un hallazgo
pero nunca corregirlo— y convierte un error en permanente.

El flujo que lo destapa es de lo más normal: el agente registra un candidato
como HIGH a partir de la NVD, lo prueba después y descubre que el modelo no
aplica. Su `record_finding(confirmed=false, severity="INFO")` se descartaba en
silencio y el informe seguía publicando el HIGH.

`retract=true` hace explícita la corrección. Sigue pasando por la gobernanza:
no es una vía para inflar.
"""
import pytest

import core.tools as toolbox
from core.severity import compute_risk_score, effective_severity


@pytest.fixture
def session():
    s = toolbox.AgentSession(target_ip="10.0.0.7")
    toolbox.bind_session(s)
    yield s
    toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))


def _record(**kw):
    return toolbox._record_finding(kw)


# ── El trinquete sigue vigente por defecto ─────────────────────────────────

def test_without_retract_a_downgrade_is_ignored(session):
    """Comportamiento previo intacto: sin `retract`, no se degrada."""
    _record(cve_id="CVE-2020-1", title="x", severity="HIGH", confirmed=True,
            impact="ACCESS", raw_output="230 login successful")
    _record(cve_id="CVE-2020-1", title="x", severity="INFO", confirmed=False)
    f = session.findings[0]
    assert f["confirmed"] is True
    assert f["severity"] == "HIGH"


def test_without_retract_an_upgrade_still_applies(session):
    _record(cve_id="CVE-2020-2", title="x", severity="LOW", confirmed=False)
    _record(cve_id="CVE-2020-2", title="x", severity="HIGH", confirmed=True,
            impact="ACCESS", raw_output="230 login successful")
    f = session.findings[0]
    assert f["confirmed"] is True and f["severity"] == "HIGH"


# ── La retractación explícita corrige ──────────────────────────────────────

def test_retract_downgrades_confirmed_and_severity(session):
    _record(cve_id="CVE-2020-3", title="Candidato NVD", severity="HIGH",
            confirmed=True, impact="ACCESS", raw_output="230 login successful")
    result = _record(cve_id="CVE-2020-3", title="Candidato NVD", severity="INFO",
                     confirmed=False, retract=True,
                     interpretation="El modelo real no está en el rango afectado.")
    assert result["retracted"] is True
    f = session.findings[0]
    assert f["confirmed"] is False
    assert f["severity"] == "INFO"
    assert f["retracted"] is True


def test_retraction_removes_it_from_the_score(session):
    _record(cve_id="CVE-2020-4", title="x", severity="CRITICAL", confirmed=True,
            impact="EXEC", raw_output="uid=0(root)")
    assert compute_risk_score(session.findings)["confirmed_count"] == 1
    _record(cve_id="CVE-2020-4", title="x", severity="INFO", confirmed=False,
            retract=True, interpretation="Falso positivo: era el banner de otro servicio.")
    assert compute_risk_score(session.findings)["confirmed_count"] == 0
    assert compute_risk_score(session.findings)["risk_score"] == 0


def test_retract_clears_the_impact_class(session):
    _record(cve_id="CVE-2020-5", title="x", severity="CRITICAL", confirmed=True,
            impact="EXEC", raw_output="uid=0(root)")
    _record(cve_id="CVE-2020-5", title="x", severity="LOW", confirmed=True,
            retract=True, interpretation="Solo se alcanzó el puerto.")
    f = session.findings[0]
    assert f["impact"] == ""
    assert effective_severity(f) == "LOW"


# ── No es una puerta trasera para inflar ───────────────────────────────────

def test_retract_still_obeys_the_canonical_ceiling(session):
    """Retractar no permite saltarse el techo del tipo de hallazgo."""
    toolbox._record_finding({
        "cve_id": "MDNS-EXPOSED", "title": "mDNS", "severity": "INFO",
        "confirmed": True, "canonical_severity": "INFO",
        "raw_output": '{"model_name": "TV"}',
    })
    _record(cve_id="MDNS-EXPOSED", title="mDNS", severity="CRITICAL",
            confirmed=True, impact="EXEC", retract=True,
            raw_output='{"model_name": "TV"}')
    f = session.findings[0]
    # La severidad declarada sube, pero la EFECTIVA sigue topada por el techo.
    assert effective_severity(f) == "INFO"


def test_retract_on_an_unknown_id_just_records_it(session):
    """Retractar algo que no existe no debe petar ni crear un estado raro."""
    result = _record(cve_id="CVE-2099-9", title="x", severity="INFO",
                     confirmed=False, retract=True)
    assert result["ok"] is True
    assert result.get("merged") is False
    assert len(session.findings) == 1
