"""La gobernanza de severidad debe aplicarse en TODO el sistema, no solo en el informe.

`is_confirmed_vuln` existe para que un resultado NEGATIVO verificado —«las
credenciales por defecto NO funcionan», registrado como INFO con
`confirmed=True`— no cuente como vulnerabilidad. Pero la función vivía dentro de
`core/tools.py` y solo se usaba allí: la KB, la reflexión, `audit_status` y el
arnés de baseline leían el campo crudo `confirmed`. Consecuencia: el informe
publicaba «1 confirmado» mientras la KB aprendía «2», el revisor post-run
elogiaba hallazgos inexistentes y el CVE recién descartado se borraba de
`patched_cves` como si se hubiera explotado.

Estas pruebas fijan que todos los consumidores cuenten IGUAL.
"""
import core.tools as toolbox
from core.knowledge_base import KnowledgeBase
from core.reflection import _build_findings_summary
from core.severity import compute_risk_score, is_confirmed_vuln


# Un negativo verificado: el agente comprobó la AUSENCIA de la vuln.
NEGATIVE = {
    "cve_id": "WEB-AUTH-DEFAULT-CREDS",
    "severity": "INFO",
    "confirmed": True,
    "interpretation": "Las credenciales por defecto NO funcionan (401 en todas).",
}
# Una vulnerabilidad real con impacto demostrado.
REAL = {
    "cve_id": "CVE-2020-1111",
    "severity": "CRITICAL",
    "confirmed": True,
    "impact": "EXEC",
    "raw_output": "uid=0(root) gid=0(root)",
}
FINDINGS = [NEGATIVE, REAL]


def test_the_premise_one_of_the_two_is_not_a_vulnerability():
    assert is_confirmed_vuln(NEGATIVE) is False
    assert is_confirmed_vuln(REAL) is True
    assert compute_risk_score(FINDINGS)["confirmed_count"] == 1


def test_kb_device_record_counts_like_the_report():
    kb = KnowledgeBase(path="/tmp/does-not-need-to-exist.json")
    kb.upsert_device("10.0.0.9", {"vendor": "Acme", "mac": "00:1A:2B:3C:4D:5E"},
                     FINDINGS)
    record = kb.get_device_record(mac="00:1A:2B:3C:4D:5E")
    assert record["confirmed_count_last"] == 1, "la KB no debe contar el negativo"


def test_reflection_summary_does_not_mark_the_negative_as_confirmed():
    summary = _build_findings_summary(FINDINGS)
    lines = summary.strip().split("\n")
    negative_line = next(l for l in lines if "WEB-AUTH-DEFAULT-CREDS" in l)
    real_line = next(l for l in lines if "CVE-2020-1111" in l)
    assert "✗ unconfirmed" in negative_line
    assert "✓ CONFIRMED" in real_line


def test_reflection_summary_shows_when_severity_was_capped():
    """El revisor debe poder ver que el agente reclamó más de lo que demostró."""
    inflated = {"cve_id": "X-1", "severity": "CRITICAL", "confirmed": True,
                "impact": "EXPOSURE", "raw_output": "port 23 open"}
    line = _build_findings_summary([inflated])
    assert "LOW←CRITICAL" in line


def test_audit_status_agrees_with_the_report(monkeypatch):
    session = toolbox.AgentSession(target_ip="10.0.0.9")
    session.findings = list(FINDINGS)
    toolbox.bind_session(session)
    try:
        status = toolbox._audit_status({})
        risk = compute_risk_score(session.findings)
        assert status["findings_confirmed"] == risk["confirmed_count"] == 1
        # Y expone la diferencia en vez de esconderla.
        assert status["findings_marked_confirmed"] == 2
    finally:
        toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))


def test_baseline_harness_uses_the_same_rule():
    from scripts.baseline_scan import build_comparison
    risk = compute_risk_score(FINDINGS)
    comparison = build_comparison("nmap", FINDINGS, risk)
    assert comparison["confirmed_exploited"] == 1
    assert comparison["candidates_unconfirmed"] == 1


def test_no_undeclared_raw_confirmed_reads():
    """Guard de arquitectura: contar `confirmed` a mano reabre la brecha.

    Este defecto no se arregla una vez: reaparece cada vez que alguien necesita
    «cuántos confirmados hay» y escribe el filtro obvio. En lugar de confiar en
    la disciplina, se comprueba mecánicamente.

    Hay dos lecturas crudas legítimas —la heurística de fabricante y el
    diagnóstico `capped` de `audit_status`—, ambas marcadas en el código con
    `GOBERNANZA-OK` y una razón. El marcador convierte la excepción en una
    decisión explícita y revisable; su ausencia delata un descuido.
    """
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parent.parent
    pattern = re.compile(r'\.get\(\s*["\']confirmed["\']\s*\)')
    offenders = []
    for path in (list(root.glob("core/*.py")) + list(root.glob("api/**/*.py"))
                 + list(root.glob("scripts/*.py")) + list(root.glob("modules/*.py"))):
        if path.name == "severity.py":
            continue  # es la definición de la política, no un consumidor
        lines = path.read_text(encoding="utf-8").split("\n")
        for n, line in enumerate(lines, 1):
            if not pattern.search(line):
                continue
            context = "\n".join(lines[max(0, n - 10):n])
            if "GOBERNANZA-OK" in context:
                continue
            offenders.append(f"{path.relative_to(root)}:{n}  {line.strip()}")
    assert not offenders, (
        "Lecturas crudas de `confirmed` sin declarar. Usa `is_confirmed_vuln` o, "
        "si de verdad es una excepción, márcala con `GOBERNANZA-OK` y explica "
        "por qué:\n  " + "\n  ".join(offenders)
    )
