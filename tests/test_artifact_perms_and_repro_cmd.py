"""Persistencia usable y nombres de campo honestos (iter_18, 2.ª tanda).

Dos defectos que compartían la misma naturaleza: el sistema *decía* una cosa y
*hacía* otra, sin producir ningún error.

  1. **Artefactos ilegibles.** `tempfile` crea los ficheros con modo 0600 por
     diseño y `os.replace` conserva ese modo, así que la escritura atómica —
     introducida para no corromper la KB ante un `kill -9`— dejaba
     `data/kb.json` y `data/nvd_cache.json` en 0600. Ejecutando con `sudo` (que
     `nmap` exige) quedaban además `root:root`: ni el dashboard ni una ejecución
     sin sudo podían leerlos, de modo que el aprendizaje entre auditorías (OM2) y
     la caché NVD en disco estaban apagados con un simple WARNING de aviso.
  2. **`executed_cmd`.** El campo contiene el comando que *reproduce* un hallazgo
     —a menudo solo el nombre de la sonda que lo emitió—, no una prueba de que se
     ejecutara. En un informe cuya disciplina es separar la prueba de la
     interpretación, el nombre afirmaba más que el dato.
"""
import json
import os
import stat

import pytest

from core import fsutil
from modules.reporter import repro_cmd_of


# --------------------------------------------------------------- permisos

def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_kb_save_leaves_the_file_readable(tmp_path, monkeypatch):
    """La KB persistida tiene que poder leerla alguien que no sea quien la escribió."""
    from core.knowledge_base import KnowledgeBase
    kb_path = tmp_path / "data" / "kb.json"
    kb = KnowledgeBase(path=str(kb_path))
    kb.save()
    assert kb_path.is_file()
    assert _mode(str(kb_path)) == fsutil.FILE_MODE, (
        "kb.json quedaba en 0600 por el tempfile de la escritura atómica")
    # Y sigue siendo JSON válido: el fix de permisos no toca el contenido.
    assert json.loads(kb_path.read_text(encoding="utf-8"))["version"] == 1


def test_nvd_disk_cache_leaves_the_file_readable(tmp_path, monkeypatch):
    """Misma trampa en la caché NVD: si nace 0600, cada run vuelve a la red."""
    import modules.cve_api as cve_api
    cache_path = tmp_path / "data" / "nvd_cache.json"
    monkeypatch.setattr(cve_api, "_DISK_CACHE_PATH", str(cache_path))
    cve_api._disk_cache_put("dnsmasq|2.45|", [{"id": "CVE-2017-14491"}])
    assert cache_path.is_file()
    assert _mode(str(cache_path)) == fsutil.FILE_MODE


def test_reports_are_published_readable(tmp_path):
    from modules.reporter import Reporter
    r = Reporter(report_dir=str(tmp_path / "reports"))
    r.add_entry(ip="192.168.1.50", os_match="Linux", ports=[], attack_plan="",
                attack_results=[])
    base = r.generate_reports()
    for suffix in (".json", ".md", ".html", ".sarif"):
        path = f"{base}{suffix}"
        assert os.path.isfile(path)
        assert _mode(path) == fsutil.FILE_MODE, f"{suffix} no legible"


def test_publish_artifact_is_best_effort_and_idempotent(tmp_path):
    """Nunca debe tumbar una auditoría ya terminada por un problema de permisos."""
    fsutil.publish_artifact(str(tmp_path / "no-existe.json"))  # no revienta
    f = tmp_path / "x.json"
    f.write_text("{}", encoding="utf-8")
    fsutil.publish_artifact(str(f))
    fsutil.publish_artifact(str(f))  # idempotente
    assert _mode(str(f)) == fsutil.FILE_MODE


def test_sudo_owner_reads_the_invoking_user(monkeypatch):
    """Bajo sudo hay que devolver la propiedad al usuario real, no dejarla en root."""
    monkeypatch.setattr(fsutil.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1001")
    assert fsutil.sudo_owner() == (1000, 1001)
    # Sin SUDO_UID (root de verdad, no sudo) no hay a quién devolverla.
    monkeypatch.delenv("SUDO_UID")
    assert fsutil.sudo_owner() is None
    # Y sin ser root tampoco: el propietario ya es el correcto.
    monkeypatch.setattr(fsutil.os, "geteuid", lambda: 1000)
    monkeypatch.setenv("SUDO_UID", "1000")
    assert fsutil.sudo_owner() is None


def test_sudo_owner_survives_a_corrupt_environment(monkeypatch):
    monkeypatch.setattr(fsutil.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "no-es-un-numero")
    assert fsutil.sudo_owner() is None


# --------------------------------------------------------------- repro_cmd

def test_report_payload_uses_repro_cmd():
    import core.tools as toolbox
    toolbox.build_registry()
    toolbox.bind_session(toolbox.AgentSession(target_ip="192.168.1.50"))
    toolbox.dispatch("record_finding", {
        "cve_id": "TELNET-DEFAULT-CRED", "title": "Telnet con credenciales por defecto",
        "severity": "CRITICAL", "confirmed": True, "impact": "ACCESS",
        "raw_output": "uid=0(root) gid=0(root)",
        "cmd": "printf 'root\\nroot\\nid\\nexit\\n' | nc 192.168.1.50 23",
    })
    payload = toolbox._build_report_payload() if hasattr(toolbox, "_build_report_payload") else None
    if payload is None:  # el payload se construye dentro de _save_report
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            toolbox.dispatch("save_report", {"out_dir": d})
            report = json.load(open(f"{toolbox.get_session().report_saved_path}.json"))
    else:
        report = payload
    entry = report["findings"][0]["attack_results"][0]
    assert "repro_cmd" in entry, "el informe debe emitir `repro_cmd`"
    assert entry["repro_cmd"].startswith("printf")
    assert "executed_cmd" not in entry, "no se reemite el nombre engañoso"


@pytest.mark.parametrize("entry,expected", [
    ({"repro_cmd": "curl -sk http://x/"}, "curl -sk http://x/"),
    ({"executed_cmd": "curl -sk http://x/"}, "curl -sk http://x/"),   # legado
    ({"repro_cmd": "nuevo", "executed_cmd": "viejo"}, "nuevo"),        # gana el actual
    ({}, ""),
    ({"repro_cmd": None, "executed_cmd": None}, ""),
    ("no soy un dict", ""),
])
def test_repro_cmd_of_accepts_both_keys(entry, expected):
    """Los 200+ informes ya generados llevan la clave antigua y el dashboard los
    sigue leyendo: el renombrado no puede romper el histórico."""
    assert repro_cmd_of(entry) == expected


def test_aggregator_reads_legacy_reports(tmp_path, monkeypatch):
    """Un informe con la clave antigua debe seguir mostrando su comando."""
    import api.services.aggregator as agg
    report = {
        "findings": [{
            "target_ip": "192.168.1.50",
            "device_identity": {"vendor": "Netgear", "model": "WNAP320",
                                "mac": "00:DE:FA:1A:01:00"},
            "attack_results": [{
                "cve_id": "CVE-2016-10176", "vuln_found": True, "severity": "HIGH",
                "title": "noauth", "executed_cmd": "curl -sk http://x/apply_noauth.cgi",
                "raw_output": "HTTP/1.1 200 OK",
            }],
        }],
    }
    rep_dir = tmp_path / "reports"
    rep_dir.mkdir()
    (rep_dir / "audit_report_20260725_120000.json").write_text(
        json.dumps(report), encoding="utf-8")
    monkeypatch.setattr(agg, "REPORTS_DIR", str(rep_dir))
    monkeypatch.setattr(agg, "KB_PATH", str(tmp_path / "kb.json"))
    agg.invalidate_cache()

    detail = agg.get_cve("CVE-2016-10176")
    assert detail is not None, "el agregador no leyó el informe legado"
    occurrences = detail.get("occurrences") or []
    assert occurrences
    assert occurrences[0]["repro_cmd"].startswith("curl -sk"), (
        "la clave legada executed_cmd debe seguir alimentando repro_cmd")


def test_aggregator_reads_current_reports(tmp_path, monkeypatch):
    """Y con la clave nueva, obviamente, también."""
    import api.services.aggregator as agg
    report = {
        "findings": [{
            "target_ip": "192.168.1.50",
            "device_identity": {"vendor": "Netgear", "model": "WNAP320",
                                "mac": "00:DE:FA:1A:01:00"},
            "attack_results": [{
                "cve_id": "CVE-2016-10176", "vuln_found": True, "severity": "HIGH",
                "title": "noauth", "repro_cmd": "curl -sk http://x/apply_noauth.cgi",
                "raw_output": "HTTP/1.1 200 OK",
            }],
        }],
    }
    rep_dir = tmp_path / "reports"
    rep_dir.mkdir()
    (rep_dir / "audit_report_20260725_130000.json").write_text(
        json.dumps(report), encoding="utf-8")
    monkeypatch.setattr(agg, "REPORTS_DIR", str(rep_dir))
    monkeypatch.setattr(agg, "KB_PATH", str(tmp_path / "kb.json"))
    agg.invalidate_cache()

    detail = agg.get_cve("CVE-2016-10176")
    assert detail["occurrences"][0]["repro_cmd"].startswith("curl -sk")
