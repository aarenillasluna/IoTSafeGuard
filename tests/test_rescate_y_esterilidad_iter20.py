"""iter_20 — que el trabajo sobreviva a la forma de terminar.

De las quince ejecuciones de campo del 2026-08-09, **dos se perdieron enteras**
y por motivos opuestos:

  · una encadenó 274 turnos adivinando rutas (`te_zoom.asp`, `te_yes.asp`,
    `te_404.asp`…) contra un router que devolvía 404 a todas, y hubo que
    matarla a mano;
  · otra murió en el turno 7, con la identidad ya fijada y 32 CVE candidatos
    en la mano, porque se apagó el ordenador.

Ninguna dejó informe. El pipeline solo escribía artefactos cuando el modelo
llamaba a `done()`, de modo que las otras diez formas de terminar —presupuesto,
reloj, 429, error de API, Ctrl+C, el `SIGTERM` del panel, un apagón— tiraban a
la basura todo lo obtenido. En una tanda de N réplicas eso no es una molestia:
es que N deja de ser N, y los umbrales de la varianza no se alcanzan.

Se cubren aquí las tres piezas que lo arreglan:
  1. el rescate del informe en `BaseReActAgent.run`,
  2. la guarda de esterilidad, que mira el RESULTADO y no la petición,
  3. la reparación de invariantes de la KB en el punto de ESCRITURA.
"""
import json

import pytest

from core import tools as toolbox
from core.agent_guards import (
    SterileStreakDetector,
    _is_sterile,
    build_sterile_warning,
)
from core.base_agent import BaseReActAgent


# ── 1. Rescate del informe ─────────────────────────────────────────────────

@pytest.fixture
def sesion(tmp_path, monkeypatch):
    """Sesión ligada con un hallazgo y un escaneo, como a mitad de auditoría."""
    s = toolbox.AgentSession(target_ip="192.0.2.10")
    s.findings = [{"cve_id": "TEST-1", "severity": "MEDIUM", "confirmed": True,
                   "impact": "DISCLOSURE", "title": "hallazgo de prueba"}]
    s.scan_cache = {"mac": "14:7F:67:11:22:33", "vendor": "ACME",
                    "ports": [{"port": 80, "proto": "tcp"}]}
    toolbox.bind_session(s)
    return s


def test_el_informe_se_guarda_aunque_no_se_llame_a_done(sesion, tmp_path, monkeypatch):
    """El caso del apagón: el run muere en el turno 7 y el trabajo se conserva."""
    guardados = {}

    def _fake_save(args):
        guardados["llamado"] = True
        sesion.report_saved_path = str(tmp_path / "audit_report_X")
        return {"ok": True, "path": sesion.report_saved_path}

    monkeypatch.setattr(toolbox, "_save_report", _fake_save)
    BaseReActAgent._rescue_report("wall_clock_timeout", turns=7)

    assert guardados.get("llamado"), "un run sin done() debe dejar informe igual"
    assert sesion.finish_reason == "wall_clock_timeout"
    assert sesion.turns_completed == 7


def test_el_rescate_no_duplica_el_informe_que_done_ya_guardo(sesion, monkeypatch):
    """La ruta feliz no debe escribir dos veces: `done()` ya guardó."""
    sesion.report_saved_path = "/ya/existe"
    monkeypatch.setattr(toolbox, "_save_report",
                        lambda a: pytest.fail("no debería volver a guardar"))
    assert BaseReActAgent._rescue_report("done_called", turns=40) is None


def test_un_run_que_no_vio_nada_no_deja_informe_vacio(monkeypatch):
    """Sin hallazgos y sin escaneo no hay nada que contar. Un informe de cero
    puertos y cero hallazgos es exactamente el artefacto que la suite estuvo
    dejando en `reports/` e inflando las estadísticas de varianza."""
    toolbox.bind_session(toolbox.AgentSession(target_ip="192.0.2.11"))
    monkeypatch.setattr(toolbox, "_save_report",
                        lambda a: pytest.fail("no debería guardar un run vacío"))
    assert BaseReActAgent._rescue_report("auth_error", turns=1) is None


def test_el_rescate_sobrevive_a_un_fallo_al_guardar(sesion, monkeypatch):
    """Si el guardado falla, se registra y se sigue: el rescate corre en el
    camino de salida (a veces con una señal encima) y no puede ser el motivo de
    que el proceso reviente."""
    def _explota(args):
        raise OSError("disco lleno")

    monkeypatch.setattr(toolbox, "_save_report", _explota)
    assert BaseReActAgent._rescue_report("aborted: AbortadaPorSenal") is None


def test_run_rescata_el_informe_cuando_el_bucle_lanza(monkeypatch, tmp_path):
    """La captura es de `BaseException`: un Ctrl+C o el SIGTERM del panel no
    heredan de `Exception` y eran justo los que más informes perdían."""
    rescates = []

    class _AgenteQueMuere(BaseReActAgent):
        cfg = type("cfg", (), {"model": "m", "initial_phase": "recon"})()
        observer = type("obs", (), {
            "trace": lambda self, **k: __import__("contextlib").nullcontext(
                type("t", (), {"update": lambda s, **kk: None})()),
            "flush": lambda self: None,
        })()

        def _run_inner(self, goal, root_trace):
            raise KeyboardInterrupt()

    monkeypatch.setattr(BaseReActAgent, "_rescue_report",
                        staticmethod(lambda r, t=0: rescates.append(r)))
    with pytest.raises(KeyboardInterrupt):
        _AgenteQueMuere().run("objetivo")
    assert rescates == ["aborted: KeyboardInterrupt"]


def test_done_marca_el_run_como_completo(sesion, monkeypatch):
    """`interrupted` en el informe se deriva de `finish_reason`, así que `done()`
    tiene que dejarlo puesto o todo run completo se etiquetaría como rescatado."""
    monkeypatch.setattr(toolbox, "_save_report",
                        lambda a: {"ok": True, "path": "/x"})
    sesion.report_saved_path = "/x"  # evita el auto-guardado interno
    toolbox._done({"summary": "fin"})
    assert sesion.finish_reason == "done_called"


# ── 2. Guarda de esterilidad ───────────────────────────────────────────────

_404 = {"ok": True, "error_type": "FAIL",
        "output": "<H2>Access Error: 404 -- Not Found</H2>"}
_UTIL = {"ok": True, "error_type": "NONE", "output": "Server: lighttpd/1.4.35"}


def test_un_404_es_esteril_aunque_el_comando_funcione():
    """La distinción que faltaba: el comando se ejecuta bien (`ok=True`) y aun
    así no dice nada nuevo. Mirar `ok` no bastaba."""
    assert _is_sterile(_404) is True
    assert _is_sterile(_UTIL) is False
    assert _is_sterile({"ok": True, "output": "   "}) is True
    assert _is_sterile({"_finish": True, "ok": False}) is False


def test_la_enumeracion_a_ciegas_dispara_aviso_y_luego_corte():
    """Reproduce el run perdido: llamadas TODAS DISTINTAS, todas estériles."""
    det = SterileStreakDetector(threshold=10, hard_limit=25)
    veredictos = [
        det.observe("execute_command", {"cmd": f"curl http://h/te_{i}.asp"},
                    _404, gained_finding=False)
        for i in range(25)
    ]
    assert veredictos[9] == "warn", "aviso en la décima"
    assert veredictos[24] == "stop", "corte en la vigesimoquinta"
    assert veredictos.count("stop") == 1


def test_un_hallazgo_rompe_la_racha_aunque_el_comando_falle():
    """Registrar un negativo confirmado ES un resultado. Si la guarda no lo
    tuviera en cuenta, castigaría justo la disciplina que el informe exige."""
    det = SterileStreakDetector(threshold=3, hard_limit=6)
    for _ in range(2):
        det.observe("execute_command", {"cmd": "x"}, _404, gained_finding=False)
    assert det.streak == 2
    det.observe("probe_rtsp", {"ip": "h"}, _404, gained_finding=True)
    assert det.streak == 0


def test_un_resultado_util_rompe_la_racha():
    det = SterileStreakDetector(threshold=3)
    det.observe("execute_command", {"cmd": "a"}, _404, gained_finding=False)
    det.observe("execute_command", {"cmd": "b"}, _UTIL, gained_finding=False)
    assert det.streak == 0


def test_volver_a_una_ruta_ya_descartada_se_detecta():
    """`te_block.asp` se pidió en el turno 175 y otra vez en el 274: el modelo
    recorrió su lista de palabras entera y volvió a empezar. Noventa y nueve
    turnos de distancia lo hacen invisible para el detector de ciclos, que solo
    mira los últimos 50 y patrones de hasta 4."""
    det = SterileStreakDetector(threshold=50, hard_limit=200)
    args = {"cmd": "curl http://h/te_block.asp"}
    assert det.observe("execute_command", args, _404, gained_finding=False) is None
    for i in range(30):
        det.observe("execute_command", {"cmd": f"curl http://h/x{i}"}, _404,
                    gained_finding=False)
    assert det.observe("execute_command", args, _404, gained_finding=False) == "warn"
    assert det.last_reason == "revisit"


def test_el_reset_de_fase_olvida_la_racha_pero_no_lo_descartado():
    """Que una ruta diera 404 en recon sigue siendo cierto en exploit."""
    det = SterileStreakDetector(threshold=3)
    det.observe("execute_command", {"cmd": "a"}, _404, gained_finding=False)
    ya_vistas = len(det.sterile_hashes)
    det.reset()
    assert det.streak == 0
    assert len(det.sterile_hashes) == ya_vistas


def test_los_avisos_nombran_la_salida_no_solo_el_problema():
    """Un rechazo que no dice qué hacer produce reintentos; se aprendió en
    iter_19 con los mensajes del PolicyEngine."""
    for reason in ("sterile_streak", "revisit"):
        aviso = build_sterile_warning("execute_command", 12, reason)
        assert "audit_status" in aviso or "save_report" in aviso
        assert aviso.strip()


# ── 3. Invariantes de la KB, reparados donde se escribe ────────────────────

def _kb_corrupta(tmp_path):
    from core.knowledge_base import KnowledgeBase, KB_SCHEMA_VERSION, _empty_kb
    path = tmp_path / "kb.json"
    data = _empty_kb()
    data["version"] = KB_SCHEMA_VERSION
    data["global_stats"] = {"runs_total": 42, "findings_total": 9, "confirmed_total": 3}
    data["devices_seen"] = {
        "74:93:DA:5B:8B:80": {"vendor": "ASKEY", "model": "CURVE25519",
                              "mac": "74:93:DA:5B:8B:80",
                              "audit_count": 1015839, "ip": "192.0.2.1"},
    }
    data["vendor_profiles"] = {"ASKEY": {"device_count": 2490491, "useful_probes": []}}
    path.write_text(json.dumps(data), encoding="utf-8")
    return KnowledgeBase, path


def test_el_contador_imposible_no_resucita_al_guardar(tmp_path):
    """El fallo que sobrevivió a la versión que decía haberlo arreglado.

    La reparación estaba solo en `load()`, pero `save()` refunde el fichero de
    disco tomando el MÁXIMO entre disco y memoria: el valor corrupto —que seguía
    ahí— ganaba siempre y volvía a escribirse. Un `audit_count` de 1.040.188.384
    aguantó así una tanda entera de quince ejecuciones.
    """
    KnowledgeBase, path = _kb_corrupta(tmp_path)
    kb = KnowledgeBase(path=str(path))
    kb.load()
    kb.save()

    en_disco = json.loads(path.read_text(encoding="utf-8"))
    assert en_disco["devices_seen"]["74:93:DA:5B:8B:80"]["audit_count"] == 42
    assert en_disco["vendor_profiles"]["ASKEY"]["device_count"] == 1


def test_el_modelo_criptografico_se_purga_del_almacen(tmp_path):
    """`_extract_model_from_text` ya no produce «CURVE25519», pero el que produjo
    seguía en la KB y de ahí salía al informe, al CPE y a la búsqueda de CVE:
    arreglar el extractor no tocó ni uno de los registros ya envenenados."""
    KnowledgeBase, path = _kb_corrupta(tmp_path)
    kb = KnowledgeBase(path=str(path))
    kb.load()
    kb.save()
    en_disco = json.loads(path.read_text(encoding="utf-8"))
    assert en_disco["devices_seen"]["74:93:DA:5B:8B:80"]["model"] is None


def test_la_reparacion_es_idempotente(tmp_path):
    """Sobre una KB sana no debe cambiar nada: si no, cada guardado movería las
    cifras y el aprendizaje entre auditorías dejaría de ser comparable."""
    KnowledgeBase, path = _kb_corrupta(tmp_path)
    kb = KnowledgeBase(path=str(path)); kb.load(); kb.save()
    primera = json.loads(path.read_text(encoding="utf-8"))
    kb2 = KnowledgeBase(path=str(path)); kb2.load(); kb2.save()
    segunda = json.loads(path.read_text(encoding="utf-8"))
    primera.pop("last_updated"); segunda.pop("last_updated")
    assert primera == segunda
