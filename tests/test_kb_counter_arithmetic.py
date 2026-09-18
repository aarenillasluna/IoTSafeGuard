"""Los contadores de la KB no pueden crecer solos.

Hay dos escenarios de fusión con aritmética OPUESTA, y usar la de uno en el
otro fue el fallo que estas pruebas fijan:

  · historiales DISJUNTOS — dos claves distintas resultan ser el mismo aparato
    (migración IP→MAC, alias de interfaz). Sumar es correcto.
  · historiales SOLAPADOS — la misma clave en memoria y en disco
    (`_merge_from_disk`). El registro en memoria ya contiene el del disco: se
    cargó al arrancar. Sumar duplica en CADA save.

Como se guarda varias veces por auditoría, el crecimiento era exponencial. En
15 ejecuciones reales contra tres aparatos de casa quedó así::

    LG     audit_count: 1.040.188.384   device_count: 3.556.776.512
    Amazon audit_count:    32.537.600   device_count:    58.756.096
    ASKEY  audit_count:     1.015.839   device_count:     2.490.491

Y no era solo cosmético: `audit_count` viaja al prompt del run siguiente dentro
de `kb_context.previous_audit`, así que al modelo se le decía que ese router
llevaba medio millón de auditorías encima.
"""
import json

import pytest

from core.knowledge_base import (KnowledgeBase, _merge_device_records,
                                 _merge_vendor_profiles)


@pytest.fixture
def kb(tmp_path):
    return KnowledgeBase(path=str(tmp_path / "kb.json"))


# ── La aritmética de cada escenario ────────────────────────────────────────

def test_historiales_disjuntos_suman():
    """Migración: dos claves que resultan ser el mismo aparato."""
    a = {"audit_count": 3, "last_seen": "2026-01-01"}
    b = {"audit_count": 4, "last_seen": "2026-02-01"}
    assert _merge_device_records(a, b)["audit_count"] == 7


def test_historiales_solapados_toman_el_maximo():
    """Disco vs. memoria: el de memoria ya incluye al de disco."""
    disco = {"audit_count": 5, "last_seen": "2026-01-01"}
    memoria = {"audit_count": 6, "last_seen": "2026-02-01"}
    assert _merge_device_records(disco, memoria, counters="max")["audit_count"] == 6


def test_perfiles_de_vendor_siguen_el_mismo_criterio():
    a = {"device_count": 2}
    b = {"device_count": 3}
    assert _merge_vendor_profiles(a, b)["device_count"] == 5
    assert _merge_vendor_profiles(a, b, counters="max")["device_count"] == 3


# ── El síntoma que se veía en campo ────────────────────────────────────────

def test_guardar_muchas_veces_no_multiplica_el_contador(kb):
    """Diez auditorías del mismo aparato → diez, no 2¹⁰."""
    scan = {"mac": "14:7F:67:AF:0C:6A", "vendor": "LG", "ports": []}
    for i in range(10):
        kb.upsert_device("192.168.1.34", scan, [], run_id=f"run-{i}")
        kb.save()          # cada save funde con lo que hay en disco
        kb.save()          # y guardar dos veces seguidas tampoco debe doblar

    record = kb.get_device_record(mac="14:7F:67:AF:0C:6A")
    assert record["audit_count"] == 10

    en_disco = json.loads((kb.path and open(kb.path).read()) or "{}")
    grabado = en_disco["devices_seen"]["14:7F:67:AF:0C:6A"]["audit_count"]
    assert grabado == 10, "el fichero debe coincidir con la memoria"


def test_dos_procesos_concurrentes_no_se_duplican_mutuamente(tmp_path):
    """Dos auditorías solapadas (el caso que motivó `_merge_from_disk`).

    Cada una carga el mismo estado inicial y guarda al terminar. Lo aprendido
    por ambas debe conservarse, y el contador no puede sumarse dos veces.

    Esta prueba esperaba **2** mientras el contador se fusionaba con `max()`, y
    ese 2 era el error simétrico del que motivó el arreglo: tomando el máximo,
    dos auditorías solapadas contaban como una sola y el histórico PERDÍA
    ejecuciones. Con el conjunto de identificadores no hay que elegir entre
    duplicar y perder: la unión da 3, que es cuántas auditorías hubo.
    """
    path = str(tmp_path / "kb.json")
    scan = {"mac": "14:7F:67:11:22:33", "vendor": "Acme", "ports": []}

    primera = KnowledgeBase(path=path)
    primera.load()
    primera.upsert_device("10.0.0.1", scan, [], run_id="run-1")
    primera.save()                                   # audit_count = 1

    a, b = KnowledgeBase(path=path), KnowledgeBase(path=path)
    a.load(); b.load()                               # ambas ven 1
    a.upsert_device("10.0.0.1", scan, [], run_id="run-2")
    b.upsert_device("10.0.0.1", scan, [], run_id="run-3")
    a.save(); b.save()

    final = KnowledgeBase(path=path)
    final.load()
    record = final.get_device_record(mac="14:7F:67:11:22:33")
    assert record["audit_count"] == 3, "tres auditorías, ninguna perdida"
    assert record["audit_runs"] == ["run-1", "run-2", "run-3"]


# ── Reparación de lo ya corrupto ───────────────────────────────────────────

def test_la_carga_repara_contadores_imposibles(tmp_path):
    path = tmp_path / "kb.json"
    path.write_text(json.dumps({
        "version": 1,
        "global_stats": {"runs_total": 30, "findings_total": 0, "confirmed_total": 0},
        "devices_seen": {
            "14:7F:67:AF:0C:6A": {"vendor": "LG", "mac": "14:7F:67:AF:0C:6A",
                                  "audit_count": 1040188384},
        },
        "vendor_profiles": {
            "LG": {"device_count": 3556776512, "useful_probes": []},
        },
    }))
    kb = KnowledgeBase(path=str(path))
    kb.load()

    # `runs_total` es una cota superior, no el valor real: la cifra original es
    # irrecuperable. Se prefiere una cota defendible a un número inventado.
    assert kb.data["devices_seen"]["14:7F:67:AF:0C:6A"]["audit_count"] <= 30
    assert kb.data["vendor_profiles"]["LG"]["device_count"] == 1


def test_la_reparacion_no_toca_una_kb_sana(tmp_path):
    path = tmp_path / "kb.json"
    sana = {
        "version": 1,
        "global_stats": {"runs_total": 30, "findings_total": 0, "confirmed_total": 0},
        "devices_seen": {
            "14:7F:67:AF:0C:6A": {"vendor": "LG", "mac": "14:7F:67:AF:0C:6A",
                                  "audit_count": 12},
        },
        "vendor_profiles": {"LG": {"device_count": 1, "useful_probes": ["probe_snmp"]}},
    }
    path.write_text(json.dumps(sana))
    kb = KnowledgeBase(path=str(path))
    kb.load()
    assert kb.data["devices_seen"]["14:7F:67:AF:0C:6A"]["audit_count"] == 12
    assert kb.data["vendor_profiles"]["LG"]["device_count"] == 1
    assert kb.data["vendor_profiles"]["LG"]["useful_probes"] == ["probe_snmp"]
