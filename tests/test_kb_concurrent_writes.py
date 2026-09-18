"""Dos auditorías concurrentes no deben borrarse el aprendizaje mutuamente.

Cada run carga la KB al arrancar y la guarda ENTERA al terminar. El dashboard
lanza auditorías concurrentes —una por target, hasta 16—, así que dos runs
solapados partían del mismo estado inicial y el segundo en terminar
sobrescribía lo aprendido por el primero. El aprendizaje entre auditorías (OM2)
se perdía justamente cuando más ejecuciones había, y de forma invisible: el
fichero resultante siempre es JSON válido.

`save()` relee ahora el disco bajo cerrojo y funde antes de escribir.
"""
import json
import os

import pytest

from core.knowledge_base import KnowledgeBase


@pytest.fixture
def kb_path(tmp_path):
    return str(tmp_path / "kb.json")


def _fresh(path):
    kb = KnowledgeBase(path=path)
    kb.load()
    return kb


def test_concurrent_runs_keep_both_devices(kb_path):
    """El escenario real: dos targets distintos auditados a la vez."""
    run_a = _fresh(kb_path)
    run_b = _fresh(kb_path)          # ambos parten del mismo estado (vacío)

    run_a.upsert_device("10.0.0.1", {"vendor": "Acme",
                                     "mac": "00:1A:2B:00:00:01"}, [])
    run_b.upsert_device("10.0.0.2", {"vendor": "Globex",
                                     "mac": "00:1A:2B:00:00:02"}, [])

    run_a.save()
    run_b.save()                     # el que termina el último no debe pisar

    disk = json.loads(open(kb_path, encoding="utf-8").read())
    macs = {d.get("mac") for d in disk["devices_seen"].values()}
    assert macs == {"00:1A:2B:00:00:01", "00:1A:2B:00:00:02"}


def test_vendor_profiles_from_both_runs_survive(kb_path):
    run_a = _fresh(kb_path)
    run_b = _fresh(kb_path)
    run_a.upsert_vendor_profile("Acme", useful_probes=["probe_ssh"])
    run_b.upsert_vendor_profile("Globex", useful_probes=["probe_mqtt"])
    run_a.save()
    run_b.save()

    reloaded = _fresh(kb_path)
    assert reloaded.get_vendor_profile("Acme") is not None
    assert reloaded.get_vendor_profile("Globex") is not None


def test_same_vendor_learned_by_both_runs_is_merged(kb_path):
    run_a = _fresh(kb_path)
    run_b = _fresh(kb_path)
    run_a.upsert_vendor_profile("Acme", useful_probes=["probe_ssh"])
    run_b.upsert_vendor_profile("Acme", useful_probes=["probe_mqtt"])
    run_a.save()
    run_b.save()

    probes = _fresh(kb_path).get_vendor_profile("Acme")["useful_probes"]
    assert set(probes) == {"probe_ssh", "probe_mqtt"}


def test_cve_history_counters_are_not_rolled_back(kb_path):
    run_a = _fresh(kb_path)
    run_b = _fresh(kb_path)
    for _ in range(3):
        run_a.record_cve_test("CVE-2020-1", confirmed=False, vendor="Acme")
    run_b.record_cve_test("CVE-2020-1", confirmed=False, vendor="Acme")
    run_a.save()
    run_b.save()

    hist = _fresh(kb_path).get_cve_history("CVE-2020-1")
    # Se conserva el recuento MÁS ALTO: el run corto no puede deshacer el largo.
    assert hist["tested_n_times"] == 3


def test_global_stats_never_decrease(kb_path):
    run_a = _fresh(kb_path)
    run_b = _fresh(kb_path)
    for _ in range(5):
        run_a.increment_run_stats(findings=2, confirmed=1)
    run_b.increment_run_stats(findings=1, confirmed=0)
    run_a.save()
    run_b.save()

    stats = _fresh(kb_path).data["global_stats"]
    assert stats["runs_total"] == 5
    assert stats["confirmed_total"] == 5


def test_save_still_works_without_flock(kb_path, monkeypatch):
    """En sistemas de ficheros sin `flock`, guardar sin cerrojo es preferible a
    no guardar."""
    import builtins
    real_import = builtins.__import__

    def no_fcntl(name, *args, **kwargs):
        if name == "fcntl":
            raise ImportError("sin fcntl en esta plataforma")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_fcntl)
    kb = _fresh(kb_path)
    kb.upsert_device("10.0.0.3", {"vendor": "Acme", "mac": "00:1A:2B:00:00:03"}, [])
    kb.save()
    monkeypatch.undo()
    assert os.path.isfile(kb_path)
    assert _fresh(kb_path).get_device_record(mac="00:1A:2B:00:00:03") is not None


def test_corrupt_file_on_disk_does_not_lose_the_session(kb_path):
    """Si otro proceso deja el fichero ilegible, este run debe poder guardar
    igualmente lo suyo en vez de abortar."""
    kb = _fresh(kb_path)
    kb.upsert_device("10.0.0.4", {"vendor": "Acme", "mac": "00:1A:2B:00:00:04"}, [])
    with open(kb_path, "w", encoding="utf-8") as f:
        f.write("{ esto no es json")
    kb.save()
    assert _fresh(kb_path).get_device_record(mac="00:1A:2B:00:00:04") is not None
