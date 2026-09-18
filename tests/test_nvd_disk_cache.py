"""Cache NVD persistente en disco (iter_10): deduplica consultas a la NVD ENTRE
runs del CLI (cada invocación es un proceso nuevo), con TTL. Reduce throttling y
hace los runs reproducibles dentro de la ventana.
"""
import time

import pytest

import modules.cve_api as cve_api
from modules.cve_api import NVDCVEClient


@pytest.fixture
def disk_cache(tmp_path, monkeypatch):
    """Aísla la cache en un fichero temporal y resetea el estado de módulo."""
    path = str(tmp_path / "nvd_cache.json")
    monkeypatch.setattr(cve_api, "_DISK_CACHE_PATH", path)
    monkeypatch.setattr(cve_api, "_DISK_CACHE", None)          # fuerza recarga
    monkeypatch.setattr(cve_api, "_DISK_CACHE_TTL", 24 * 3600)
    NVDCVEClient._RESULT_CACHE.clear()                          # L1 limpia
    yield path
    NVDCVEClient._RESULT_CACHE.clear()


def test_put_get_roundtrip(disk_cache):
    cve_api._disk_cache_put("nginx|1.18||1", [{"id": "CVE-2021-23017"}])
    assert cve_api._disk_cache_get("nginx|1.18||1") == [{"id": "CVE-2021-23017"}]


def test_ttl_expiry(disk_cache, monkeypatch):
    cve_api._disk_cache_put("old|x||1", [{"id": "CVE-2000-0001"}])
    # Envejece artificialmente la entrada más allá del TTL.
    cache = cve_api._disk_cache_load()
    cache["old|x||1"]["ts"] = time.time() - (25 * 3600)
    assert cve_api._disk_cache_get("old|x||1") is None


def test_get_cves_persists_across_processes(disk_cache, monkeypatch):
    """La 2ª "ejecución" (L1 limpia, como un proceso nuevo) NO recomputa: lee disco."""
    calls = {"n": 0}

    def fake_uncached(self, product, version, nmap_cpe=None, allow_broad_keyword=True):
        calls["n"] += 1
        return [{"id": "CVE-2016-7406", "severity": "CRITICAL"}]

    monkeypatch.setattr(NVDCVEClient, "_get_cves_uncached", fake_uncached)

    # Run 1: cliente nuevo, computa y escribe a disco.
    c1 = NVDCVEClient(api_key=None)
    r1 = c1.get_cves_for_product("dropbear", "2016.74")
    assert r1 and calls["n"] == 1

    # Simula proceso nuevo: L1 (cache de clase) vacía + nuevo cliente.
    NVDCVEClient._RESULT_CACHE.clear()
    cve_api._DISK_CACHE = None  # fuerza recarga desde el fichero
    c2 = NVDCVEClient(api_key=None)
    r2 = c2.get_cves_for_product("dropbear", "2016.74")

    assert r2 == r1
    assert calls["n"] == 1            # NO se recomputó: vino del disco


def test_corrupt_cache_degrades_gracefully(disk_cache):
    with open(disk_cache, "w") as f:
        f.write("{ not json")
    cve_api._DISK_CACHE = None
    # No crashea: cache ilegible → dict vacío.
    assert cve_api._disk_cache_get("whatever|||1") is None
