"""Un aparato con varias interfaces no puede aprenderse como varios dispositivos.

La regla fundacional del proyecto es identificar por `vendor + modelo + MAC`,
nunca por IP. Pero `device_key` clava sobre UNA MAC, y un equipo real tiene
varias: en la tanda de campo del 2026-08-08 el televisor LG declaró tres
—ethernet por ARP, wifi y P2P/Miracast por mDNS—. Conectado hoy por cable y
mañana por wifi, el mismo aparato producía dos claves distintas: la base de
conocimiento partía su histórico, `audit_count` se reiniciaba y el análisis de
varianza contaba sus réplicas como dispositivos separados.

El propio mDNS publica las MAC alternativas, así que hay señal para
correlacionarlas. Se registran como alias, con una cautela importante: NUNCA se
enlaza por una MAC sintética o aleatoria, porque fusionar dos aparatos distintos
es un error peor que no fusionar.
"""
import pytest

from core.knowledge_base import KnowledgeBase
from modules.fingerprint import harvest_macs

ETH = "14:7F:67:AF:0C:6A"     # la que ve ARP
WIFI = "F8:01:B4:BB:5C:15"    # la que publica mDNS en el número de serie
RANDOM = "FE:FB:02:5F:3C:33"  # localmente administrada → rota, no sirve de ancla


@pytest.fixture
def kb(tmp_path):
    k = KnowledgeBase(path=str(tmp_path / "kb.json"))
    k.load()
    return k


# ── Cosecha de MAC desde la evidencia ──────────────────────────────────────

def test_it_finds_a_mac_embedded_in_a_serial_number():
    """El caso real: mDNS publica `404MAJMNJ716_f8:01:b4:bb:5c:15`. Con un `\\b`
    delante la MAC se perdía, porque el guion bajo ES carácter de palabra."""
    evidence = {"tcp_banners": {"x": "serial 404MAJMNJ716_f8:01:b4:bb:5c:15"}}
    assert WIFI in harvest_macs(evidence)


def test_random_and_null_macs_are_never_harvested():
    """Enlazar por una MAC que rota fusionaría aparatos sin relación."""
    found = harvest_macs({"a": RANDOM, "b": "00:00:00:00:00:00"})
    assert found == []


def test_it_deduplicates_across_sources():
    assert harvest_macs({"mac": ETH}, {"other": ETH.lower()}) == [ETH]


# ── Alias en la base de conocimiento ───────────────────────────────────────

def test_the_same_device_on_another_interface_is_the_same_device(kb):
    kb.upsert_device("192.168.1.34", {"vendor": "LG", "mac": ETH,
                                      "also_macs": [WIFI]}, [])
    # Mañana el televisor se conecta por wifi: ARP ve la OTRA MAC.
    record = kb.get_device_record(mac=WIFI)
    assert record is not None, "debe reconocerse como el mismo aparato"
    assert record["vendor"] == "LG"


def test_history_accumulates_instead_of_splitting(kb):
    # Dos auditorías distintas del mismo aparato, una por cada interfaz.
    kb.upsert_device("192.168.1.34", {"vendor": "LG", "mac": ETH,
                                      "also_macs": [WIFI]}, [], run_id="run-A")
    kb.upsert_device("192.168.1.34", {"vendor": "LG", "mac": WIFI}, [], run_id="run-B")
    assert kb.get_device_record(mac=ETH)["audit_count"] == 2
    assert len(kb.data["devices_seen"]) == 1, "un aparato, un registro"


def test_a_record_already_learned_apart_gets_merged(kb):
    """Si la MAC alternativa ya tenía su propio histórico —porque se auditó
    antes de conocer el vínculo—, se funde en lugar de quedar huérfano."""
    kb.upsert_device("192.168.1.40", {"vendor": "LG", "mac": WIFI}, [], run_id="run-A")
    kb.upsert_device("192.168.1.34", {"vendor": "LG", "mac": ETH,
                                      "also_macs": [WIFI]}, [], run_id="run-B")
    assert len(kb.data["devices_seen"]) == 1
    assert kb.get_device_record(mac=WIFI)["audit_count"] == 2


def test_linking_is_idempotent(kb):
    kb.upsert_device("192.168.1.34", {"vendor": "LG", "mac": ETH,
                                      "also_macs": [WIFI]}, [])
    assert kb.link_device_macs(ETH, [WIFI]) == 0


def test_unrelated_devices_are_never_merged(kb):
    kb.upsert_device("192.168.1.34", {"vendor": "LG", "mac": ETH}, [])
    kb.upsert_device("192.168.1.37", {"vendor": "Amazon",
                                      "mac": "C0:8D:51:67:29:4B"}, [])
    assert len(kb.data["devices_seen"]) == 2


def test_aliases_survive_a_save_and_reload(kb, tmp_path):
    kb.upsert_device("192.168.1.34", {"vendor": "LG", "mac": ETH,
                                      "also_macs": [WIFI]}, [])
    kb.save()
    reloaded = KnowledgeBase(path=kb.path)
    reloaded.load()
    assert reloaded.get_device_record(mac=WIFI) is not None


# ── No fusionar aparatos distintos: el riesgo real ────────────────────────
#
# El televisor publica en `/setup/scan_results` el resultado de SU escaneo wifi,
# con el BSSID de los puntos de acceso VECINOS. Un barrido ingenuo del blob los
# recogía y los enlazaba como «otra interfaz» de la tele: la KB habría fusionado
# el televisor con el router del vecino. En la tanda de campo no llegó a pasar
# solo porque esa BSSID concreta era localmente administrada — suerte, no
# diseño: la mayoría de los AP tienen OUI universal.

def test_a_neighbours_access_point_is_never_linked():
    evidence = {
        "serial": "404MAJMNJ716_f8:01:b4:bb:5c:15",
        "scan_results": {"hotspot_bssid": "00:1A:2B:99:88:77"},   # OUI universal
    }
    found = harvest_macs({"mac": ETH}, evidence)
    assert ETH in found and WIFI in found
    assert "00:1A:2B:99:88:77" not in found, "es el AP del vecino, no la tele"


@pytest.mark.parametrize("foreign_key", [
    "scan_results", "configured_networks", "neighbors", "arp_table",
    "wifi_networks", "dhcp_leases", "connected_clients",
])
def test_every_third_party_context_is_pruned(foreign_key):
    found = harvest_macs({foreign_key: {"mac": "00:1A:2B:99:88:77"}})
    assert found == []


def test_pruning_does_not_swallow_the_devices_own_mac():
    """La poda no puede pasarse de celosa: la MAC propia debe seguir saliendo."""
    assert ETH in harvest_macs({"device_identity": {"mac": ETH}})


def test_kb_never_merges_two_real_devices_through_a_foreign_mac(tmp_path):
    kb = KnowledgeBase(path=str(tmp_path / "kb.json")); kb.load()
    router = "00:1A:2B:99:88:77"
    kb.upsert_device("192.168.1.1", {"vendor": "Askey", "mac": router}, [])
    # La tele reporta ese BSSID en su escaneo wifi: no debe absorber al router.
    evidence = {"scan_results": {"hotspot_bssid": router}}
    kb.upsert_device("192.168.1.34", {"vendor": "LG", "mac": ETH,
                                      "also_macs": harvest_macs(evidence)}, [])
    assert len(kb.data["devices_seen"]) == 2
    assert kb.get_device_record(mac=router)["vendor"] == "Askey"
