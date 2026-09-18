"""KB clavada por identidad (MAC), nunca por IP. Dos dispositivos en la misma
IP (IP reutilizada) tienen registros separados y no heredan identidad; el mismo
dispositivo en distinta IP acumula su histórico. Incluye la migración perezosa
de claves legadas (IP cruda → identidad).
Regresión: un iPhone tomaba la identidad LG persistida en kb.json por la IP.
"""
import json
from core.knowledge_base import KnowledgeBase, KB_SCHEMA_VERSION

_LG = {"vendor": "LG", "model": "65QNED826RE", "firmware": "p20.33.31.23",
       "mac": "14:7F:67:AF:0C:6A"}


def _fresh(tmp_path):
    kb = KnowledgeBase(path=str(tmp_path / "kb.json"))
    kb.load()
    return kb


def test_iphone_does_not_inherit_lg_at_reused_ip(tmp_path):
    kb = _fresh(tmp_path)
    kb.upsert_device("192.168.1.33", dict(_LG), [])                 # LG auditada en .33
    # iPhone toma la misma IP (MAC privada, sin vendor/model)
    kb.upsert_device("192.168.1.33",
                     {"mac": "2E:F5:E7:FA:84:20", "os_match": "Apple"}, [])
    lg = kb.get_device_record(mac="14:7F:67:AF:0C:6A")
    iph = kb.get_device_record(ip="192.168.1.33", mac="2E:F5:E7:FA:84:20")
    assert lg and lg["vendor"] == "LG" and lg["audit_count"] == 1   # LG intacta
    assert iph is not None and iph.get("vendor") != "LG"           # iPhone NO hereda LG
    assert lg is not iph                                            # registros separados


def test_same_device_accumulates_across_ips(tmp_path):
    kb = _fresh(tmp_path)
    # `run_id` explícito: son DOS auditorías distintas, y simularlas con dos
    # llamadas en el mismo proceso era exactamente la suposición («una llamada =
    # una auditoría») que hacía imposible confiar en el contador.
    kb.upsert_device("192.168.1.10", dict(_LG), [], run_id="run-A")
    first_seen = kb.get_device_record(mac=_LG["mac"])["first_seen"]
    # misma LG (misma MAC) en OTRA IP → mismo registro, acumula
    kb.upsert_device("192.168.1.99", dict(_LG), [], run_id="run-B")
    rec = kb.get_device_record(mac=_LG["mac"])
    assert rec["audit_count"] == 2
    assert rec["first_seen"] == first_seen
    assert rec["ip"] == "192.168.1.99"          # última IP vista (informativo)


def test_lookup_by_ip_only_does_not_match_real_device(tmp_path):
    # Sin MAC, el lookup cae a ip:<ip> y NO debe devolver el device real (MAC).
    kb = _fresh(tmp_path)
    kb.upsert_device("192.168.1.33", dict(_LG), [])
    assert kb.get_device_record(ip="192.168.1.33") is None    # sin mac → no lo encuentra
    assert kb.get_device_record(mac=_LG["mac"]) is not None    # con mac → sí


def test_lazy_migration_rekeys_legacy_ip_keys(tmp_path):
    # kb.json legado con devices_seen clavado por IP cruda → migración a identidad.
    path = tmp_path / "kb.json"
    path.write_text(json.dumps({
        "version": KB_SCHEMA_VERSION,
        "devices_seen": {
            "192.168.1.33": {"vendor": "LG", "model": "65QNED826RE",
                             "mac": "14:7F:67:AF:0C:6A", "audit_count": 5,
                             "first_seen": "2026-01-01T00:00:00"},
            "10.0.0.5": {"vendor": "Sin MAC", "audit_count": 1},  # sin mac → ip:
        },
        "vendor_profiles": {}, "cve_validation_history": {},
        "reflection_log": [], "global_stats": {"runs_total": 0,
                                                "findings_total": 0,
                                                "confirmed_total": 0},
    }))
    kb = KnowledgeBase(path=str(path))
    kb.load()
    # la LG ya no está bajo la IP cruda, sino bajo su MAC
    assert "192.168.1.33" not in kb.data["devices_seen"]
    assert kb.get_device_record(mac="14:7F:67:AF:0C:6A")["audit_count"] == 5
    # el de sin-MAC queda bajo ip:<ip>
    assert kb.get_device_record(ip="10.0.0.5")["vendor"] == "Sin MAC"


def test_migration_idempotent(tmp_path):
    kb = _fresh(tmp_path)
    kb.upsert_device("192.168.1.33", dict(_LG), [])
    keys_before = set(kb.data["devices_seen"].keys())
    kb._migrate_devices_to_identity_keys()       # re-ejecutar no cambia nada
    assert set(kb.data["devices_seen"].keys()) == keys_before
