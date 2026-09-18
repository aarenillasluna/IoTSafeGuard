"""Identidad por MAC, nunca por IP: un dispositivo en una IP reutilizada NO debe
heredar la identidad del registro KB previo (indexado por IP) si la MAC difiere.
Regresión del bug: Xiaomi/ESP8266 (MAC 7C:C2:94…) aparecía como LG 65QNED826RE
porque esa IP la tuvo antes la LG TV.
"""
from core.tools import _resolve_device_identity

_LG = {"vendor": "LG", "model": "65QNED826RE", "firmware": "p20.33.31.23",
       "mac": "14:7F:67:AF:0C:6A"}


def test_different_mac_does_not_inherit_lg_identity():
    scan = {"mac": "7C:C2:94:85:C5:19"}  # Xiaomi, sin vendor/model (0 puertos)
    ident, prev = _resolve_device_identity(scan, dict(_LG), findings=[])
    assert ident["vendor"] != "LG"        # NO hereda LG
    assert ident["model"] != "65QNED826RE"
    assert ident["firmware"] != "p20.33.31.23"
    assert ident["mac"] == "7C:C2:94:85:C5:19"
    assert prev == {}                      # kb_prev descartado (otro device)


def test_same_mac_inherits_identity():
    scan = {"mac": "14:7F:67:AF:0C:6A"}    # misma MAC que la LG → mismo device
    ident, prev = _resolve_device_identity(scan, dict(_LG), findings=[])
    assert ident["vendor"] == "LG"
    assert ident["model"] == "65QNED826RE"
    assert prev.get("vendor") == "LG"      # se conserva el histórico


def test_scan_vendor_always_wins():
    scan = {"mac": "7C:C2:94:85:C5:19", "vendor": "Xiaomi", "model": "ESP-X"}
    ident, _ = _resolve_device_identity(scan, dict(_LG), findings=[])
    assert ident["vendor"] == "Xiaomi" and ident["model"] == "ESP-X"


def test_no_scan_mac_keeps_best_effort_inherit():
    # Sin MAC en el escaneo no se puede comparar → se respeta el fallback previo.
    scan = {}
    ident, prev = _resolve_device_identity(scan, dict(_LG), findings=[])
    assert ident["vendor"] == "LG"
    assert prev.get("vendor") == "LG"


def test_case_insensitive_mac_match():
    scan = {"mac": "14:7f:67:af:0c:6a"}    # minúsculas, misma MAC
    ident, prev = _resolve_device_identity(scan, dict(_LG), findings=[])
    assert ident["vendor"] == "LG" and prev.get("vendor") == "LG"
