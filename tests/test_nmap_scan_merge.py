"""Regresión: un rescan más pobre (IoT frágil que se ahoga ante -p 1-65535 y
devuelve 0 puertos) NO debe borrar los puertos ya descubiertos. _merge_scan
conserva la unión y avisa de la degradación.
"""
from core.tools import _merge_scan


def _scan(ip, ports, mac="AA:BB:CC:DD:EE:FF", os_match="Linux"):
    return {"ip": ip, "mac": mac, "os_match": os_match, "os_cpe": "cpe:x",
            "ports": [{"port": p, "protocol": "tcp", "service_name": "s"} for p in ports]}


def test_no_prev_returns_new():
    new = _scan("192.168.1.37", [80, 443])
    merged, warn = _merge_scan(None, new, "192.168.1.37")
    assert merged is new and warn is None


def test_emptier_rescan_keeps_prior_ports_and_warns():
    prev = _scan("192.168.1.37", [80, 443, 8080, 8266])
    new = {"ip": "192.168.1.37", "mac": None, "os_match": "Unknown",
           "os_cpe": None, "ports": []}  # device se ahogó
    merged, warn = _merge_scan(prev, new, "192.168.1.37")
    assert len(merged["ports"]) == 4          # no se pierden
    assert warn is not None and "returned 0 ports" in warn
    # identidad recuperada del previo (el rescan vino vacío)
    assert merged["mac"] == "AA:BB:CC:DD:EE:FF"
    assert merged["os_match"] == "Linux"


def test_rescan_with_new_port_unions():
    prev = _scan("192.168.1.37", [80, 443])
    new = _scan("192.168.1.37", [443, 9999])  # aporta 9999, repite 443
    merged, warn = _merge_scan(prev, new, "192.168.1.37")
    got = {p["port"] for p in merged["ports"]}
    assert got == {80, 443, 9999}             # unión
    assert warn is None                        # no encontró menos


def test_different_ip_does_not_merge():
    prev = _scan("192.168.1.50", [80, 443, 8080])
    new = _scan("192.168.1.37", [22])
    merged, warn = _merge_scan(prev, new, "192.168.1.37")
    assert {p["port"] for p in merged["ports"]} == {22}
    assert warn is None
