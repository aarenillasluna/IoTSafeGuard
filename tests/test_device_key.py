"""Clave de identidad anclada a MAC (modules.fingerprint.device_key)."""
from modules.fingerprint import device_key


def test_real_mac_is_the_key():
    assert device_key("14:7F:67:AF:0C:6A") == "14:7F:67:AF:0C:6A"
    assert device_key("14-7f-67-af-0c-6a") == "14:7F:67:AF:0C:6A"   # normaliza formato


def test_real_mac_ignores_ip():
    # misma MAC, IPs distintas → misma clave (IP nunca entra)
    assert device_key("DC:A6:32:11:22:33", ip="192.168.0.5") == \
           device_key("DC:A6:32:11:22:33", ip="10.0.0.9")


def test_synthetic_mac_disambiguated_by_firmware():
    k1 = device_key("52:54:00:12:34:56", firmware="1.01")
    k2 = device_key("52:54:00:12:34:56", firmware="1.03")
    assert k1 != k2 and k1.endswith("|emu") and k2.endswith("|emu")


def test_synthetic_mac_falls_back_to_ip():
    k1 = device_key("52:54:00:12:34:56", ip="192.168.0.10")
    k2 = device_key("52:54:00:12:34:56", ip="192.168.0.11")
    assert k1 != k2 and k1.endswith("|emu")


def test_no_mac_falls_back_to_ip_marked():
    assert device_key(None, ip="192.168.1.50") == "ip:192.168.1.50"
    assert device_key("", ip="192.168.1.50") == "ip:192.168.1.50"


def test_private_iphone_mac_is_synthetic():
    # MAC localmente administrada (iPhone privada) → tratada como sintética
    k = device_key("2E:F5:E7:FA:84:20", ip="192.168.1.33")
    assert k.endswith("|emu")
