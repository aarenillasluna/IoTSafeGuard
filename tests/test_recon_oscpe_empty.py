"""Regresión: nmap_scan crasheaba con `IndexError: list index out of range`
cuando el host hace OS-match SIN CPE (`'cpe': []`) — caso real de dispositivos
IoT como Espressif/ESP. `.get('cpe', [None])[0]` no usa el default si la clave
existe vacía. Se cubren la osclass del host y la cpe de un puerto.
"""
from modules.recon import ReconScanner


class _FakeHost(dict):
    """dict que imita el host de python-nmap (state() y all_protocols())."""
    def state(self):
        return "up"

    def all_protocols(self):
        return [k for k in ("tcp", "udp") if k in self]


class _FakeNm:
    def __init__(self, host):
        self._host = host

    def scan(self, *a, **k):
        return {}

    def all_hosts(self):
        return ["192.168.1.37"]

    def __getitem__(self, ip):
        return self._host


def _scanner_with(host):
    s = object.__new__(ReconScanner)  # evita nmap.PortScanner() real
    s.nm = _FakeNm(host)
    return s


def test_osmatch_without_cpe_does_not_crash():
    host = _FakeHost({
        "addresses": {"mac": "24:6F:28:AA:BB:CC"},
        "osmatch": [{
            "name": "Espressif embedded",
            "osclass": [{"type": "specialized", "vendor": "Espressif", "cpe": []}],
        }],
        "tcp": {80: {"state": "open", "name": "http", "cpe": []}},
    })
    res = _scanner_with(host).scan_device("192.168.1.37", ports="80")
    assert res is not None
    assert res["os_match"] == "Espressif embedded"
    assert res["os_cpe"] is None            # cpe vacío → None, sin crash
    assert res["ports"][0]["port"] == 80
    assert res["ports"][0]["cpe"] is None    # cpe de puerto vacío → None


def test_osmatch_with_empty_osclass_does_not_crash():
    host = _FakeHost({
        "addresses": {},
        "osmatch": [{"name": "Generic", "osclass": []}],  # osclass vacío
        "tcp": {},
    })
    res = _scanner_with(host).scan_device("192.168.1.37", ports="1-100")
    assert res is not None and res["os_cpe"] is None


def test_osmatch_with_cpe_preserved():
    host = _FakeHost({
        "addresses": {"mac": "DC:A6:32:11:22:33"},
        "osmatch": [{"name": "Linux 5.x",
                     "osclass": [{"cpe": ["cpe:/o:linux:linux_kernel:5"]}]}],
        "tcp": {22: {"state": "open", "name": "ssh", "cpe": ["cpe:/a:openbsd:openssh"]}},
    })
    res = _scanner_with(host).scan_device("192.168.1.37", ports="22")
    assert res["os_cpe"] == "cpe:/o:linux:linux_kernel:5"
    assert res["ports"][0]["cpe"] == "cpe:/a:openbsd:openssh"
