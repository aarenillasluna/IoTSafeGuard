"""Perfil de escaneo SUAVE para dispositivos embebidos frágiles (ESP8266/lwIP):
no saturar su pila de red. Cubre la decisión (fragile → gentle), el aviso (B)
ante rango amplio, y que el perfil suave usa ritmo limitado.
"""
import core.tools as t
from modules.recon import ReconScanner


# ── helpers de clasificación ────────────────────────────────────────────────
def test_is_fragile_os():
    assert t._is_fragile_os("Espressif esp8266 firmware (lwIP stack)")
    assert t._is_fragile_os("FreeRTOS embedded")
    assert not t._is_fragile_os("Linux 5.3 - 5.4")
    assert not t._is_fragile_os(None)


def test_is_large_port_range():
    assert t._is_large_port_range("1-65535")
    assert t._is_large_port_range("1-5000")
    assert not t._is_large_port_range("80,443")
    assert not t._is_large_port_range("1-100")
    assert not t._is_large_port_range(None)


# ── perfil suave a nivel recon (args reales pasados a nmap) ──────────────────
class _CapturingNm:
    def __init__(self):
        self.last_args = None

    def scan(self, ip, ports=None, arguments=None):
        self.last_args = arguments

    def all_hosts(self):
        return ["10.0.0.5"]

    def __getitem__(self, ip):
        class _H(dict):
            def state(self_):
                return "up"

            def all_protocols(self_):
                return []
        return _H({"addresses": {}, "osmatch": []})


def _scanner():
    s = object.__new__(ReconScanner)
    s.nm = _CapturingNm()
    return s


def test_gentle_profile_uses_rate_limit():
    s = _scanner()
    s.scan_device("10.0.0.5", ports="1-65535", gentle=True)
    args = s.nm.last_args
    assert "--max-rate 100" in args and "-T2" in args
    assert "--version-all" not in args        # aligerado
    assert "--host-timeout" in args


def test_normal_profile_is_aggressive():
    s = _scanner()
    s.scan_device("10.0.0.5", ports="1-1000", gentle=False)
    args = s.nm.last_args
    assert "--max-rate" not in args            # sin throttling en modo normal


# ── integración _nmap_scan: prev frágil → gentle + warning ──────────────────
class _FakeScanner:
    last_gentle = None

    def __init__(self, *a, **k):
        pass

    def scan_device(self, ip, ports=None, gentle=False):
        _FakeScanner.last_gentle = gentle
        return {"ip": ip, "mac": None, "os_match": "Unknown", "os_cpe": None, "ports": []}


def test_nmap_scan_goes_gentle_on_fragile_prior(monkeypatch):
    monkeypatch.setattr("modules.recon.ReconScanner", _FakeScanner)
    sess = t.AgentSession(target_ip="192.168.1.37")
    sess.scan_cache = {
        "ip": "192.168.1.37",
        "os_match": "Espressif esp8266 firmware (lwIP stack)",
        "mac": "7C:C2:94:85:C5:19",
        "ports": [{"port": 80, "protocol": "tcp", "service_name": "http"}],
    }
    t.bind_session(sess)
    res = t._nmap_scan({"ip": "192.168.1.37", "ports": "1-65535"})
    assert _FakeScanner.last_gentle is True            # escaneo suave
    assert "GENTLE MODE" in (res.get("warning") or "")  # aviso B
    # el rescan vacío NO borró el puerto previo (merge)
    assert res["port_count"] == 1
    assert res["mac"] == "7C:C2:94:85:C5:19"           # identidad conservada
