"""Regresión: cuando el pase primario `-sS` (raw-socket, modo root) "tiene
éxito" para python-nmap pero NO encuentra el host —caso real en hosts con
varios bridges Docker, donde nmap emite `dnet: Failed to open device br-...`
y devuelve vacío sin lanzar excepción—, `scan_device` debe reintentar con
connect-scan `-sT` antes de rendirse, en vez de devolver None directamente.

(Observado en una auditoría real contra un Amazon Echo: el primer
`nmap_scan` devolvió `scan returned None`; el agente tuvo que reintentar a
mano. El fallback `-sT` automatiza esa recuperación.)
"""
import modules.recon as recon
from modules.recon import ReconScanner


class _FakeHost(dict):
    def state(self):
        return "up"

    def all_protocols(self):
        return [k for k in ("tcp", "udp") if k in self]


class _FlakySsNm:
    """nm que falla el pase -sS (no encuentra host) y solo puebla en -sT."""

    def __init__(self, ip, host):
        self.ip = ip
        self.host = host
        self.calls = []          # args de cada scan
        self._has_host = False

    def scan(self, ip, ports=None, arguments=""):
        self.calls.append(arguments)
        # Solo el connect-scan (-sT) encuentra el host; el -sS "falla" vacío.
        if "-sT" in arguments:
            self._has_host = True
        return {}

    def all_hosts(self):
        return [self.ip] if self._has_host else []

    def __getitem__(self, ip):
        return self.host


def _scanner_with(nm):
    s = object.__new__(ReconScanner)
    s.nm = nm
    return s


def test_ss_empty_triggers_st_fallback(monkeypatch):
    monkeypatch.setattr(recon.os, "geteuid", lambda: 0)  # fuerza ruta root → -sS
    ip = "192.168.1.34"
    host = _FakeHost({
        "addresses": {"mac": "C0:8D:51:67:29:4B"},
        "osmatch": [{"name": "Linux 3.2 - 4.9", "osclass": [{"cpe": []}]}],
        "tcp": {1080: {"state": "open", "name": "socks5", "cpe": []}},
    })
    nm = _FlakySsNm(ip, host)
    res = _scanner_with(nm).scan_device(ip, ports="1-1000")

    # Primero el -sS vacío, e inmediatamente después el -sT de recuperación
    # (pueden seguir otros pases, p. ej. UDP, pero esos dos van primero y en orden).
    assert "-sS" in nm.calls[0]
    assert "-sT" in nm.calls[1]
    # Y el resultado se recuperó (no None) con el puerto del connect-scan.
    assert res is not None
    assert res["mac"] == "C0:8D:51:67:29:4B"
    assert any(p["port"] == 1080 for p in res["ports"])


def test_st_primary_does_not_double_scan(monkeypatch):
    """Sin root el pase primario ya es -sT; si no hay host, NO se reintenta
    (evita doblar el escaneo cuando el host está realmente caído)."""
    monkeypatch.setattr(recon.os, "geteuid", lambda: 1000)  # no root → -sT directo
    ip = "10.0.0.9"

    class _EmptyNm:
        def __init__(self):
            self.calls = []

        def scan(self, ip, ports=None, arguments=""):
            self.calls.append(arguments)
            return {}

        def all_hosts(self):
            return []

    nm = _EmptyNm()
    res = _scanner_with(nm).scan_device(ip, ports="1-1000")
    assert res is None
    assert len(nm.calls) == 1            # un solo pase, sin retry redundante
    assert "-sT" in nm.calls[0]
