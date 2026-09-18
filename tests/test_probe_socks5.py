"""Un proxy SOCKS5 abierto tiene que poder demostrarse, y uno cerrado no puede puntuar.

Caso de campo (altavoz Amazon, 192.168.1.37:1080, cinco réplicas):

  · el agente confirmó el handshake a mano con `probe_tcp payload_hex=050100`
    → `05 00`, correcto, pero eso solo prueba alcanzabilidad. El tope
    correspondiente lo dejaba en LOW —con razón—, y los intentos de demostrar
    el relay (`curl -x socks5://…`, `nc -x …`) chocaban con la PolicyEngine. El
    sistema prohibía la única evidencia capaz de levantar su propio tope, y el
    informe acababa diciendo «vector de acceso crítico» con score NEGLIGIBLE;
  · cada réplica inventó un identificador distinto para el mismo hecho:
    `SOCKS5-NOAUTH-1080`, `SOCKS5-OPEN-PROXY`, `SOCKS5-AUTH-REQUIRED`;
  · la réplica que recibió `05 ff` —un proxy que SÍ exige credenciales, es
    decir, buena noticia— registró un hallazgo confirmado y sacó el mismo score
    que la que lo encontró abierto de par en par.
"""
import socket
import struct
import threading

import pytest

from core.severity import effective_severity, is_confirmed_vuln
from modules.iot_probes import probe_socks5


class _FakeSocks5:
    """Servidor SOCKS5 mínimo y guionizado.

    `method` es lo que contesta al saludo; `connect_code` la respuesta al
    CONNECT; `body` lo que devuelve el servicio del otro lado del túnel.
    """

    def __init__(self, method=0x00, connect_code=0x00, body=b"", speak_socks=True):
        self.method, self.connect_code = method, connect_code
        self.body, self.speak_socks = body, speak_socks
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        with conn:
            try:
                conn.recv(16)                       # saludo
                if not self.speak_socks:
                    conn.sendall(b"HTTP/1.0 400 Bad Request\r\n")
                    return
                conn.sendall(bytes([0x05, self.method]))
                if self.method != 0x00:
                    return
                conn.recv(32)                       # CONNECT
                conn.sendall(bytes([0x05, self.connect_code, 0x00, 0x01])
                             + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0))
                if self.connect_code != 0x00:
                    return
                conn.recv(512)                      # petición tunelizada
                if self.body:
                    conn.sendall(self.body)
            except OSError:
                pass

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


@pytest.fixture
def servidor():
    creados = []

    def _crear(**kwargs):
        s = _FakeSocks5(**kwargs)
        creados.append(s)
        return s

    yield _crear
    for s in creados:
        s.close()


def _vuln(resultado):
    assert resultado["vulnerabilities"], f"sin hallazgos: {resultado}"
    return resultado["vulnerabilities"][0]


# ── Los tres veredictos ────────────────────────────────────────────────────

def test_relay_demostrado_es_acceso(servidor):
    s = servidor(body=b"HTTP/1.0 200 OK\r\nServer: lighttpd\r\n\r\nhola")
    v = _vuln(probe_socks5("127.0.0.1", port=s.port))
    assert v["id"] == "SOCKS5-OPEN-RELAY"
    assert v["impact"] == "ACCESS"
    assert "lighttpd" in v["evidence"]


def test_handshake_abierto_pero_connect_denegado_no_es_acceso(servidor):
    s = servidor(connect_code=0x05)  # connection refused
    v = _vuln(probe_socks5("127.0.0.1", port=s.port))
    assert v["id"] == "SOCKS5-NOAUTH"
    assert v["impact"] == "EXPOSURE"


def test_proxy_que_pide_credenciales_es_un_negativo(servidor):
    s = servidor(method=0xFF)
    v = _vuln(probe_socks5("127.0.0.1", port=s.port))
    assert v["id"] == "SOCKS5-AUTH-REQUIRED"
    assert v["severity"] == "INFO"
    assert v["confirmed_negative"] is True


def test_tunel_concedido_sin_datos_se_declara_como_tal(servidor):
    s = servidor(body=b"")
    v = _vuln(probe_socks5("127.0.0.1", port=s.port))
    assert v["id"] == "SOCKS5-OPEN-RELAY-NODATA"
    assert v["impact"] == "EXPOSURE"


def test_un_puerto_que_no_habla_socks5_no_inventa_hallazgos(servidor):
    s = servidor(speak_socks=False)
    r = probe_socks5("127.0.0.1", port=s.port)
    assert r["vulnerabilities"] == []
    assert r["protocol_confirmed"] is False
    assert r["error"] == "not_socks5"


def test_puerto_cerrado_no_revienta():
    r = probe_socks5("127.0.0.1", port=1, timeout=1)
    assert r["vulnerabilities"] == []
    assert r["error"]


# ── Lo que la gobernanza hace con cada veredicto ───────────────────────────

class TestSeveridadEfectiva:
    """El gradiente completo, que es lo que fallaba en campo."""

    def test_el_relay_probado_sube_de_low(self):
        f = {"cve_id": "SOCKS5-OPEN-RELAY", "severity": "HIGH", "impact": "ACCESS",
             "confirmed": True,
             "raw_output": "CONNECT 127.0.0.1:80 → 05 00\nHTTP/1.0 200 OK\nServer: lighttpd"}
        assert effective_severity(f) == "HIGH"
        assert is_confirmed_vuln(f)

    def test_el_handshake_solo_sigue_topado(self):
        f = {"cve_id": "SOCKS5-NOAUTH", "severity": "MEDIUM", "impact": "EXPOSURE",
             "confirmed": True, "raw_output": "greeting 05 00; connection refused"}
        assert effective_severity(f) == "LOW"

    def test_el_negativo_no_puntua_ni_declarandolo_critico(self):
        """El LLM puede re-registrarlo con la severidad que quiera; da igual."""
        f = {"cve_id": "SOCKS5-AUTH-REQUIRED", "severity": "CRITICAL",
             "impact": "ACCESS", "confirmed": True,
             "raw_output": "El proxy exige autenticación — riesgo de pivoting"}
        assert effective_severity(f) == "INFO"
        assert not is_confirmed_vuln(f)

    def test_seguro_e_inseguro_ya_no_puntuan_igual(self):
        """Lo que motivó todo: `05 ff` y `05 00` daban el mismo score."""
        from core.severity import compute_risk_score
        abierto = [{"cve_id": "SOCKS5-OPEN-RELAY", "severity": "HIGH",
                    "impact": "ACCESS", "confirmed": True,
                    "raw_output": "05 00\nHTTP/1.0 200 OK\nServer: lighttpd"}]
        cerrado = [{"cve_id": "SOCKS5-AUTH-REQUIRED", "severity": "HIGH",
                    "impact": "ACCESS", "confirmed": True, "raw_output": "05 ff"}]
        assert compute_risk_score(abierto)["risk_score"] > \
               compute_risk_score(cerrado)["risk_score"]


def test_la_herramienta_esta_registrada():
    from core.tools import _REGISTRY
    assert "probe_socks5" in _REGISTRY
