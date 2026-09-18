"""
Cobertura de los dos cambios introducidos para hacer la detección de CVEs de
dnsmasq determinista entre ejecuciones:

1. modules.iot_probes.probe_dns
     - Detección de open recursion (servidor responde con RA=1, NOERROR y answer count > 0)
     - Confirmación por versión de CVE-2019-14513 cuando dnsmasq < 2.76
     - Marcado explícito de CVEs DNSSEC como NO aplicables cuando dnsmasq < 2.57

2. core/tools.py::_cve_search
     - Auto-broadening: si la consulta inicial con `keyword="<producto> <versión>"`
       devuelve 0, reintenta con `<producto>` sin versión

Los tests no tocan la red real:
  - probe_dns: servidor UDP local que responde con frames DNS sintéticos
  - _cve_search: monkeypatch sobre NVDCVEClient.get_cves_for_product
"""
from __future__ import annotations

import os
import socket
import struct
import sys
import threading


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from modules.iot_probes import (
    _build_dns_query,
    _dnsmasq_has_dnssec,
    _parse_dns_flags,
    probe_dns,
)


# ---------------------------------------------------------------------------
# Helpers: servidor UDP DNS sintético
# ---------------------------------------------------------------------------
def _free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _build_dns_response(query: bytes, *, ra: bool, rcode: int = 0,
                       answer_count: int = 1) -> bytes:
    """Construye una respuesta DNS válida que reusa el QNAME del query.

    Mínimo: copia header + question del query, ajusta flags (QR=1, RA según
    parámetro, RCODE), y añade `answer_count` RRs A apuntando a 1.2.3.4.
    """
    if len(query) < 12:
        return b""
    txid = struct.unpack("!H", query[:2])[0]
    # QR=1, RD=1, RA conditionally, RCODE
    flags = 0x8000 | 0x0100 | (0x0080 if ra else 0) | (rcode & 0xF)
    hdr = struct.pack("!HHHHHH", txid, flags, 1, answer_count, 0, 0)
    # Encuentra el final de la question (qname terminado en 0x00 + qtype + qclass)
    i = 12
    while i < len(query) and query[i] != 0:
        i += 1 + query[i]
    qname_end = i + 1  # incluye el byte 0x00
    question = query[12:qname_end + 4]  # +4 = qtype(2) + qclass(2)
    body = hdr + question
    # Construye `answer_count` RRs A → 1.2.3.4, TTL=60
    for _ in range(answer_count):
        rr = (
            b"\xc0\x0c"                          # name pointer al QNAME
            + struct.pack("!HHIH", 1, 1, 60, 4)  # TYPE=A, CLASS=IN, TTL=60, RDLENGTH=4
            + bytes([1, 2, 3, 4])
        )
        body += rr
    return body


class _DNSFakeServer:
    """Servidor UDP de una sola respuesta — controla los flags devueltos."""

    def __init__(self, *, ra: bool = True, rcode: int = 0,
                 answer_count: int = 1):
        self.port = _free_udp_port()
        self.ra = ra
        self.rcode = rcode
        self.answer_count = answer_count
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.settimeout(3)
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> "_DNSFakeServer":
        self.thread.start()
        return self

    def _run(self) -> None:
        try:
            data, addr = self._sock.recvfrom(512)
            resp = _build_dns_response(
                data, ra=self.ra, rcode=self.rcode,
                answer_count=self.answer_count,
            )
            if resp:
                self._sock.sendto(resp, addr)
        except socket.timeout:
            pass
        finally:
            self._sock.close()


# ---------------------------------------------------------------------------
# probe_dns: helpers de parseo y construcción
# ---------------------------------------------------------------------------
class TestDNSHelpers:

    def test_build_dns_query_well_formed(self):
        q = _build_dns_query("example.com", qtype=1, txid=0xDEAD)
        txid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", q[:12])
        assert txid == 0xDEAD
        assert qd == 1 and an == 0
        assert flags & 0x0100  # RD set
        # QNAME: 7 e x a m p l e 3 c o m 0  →  longitud 13 bytes
        assert q[12:25] == b"\x07example\x03com\x00"
        # qtype A (1) + qclass IN (1)
        assert q[25:29] == struct.pack("!HH", 1, 1)

    def test_parse_dns_flags_round_trip(self):
        q = _build_dns_query("example.com", txid=0x1111)
        resp = _build_dns_response(q, ra=True, rcode=0, answer_count=2)
        parsed = _parse_dns_flags(resp)
        assert parsed["valid"] is True
        assert parsed["rcode"] == 0
        assert parsed["recursion_available"] is True
        assert parsed["answer_count"] == 2

    def test_parse_dns_flags_refused(self):
        q = _build_dns_query("example.com")
        resp = _build_dns_response(q, ra=False, rcode=5, answer_count=0)
        parsed = _parse_dns_flags(resp)
        assert parsed["rcode"] == 5  # REFUSED
        assert parsed["recursion_available"] is False

    def test_parse_dns_flags_short_buffer_invalid(self):
        assert _parse_dns_flags(b"\x00" * 5) == {"valid": False}

    def test_dnsmasq_dnssec_capability_boundary(self):
        assert _dnsmasq_has_dnssec("2.45") is False
        assert _dnsmasq_has_dnssec("2.56") is False
        assert _dnsmasq_has_dnssec("2.57") is True
        assert _dnsmasq_has_dnssec("2.83") is True
        # Conservador ante input invalido
        assert _dnsmasq_has_dnssec("not-a-version") is True


# ---------------------------------------------------------------------------
# probe_dns: comportamiento de red end-to-end
# ---------------------------------------------------------------------------
class TestProbeDNS:

    def test_connection_refused(self):
        port = _free_udp_port()  # nadie escucha
        result = probe_dns("127.0.0.1", port=port, timeout=1)
        # UDP sin servidor → timeout (no hay 'connection refused' en UDP local)
        assert result["ok"] is False
        assert result["protocol_confirmed"] is False
        assert result["error"] is not None

    def test_open_recursion_detected(self):
        srv = _DNSFakeServer(ra=True, rcode=0, answer_count=1).start()
        result = probe_dns("127.0.0.1", port=srv.port, timeout=2)
        assert result["ok"] is True
        assert result["protocol_confirmed"] is True
        assert result["details"]["open_recursion"] is True
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "DNS-OPEN-RECURSION" in ids

    def test_no_open_recursion_when_refused(self):
        srv = _DNSFakeServer(ra=False, rcode=5, answer_count=0).start()
        result = probe_dns("127.0.0.1", port=srv.port, timeout=2)
        assert result["ok"] is True
        assert result["details"]["open_recursion"] is False
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "DNS-OPEN-RECURSION" not in ids

    def test_cve_2019_14513_version_confirmed_when_old_and_recursive(self):
        srv = _DNSFakeServer(ra=True, rcode=0, answer_count=1).start()
        result = probe_dns("127.0.0.1", port=srv.port, timeout=2,
                           dnsmasq_version="2.45")
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "CVE-2019-14513" in ids
        cve = next(v for v in result["vulnerabilities"] if v["id"] == "CVE-2019-14513")
        assert cve.get("version_confirmed") is True
        assert cve.get("confirmed") is False  # vector confirmed, exploit not run

    def test_cve_2019_14513_not_added_without_open_recursion(self):
        """Sin open recursion el vector upstream no aplica, aunque la versión sea < 2.76."""
        srv = _DNSFakeServer(ra=False, rcode=5, answer_count=0).start()
        result = probe_dns("127.0.0.1", port=srv.port, timeout=2,
                           dnsmasq_version="2.45")
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "CVE-2019-14513" not in ids

    def test_dnssec_cves_marked_not_applicable_for_old_dnsmasq(self):
        srv = _DNSFakeServer(ra=True, rcode=0, answer_count=1).start()
        result = probe_dns("127.0.0.1", port=srv.port, timeout=2,
                           dnsmasq_version="2.45")
        note = result["details"].get("dnssec_cves_not_applicable", "")
        assert "DNSSEC" in note
        assert "CVE-2020-25681" in note
        assert "CVE-2020-25682" in note
        assert "CVE-2017-15107" in note
        # Y ninguno de esos CVEs debe estar en la lista de vulnerabilities
        ids = [v["id"] for v in result["vulnerabilities"]]
        for cve_id in ("CVE-2020-25681", "CVE-2020-25682", "CVE-2017-15107"):
            assert cve_id not in ids


# ---------------------------------------------------------------------------
# _cve_search: auto-broadening cuando hay 0 resultados
# ---------------------------------------------------------------------------
class TestCVESearchAutoBroadening:

    def _patch_client(self, monkeypatch, results_by_keyword):
        """Reemplaza get_cves_for_product por una versión que respeta el dict."""
        from modules import cve_api

        def fake(self, product, version, nmap_cpe=None):  # noqa: ARG001
            return list(results_by_keyword.get(product, []))

        monkeypatch.setattr(cve_api.NVDCVEClient, "get_cves_for_product", fake)

    def test_no_broadening_when_first_query_succeeds(self, monkeypatch):
        from core.tools import _cve_search

        sample = [{"id": "CVE-X", "severity": "HIGH", "score": 7.5,
                   "description": "test"}]
        self._patch_client(monkeypatch, {"dnsmasq 2.45": sample})
        result = _cve_search({"keyword": "dnsmasq 2.45"})
        assert result["count"] == 1
        assert result["keyword"] == "dnsmasq 2.45"

    def test_broadens_when_zero_results_and_version_suffix(self, monkeypatch):
        from core.tools import _cve_search

        broader = [{"id": "CVE-Y", "severity": "HIGH", "score": 8.1,
                    "description": "test"}]
        # Versión exacta vacía → forzamos retry con producto solo
        self._patch_client(monkeypatch, {
            "dnsmasq 2.45": [],
            "dnsmasq": broader,
        })
        result = _cve_search({"keyword": "dnsmasq 2.45"})
        assert result["count"] == 1
        # El keyword devuelto refleja la búsqueda que realmente trajo resultados
        assert result["keyword"] == "dnsmasq"
        assert result["cves"][0]["id"] == "CVE-Y"

    def test_no_broadening_when_keyword_has_no_version_suffix(self, monkeypatch):
        from core.tools import _cve_search

        self._patch_client(monkeypatch, {})  # toda búsqueda devuelve 0
        result = _cve_search({"keyword": "dnsmasq"})
        # Sin sufijo numérico no debe re-buscar — sería bucle infinito
        assert result["count"] == 0
        assert result["keyword"] == "dnsmasq"

    def test_no_broadening_when_explicit_version_arg(self, monkeypatch):
        from core.tools import _cve_search

        # Cuando `version` viene como argumento separado, asumimos que el caller
        # eligió esa precisión deliberadamente; no broadenamos.
        self._patch_client(monkeypatch, {"dnsmasq": [{"id": "CVE-Z",
                                                       "severity": "LOW",
                                                       "score": 1.0,
                                                       "description": ""}]})
        result = _cve_search({"keyword": "dnsmasq", "version": "2.45"})
        assert result["keyword"] == "dnsmasq"
        # 0 hits porque la consulta concreta usó version="2.45" pero el mock
        # solo indexa "dnsmasq" sin pasar por version (que sí lo recibe el
        # cliente real); aquí lo relevante es que no haya retry.
        assert result["count"] == 1  # nuestro mock ignora version, así que aún devuelve


# ---------------------------------------------------------------------------
# _cve_search: rechazo de keywords genéricos que producen vendor-spray
# ---------------------------------------------------------------------------
class TestCVESearchGenericKeywordGuard:
    """Regresión empírica del run vs Movistar 192.168.1.1: búsquedas como
    'router default credentials' o 'hardcoded credentials device' devolvían
    CVEs aleatorios de TP-Link, NETGEAR, FiberHome, Crestron... que el agente
    luego registraba como findings descartados, inflando el reporte con ruido
    y la KB con vendors erróneos.
    """

    def test_rejects_pure_generic_query(self):
        from core.tools import _cve_search
        result = _cve_search({"keyword": "router default credentials"})
        assert result["ok"] is False
        assert result["count"] == 0
        assert result["error"] == "generic_keyword_rejected"
        assert "vendor/product" in result["note"]

    def test_rejects_router_vulnerability(self):
        from core.tools import _cve_search
        result = _cve_search({"keyword": "router web interface vulnerability"})
        assert result["ok"] is False
        assert result["error"] == "generic_keyword_rejected"

    def test_rejects_hardcoded_credentials_device(self):
        from core.tools import _cve_search
        result = _cve_search({"keyword": "hardcoded credentials device"})
        assert result["ok"] is False
        assert result["error"] == "generic_keyword_rejected"

    def test_rejects_generic_protocol_queries(self):
        """Regresión (Echo run 20260613): el agente buscó por protocolo genérico
        ('SNMP remote code execution', 'TFTP remote code execution'…) y obtuvo
        CVEs de vendors aleatorios. Ahora se rechazan."""
        from core.tools import _cve_search
        for kw in (
            "SNMP remote code execution",
            "TFTP remote code execution",
            "L2TP IPSec vulnerability",
            "SNMP community string vulnerability",
            "NetBIOS vulnerability",
            "NTP amplification attack",
            "SOCKS5 proxy vulnerability",
        ):
            result = _cve_search({"keyword": kw})
            assert result["error"] == "generic_keyword_rejected", f"no rechazó: {kw}"

    def test_accepts_product_with_protocol_word(self, monkeypatch):
        """Un producto/versión real NO se rechaza aunque incluya un acrónimo de
        protocolo (la implementación sí es buscable: 'net-snmp 5.7')."""
        from core.tools import _is_generic_cve_keyword
        # Tokens con producto/versión reales → no es genérico.
        assert _is_generic_cve_keyword("net-snmp 5.7") is False
        assert _is_generic_cve_keyword("SMB v1") is False
        assert _is_generic_cve_keyword("Nagios NSCA") is False

    def test_accepts_product_specific_query(self, monkeypatch):
        from core.tools import _cve_search
        from modules import cve_api

        def fake(self, product, version, nmap_cpe=None):  # noqa: ARG001
            return [{"id": "CVE-X", "severity": "HIGH", "score": 7.5,
                     "description": "test"}]

        monkeypatch.setattr(cve_api.NVDCVEClient, "get_cves_for_product", fake)
        # 'Dropbear SSH 2019.78' contiene tokens específicos → pasa el guard
        result = _cve_search({"keyword": "Dropbear SSH 2019.78"})
        assert result["ok"] is True
        assert result["count"] == 1

    def test_accepts_vendor_specific_query_even_with_generic_tail(self, monkeypatch):
        from core.tools import _cve_search
        from modules import cve_api

        def fake(self, product, version, nmap_cpe=None):  # noqa: ARG001
            return []

        monkeypatch.setattr(cve_api.NVDCVEClient, "get_cves_for_product", fake)
        # 'D-Link router vulnerability' mezcla vendor real con tokens genéricos
        # — pasa el guard porque 'd-link' no está en la lista genérica.
        result = _cve_search({"keyword": "D-Link router vulnerability"})
        assert result["ok"] is True  # no rechazado por el guard

    def test_emits_model_specific_warning_in_instruction(self, monkeypatch):
        """Cuando los resultados incluyen CVEs con model_hint, la respuesta
        debe instruir al agente a NO registrarlos si el modelo no coincide.
        """
        from core.tools import _cve_search
        from modules import cve_api

        def fake(self, product, version, nmap_cpe=None):  # noqa: ARG001
            return [{
                "id": "CVE-2018-12575",
                "severity": "CRITICAL", "score": 9.8,
                # La descripción menciona un modelo HW específico → model_hint
                "description": "Authentication bypass in TP-Link TL-WR841N v13 routers.",
            }]

        monkeypatch.setattr(cve_api.NVDCVEClient, "get_cves_for_product", fake)
        result = _cve_search({"keyword": "TP-Link auth bypass"})
        assert result["count"] == 1
        assert "instruction" in result
        assert "model_hint" in result["instruction"]
        assert "Do NOT record them" in result["instruction"] or "out of scope" in result["instruction"]
