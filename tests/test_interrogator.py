"""Interrogatorio web (`modules/interrogator.py`) — de donde sale el hallazgo web.

Estaba al 29 % de cobertura pese a producir `unauth_data_endpoints`, la lista de
URLs que sirven datos SIN autenticación y que origina la mayoría de los hallazgos
web confirmados del Capítulo 5.

Reparto deliberado con `tests/test_web_auth.py`, que ya cubre `web_login` y la
**clasificación** de respuestas (`_classify_response`): aquí NO se repite nada de
eso. Se cubre lo que faltaba —el flujo real contra un servidor HTTP local: qué
endpoints se extraen del HTML, cuáles se descartan tras probarlos, y qué evidencia
de cabeceras/banners se consolida— porque es la parte que solo se rompe cuando
hay un dispositivo al otro lado.
"""
import socket
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from modules.interrogator import IoTInterrogator, _safe_parse_xml

INDEX_HTML = b"""<!DOCTYPE html>
<html><head><title>VulnRouter X1000 Admin</title>
<script src="/js/app.js"></script></head>
<body>
  <img src="/logo.png">
  <a href="/config.json">config</a>
  <a href="/status.php">estado</a>
  <a href="/admin.cgi">admin</a>
  <a href="/nope.json">inexistente</a>
</body></html>"""

CONFIG_JSON = b'{"admin_user":"admin","admin_pass":"Sup3rS3cret","ssid":"CasaWiFi"}'
LOGIN_HTML = b"<!DOCTYPE html><html><body><form>login</form></body></html>"


@contextmanager
def web_server(routes=None, extra_headers=None):
    """Servidor HTTP local que emula el panel de un dispositivo IoT."""
    routes = routes if routes is not None else {
        "/": (200, "text/html", INDEX_HTML),
        "/config.json": (200, "application/json", CONFIG_JSON),
        "/status.php": (200, "text/html", LOGIN_HTML),
        "/admin.cgi": (401, "text/html", b"unauthorized"),
        "/js/app.js": (200, "application/javascript",
                       b"new Ajax.Request('/getcfg.php', {method:'get'});\n"
                       b"fetch('/api/v1/system');"),
        "/getcfg.php": (200, "application/json", b'{"firmware":"1.04","model":"X1000"}'),
        "/api/v1/system": (200, "application/json", b'{"firmware":"1.04"}'),
    }
    requested = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):                              # noqa: N802
            requested.append(self.path)
            status, ctype, body = routes.get(
                self.path.split("?")[0], (404, "text/plain", b"not found"))
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Server", "VulnHTTPd/1.0 (Boa 0.94.13)")
            self.send_header("X-Powered-By", "PHP/5.6.40")
            self.send_header("Set-Cookie", "SESSIONID=abc123")
            if status == 401:
                self.send_header("WWW-Authenticate", 'Basic realm="VulnRouter"')
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_HEAD = do_GET                               # noqa: N815

        def log_message(self, *args):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield srv.server_address[1], requested
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=3)


@pytest.fixture
def interr():
    return IoTInterrogator(timeout=2)


# ------------------------------------------------- selección de puertos web

class TestSelectWebPorts:
    """Qué puertos se interrogan: por nombre de servicio de nmap o por fallback."""

    @pytest.mark.parametrize("ports,expected", [
        # nombre de servicio HTTP → se selecciona aunque el puerto sea raro
        ([{"port": 7777, "service_name": "http-alt"}], [7777]),
        ([{"port": 9999, "service_name": "https"}], [9999]),
        # puerto de la lista de fallback aunque nmap no diera servicio
        ([{"port": 80, "service_name": ""}], [80]),
        # UDP nunca se interroga por HTTP
        ([{"port": 80, "protocol": "udp", "service_name": "http"}], []),
        # sin indicios ni fallback → no se toca
        ([{"port": 5555, "service_name": "unknown"}], []),
    ])
    def test_selection(self, interr, ports, expected):
        assert interr._select_web_ports(ports) == expected

    def test_result_is_sorted_and_deduplicated(self, interr):
        ports = [{"port": 443, "service_name": "https"},
                 {"port": 80, "service_name": "http"},
                 {"port": 80, "service_name": "http"}]
        assert interr._select_web_ports(ports) == [80, 443]


# --------------------------------------------------------- parseo XML seguro

def test_safe_parse_xml_reads_a_normal_descriptor():
    root = _safe_parse_xml(b"<root><friendlyName>Router</friendlyName></root>")
    assert root is not None


def test_safe_parse_xml_rejects_entity_expansion():
    """XXE: el descriptor SSDP viene del objetivo, que puede ser hostil."""
    xxe = (b'<?xml version="1.0"?>'
           b'<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]>'
           b"<r><friendlyName>&x;</friendlyName></r>")
    root = _safe_parse_xml(xxe)
    if root is not None:
        assert "/" not in "".join(e.text or "" for e in root.iter())


def test_safe_parse_xml_propagates_on_garbage_and_callers_absorb_it():
    """El parser NO devuelve None ante XML inválido: lanza. El contrato real es que
    cada llamante lo absorbe, y eso es lo que evita que un descriptor corrupto
    tumbe la auditoría."""
    with pytest.raises(Exception):
        _safe_parse_xml(b"no soy xml <<<")


# ------------------------------------ descubrimiento de endpoints sin auth

def test_unauth_endpoints_keeps_only_those_serving_data(interr):
    """El corazón del hallazgo web: se extraen los endpoints referenciados por la
    página sin autenticar, se PRUEBAN, y solo sobreviven los que devuelven datos."""
    with web_server() as (port, requested):
        base = f"http://127.0.0.1:{port}"
        found = interr._discover_unauth_endpoints(base, INDEX_HTML.decode())

    urls = [e["url"] for e in found]
    assert any("/config.json" in u for u in urls), "el JSON con credenciales debe salir"
    # Una página de login no es un dato expuesto, y un 401 prueba lo contrario.
    assert not any("/status.php" in u for u in urls)
    assert not any("/admin.cgi" in u for u in urls)
    assert not any("/nope.json" in u for u in urls)
    # Cada entrada trae con qué se clasificó y una muestra del dato, para que la
    # decisión sea auditable sin volver a pedir la URL.
    for entry in found:
        assert entry["type"] in ("data_json", "data_js_var", "data_xml",
                                 "data_text", "path_disclosure")
        assert entry["status"] == 200
        assert entry["data_preview"]


def test_unauth_endpoints_follows_ajax_calls_inside_referenced_js(interr):
    """Los paneles IoT esconden su API en el JS: se sigue el `Ajax.Request` del
    fichero referenciado, que es donde suele estar el endpoint interesante."""
    with web_server() as (port, requested):
        base = f"http://127.0.0.1:{port}"
        found = interr._discover_unauth_endpoints(base, INDEX_HTML.decode())
    assert "/js/app.js" in requested, "debía leer el JS referenciado"
    assert any("/getcfg.php" in e["url"] for e in found)


def test_js_scan_extracts_modern_endpoints_too(interr):
    """LIMITACIÓN CERRADA. Este test fijaba lo contrario: que el barrido del JS
    solo reconocía `Ajax.Request(...)` con destino `.php`, dejando fuera una API
    REST moderna (`fetch('/api/v1/system')`). Se aceptó entonces como decisión
    de diseño —ampliar el patrón agranda el rastreo— con la condición explícita
    de que, si se cambiaba, el test cambiara con ella. Se cambia aquí.

    El motivo es empírico: en la tanda del 2026-08-08 el barrido quedó ciego
    ante un router de operador cuyo panel no usa `.php` en absoluto. El coste de
    peticiones sigue acotado por el tope de 20 candidatos y los 3 ficheros JS,
    que es lo que de verdad limita el rastreo; restringir además el patrón solo
    limitaba el hallazgo."""
    with web_server() as (port, requested):
        base = f"http://127.0.0.1:{port}"
        interr._discover_unauth_endpoints(base, INDEX_HTML.decode())
    assert "/getcfg.php" in requested          # lo de siempre sigue
    assert "/api/v1/system" in requested       # y ahora también el REST


def test_unauth_endpoints_ignores_static_assets(interr):
    """No se prueban imágenes: solo extensiones que pueden servir datos."""
    with web_server() as (port, requested):
        interr._discover_unauth_endpoints(f"http://127.0.0.1:{port}",
                                          INDEX_HTML.decode())
    assert "/logo.png" not in requested


def test_unauth_endpoints_survives_a_dead_server(interr):
    """Si el servicio muere a mitad del interrogatorio, se devuelve lo que haya."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    dead = s.getsockname()[1]
    s.close()
    assert interr._discover_unauth_endpoints(
        f"http://127.0.0.1:{dead}", INDEX_HTML.decode()) == []


def test_unauth_endpoints_probes_config_paths_even_without_references(interr):
    """El descubrimiento ya no es SOLO dirigido por enlaces.

    Antes, una raíz sin referencias significaba «no hay nada que probar», y esa
    es exactamente la situación de un volcado de configuración: nadie pone un
    `<a href="/config.cfg">` en su panel. El vector más jugoso de un dispositivo
    IoT era, por construcción, el invisible. Ahora se siembra una lista corta de
    rutas de configuración y API que la experiencia de campo señala como
    habituales."""
    with web_server() as (port, requested):
        interr._discover_unauth_endpoints(
            f"http://127.0.0.1:{port}", "<html><body>nada</body></html>")
    assert "/config.cfg" in requested
    assert any(r.startswith("/api/") for r in requested)


# ------------------------------------------------- evidencia de cabeceras

def test_http_get_returns_none_instead_of_raising(interr):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    dead = s.getsockname()[1]
    s.close()
    assert interr._http_get(f"http://127.0.0.1:{dead}/", timeout=1) is None


def test_extract_http_fields_collects_the_fingerprint_headers(interr):
    with web_server() as (port, _):
        r = interr._http_get(f"http://127.0.0.1:{port}/", timeout=2)
    info = {}
    interr._extract_http_fields(r, info)
    assert "Boa 0.94.13" in (info.get("server") or ""), info
    assert "PHP/5.6.40" in (info.get("powered_by") or "")
    assert "VulnRouter X1000 Admin" in (info.get("title") or "")
    assert "SESSIONID" in (info.get("set_cookie") or "")


def test_evidence_tuple_records_url_status_and_snippet(interr):
    with web_server() as (port, _):
        r = interr._http_get(f"http://127.0.0.1:{port}/config.json", timeout=2)
    ev = interr._evidence_tuple(r)
    assert ev["status"] == 200
    assert ev["length"] > 0
    assert "admin" in ev["snippet"]
    assert ev["url"].endswith("/config.json")


def test_realm_is_captured_from_a_401(interr):
    """El `realm` del WWW-Authenticate suele nombrar el modelo del dispositivo."""
    with web_server() as (port, _):
        r = interr._http_get(f"http://127.0.0.1:{port}/admin.cgi", timeout=2)
    info = {}
    interr._extract_http_fields(r, info)
    assert "VulnRouter" in (info.get("realm") or "")
    assert info.get("www_authenticate")


# --------------------------------------------------------- banner TCP crudo

def test_tcp_banner_grab_reads_what_the_service_announces(interr, monkeypatch):
    """Solo se sondean puertos con banner conocido (`TCP_BANNER_PORTS`); se inyecta
    el puerto efímero en esa tabla para no necesitar privilegios sobre el 21."""
    import modules.interrogator as interrogator_mod

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    monkeypatch.setitem(interrogator_mod.TCP_BANNER_PORTS, port,
                        {"service": "ftp", "probe": b""})

    def serve():
        try:
            conn, _ = srv.accept()
            conn.sendall(b"220 VulnRouter FTP ready\r\n")
            conn.close()
        except OSError:
            pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        banner = interr._probe_tcp_banner("127.0.0.1", port)
    finally:
        t.join(timeout=3)
        srv.close()
    assert banner and "VulnRouter FTP" in banner


def test_tcp_banner_grab_skips_ports_without_a_known_banner(interr):
    """Un puerto que no está en la tabla no se sondea: evita ruido y tiempo."""
    assert interr._probe_tcp_banner("127.0.0.1", 65001) is None


def test_tcp_banner_grab_on_closed_port_returns_none(interr):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert interr._probe_tcp_banner("127.0.0.1", port) is None


# ------------------------------------------------------- flujo completo

def test_interrogate_consolidates_all_the_evidence(interr, monkeypatch):
    """`interrogate` es lo que consume `http_interrogate`: debe devolver el dict
    completo de evidencia aunque partes del sondeo (SSDP, TLS) no apliquen."""
    monkeypatch.setattr(interr, "_probe_ssdp_multi", lambda ip: None)
    with web_server() as (port, _):
        evidence = interr.interrogate("127.0.0.1", [
            {"port": port, "protocol": "tcp", "service_name": "http"},
        ])
    assert "VulnRouter X1000 Admin" in (evidence["http_title"] or "")
    assert "Boa 0.94.13" in (evidence["http_server"] or "")
    assert any("/config.json" in e["url"] for e in evidence["unauth_data_endpoints"])
    # Las claves del contrato existen siempre, aunque vengan vacías.
    for key in ("ssdp_model", "favicon_mmh3", "tls_cert_cn", "tcp_banners",
                "http_paths_evidence", "exact_model"):
        assert key in evidence


def test_interrogate_merges_ssdp_identity_when_present(interr, monkeypatch):
    monkeypatch.setattr(interr, "_probe_ssdp_multi", lambda ip: {
        "ssdp_model": "DIR-815", "ssdp_manufacturer": "D-Link",
        "ssdp_exact_model": "D-Link DIR-815",
    })
    with web_server() as (port, _):
        evidence = interr.interrogate("127.0.0.1", [
            {"port": port, "protocol": "tcp", "service_name": "http"}])
    assert evidence["ssdp_manufacturer"] == "D-Link"
    assert evidence["exact_model"] == "D-Link DIR-815"


def test_interrogate_with_no_web_ports_still_returns_the_contract(interr, monkeypatch):
    monkeypatch.setattr(interr, "_probe_ssdp_multi", lambda ip: None)
    evidence = interr.interrogate("127.0.0.1", [
        {"port": 161, "protocol": "udp", "service_name": "snmp"}])
    assert evidence["unauth_data_endpoints"] == []
    assert evidence["http_title"] is None
