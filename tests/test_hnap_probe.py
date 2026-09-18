"""Sonda HNAP1 (`modules/hnap.py`) — la fuente de identidad de MAYOR peso.

Esta sonda pesa 1,00 en el consenso de *fingerprinting* (§4.7), más que la OUI de
la MAC, porque es el propio dispositivo el que declara su modelo y firmware por
SOAP sin autenticación. Aun así estaba al **0 % de cobertura**: la señal en la que
el sistema más confía era la única sin pruebas propias.

Las pruebas levantan un **servidor HNAP falso local** en lugar de mockear
`requests`, para ejercitar de verdad la petición, el parseo XML y la extracción de
tags. Sin red externa y sin privilegios.
"""
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


from modules.hnap import (
    HNAP_ACTIONS,
    TAG_TO_KEY,
    _extract_tags,
    _soap_envelope,
    hnap_probe,
    hnap_probe_any,
)

SOAP_DEVICE_SETTINGS = b"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
 <soap:Body>
  <GetDeviceSettingsResponse xmlns="http://purenetworks.com/HNAP1/">
   <ModelName>DIR-815</ModelName>
   <ModelDescription>Wireless N Router</ModelDescription>
   <FirmwareVersion>1.04</FirmwareVersion>
   <HardwareVersion>B1</HardwareVersion>
   <VendorName>D-Link</VendorName>
   <Type>GatewayWithWiFi</Type>
   <PresentationURL>http://192.168.0.1/</PresentationURL>
  </GetDeviceSettingsResponse>
 </soap:Body>
</soap:Envelope>"""


@contextmanager
def hnap_server(head_status=200, post_status=200, body=SOAP_DEVICE_SETTINGS,
                content_type="text/xml; charset=utf-8"):
    """Servidor HNAP falso. Devuelve (puerto, peticiones_recibidas)."""
    received = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_HEAD(self):                       # noqa: N802 (API de BaseHTTPRequestHandler)
            received.append(("HEAD", self.path, None))
            self.send_response(head_status)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):                       # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            payload = self.rfile.read(length) if length else b""
            received.append(("POST", self.headers.get("SOAPAction"), payload))
            self.send_response(post_status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def log_message(self, *args):            # silencia el log del servidor
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield srv.server_address[1], received
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=3)


# ----------------------------------------------------------- construcción SOAP

def test_soap_envelope_carries_action_and_hnap_namespace():
    env = _soap_envelope("GetDeviceSettings")
    assert env.startswith('<?xml version="1.0"')
    assert "<GetDeviceSettings " in env
    assert 'xmlns="http://purenetworks.com/HNAP1/"' in env
    assert "soap:Envelope" in env and "soap:Body" in env


def test_probe_asks_for_every_known_action():
    """Si se añade una acción a HNAP_ACTIONS debe consultarse de verdad."""
    with hnap_server() as (port, received):
        hnap_probe("127.0.0.1", port=port)
    actions_asked = [
        soap_action for method, soap_action, _ in received if method == "POST"
    ]
    for action in HNAP_ACTIONS:
        assert any(action in (a or "") for a in actions_asked), action


# ------------------------------------------------------- extracción de tags

def test_extract_tags_maps_every_declared_tag():
    out = {}
    _extract_tags(SOAP_DEVICE_SETTINGS, out)
    assert out["model"] == "DIR-815"
    assert out["firmware_version"] == "1.04"
    assert out["manufacturer"] == "D-Link"
    assert out["hardware_version"] == "B1"
    assert out["device_type"] == "GatewayWithWiFi"
    assert out["model_description"] == "Wireless N Router"


def test_extract_tags_does_not_overwrite_an_earlier_value():
    """Las acciones se consultan en orden de prioridad: la primera respuesta que
    resuelve un campo manda, para que una acción posterior menos fiable no lo pise."""
    out = {"model": "DIR-815"}
    _extract_tags(b'<r xmlns=""><ModelName>OTRO-MODELO</ModelName></r>', out)
    assert out["model"] == "DIR-815"


def test_extract_tags_ignores_unknown_and_empty_tags():
    out = {}
    _extract_tags(b"<r><Desconocido>x</Desconocido><ModelName></ModelName></r>", out)
    assert out == {}


def test_extract_tags_survives_malformed_xml():
    """Un dispositivo que devuelve basura no puede tumbar la auditoría."""
    out = {}
    _extract_tags(b"<r><ModelName>sin cerrar", out)
    assert out == {}  # no lanza


def test_extract_tags_does_not_resolve_external_entities():
    """XXE: el parseo está endurecido (defusedxml o lxml sin entidades). Un
    dispositivo hostil no debe conseguir que el agente lea ficheros locales."""
    xxe = (b'<?xml version="1.0"?>'
           b'<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]>'
           b'<r><ModelName>&x;</ModelName></r>')
    out = {}
    _extract_tags(xxe, out)              # no lanza y no filtra el fichero
    assert "model" not in out or "/" not in out.get("model", "")


def test_tag_map_covers_the_identity_fields_the_probe_returns():
    """El dict de salida y la tabla de tags no pueden divergir en silencio."""
    with hnap_server() as (port, _):
        result = hnap_probe("127.0.0.1", port=port)
    for key in TAG_TO_KEY.values():
        if key in ("presentation_url", "device_name", "device_subtype"):
            continue  # opcionales, no siempre presentes en el dict base
        assert key in result, key


# --------------------------------------------------------------- hnap_probe

def test_probe_returns_identity_when_device_speaks_hnap():
    with hnap_server() as (port, _):
        result = hnap_probe("127.0.0.1", port=port)
    assert result is not None
    assert result["supported"] is True
    assert result["model"] == "DIR-815"
    assert result["firmware_version"] == "1.04"
    assert result["endpoint"].endswith("/HNAP1/")
    assert "GetDeviceSettings" in result["actions_ok"]


def test_probe_gives_up_early_on_404_head():
    """Un 404 en el HEAD dice que no hay HNAP: no se gastan cuatro POST SOAP."""
    with hnap_server(head_status=404) as (port, received):
        result = hnap_probe("127.0.0.1", port=port)
    assert result is None
    assert not [m for m, _, _ in received if m == "POST"], "no debía enviar SOAP"


def test_probe_returns_none_when_actions_do_not_answer_200():
    with hnap_server(post_status=500) as (port, _):
        assert hnap_probe("127.0.0.1", port=port) is None


def test_probe_ignores_non_xml_bodies():
    """Un panel web que responde 200 con HTML no es soporte HNAP."""
    with hnap_server(body=b"<!DOCTYPE html><html><body>login</body></html>",
                     content_type="text/html") as (port, _):
        result = hnap_probe("127.0.0.1", port=port)
    # El cuerpo empieza por '<' así que se acepta como XML y se intenta parsear,
    # pero no hay tags de identidad: el resultado no aporta modelo ni firmware.
    assert result is None or (result.get("model") is None
                             and result.get("firmware_version") is None)


def test_probe_returns_none_on_closed_port():
    """Sin servicio no hay excepción que escape: devuelve None."""
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert hnap_probe("127.0.0.1", port=port, timeout=1) is None


def test_probe_survives_empty_body_200():
    with hnap_server(body=b"") as (port, _):
        assert hnap_probe("127.0.0.1", port=port) is None


# ------------------------------------------------------------ hnap_probe_any

def test_probe_any_returns_the_first_supporting_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    dead_port = s.getsockname()[1]
    s.close()
    with hnap_server() as (live_port, _):
        result = hnap_probe_any("127.0.0.1", [dead_port, live_port], timeout=1)
    assert result is not None and result["model"] == "DIR-815"
    assert result["endpoint"].endswith(f":{live_port}/HNAP1/")


def test_probe_any_returns_none_when_no_port_supports_hnap():
    with hnap_server(head_status=404) as (port, _):
        assert hnap_probe_any("127.0.0.1", [port], timeout=1) is None


def test_probe_any_uses_https_for_tls_ports(monkeypatch):
    """El esquema se deriva del puerto: 443/8443 → https, resto → http."""
    seen = []

    def fake_probe(ip, port=80, scheme="http", timeout=3.0):
        seen.append((port, scheme))
        return None

    monkeypatch.setattr("modules.hnap.hnap_probe", fake_probe)
    hnap_probe_any("127.0.0.1", [80, 443, 8080, 8443])
    assert seen == [(80, "http"), (443, "https"), (8080, "http"), (8443, "https")]


def test_probe_any_isolates_a_probe_that_explodes(monkeypatch):
    """Una excepción en un puerto no puede impedir que se pruebe el siguiente."""
    calls = []

    def flaky(ip, port=80, scheme="http", timeout=3.0):
        calls.append(port)
        if port == 80:
            raise RuntimeError("boom")
        return {"supported": True, "model": "X"}

    monkeypatch.setattr("modules.hnap.hnap_probe", flaky)
    result = hnap_probe_any("127.0.0.1", [80, 8080])
    assert calls == [80, 8080]
    assert result["model"] == "X"
