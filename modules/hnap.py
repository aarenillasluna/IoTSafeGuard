"""
HNAP1 probe — revela modelo/firmware exacto en routers D-Link/otros.

HNAP (Home Network Administration Protocol) responde a SOAP sin auth para
acciones de lectura como GetDeviceSettings. Es la fuente más determinista
para D-Link DIR-*, algunos Cisco Linksys y derivados.
"""
import warnings
import requests
from loguru import logger

try:
    import urllib3
    _HAS_URLLIB3 = True
except ImportError:
    _HAS_URLLIB3 = False

try:
    from lxml import etree
    _HAS_LXML = True
except ImportError:
    _HAS_LXML = False
    import xml.etree.ElementTree as etree  # type: ignore[no-redef]

try:
    from defusedxml import ElementTree as _defused_ET
    _HAS_DEFUSED = True
except ImportError:
    _HAS_DEFUSED = False
    _defused_ET = None

# Parser lxml endurecido (sin resolución de entidades ni red): equivale a lo
# que hacía defusedxml.lxml, hoy deprecado. Solo se usa si falta defusedxml.
_SAFE_LXML_PARSER = (
    etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    if _HAS_LXML else None
)


def _safe_fromstring(xml_bytes: bytes):
    """Parse XML with XXE protection when defusedxml is available."""
    if _HAS_DEFUSED and _defused_ET:
        return _defused_ET.fromstring(xml_bytes)
    if _HAS_LXML:
        return etree.fromstring(xml_bytes, parser=_SAFE_LXML_PARSER)
    return etree.fromstring(xml_bytes)


HNAP_ACTIONS = ("GetDeviceSettings", "GetFirmwareStatus", "GetWanSettings", "GetWLanSettings")

# Tags SOAP que revelan identidad. Prioridad desc.
TAG_TO_KEY = {
    "ModelName": "model",
    "ModelDescription": "model_description",
    "FirmwareVersion": "firmware_version",
    "PresentationURL": "presentation_url",
    "VendorName": "manufacturer",
    "DeviceName": "device_name",
    "Type": "device_type",
    "SubType": "device_subtype",
    "HardwareVersion": "hardware_version",
}


def _soap_envelope(action: str) -> str:
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
        f'<soap:Body><{action} xmlns="http://purenetworks.com/HNAP1/"/></soap:Body>'
        '</soap:Envelope>'
    )


def _extract_tags(xml_bytes: bytes, out: dict) -> None:
    try:
        root = _safe_fromstring(xml_bytes)
    except Exception:
        return
    for elem in root.iter():
        tag = elem.tag.split('}')[-1]
        if tag in TAG_TO_KEY and elem.text:
            key = TAG_TO_KEY[tag]
            if not out.get(key):
                out[key] = elem.text.strip()


def hnap_probe(ip: str, port: int = 80, scheme: str = "http", timeout: float = 3.0) -> dict | None:
    """
    Llama a /HNAP1/ con varias actions; devuelve dict con evidencia o None si no hay soporte.
    """
    url = f"{scheme}://{ip}:{port}/HNAP1/"
    result: dict = {
        "supported": False,
        "endpoint": url,
        "manufacturer": None,
        "model": None,
        "model_description": None,
        "firmware_version": None,
        "hardware_version": None,
        "device_type": None,
        "actions_ok": [],
    }

    headers_base = {"Content-Type": "text/xml; charset=utf-8"}
    verify_flag = False
    with warnings.catch_warnings():
        if _HAS_URLLIB3:
            warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

        # Sondeo inicial: OPTIONS para detectar endpoint sin gastar SOAP
        try:
            r = requests.request("HEAD", url, timeout=timeout, verify=verify_flag)
            # Muchos HNAP devuelven 200 o 405; 404 ya nos dice que no hay.
            if r.status_code == 404:
                return None
        except requests.RequestException as e:
            logger.debug(f"[HNAP] HEAD falló en {url}: {e}")
            # no abortamos; a veces HEAD está deshabilitado

        for action in HNAP_ACTIONS:
            headers = dict(headers_base)
            headers["SOAPAction"] = f'"http://purenetworks.com/HNAP1/{action}"'
            try:
                r = requests.post(
                    url,
                    data=_soap_envelope(action),
                    headers=headers,
                    timeout=timeout,
                    verify=verify_flag,
                )
            except requests.RequestException as e:
                logger.debug(f"[HNAP] {action} error red: {e}")
                continue

            if r.status_code != 200:
                continue
            ct = r.headers.get("Content-Type", "").lower()
            body = r.content
            if not body or (b"<" not in body[:16] and "xml" not in ct):
                continue

            result["supported"] = True
            result["actions_ok"].append(action)
            _extract_tags(body, result)

    if not result["supported"]:
        return None
    logger.success(
        f"[HNAP] {ip}:{port} model={result.get('model')} fw={result.get('firmware_version')}"
    )
    return result


def hnap_probe_any(ip: str, candidate_ports: list[int], timeout: float = 3.0) -> dict | None:
    """
    Prueba HNAP en varios puertos web; devuelve el primer resultado con soporte.
    """
    for port in candidate_ports:
        scheme = "https" if port in (443, 8443) else "http"
        try:
            res = hnap_probe(ip, port=port, scheme=scheme, timeout=timeout)
        except Exception as e:
            logger.debug(f"[HNAP] excepción en {ip}:{port}: {e}")
            continue
        if res and res.get("supported"):
            return res
    return None
