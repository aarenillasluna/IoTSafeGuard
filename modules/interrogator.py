"""
IoT Interrogator — captura agresiva de evidencia de identidad.

Fuentes:
- SSDP Unicast M-SEARCH (múltiples ST) + parseo XML de descripción
- HTTP/HTTPS en puertos web detectados + paths well-known
- Favicon hash (MurmurHash3) estilo Shodan
- TLS cert CN/SAN para HTTPS/8443/etc.
- Banner-grab TCP crudo para servicios no-HTTP (telnet, ssh, ftp, smtp, redis, mqtt)
"""
from __future__ import annotations

import base64
import hashlib
import re
import socket
import ssl
import warnings
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests
from colorama import Fore
from loguru import logger

try:
    import urllib3
    _HAS_URLLIB3 = True
except ImportError:
    _HAS_URLLIB3 = False

try:
    from lxml import etree
    HAS_LXML = True
except ImportError:
    HAS_LXML = False

try:
    from defusedxml import ElementTree as defused_ET
except ImportError:
    defused_ET = None
    if not HAS_LXML:
        logger.warning("[INTERROGATOR] 'defusedxml' no instalado. Vulnerable a ataques XXE externos.")

# Parser lxml endurecido (sin resolución de entidades ni red): protección XXE
# equivalente a la del deprecado defusedxml.lxml, conservando la API lxml
# (xpath) que necesita el parseo SSDP.
_SAFE_LXML_PARSER = (
    etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    if HAS_LXML else None
)

if not HAS_LXML:
    logger.warning("[INTERROGATOR] 'lxml' no instalado. Usando parser estándar (más lento).")

try:
    import mmh3
    _HAS_MMH3 = True
except ImportError:
    _HAS_MMH3 = False

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


# -------------------------------------------------------------------------
# Constantes
# -------------------------------------------------------------------------

SSDP_SEARCH_TARGETS = (
    "ssdp:all",
    "upnp:rootdevice",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:MediaServer:1",
    "urn:dial-multiscreen-org:service:dial:1",
)

WELL_KNOWN_PATHS = (
    "/",
    "/index.html",
    "/index.htm",
    "/login.htm",
    "/login.html",
    "/device.xml",
    "/DeviceInfo.xml",
    "/system.xml",
    "/status.xml",
    "/info.cgi",
    "/common/info.cgi",
    "/cgi-bin/webproc",
    "/cgi-bin/webproc?getpage=html/index.html",
    "/goform/formLogin",
    "/manifest.json",
    "/robots.txt",
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/setup.cgi",
    "/hedwig.cgi",
    "/HNAP1/",
    "/rootDesc.xml",
    "/Ipc/WebComponents/WebComponents.xml",
    # --- Volcados de configuración y APIs REST ---
    #
    # Añadidos al validar el laboratorio: su vector `http-info-disclosure`
    # —`/config.cfg` y `/api/v1/system` sirviendo 200 sin autenticación— era
    # INDETECTABLE. No estaban en esta lista, la página raíz no los enlaza (así
    # que el barrido de HTML tampoco los veía) y `.cfg` ni siquiera figuraba
    # entre las extensiones reconocidas. El Anexo C daba el vector por
    # detectable y el recall de §5.2.4 lo contaba como fallo del agente.
    #
    # No es un caso de laboratorio: volcar la configuración en un fichero suelto
    # es de los patrones más comunes en firmware IoT, y una API REST sin
    # extensión es hoy la norma, no la excepción.
    "/config.cfg",
    "/config.xml",
    "/config.json",
    "/backup.cfg",
    "/system.ini",
    "/settings.json",
    "/api/system",
    "/api/status",
    "/api/info",
    "/api/v1/system",
    "/api/v1/status",
    "/cgi-bin/luci",
)

HTTP_INDICATORS = ("http", "https", "ssl", "soap", "upnp", "xml", "www", "hadoop")
FALLBACK_WEB_PORTS = (80, 443, 8080, 8081, 3000, 3001, 5000, 8000, 8008, 8443, 8888, 49152)
TLS_PORTS = (443, 8443, 9443, 4443, 10443)

# Servicios TCP no-HTTP donde el banner crudo suele traer modelo/versión.
TCP_BANNER_PORTS = {
    21: {"service": "ftp", "probe": b""},
    22: {"service": "ssh", "probe": b""},
    23: {"service": "telnet", "probe": b""},
    25: {"service": "smtp", "probe": b""},
    110: {"service": "pop3", "probe": b""},
    143: {"service": "imap", "probe": b""},
    554: {"service": "rtsp", "probe": b"OPTIONS rtsp://{ip}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"},
    2323: {"service": "telnet-alt", "probe": b""},
    6379: {"service": "redis", "probe": b"INFO\r\n"},
    9100: {"service": "jetdirect", "probe": b"\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X"},
    1883: {"service": "mqtt", "probe": b""},
}


# Puertos cuyo banner es una LÍNEA de identificación seguida de protocolo
# binario en el mismo segmento TCP. Solo la primera línea es banner.
_LINE_IDENT_PORTS = {22}

# Bytes de control que nunca forman parte de un banner legible. Se quitan antes
# de loguear y antes de parsear: `bytes.decode(errors="ignore")` NO los elimina
# —son codepoints Unicode válidos— y acababan en el fichero de log.
_CTRL_CHARS_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _clean_banner(raw: bytes, port: int) -> str:
    """Normaliza un banner crudo a texto imprimible de una sola línea.

    Dos cosas que el volcado directo hacía mal, ambas observadas en campo
    contra un router Askey con Dropbear:

    1. **SSH manda el ident y el KEXINIT en el mismo segmento.** El corte por
       `\\n` no basta: la línea de identificación termina en CRLF (RFC 4253
       §4.2) y justo detrás vienen los bytes del intercambio de claves. Se
       guardaban enteros::

           SSH-2.0-dropbear_2019.78 \\x00\\x00\\x01t\\x05\\x14...curve25519-sha256,...

    2. **Los bytes de control llegaban al log.** Cinco NUL bastaban para que
       `file` clasificase el log como `data` y `grep`/`tail` lo tratasen como
       binario — y el dashboard lo transmite línea a línea.

    Además de romper las herramientas, el ruido contaminaba la identidad: el
    extractor de modelo leía `curve25519-sha256` y publicaba el aparato como
    modelo «CURVE25519», que se propagaba a la KB y a las búsquedas de CVE.
    """
    if port in _LINE_IDENT_PORTS:
        for terminator in (b"\r\n", b"\n"):
            idx = raw.find(terminator)
            if idx != -1:
                raw = raw[:idx]
                break
    text = raw.decode(errors="ignore")
    text = _CTRL_CHARS_RE.sub(" ", text)
    return re.sub(r"\s+", " ", text).strip()[:400]


# -------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------

def _quiet_tls_warnings():
    if _HAS_URLLIB3:
        try:
            warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass


def _safe_parse_xml(content: bytes):
    """Parseo XML con protección XXE cuando está disponible."""
    if HAS_LXML:
        return etree.fromstring(content, parser=_SAFE_LXML_PARSER)
    if defused_ET:
        return defused_ET.fromstring(content)
    logger.warning("[XML] defusedxml no disponible, parser sin protección XXE")
    return ET.fromstring(content)


# -------------------------------------------------------------------------
# Interrogator
# -------------------------------------------------------------------------

class IoTInterrogator:
    """
    Recolección multi-fuente de evidencia HTTP/SSDP + TLS + banners + favicon.
    """

    def __init__(self, timeout: int = 3):
        self.timeout = timeout

    # ----- Entrada pública -------------------------------------------------

    def interrogate(self, ip: str, ports: List[Dict]) -> Dict:
        evidence: Dict = {
            "ssdp_model": None,
            "ssdp_manufacturer": None,
            "ssdp_exact_model": None,
            "ssdp_services": [],
            "http_title": None,
            "http_server": None,
            "http_realm": None,
            "http_powered_by": None,
            "http_set_cookie": None,
            "http_www_authenticate": None,
            "http_www_headers_map": {},        # puerto -> headers
            "http_paths_evidence": [],         # lista de (url, status, len, snippet)
            "unauth_data_endpoints": [],       # endpoints con datos sin autenticación
            "favicon_mmh3": None,
            "favicon_sha256": None,
            "tls_cert_cn": None,
            "tls_cert_san": [],
            "tls_cert_issuer": None,
            "tcp_banners": {},                 # puerto -> banner snippet
            "exact_model": None,               # consolidado SSDP/HNAP/banner
        }

        logger.info(f"[INTERROGATOR] Forzando identificación en {ip}")
        print(f"{Fore.CYAN}    [INTERROGATOR] Forzando identificación en {ip}...{Fore.RESET}")

        # 1) SSDP
        ssdp = self._probe_ssdp_multi(ip)
        if ssdp:
            evidence.update(ssdp)
            if ssdp.get("ssdp_exact_model"):
                evidence["exact_model"] = ssdp["ssdp_exact_model"]
            logger.success(f"[SSDP] Modelo: {evidence.get('ssdp_exact_model')}")

        # 2) Puertos web inteligentes (sin break anticipado)
        web_ports = self._select_web_ports(ports)
        self._probe_web_ports(ip, web_ports, evidence)

        # 3) TLS cert
        tls_ports = [p for p in web_ports if p in TLS_PORTS or p == 443]
        for tp in tls_ports:
            cert = self._probe_tls_cert(ip, tp)
            if cert:
                evidence["tls_cert_cn"] = evidence["tls_cert_cn"] or cert.get("cn")
                sans = cert.get("san") or []
                evidence["tls_cert_san"] = list({*evidence["tls_cert_san"], *sans})
                evidence["tls_cert_issuer"] = evidence["tls_cert_issuer"] or cert.get("issuer")

        # 4) Banner grab TCP crudo para servicios no-HTTP
        non_http_ports = [
            p["port"] for p in ports
            if p.get("protocol", "tcp") == "tcp" and p["port"] in TCP_BANNER_PORTS
        ]
        with ThreadPoolExecutor(max_workers=min(8, max(1, len(non_http_ports)))) as ex:
            futs = {ex.submit(self._probe_tcp_banner, ip, p): p for p in non_http_ports}
            for fut in as_completed(futs):
                port = futs[fut]
                banner = fut.result()
                if banner:
                    evidence["tcp_banners"][port] = banner

        return evidence

    # ----- Selección de puertos web ---------------------------------------

    def _select_web_ports(self, ports: List[Dict]) -> List[int]:
        selected: List[int] = []
        for p in ports:
            if p.get("protocol", "tcp") != "tcp":
                continue
            pn = p["port"]
            sn = (p.get("service_name") or "").lower()
            if any(ind in sn for ind in HTTP_INDICATORS):
                selected.append(pn)
            elif pn in FALLBACK_WEB_PORTS and pn not in selected:
                selected.append(pn)
        return sorted(set(selected))

    # ----- SSDP multi-ST ---------------------------------------------------

    def _probe_ssdp_multi(self, ip: str) -> Optional[Dict]:
        for st in SSDP_SEARCH_TARGETS:
            res = self._probe_ssdp(ip, st)
            if res:
                return res
        return None

    def _probe_ssdp(self, ip: str, search_target: str) -> Optional[Dict]:
        query = (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {ip}:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 1\r\n"
            f"ST: {search_target}\r\n"
            "\r\n"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(2)
            sock.sendto(query.encode(), (ip, 1900))
            data, _ = sock.recvfrom(2048)
        except socket.timeout:
            return None
        except Exception as e:
            logger.debug(f"[SSDP:{search_target}] {e}")
            return None
        finally:
            sock.close()

        response = data.decode(errors="ignore")
        loc = re.search(r"LOCATION:\s*(http[s]?://\S+)", response, re.IGNORECASE)
        if not loc:
            return None
        return self._fetch_ssdp_xml(loc.group(1).strip())

    def _fetch_ssdp_xml(self, url: str) -> Optional[Dict]:
        try:
            with warnings.catch_warnings():
                _quiet_tls_warnings()
                try:
                    r = requests.get(url, timeout=2, verify=False)
                except requests.exceptions.SSLError as e:
                    logger.warning(f"[SSDP XML] SSL fail {url}: {e}")
                    return None
            if r.status_code != 200:
                return None
            root = _safe_parse_xml(r.content)

            model = manufacturer = None
            services: List[Dict] = []

            if HAS_LXML:
                xp_ns = {"u": "urn:schemas-upnp-org:device-1-0",
                         "d": "urn:schemas-dlna-org:device-1-0"}
                mn = root.xpath(
                    '//u:modelName/text() | //d:modelName/text() | //*[local-name()="modelName"]/text()',
                    namespaces=xp_ns,
                )
                mf = root.xpath(
                    '//u:manufacturer/text() | //d:manufacturer/text() | //*[local-name()="manufacturer"]/text()',
                    namespaces=xp_ns,
                )
                model = (mn[0].strip() if mn else None)
                manufacturer = (mf[0].strip() if mf else None)

            if not model or not manufacturer:
                for elem in root.iter():
                    tag = elem.tag.split("}")[-1].lower()
                    if not model and tag == "modelname" and elem.text:
                        model = elem.text.strip()
                    if not manufacturer and tag == "manufacturer" and elem.text:
                        manufacturer = elem.text.strip()

            # Services
            for service in root.iter():
                tag = service.tag.split("}")[-1].lower()
                if tag != "service":
                    continue
                srv_type = ctrl_url = event_url = None
                for child in service.iter():
                    ctag = child.tag.split("}")[-1].lower()
                    if ctag == "servicetype" and child.text:
                        srv_type = child.text.strip()
                    elif ctag == "controlurl" and child.text:
                        ctrl_url = child.text.strip()
                    elif ctag == "eventsuburl" and child.text:
                        event_url = child.text.strip()
                if srv_type:
                    services.append({
                        "type": srv_type,
                        "control_url": ctrl_url,
                        "event_url": event_url,
                    })

            if not model:
                return None

            return {
                "ssdp_model": model,
                "ssdp_manufacturer": manufacturer or "Unknown",
                "ssdp_exact_model": f"{manufacturer or ''} {model}".strip(),
                "ssdp_services": services,
            }
        except Exception as e:
            logger.warning(f"[SSDP XML] Error {url}: {e}")
            return None

    # ----- HTTP probes -----------------------------------------------------

    def _probe_web_ports(self, ip: str, web_ports: List[int], evidence: Dict) -> None:
        """Sondea TODOS los puertos web en paralelo — no hace early break."""
        if not web_ports:
            return
        with ThreadPoolExecutor(max_workers=min(8, len(web_ports))) as ex:
            futs = {ex.submit(self._probe_http_port_full, ip, p): p for p in web_ports}
            for fut in as_completed(futs):
                port = futs[fut]
                try:
                    info = fut.result()
                except Exception as e:
                    logger.debug(f"[HTTP] {ip}:{port} excepción: {e}")
                    continue
                if not info:
                    continue

                # Consolida campos prioritarios (primer hallazgo por tipo)
                if not evidence["http_title"] and info.get("title"):
                    evidence["http_title"] = info["title"]
                if info.get("server"):
                    # Agrega TODOS los Server headers de los puertos (dedup), no solo el
                    # primero: servicios distintos exponen banners distintos (Boa:8080,
                    # RomPager:7547) y todos importan para fingerprint + cve_scan_recon.
                    # Antes se quedaba con el primer puerto → Boa/RomPager aparecía de
                    # forma no determinista según el orden de respuesta.
                    _existing = evidence.get("http_server") or ""
                    _parts = [t.strip() for t in re.split(r",\s*", _existing) if t.strip()]
                    for _tok in re.split(r",\s*", info["server"]):
                        _tok = _tok.strip()
                        if _tok and _tok not in _parts:
                            _parts.append(_tok)
                    evidence["http_server"] = ", ".join(_parts)
                if not evidence["http_realm"] and info.get("realm"):
                    evidence["http_realm"] = info["realm"]
                if not evidence["http_www_authenticate"] and info.get("www_authenticate"):
                    evidence["http_www_authenticate"] = info["www_authenticate"]
                if not evidence["http_powered_by"] and info.get("powered_by"):
                    evidence["http_powered_by"] = info["powered_by"]
                if not evidence["http_set_cookie"] and info.get("set_cookie"):
                    evidence["http_set_cookie"] = info["set_cookie"]
                if info.get("headers_map"):
                    evidence["http_www_headers_map"][port] = info["headers_map"]
                if info.get("paths_evidence"):
                    evidence["http_paths_evidence"].extend(info["paths_evidence"])
                if info.get("favicon_mmh3") and not evidence["favicon_mmh3"]:
                    evidence["favicon_mmh3"] = info["favicon_mmh3"]
                if info.get("favicon_sha256") and not evidence["favicon_sha256"]:
                    evidence["favicon_sha256"] = info["favicon_sha256"]
                # Aggregate unauthenticated data endpoints (deduplicate by URL)
                existing_urls = {e["url"] for e in evidence["unauth_data_endpoints"]}
                for ep in info.get("unauth_data_endpoints", []):
                    if ep["url"] not in existing_urls:
                        evidence["unauth_data_endpoints"].append(ep)
                        existing_urls.add(ep["url"])

    def _probe_http_port_full(self, ip: str, port: int) -> Optional[Dict]:
        """Sondeo completo de un puerto web: root + well-known + favicon."""
        scheme = "https" if port in TLS_PORTS else "http"
        base = f"{scheme}://{ip}:{port}"

        info: Dict = {
            "paths_evidence": [],
            "headers_map": {},
        }

        # 1) Root GET
        root_resp = self._http_get(base + "/", timeout=self.timeout)
        if root_resp is None and scheme == "http":
            # Puerto no respondió como HTTP — intentar HTTPS (común en 443, 8443 y otros TLS)
            root_resp = self._http_get(f"https://{ip}:{port}/", timeout=self.timeout)
            if root_resp is not None:
                base = f"https://{ip}:{port}"
                scheme = "https"

        if root_resp is not None:
            self._extract_http_fields(root_resp, info)
            info["paths_evidence"].append(self._evidence_tuple(root_resp))
            info["headers_map"] = dict(root_resp.headers)
            # Discover endpoints referenced by the unauthenticated page
            unauth = self._discover_unauth_endpoints(base, root_resp.text or "")
            if unauth:
                info["unauth_data_endpoints"] = unauth

        # 2) Well-known paths (limitadas para no saturar)
        for path in WELL_KNOWN_PATHS:
            if path == "/":
                continue
            url = base + path
            r = self._http_get(url, timeout=self.timeout)
            if r is None:
                continue
            # Captura evidencia solo si hay contenido o status interesante
            if r.status_code in (200, 401, 403) or len(r.content) > 50:
                self._extract_http_fields(r, info)
                info["paths_evidence"].append(self._evidence_tuple(r))

        # 3) Favicon
        fav = self._http_get(base + "/favicon.ico", timeout=self.timeout, stream=False)
        if fav is not None and fav.status_code == 200 and fav.content:
            info["favicon_sha256"] = hashlib.sha256(fav.content).hexdigest()
            if _HAS_MMH3:
                b64 = base64.encodebytes(fav.content)
                info["favicon_mmh3"] = mmh3.hash(b64)

        return info if (info["paths_evidence"] or info.get("favicon_sha256")) else None

    def _http_get(self, url: str, timeout: float, stream: bool = False) -> Optional[requests.Response]:
        try:
            with warnings.catch_warnings():
                _quiet_tls_warnings()
                try:
                    return requests.get(url, timeout=timeout, verify=False, allow_redirects=True, stream=stream)
                except requests.exceptions.SSLError as e:
                    logger.debug(f"[HTTP] SSL fail {url}: {e}")
                    return None
        except requests.Timeout:
            return None
        except requests.RequestException as e:
            logger.debug(f"[HTTP] req error {url}: {e}")
            return None
        except Exception as e:
            logger.debug(f"[HTTP] unknown {url}: {e}")
            return None

    # ----- Unauthenticated endpoint discovery --------------------------------

    # Volcado de configuración en texto plano: clave con carga + valor.
    # Ancla a principio de línea para no casar con el `?password=` de una URL
    # ni con el `name="password"` de un formulario HTML.
    _CONFIG_DUMP_RE = re.compile(
        r"^\s*[\w.\-]*(?:pass(?:wd|word)?|psk|secret|api[_-]?key|token|"
        r"private[_-]?key|community)[\w.\-]*\s*=\s*\S+",
        re.IGNORECASE | re.MULTILINE)

    _DATA_SIGNATURES = (
        # JSON / JS config blobs
        "var config=", "var settings=", "var system=",
        # Common IoT data keywords inside JSON/text
        '"ssid"', '"firmware"', '"version"', '"password"',
        '"model"', '"serial"', '"admin"', '"hostname"',
        # Error traces exposing paths/internals
        "Warning:", "Fatal error:", "in /home", "in /var", "in /etc",
        # XML data (not HTML)
        "<sysDescr>", "<modelName>", "<firmware>",
    )

    def _classify_response(self, r: requests.Response) -> str:
        """Classify a response as data/redirect/html/error for unauth endpoint discovery."""
        status = r.status_code
        if status in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "").lower()
            return "redirect_to_login" if "login" in loc else "redirect"
        if status in (401, 403):
            return "auth_required"
        if status == 404:
            return "not_found"
        if status != 200:
            return f"status_{status}"

        body = (r.text or "")[:600]
        ct = r.headers.get("Content-Type", "").lower()

        # Definitely HTML (login page, frameset, etc.) — not interesting as data
        if body.lstrip().startswith("<!") or "<html" in body[:100].lower():
            # But check for error traces that leak internals
            if any(sig in body for sig in ("Warning:", "Fatal error:", "in /home", "in /var")):
                return "path_disclosure"
            return "html_page"

        # JSON blob or JS variable assignment
        stripped = body.lstrip()
        if "json" in ct or stripped.startswith("{") or stripped.startswith("["):
            return "data_json"
        if stripped.startswith("var ") and "=" in stripped[:30]:
            return "data_js_var"

        # XML that is not HTML
        if ("xml" in ct or stripped.startswith("<?xml")) and "<!DOCTYPE html" not in body:
            return "data_xml"

        # Volcado de configuración estilo `clave=valor`.
        #
        # Las firmas de abajo exigen la clave ENTRECOMILLADA (`"password"`),
        # que es la forma JSON. El firmware IoT vuelca su configuración en
        # ficheros de texto plano sin comillas —`admin_password=…`,
        # `wifi_psk=…`— y ese caso quedaba sin clasificar. Detectado al validar
        # el laboratorio: `/config.cfg` servía usuario, contraseña de
        # administrador y PSK del wifi EN CLARO con un 200, y el clasificador lo
        # descartaba por no parecer «datos».
        #
        # Se exige que la clave tenga carga (`pass`, `psk`, `secret`, `key`,
        # `token`) y un valor no vacío detrás, para no marcar como filtración
        # cualquier fichero `.ini` inocuo.
        if self._CONFIG_DUMP_RE.search(body):
            return "config_dump"

        # Plain text with device-identifying content
        if any(sig in body for sig in self._DATA_SIGNATURES):
            return "data_text"

        return "html_page"

    def _discover_unauth_endpoints(self, base_url: str, html: str) -> List[Dict]:
        """
        Extract endpoints referenced by the unauthenticated main page and probe
        each without credentials. Returns only those that expose actual data.
        """
        # El descubrimiento era PURAMENTE dirigido por enlaces: solo se probaba
        # lo que la página raíz referenciaba. Y un volcado de configuración no
        # se enlaza NUNCA —nadie pone un `<a href="/config.cfg">` en su panel—,
        # de modo que el caso más jugoso de un dispositivo IoT era justo el
        # invisible. Detectado al validar el laboratorio: `/config.cfg` servía
        # las credenciales de administrador y la PSK del wifi en claro con un
        # 200, y ninguna auditoría lo encontró.
        #
        # Se siembra la lista con las rutas que la experiencia de campo señala
        # como habituales. Siguen acotadas por el tope de 20 candidatos.
        candidates: "set[str]" = {
            "/config.cfg", "/config.xml", "/config.json", "/backup.cfg",
            "/system.ini", "/settings.json", "/status.json", "/info.json",
            "/api/system", "/api/status", "/api/info",
            "/api/v1/system", "/api/v1/status",
        }

        # --- Extract from HTML src/href attributes ---
        for m in re.finditer(
            # `cfg|conf|ini|bak` se añaden por el mismo motivo que las rutas de
            # configuración de WELL_KNOWN_PATHS: son las extensiones con las que
            # el firmware IoT vuelca sus ajustes, y quedaban fuera.
            r'(?:src|href|action)=["\']([^"\'#?][^"\']*\.(?:php|json|xml|cgi|cfg|conf|ini|bak)[^"\']*)["\']',
            html, re.IGNORECASE,
        ):
            candidates.add(m.group(1).split("?")[0])  # strip cache-buster query

        # Also keep known data-bearing query-string variants already in the src
        for m in re.finditer(
            r'src=["\']([^"\']*\.php\?[^"\']+)["\']', html, re.IGNORECASE
        ):
            url = m.group(1)
            # Keep only short, clearly data-bearing query strings (json=true, etc.)
            if len(url) < 80:
                candidates.add(url)

        # --- Scan top-3 referenced JS files for endpoint references ---
        # Antes solo se reconocía `Ajax.Request(...)`/`new Request(...)` con
        # destino `.php` —limitación declarada en §4.1.3—, de modo que el
        # barrido era ciego ante `fetch`, `XMLHttpRequest`, jQuery o axios, y
        # ante cualquier endpoint `.cgi`, `.asp` o `/api/...`. Es decir, ciego
        # justo en el firmware de operador, que es donde más falta hace. Se
        # comparte ahora el extractor con el descubrimiento de login, para que
        # «qué parece un endpoint» tenga una sola definición en el sistema.
        js_refs = re.findall(r'src=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', html, re.IGNORECASE)
        for js_href in js_refs[:3]:
            js_url = js_href if js_href.startswith("http") else f"{base_url.rstrip('/')}/{js_href.lstrip('/')}"
            try:
                jr = requests.get(js_url, timeout=self.timeout, verify=False)
                if jr.status_code != 200:
                    continue
                for ref in extract_js_endpoints(jr.text):
                    candidates.add(ref.split("?")[0])
            except Exception:
                continue

        # --- Probe each candidate ---
        parsed = urlparse(base_url)
        results: List[Dict] = []
        seen_normalized: "set[str]" = set()

        for cand in list(candidates)[:20]:
            if cand.startswith("http"):
                test_url = cand
            elif cand.startswith("/"):
                test_url = f"{parsed.scheme}://{parsed.netloc}{cand}"
            else:
                test_url = f"{base_url.rstrip('/')}/{cand}"

            # Normalize for deduplication
            norm = re.sub(r"\?.*", "", test_url).rstrip("/")
            if norm in seen_normalized:
                continue
            seen_normalized.add(norm)

            try:
                r = requests.get(test_url, timeout=self.timeout, verify=False, allow_redirects=False)
            except Exception:
                continue

            rtype = self._classify_response(r)
            if rtype in ("data_json", "data_js_var", "data_xml", "data_text",
                         "config_dump", "path_disclosure"):
                results.append({
                    "url": test_url,
                    "status": r.status_code,
                    "type": rtype,
                    "data_preview": (r.text or "")[:400],
                })
                logger.warning(f"[UNAUTH] {rtype} @ {test_url}")

        return results

    def _extract_http_fields(self, r: requests.Response, info: Dict) -> None:
        # Title (DOTALL + multiline)
        if not info.get("title"):
            m = re.search(r"<title[^>]*>(.*?)</title>", r.text or "", re.IGNORECASE | re.DOTALL)
            if m:
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
                if title:
                    info["title"] = title
        if not info.get("server") and r.headers.get("Server"):
            info["server"] = r.headers["Server"]
        if not info.get("powered_by") and r.headers.get("X-Powered-By"):
            info["powered_by"] = r.headers["X-Powered-By"]
        if not info.get("set_cookie") and r.headers.get("Set-Cookie"):
            info["set_cookie"] = r.headers["Set-Cookie"][:300]
        if r.status_code == 401 and r.headers.get("WWW-Authenticate"):
            info["www_authenticate"] = r.headers["WWW-Authenticate"]
            info["realm"] = r.headers["WWW-Authenticate"]

    def _evidence_tuple(self, r: requests.Response) -> Dict:
        snippet = (r.text or "")[:300]
        snippet = re.sub(r"\s+", " ", snippet).strip()
        return {
            "url": r.url,
            "status": r.status_code,
            "length": len(r.content or b""),
            "server": r.headers.get("Server"),
            "snippet": snippet,
        }

    # ----- TLS cert --------------------------------------------------------

    def _probe_tls_cert(self, ip: str, port: int) -> Optional[Dict]:
        if not _HAS_CRYPTO:
            return None
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                    der = ssock.getpeercert(binary_form=True)
            if not der:
                return None
            cert = x509.load_der_x509_certificate(der, default_backend())
            cn = None
            for attr in cert.subject:
                if attr.oid == x509.NameOID.COMMON_NAME:
                    cn = attr.value
                    break
            issuer = None
            for attr in cert.issuer:
                if attr.oid == x509.NameOID.COMMON_NAME:
                    issuer = attr.value
                    break
            sans: List[str] = []
            try:
                ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                sans = [str(n.value) for n in ext.value]
            except x509.ExtensionNotFound:
                pass
            return {"cn": cn, "issuer": issuer, "san": sans}
        except Exception as e:
            logger.debug(f"[TLS] {ip}:{port} cert error: {e}")
            return None

    # ----- TCP banner grab -------------------------------------------------

    def _probe_tcp_banner(self, ip: str, port: int) -> Optional[str]:
        cfg = TCP_BANNER_PORTS.get(port)
        if not cfg:
            return None
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                probe: bytes = cfg["probe"]
                if probe:
                    probe = probe.replace(b"{ip}", ip.encode())
                    try:
                        sock.sendall(probe)
                    except OSError:
                        pass
                chunks: List[bytes] = []
                total = 0
                while total < 2048:
                    try:
                        buf = sock.recv(1024)
                    except socket.timeout:
                        break
                    if not buf:
                        break
                    chunks.append(buf)
                    total += len(buf)
                    if b"\n" in buf and total > 16:
                        break
            if not chunks:
                return None
            raw = b"".join(chunks)
            banner = _clean_banner(raw, port)
            logger.info(f"[BANNER] {ip}:{port} ({cfg['service']}): {banner[:120]}")
            return banner
        except Exception as e:
            logger.debug(f"[BANNER] {ip}:{port} error: {e}")
            return None


# =========================================================================
# Descubrimiento del mecanismo de login
# =========================================================================
#
# Motivación, medida en campo (tanda del 2026-08-08, router ASKEY):
# `web_login` agotó sus cinco estrategias y devolvió `method="all_failed"` con
# una nota que decía, literalmente, «baja el JS principal y busca
# doLogin/submitForm». La misma instrucción estaba en el prompt de explotación.
# El modelo la ignoró en las 4 ejecuciones en que se dio la condición, mientras
# tenía en la mano un `GET /` que devolvía 200 con HTML.
#
# La conclusión no es que hiciera falta insistir más: el disparador ya era
# perfecto —`all_failed` es binario, lo emite código determinista y llega en el
# instante exacto—. Es que un paso mecánico que el modelo omite de forma
# sistemática deja de ser una decisión suya. Mismo razonamiento que la
# solo-lectura en recon (§4.5.1): una regla que solo vive en el prompt no
# existe. Aquí se hace, no se pide.
#
# Devuelve DATOS, no un veredicto: el agente sigue decidiendo qué hacer con los
# endpoints encontrados.

# Referencias a endpoints dentro de JavaScript. El barrido de
# `unauth_data_endpoints` solo reconocía `Ajax.Request(...)`/`new Request(...)`
# terminados en `.php` —limitación documentada en §4.1.3— y por eso no veía
# nada en firmware que use `fetch`, `XMLHttpRequest`, jQuery o axios, ni
# endpoints `.cgi`, `.asp` o `/api/...`, que es justo lo que sirve un router de
# operador. Un solo conjunto de patrones para los dos consumidores.
_JS_ENDPOINT_PATTERNS = (
    r"""(?:Ajax\.Request|new\s+Request)\s*\(\s*['"]([^'"]{1,120})['"]""",
    r"""fetch\s*\(\s*['"]([^'"]{1,120})['"]""",
    r"""\.open\s*\(\s*['"](?:GET|POST|PUT)['"]\s*,\s*['"]([^'"]{1,120})['"]""",
    r"""\$\.(?:get|post|ajax)\s*\(\s*['"]([^'"]{1,120})['"]""",
    r"""axios\.(?:get|post)\s*\(\s*['"]([^'"]{1,120})['"]""",
    r"""(?:url|action|endpoint)\s*:\s*['"]([^'"]{1,120})['"]""",
)

# Señales de que un endpoint es el de AUTENTICACIÓN y no uno cualquiera.
_LOGIN_HINT_RE = re.compile(
    r"login|logon|signin|sign_in|auth|session|passwd|password|credential|"
    r"userlogin|checkuser|dologin|submitlogin",
    re.IGNORECASE)

# Nombres habituales de los campos del formulario. Sin ellos se conoce el
# endpoint pero no cómo rellenarlo, que es justo lo que hace falta para probar
# credenciales por defecto.
_USER_FIELD_RE = re.compile(
    r"user(?:name)?|login|account|admin_?name|loginUsername", re.IGNORECASE)
_PASS_FIELD_RE = re.compile(
    r"pass(?:wo?rd)?|pwd|passwd|loginPassword", re.IGNORECASE)

_MAX_JS_FILES = 4          # cota de peticiones: no se martillea el objetivo
_MAX_JS_BYTES = 512 * 1024


def _absolutize(ref: str, base_url: str) -> str:
    if ref.startswith(("http://", "https://")):
        return ref
    parsed = urlparse(base_url)
    if ref.startswith("/"):
        return f"{parsed.scheme}://{parsed.netloc}{ref}"
    return f"{base_url.rstrip('/')}/{ref.lstrip('/')}"


def extract_js_endpoints(text: str) -> List[str]:
    """Endpoints referenciados desde JavaScript, con todos los patrones."""
    found: "set[str]" = set()
    for pattern in _JS_ENDPOINT_PATTERNS:
        for m in re.finditer(pattern, text):
            ref = m.group(1).strip()
            # Descarta protocolos no-HTTP y fragmentos vacíos o triviales.
            if not ref or ref.startswith(("data:", "javascript:", "#", "mailto:")):
                continue
            found.add(ref)
    return sorted(found)


def _parse_login_forms(html: str) -> List[Dict]:
    """Formularios cuyo contenido sugiere que son de autenticación."""
    forms: List[Dict] = []
    for m in re.finditer(r"<form\b(.*?)</form>", html, re.IGNORECASE | re.DOTALL):
        block = m.group(0)
        attrs = m.group(1)
        action = re.search(r"""action\s*=\s*['"]([^'"]*)['"]""", attrs, re.IGNORECASE)
        method = re.search(r"""method\s*=\s*['"]([^'"]*)['"]""", attrs, re.IGNORECASE)
        names = re.findall(r"""<input\b[^>]*name\s*=\s*['"]([^'"]+)['"]""",
                           block, re.IGNORECASE)
        # El campo de contraseña se toma del `type="password"` antes que del
        # nombre: el tipo es declarativo y no depende de cómo lo haya llamado el
        # fabricante. Sin esto, un `<input name="psd" type="password">` —vistos
        # en firmware de operador— se detectaba como formulario de login pero
        # dejaba el campo sin identificar, que es la mitad inútil del hallazgo.
        typed_password = re.findall(
            r"""<input\b(?=[^>]*type\s*=\s*['"]password['"])[^>]*"""
            r"""name\s*=\s*['"]([^'"]+)['"]""", block, re.IGNORECASE)
        types = re.findall(r"""<input\b[^>]*type\s*=\s*['"]password['"]""",
                           block, re.IGNORECASE)
        user_field = next((n for n in names if _USER_FIELD_RE.search(n)), None)
        pass_field = (typed_password[0] if typed_password
                      else next((n for n in names if _PASS_FIELD_RE.search(n)), None))
        if user_field is None and typed_password:
            # Con la contraseña identificada, el usuario suele ser el input de
            # texto inmediatamente anterior.
            others = [n for n in names if n not in typed_password]
            user_field = others[0] if others else None
        # Es de login si tiene un input de tipo password, o si los nombres de
        # los campos lo delatan. Un buscador con un campo `q` no cuela.
        if not (types or (user_field and pass_field)):
            continue
        forms.append({
            "action": (action.group(1) if action else "") or "(same page)",
            "method": (method.group(1).upper() if method else "GET"),
            "username_field": user_field,
            "password_field": pass_field,
            "all_fields": sorted(set(names)),
        })
    return forms


def discover_login_mechanism(base_url: str, timeout: int = 8) -> Dict:
    """Deduce cómo autentica un panel web cuando las estrategias conocidas fallan.

    Baja la página raíz, extrae los formularios de login y los endpoints
    referenciados desde el JavaScript que enlaza, y separa los que parecen de
    autenticación. Acotado a `_MAX_JS_FILES` descargas y `_MAX_JS_BYTES` por
    fichero: es una sonda de auditoría, no una araña.

    Todo lo devuelto es DATO observado. No intenta autenticarse ni concluye
    nada: esa decisión sigue siendo del agente.
    """
    out: Dict = {
        "base_url": base_url, "reachable": False, "login_forms": [],
        "login_endpoints": [], "other_endpoints": [], "js_files_scanned": [],
        "html_evidence": "", "notes": [],
    }
    try:
        r = requests.get(base_url, timeout=timeout, verify=False)
    except Exception as e:
        out["notes"].append(f"root page unreachable: {type(e).__name__}")
        return out

    out["reachable"] = True
    html = r.text or ""
    out["login_forms"] = _parse_login_forms(html)

    refs: "set[str]" = set()
    for form in out["login_forms"]:
        action = form.get("action") or ""
        if action and action != "(same page)":
            refs.add(action)

    # JS enlazado desde la raíz.
    js_refs = re.findall(r"""src=['"]([^'"]*\.js(?:\?[^'"]*)?)['"]""",
                         html, re.IGNORECASE)
    for js_href in js_refs[:_MAX_JS_FILES]:
        js_url = _absolutize(js_href, base_url)
        try:
            jr = requests.get(js_url, timeout=timeout, verify=False, stream=True)
            if jr.status_code != 200:
                continue
            body = jr.raw.read(_MAX_JS_BYTES, decode_content=True) or b""
            text = body.decode("utf-8", errors="replace")
        except Exception:
            continue
        out["js_files_scanned"].append(js_url)
        refs.update(extract_js_endpoints(text))

    # Los scripts embebidos en la propia página cuentan igual.
    for m in re.finditer(r"<script\b[^>]*>(.*?)</script>", html,
                         re.IGNORECASE | re.DOTALL):
        refs.update(extract_js_endpoints(m.group(1)))

    login, other = [], []
    for ref in sorted(refs):
        (login if _LOGIN_HINT_RE.search(ref) else other).append(
            _absolutize(ref, base_url))
    out["login_endpoints"] = login
    out["other_endpoints"] = other[:20]

    # La extracción determinista NO es la única voz, y esto es deliberado.
    #
    # El paso que el modelo omitía de forma sistemática era BAJAR la página; de
    # que fallara INTERPRETÁNDOLA no hay ninguna evidencia —nunca llegó a ese
    # punto— y leer un formulario HTML es justo lo que un LLM hace bien. Un
    # extractor por expresión regular, en cambio, se rompe con un atributo sin
    # comillas, con los atributos en otro orden o con un panel renderizado por
    # JavaScript.
    #
    # El riesgo real no es que la regex falle: es que falle EN SILENCIO y el
    # modelo se fíe del negativo, dando por inexistente un login que él mismo
    # habría encontrado leyendo el HTML. Un extractor determinista que falla
    # callando es peor que no tenerlo, porque fabrica confianza.
    #
    # Por eso se adjunta siempre el HTML observado, acotado: lo determinista
    # resuelve el caso común y ahorra turnos, y el modelo conserva la evidencia
    # para contradecirlo cuando la estructura sea rara. Determinismo donde
    # acierta; juicio donde hace falta.
    out["html_evidence"] = _bounded_evidence(html)

    if not out["login_forms"] and not login:
        out["notes"].append(
            "Deterministic extraction found no login form or auth endpoint. "
            "This is a HINT, not a verdict: the parser is regex-based and misses "
            "unquoted attributes, unusual attribute order and JS-rendered panels. "
            "Read `html_evidence` yourself before concluding there is no web "
            "login — and if you find one there, use it and say so."
        )
    return out


_EVIDENCE_MAX = 3000


def _bounded_evidence(html: str) -> str:
    """Recorte del HTML para que el modelo pueda revisar la extracción.

    Se prioriza lo que importa —formularios y scripts embebidos— sobre el
    principio del documento, porque en un panel real la cabecera son
    kilobytes de CSS y metadatos que no dicen nada del login.
    """
    if not html:
        return ""
    interesting: List[str] = []
    for pattern in (r"<form\b.*?</form>", r"<script\b[^>]*>.*?</script>"):
        for m in re.finditer(pattern, html, re.IGNORECASE | re.DOTALL):
            interesting.append(m.group(0))
    blob = "\n".join(interesting) if interesting else html
    blob = re.sub(r"\s+", " ", blob).strip()
    if len(blob) <= _EVIDENCE_MAX:
        return blob
    return blob[:_EVIDENCE_MAX] + f"… [recortado, {len(blob)} caracteres en total]"
