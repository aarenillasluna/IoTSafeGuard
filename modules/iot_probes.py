"""
Probes IoT/OT específicos de protocolo, raw socket sin dependencias externas:

- probe_modbus       → Modbus TCP (502): FC17 (Report Slave ID) + FC1 (Read Coils).
- probe_rtsp         → RTSP/ONVIF (554, 8554): OPTIONS, DESCRIBE, creds default.
- probe_bacnet       → BACnet/IP (UDP 47808): Who-Is unicast, parser I-Am.
- probe_cwmp         → TR-069/CWMP (7547): banner + Mirai (CVE-2017-17215).
- probe_telnet       → Telnet (23): banner + detección Mirai/Hikvision/BusyBox.
- probe_upnp_igd     → UPnP IGD (SSDP 1900 + SCPD): AddPortMapping sin auth.
- probe_wsdiscovery  → WS-Discovery (UDP 3702): cámaras/impresoras (ONVIF, PrinterDevice).
- probe_opcua        → OPC-UA (4840): Hello → ACK + GetEndpoints.
- probe_tftp         → TFTP (UDP 69): RRQ anónimo de firmware/config comunes.
- probe_udp_raw      → UDP genérico: un datagrama con payload propia o de librería.
- probe_tcp_raw      → TCP genérico: banner-grab y/o payload propia (Tuya, ESPHome…).

Shape estándar:
    {
      "ok": bool, "ip": str, "port": int, "service": str,
      "protocol_confirmed": bool,
      "vulnerabilities": [...], "details": {...}, "error": str|None,
    }
"""
from __future__ import annotations

import base64
import os
import re
import select
import shutil
import socket
import struct
import subprocess
import time
import zlib
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    import pty as _pty  # Unix: para introducir la contraseña SSH sin sshpass
except ImportError:  # pragma: no cover
    _pty = None


# =============================================================================
# Modbus TCP
# =============================================================================
def _modbus_frame(unit_id: int, function_code: int, data: bytes = b"",
                  trans_id: int = 1) -> bytes:
    """Construye un frame MBAP+PDU."""
    pdu = bytes([function_code]) + data
    length = len(pdu) + 1  # +1 unit_id
    return struct.pack("!HHHB", trans_id, 0, length, unit_id) + pdu


def _parse_mbap(data: bytes) -> Optional[Dict[str, Any]]:
    if len(data) < 8:
        return None
    trans_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
    if proto_id != 0:
        return None
    fc = data[7]
    pdu = data[8:8 + length - 1]
    return {"trans_id": trans_id, "length": length, "unit_id": unit_id,
            "function_code": fc, "pdu": pdu}


def probe_modbus(ip: str, port: int = 502, timeout: int = 5,
                 unit_ids: Optional[List[int]] = None) -> Dict[str, Any]:
    """Sonda Modbus TCP. FC17 (Report Slave ID) + FC1 (Read Coils).

    Worst case = 1 connect (timeout) + ~3s recv per unit_id. Si la primera unit_id
    timeout sin responder, asumimos que NO es Modbus y abortamos (no enumeramos las
    siguientes ciegamente). Si alguna unit_id confirma protocolo, usamos timeout corto
    en las siguientes para enumerar rápido.
    """
    out: Dict[str, Any] = {
        "ok": False, "ip": ip, "port": port, "service": "modbus",
        "protocol_confirmed": False,
        "vulnerabilities": [], "details": {}, "error": None,
    }
    unit_ids = unit_ids or [1, 0, 255]
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        # Primer turno con timeout completo; si nadie responde a la primera unit_id,
        # casi seguro no es Modbus → aborto rápido.
        active_timeout = timeout
        for idx, unit_id in enumerate(unit_ids):
            sock.settimeout(active_timeout)
            # FC17 — Report Slave ID
            sock.sendall(_modbus_frame(unit_id, 0x11))
            try:
                resp = sock.recv(512)
            except socket.timeout:
                if idx == 0:
                    # Puerto abierto pero no habla Modbus → out
                    out["error"] = "no Modbus response on first unit_id"
                    out["ok"] = True
                    return out
                continue
            mbap = _parse_mbap(resp)
            if not mbap:
                continue
            fc = mbap["function_code"]
            if fc == 0x91:  # excepción 0x80 | 0x11
                exc_code = mbap["pdu"][0] if mbap["pdu"] else None
                out["details"][f"unit_{unit_id}_fc17_exception"] = exc_code
                out["protocol_confirmed"] = True
                # Tras confirmar protocolo, timeout corto para no penalizar
                active_timeout = min(2, timeout)
                continue
            if fc == 0x11 and mbap["pdu"]:
                byte_count = mbap["pdu"][0]
                slave_payload = mbap["pdu"][1:1 + byte_count]
                out["protocol_confirmed"] = True
                active_timeout = min(2, timeout)
                out["details"][f"unit_{unit_id}"] = {
                    "byte_count": byte_count,
                    "slave_id": slave_payload.decode("latin-1", errors="replace"),
                }
                out["vulnerabilities"].append({
                    "id": "MODBUS-NO-AUTH-FC17",
                    "severity": "HIGH",
                    "description": (
                        f"Modbus TCP en {ip}:{port} responde a Function Code 17 "
                        f"(Report Slave ID) sin autenticación, unit_id={unit_id}."
                    ),
                    "score": 7.5,
                    "source": "modbus_probe",
                })

            # FC1 — Read Coils (0..7)
            sock.settimeout(active_timeout)
            sock.sendall(_modbus_frame(unit_id, 0x01, struct.pack("!HH", 0, 8)))
            try:
                resp = sock.recv(512)
            except socket.timeout:
                continue
            mbap = _parse_mbap(resp)
            if not mbap:
                continue
            if mbap["function_code"] == 0x01 and mbap["pdu"]:
                out["protocol_confirmed"] = True
                out["details"].setdefault(f"unit_{unit_id}", {})["coils_0_7"] = (
                    mbap["pdu"][1:].hex() if len(mbap["pdu"]) > 1 else None
                )
                out["vulnerabilities"].append({
                    "id": "MODBUS-NO-AUTH-READCOILS",
                    "severity": "CRITICAL",
                    "description": (
                        f"Modbus TCP en {ip}:{port} permite lectura de coils sin "
                        f"autenticación (unit_id={unit_id}). Equipo industrial expuesto."
                    ),
                    "score": 9.0,
                    "source": "modbus_probe",
                })
                break  # con uno basta

        out["ok"] = True
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        out["error"] = str(e)
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
    return out


# =============================================================================
# RTSP / ONVIF
# =============================================================================
RTSP_DEFAULT_PATHS = [
    "", "live", "stream1", "h264", "mpeg4", "onvif1",
    "onvif/snapshot", "av0_0", "11", "video1",
]
RTSP_DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", ""), ("admin", "12345"),
    ("admin", "password"), ("root", "root"), ("user", "user"),
]


def _rtsp_request(method: str, path: str, ip: str, port: int,
                  cseq: int, auth_header: Optional[str] = None) -> bytes:
    url = f"rtsp://{ip}:{port}/{path.lstrip('/')}"
    lines = [
        f"{method} {url} RTSP/1.0",
        f"CSeq: {cseq}",
        "User-Agent: IoTSafeGuard-Probe/1.0",
    ]
    if auth_header:
        lines.append(f"Authorization: {auth_header}")
    lines.append("\r\n")
    return ("\r\n".join(lines)).encode("ascii")


def _parse_rtsp_status(data: bytes) -> Optional[int]:
    try:
        first = data.split(b"\r\n", 1)[0].decode("latin-1")
        parts = first.split(" ", 2)
        if len(parts) >= 2 and parts[0].startswith("RTSP/"):
            return int(parts[1])
    except (ValueError, UnicodeDecodeError):
        pass
    return None


def probe_rtsp(ip: str, ports: Optional[List[int]] = None,
               timeout: int = 5) -> Dict[str, Any]:
    """RTSP: OPTIONS + DESCRIBE en paths comunes + creds default si 401."""
    out: Dict[str, Any] = {
        "ok": False, "ip": ip, "port": 0, "service": "rtsp",
        "protocol_confirmed": False,
        "vulnerabilities": [], "details": {}, "error": None,
    }
    ports = ports or [554, 8554]
    for port in ports:
        sock = None
        try:
            sock = socket.create_connection((ip, port), timeout=timeout)
            sock.settimeout(timeout)
            sock.sendall(_rtsp_request("OPTIONS", "", ip, port, cseq=1))
            data = sock.recv(2048)
            status = _parse_rtsp_status(data)
            if status is None:
                continue  # no es RTSP

            out["protocol_confirmed"] = True
            out["port"] = port
            out["details"]["options_status"] = status
            out["details"]["server"] = _extract_header(data, "Server")
            out["details"]["public_methods"] = _extract_header(data, "Public")

            # DESCRIBE en paths comunes
            # Un DESCRIBE por ruta, con RECONEXIÓN si el servidor cierra.
            #
            # Antes se reutilizaba un único socket para las diez rutas. Muchos
            # servidores RTSP cierran la conexión al rechazar una —MediaMTX lo
            # hace con la ruta vacía: «invalid path name: cannot be empty»— y,
            # como la primera de la lista es justamente `""`, las nueve
            # siguientes se enviaban sobre un socket ya muerto y se descartaban
            # como timeout. En la práctica la sonda probaba UNA ruta, no diez, y
            # el fallo era silencioso: `unauth_paths` salía vacío y parecía un
            # negativo legítimo. Afecta a cámaras reales, no solo al laboratorio.
            #
            # El `cseq` también se incrementa: repetir el 2 en cada petición es
            # incorrecto y algunos servidores descartan la respuesta.
            cseq = 2
            for path in RTSP_DEFAULT_PATHS:
                resp = b""
                try:
                    sock.sendall(_rtsp_request("DESCRIBE", path, ip, port, cseq=cseq))
                    resp = sock.recv(4096)
                except (OSError, socket.timeout):
                    resp = b""
                cseq += 1
                if not resp:
                    # Conexión caída (o sin respuesta): se reintenta la MISMA
                    # ruta sobre un socket nuevo antes de darla por muerta.
                    try:
                        sock.close()
                    except OSError:
                        pass
                    try:
                        sock = socket.create_connection((ip, port), timeout=timeout)
                        sock.settimeout(timeout)
                        sock.sendall(_rtsp_request("DESCRIBE", path, ip, port, cseq=cseq))
                        resp = sock.recv(4096)
                        cseq += 1
                    except (OSError, socket.timeout):
                        continue
                rstatus = _parse_rtsp_status(resp)
                if rstatus == 200:
                    # AirPlay/AirTunes (RAOP, típ. puerto 7000) responde 200 a
                    # DESCRIBE por diseño: es el handshake de audio de AirPlay, no
                    # un stream de vídeo expuesto. Un 200 aquí NO es "stream sin
                    # auth". Solo es hallazgo si el SDP anuncia media de vídeo
                    # (`m=video`) — señal determinista de cámara/DVR real.
                    server = (out["details"].get("server") or "")
                    body = resp.decode("latin-1", "replace")
                    is_airplay = ("airtunes" in server.lower()
                                  or "airplay" in server.lower()
                                  or port == 7000)
                    has_video = "m=video" in body.lower()
                    if is_airplay and not has_video:
                        # Responder AirPlay legítimo — nota informativa, no vuln.
                        out["details"].setdefault("airplay_paths", []).append(path)
                        continue
                    out["vulnerabilities"].append({
                        "id": "RTSP-NO-AUTH",
                        "severity": "HIGH",
                        "description": (
                            f"RTSP en {ip}:{port}/{path or '<root>'} expone stream "
                            f"sin autenticación."
                        ),
                        "score": 7.5,
                        "source": "rtsp_probe",
                        "path": path,
                    })
                    out["details"].setdefault("unauth_paths", []).append(path)
                elif rstatus in (401, 403):
                    # 401 = needs auth, 403 = forbidden (algunos cams devuelven 403 en lugar de 401).
                    # Determinista: ambos códigos disparan retry con default creds.
                    for user, pw in RTSP_DEFAULT_CREDS:
                        token = base64.b64encode(f"{user}:{pw}".encode()).decode()
                        auth = f"Basic {token}"
                        sock.sendall(_rtsp_request("DESCRIBE", path, ip, port,
                                                   cseq=3, auth_header=auth))
                        try:
                            r2 = sock.recv(4096)
                        except socket.timeout:
                            break
                        s2 = _parse_rtsp_status(r2)
                        if s2 == 200:
                            out["vulnerabilities"].append({
                                "id": "RTSP-DEFAULT-CRED",
                                "severity": "CRITICAL",
                                "description": (
                                    f"RTSP en {ip}:{port}/{path} acepta credenciales "
                                    f"por defecto: {user}:{pw} (status pre-auth: {rstatus})"
                                ),
                                "score": 9.0,
                                "source": "rtsp_probe",
                                "credentials": {"user": user, "password": pw},
                                "path": path,
                                "pre_auth_status": rstatus,
                            })
                            out["details"].setdefault("default_creds", []).append({
                                "user": user, "password": pw, "path": path,
                            })
                            break  # creds encontradas, no probar más
                    else:
                        # Ningún cred default funcionó — registrar como auth-required exposed
                        out["details"].setdefault("auth_required_paths", []).append({
                            "path": path, "status": rstatus,
                        })
            out["ok"] = True
            break  # un puerto RTSP es suficiente
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            out["error"] = str(e)
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
    return out


def _extract_header(data: bytes, name: str) -> Optional[str]:
    try:
        text = data.decode("latin-1", errors="replace")
        for line in text.split("\r\n"):
            if line.lower().startswith(name.lower() + ":"):
                return line.split(":", 1)[1].strip()
    except UnicodeDecodeError:
        pass
    return None


# =============================================================================
# BACnet/IP
# =============================================================================
BACNET_PORT = 47808


def _parse_bacnet_iam(apdu: bytes) -> Dict[str, Any]:
    """Parsea I-Am APDU. Application tags secuenciales:
       0xC4 (Unsigned ObjectId, 4B) | 0x22 (Unsigned MaxAPDU, 2B)
     | 0x91 (Enumerated Segmentation, 1B) | 0x21|0x22 (Unsigned VendorId, 1-2B)
    """
    out: Dict[str, Any] = {}
    if len(apdu) < 8:
        return out
    i = 0
    # Tag 0xC4 → ObjectIdentifier (4 bytes)
    if apdu[i] != 0xC4 or len(apdu) < i + 5:
        return out
    raw_oid = struct.unpack("!I", apdu[i + 1:i + 5])[0]
    out["object_type"] = (raw_oid >> 22) & 0x3FF
    out["object_instance"] = raw_oid & 0x3FFFFF
    i += 5
    # Tag 0x22 → MaxAPDU (2 bytes)
    if i < len(apdu) and apdu[i] == 0x22 and len(apdu) >= i + 3:
        out["max_apdu"] = struct.unpack("!H", apdu[i + 1:i + 3])[0]
        i += 3
    # Tag 0x91 → Segmentation (1 byte)
    if i < len(apdu) and apdu[i] == 0x91 and len(apdu) >= i + 2:
        out["segmentation"] = apdu[i + 1]
        i += 2
    # Tag 0x21 (1B) o 0x22 (2B) → VendorId
    if i < len(apdu):
        tag = apdu[i]
        if tag == 0x21 and len(apdu) >= i + 2:
            out["vendor_id"] = apdu[i + 1]
        elif tag == 0x22 and len(apdu) >= i + 3:
            out["vendor_id"] = struct.unpack("!H", apdu[i + 1:i + 3])[0]
    return out


def probe_bacnet(ip: str, port: int = BACNET_PORT,
                 timeout: int = 3) -> Dict[str, Any]:
    """BACnet/IP Who-Is unicast. Si responde I-Am: parsea object_id, max_apdu, vendor_id."""
    out: Dict[str, Any] = {
        "ok": False, "ip": ip, "port": port, "service": "bacnet",
        "protocol_confirmed": False,
        "vulnerabilities": [], "details": {}, "error": None,
    }

    # Frame Who-Is unicast (8 bytes)
    # BVLC: 0x81 (type=BACnet/IP) 0x0a (Original-Unicast-NPDU) 0x00 0x08 (length)
    # NPDU: 0x01 (version) 0x00 (control)
    # APDU: 0x10 (Unconfirmed-Request) 0x08 (service=Who-Is)
    frame = b"\x81\x0a\x00\x08\x01\x00\x10\x08"

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(frame, (ip, port))
        data, _addr = sock.recvfrom(1500)

        if len(data) >= 4 and data[0] == 0x81:
            out["protocol_confirmed"] = True
            out["details"]["bvlc_type"] = data[1]
            out["details"]["raw_response_hex"] = data.hex()
            # APDU empieza tras BVLC(4) + NPDU(2) = byte 6
            # APDU I-Am: 0x10 (Unconfirmed-Request) 0x00 (service=I-Am)
            if len(data) >= 8 and data[6] == 0x10 and data[7] == 0x00:
                out["details"]["service"] = "I-Am"
                parsed = _parse_bacnet_iam(data[8:])
                out["details"].update(parsed)
                out["vulnerabilities"].append({
                    "id": "BACNET-NO-AUTH-WHOIS",
                    "severity": "MEDIUM",
                    "description": (
                        f"BACnet/IP en {ip}:{port} responde a Who-Is sin autenticación. "
                        f"Dispositivo OT/building-automation expuesto"
                        + (f" (vendor_id={parsed['vendor_id']})" if "vendor_id" in parsed else "")
                        + "."
                    ),
                    "score": 5.5,
                    "source": "bacnet_probe",
                })
            out["ok"] = True
    except socket.timeout:
        out["error"] = "timeout"
    except OSError as e:
        out["error"] = str(e)
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
    return out


# =============================================================================
# Xiaomi miIO (UDP 54321)
# =============================================================================
MIIO_PORT = 54321

# "Hello" handshake miIO: 32 bytes, todo a 0xFF salvo magic(0x2131) y len(0x0020).
# El dispositivo responde con su did real, el stamp (uptime) y un campo de 16
# bytes que en firmwares antiguos contenía el TOKEN en claro.
_MIIO_HELLO = bytes.fromhex("21310020" + "ffffffff" * 7)


def probe_miio(ip: str, port: int = MIIO_PORT, timeout: int = 4) -> Dict[str, Any]:
    """Sonda del protocolo nativo de Xiaomi (miIO) sobre UDP 54321.

    Envía el handshake "hello" (un único datagrama, read-only, sin efecto sobre
    el dispositivo) y analiza la respuesta:
      - Si llega una respuesta válida (magic 0x2131, 32 bytes) → el dispositivo
        ES un Xiaomi miIO: se extrae el `did` (device id) y el `stamp` (uptime),
        lo que da identidad de dispositivo donde nmap no veía nada.
      - El campo de 16 bytes del final es el token. En firmwares antiguos venía
        en CLARO en este handshake no autenticado → control local completo del
        dispositivo (vía python-miio). Eso es un CRITICAL confirmado. En
        firmware moderno ese campo es 0xFF·16 (o 0x00·16) y solo se confirma la
        identidad.

    El probe es identity-driven, no port-gated: UDP 54321 rara vez aparece
    "abierto" en nmap (UDP da open|filtered), así que el agente debe lanzarlo
    cuando el OUI/vendor apunta a Xiaomi, sin esperar un puerto abierto.
    """
    out: Dict[str, Any] = {
        "ok": False, "ip": ip, "port": port, "service": "miio",
        "protocol_confirmed": False,
        "vulnerabilities": [], "details": {}, "error": None,
    }
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_MIIO_HELLO, (ip, port))
        data, _addr = sock.recvfrom(1024)

        # Respuesta miIO válida: magic 0x2131 y al menos la cabecera de 32 bytes.
        if len(data) >= 32 and data[0] == 0x21 and data[1] == 0x31:
            out["protocol_confirmed"] = True
            out["ok"] = True
            did = data[8:12]
            stamp = struct.unpack(">I", data[12:16])[0]
            token = data[16:32]
            out["details"]["did_hex"] = did.hex()
            out["details"]["stamp"] = stamp
            out["details"]["token_hex"] = token.hex()
            out["details"]["raw_response_hex"] = data[:32].hex()

            token_blanked = token == b"\xff" * 16 or token == b"\x00" * 16
            if not token_blanked:
                # Token en claro vía handshake no autenticado.
                out["vulnerabilities"].append({
                    "id": "MIIO-TOKEN-EXPOSED",
                    "severity": "CRITICAL",
                    "description": (
                        f"Dispositivo Xiaomi miIO en {ip}:{port} revela su token de "
                        f"16 bytes ({token.hex()}) en el handshake 'hello' NO "
                        "autenticado. Con ese token se obtiene control local "
                        "completo del dispositivo (python-miio). Firmware antiguo "
                        "sin protección del token."
                    ),
                    "score": 9.1,
                    "source": "miio_probe",
                })
            else:
                out["vulnerabilities"].append({
                    "id": "MIIO-DEVICE-EXPOSED",
                    "severity": "INFO",
                    "description": (
                        f"Dispositivo Xiaomi miIO confirmado en {ip}:{port} "
                        f"(did={did.hex()}, uptime={stamp}s). El token no se expone "
                        "en el handshake (firmware moderno). Identidad confirmada; "
                        "el control local requiere el token, no obtenible por red."
                    ),
                    "score": 0.0,
                    "source": "miio_probe",
                })
    except socket.timeout:
        out["error"] = "timeout"
    except OSError as e:
        out["error"] = str(e)
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
    return out


# =============================================================================
# UDP genérico (descubrimiento de protocolos sin probe dedicada)
# =============================================================================
def _udp_payload_library(ip: str) -> Dict[str, bytes]:
    """Payloads de descubrimiento bien conocidas y deterministas (read-only).

    Son plantillas mínimas y benignas (una sola request, sin amplificación
    deliberada) para que el agente no tenga que reconstruir de memoria los
    protocolos más comunes. Para cualquier otro protocolo, el agente pasa su
    propia `payload_hex`.
    """
    # mDNS: PTR query a _services._dns-sd._udp.local
    mdns = (struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
            + b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
            + struct.pack(">HH", 12, 1))
    # SSDP M-SEARCH (UPnP discovery)
    ssdp = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {ip}:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode("ascii")
    # CoAP GET /.well-known/core (ver 1, type CON, GET) + Uri-Path options
    coap = bytes([0x40, 0x01, 0x00, 0x01]) + bytes([0xBB]) + b".well-known" \
        + bytes([0x04]) + b"core"
    # NTP mode 6 (control) readstat — diagnóstico benigno
    ntp = bytes([0x16, 0x02, 0x00, 0x00]) + bytes(8)
    # NetBIOS Name Service node status (NBSTAT '*')
    netbios = (struct.pack(">HHHHHH", 0xA2A2, 0x0010, 1, 0, 0, 0)
               + b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
               + struct.pack(">HH", 0x0021, 0x0001))
    # DNS A-query a un nombre benigno (detección de resolver abierto)
    dns = (struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
           + b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1))
    # SNMPv1 GET de sysDescr (1.3.6.1.2.1.1.1.0) community 'public'. Atajo de
    # descubrimiento; el análisis con varias communities está en probe_snmp.
    snmp = bytes.fromhex(
        "302902010004067075626c6963a01c0204000000000201000201003"
        "00e300c06082b060102010101000500")
    # Xiaomi miIO hello (atajo; el análisis profundo está en probe_miio)
    miio = bytes.fromhex("21310020" + "ffffffff" * 7)
    # ISAKMP/IKE Main Mode SA proposal (1 transform: 3DES/SHA1/PSK/MODP1024),
    # estilo ike-scan. Un responder IKE contesta con la SA elegida. Longitudes
    # calculadas por construcción para que el paquete sea válido.
    _attrs = bytes.fromhex(
        "80010005"   # Encryption = 3DES-CBC (5)
        "80020002"   # Hash = SHA1 (2)
        "80030001"   # Auth = PSK (1)
        "80040002"   # Group = MODP1024 (2)
        "800b0001"   # Life type = seconds
        "800c7080")  # Life duration = 28800 s
    _transform = struct.pack(">BBH", 0, 0, 8 + len(_attrs)) + bytes([1, 1, 0, 0]) + _attrs
    _proposal = struct.pack(">BBH", 0, 0, 8 + len(_transform)) + bytes([1, 1, 0, 1]) + _transform
    _sa = struct.pack(">BBH", 0, 0, 12 + len(_proposal)) + struct.pack(">II", 1, 1) + _proposal
    isakmp = (b"\x11\x22\x33\x44\x55\x66\x77\x88" + b"\x00" * 8
              + bytes([0x01, 0x10, 0x02, 0x00]) + struct.pack(">I", 0)
              + struct.pack(">I", 28 + len(_sa)) + _sa)
    return {
        "mdns": mdns, "ssdp": ssdp, "coap": coap, "ntp": ntp,
        "netbios": netbios, "dns": dns, "snmp": snmp, "miio": miio,
        "isakmp": isakmp,
    }


def probe_udp_raw(ip: str, port: int, payload_hex: Optional[str] = None,
                  proto_hint: Optional[str] = None,
                  timeout: int = 4) -> Dict[str, Any]:
    """Envía un datagrama UDP y devuelve la respuesta cruda como EVIDENCIA.

    Descubrimiento, no confirmación: no infiere vulnerabilidades. La payload la
    decide el agente (su `payload_hex` construida a partir de su conocimiento del
    protocolo) o se toma de la librería integrada vía `proto_hint`. El envío y el
    parseo son deterministas; la interpretación de la evidencia queda para el
    agente / probes específicos.
    """
    out: Dict[str, Any] = {
        "ok": False, "ip": ip, "port": port, "service": "udp_raw",
        "protocol_confirmed": False,
        "vulnerabilities": [], "details": {}, "error": None,
    }
    if not port:
        out["error"] = "port es obligatorio"
        return out

    # Resolver la payload: hex explícito tiene prioridad sobre proto_hint.
    payload: Optional[bytes] = None
    if payload_hex:
        try:
            payload = bytes.fromhex(payload_hex.strip().replace(" ", ""))
        except ValueError:
            out["error"] = "payload_hex is not valid hexadecimal"
            return out
    elif proto_hint:
        payload = _udp_payload_library(ip).get(proto_hint.strip().lower())
        if payload is None:
            out["error"] = (f"proto_hint '{proto_hint}' is not in the library; "
                            "pass payload_hex with the protocol bytes")
            return out
    else:
        out["error"] = ("necesitas payload_hex o proto_hint: un servicio UDP solo "
                        "responde a la payload correcta del protocolo")
        return out

    if len(payload) > 1500:
        out["error"] = "payload demasiado grande (>1500 bytes)"
        return out

    out["details"]["payload_sent_hex"] = payload.hex()
    out["details"]["payload_source"] = "payload_hex" if payload_hex else f"library:{proto_hint}"

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(payload, (ip, port))
        data, _addr = sock.recvfrom(4096)
        if data:
            out["protocol_confirmed"] = True  # algo escucha y respondió
            out["ok"] = True
            printable = "".join(
                chr(b) if 32 <= b < 127 else "." for b in data[:512])
            out["details"]["response_len"] = len(data)
            out["details"]["response_hex"] = data[:512].hex()
            out["details"]["response_ascii"] = printable
            out["details"]["note"] = (
                "Respuesta UDP recibida: hay un servicio escuchando en este puerto "
                "(nmap pudo no verlo). Interpreta la evidencia para identificar el "
                "protocolo; confirma cualquier hallazgo aparte."
            )
    except socket.timeout:
        out["error"] = "timeout (sin respuesta: puerto cerrado/filtrado o payload incorrecta)"
    except OSError as e:
        out["error"] = str(e)
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
    return out


def _tuya_frame(command: int = 0x0A, payload: bytes = b"") -> bytes:
    """Frame del protocolo local de Tuya (TCP 6668).

    Estructura: prefijo 0x000055AA · seq · comando · longitud · payload · CRC32 ·
    sufijo 0x0000AA55. La longitud cubre payload + CRC + sufijo. Con `payload`
    vacío y comando 0x0A (DP_QUERY) el dispositivo contesta con un frame de error
    ("json obj data unvalid" / "devid not found"), que es una firma inequívoca de
    Tuya: basta para CONFIRMAR el protocolo sin autenticarse ni cambiar estado.
    """
    head = struct.pack(">IIII", 0x000055AA, 0, command, len(payload) + 8) + payload
    return head + struct.pack(">II", zlib.crc32(head) & 0xFFFFFFFF, 0x0000AA55)


def _tcp_payload_library(ip: str) -> Dict[str, bytes]:
    """Payloads TCP de descubrimiento, deterministas y de solo lectura.

    Complementa `_udp_payload_library` para los protocolos IoT que viven en TCP y
    que, por tanto, `probe_udp` no puede alcanzar. Igual que en UDP: una sola
    request benigna, sin cambio de estado en el dispositivo.
    """
    return {
        # Tuya local (6668): DP_QUERY sin credenciales → frame de error firmado.
        "tuya": _tuya_frame(),
        # ESPHome native API (6053): HelloRequest = [0x00, len=0, type=1]. Un
        # nodo sin cifrado responde con nombre y versión en claro.
        "esphome": bytes([0x00, 0x00, 0x01]),
        # HTTP GET / — banner de servidores web en puertos no estándar.
        "http": (f"GET / HTTP/1.0\r\nHost: {ip}\r\n"
                 f"User-Agent: IoTSafeGuard-Probe/1.0\r\n\r\n").encode("ascii"),
        # Redis sin auth (6379): PING → +PONG. Vector habitual en gateways IoT.
        "redis": b"PING\r\n",
    }


def probe_tcp_raw(ip: str, port: int, payload_hex: Optional[str] = None,
                  proto_hint: Optional[str] = None,
                  timeout: int = 5) -> Dict[str, Any]:
    """Sonda TCP genérica para puertos sin probe dedicada.

    Simétrica a `probe_udp_raw`, con una diferencia importante: en TCP el propio
    `connect` ya prueba que el puerto está abierto y muchos servicios **saludan
    sin que se les pregunte**, así que la payload es OPCIONAL — sin ella la sonda
    hace un banner-grab. Con `payload_hex` (bytes que construye el agente) o
    `proto_hint` (librería integrada: tuya, esphome, http, redis) alcanza los
    protocolos IoT sobre TCP que ninguna probe específica cubre.

    Descubrimiento, no confirmación: devuelve la respuesta cruda como evidencia y
    NO emite `vulnerabilities`. Interpretar y confirmar es responsabilidad del
    agente (`record_finding` con prueba práctica).
    """
    out: Dict[str, Any] = {
        "ok": False, "ip": ip, "port": port, "service": "tcp_raw",
        "protocol_confirmed": False,
        "vulnerabilities": [], "details": {}, "error": None,
    }
    if not port:
        out["error"] = "port es obligatorio"
        return out

    payload: bytes = b""
    if payload_hex:
        try:
            payload = bytes.fromhex(payload_hex.strip().replace(" ", ""))
        except ValueError:
            out["error"] = "payload_hex is not valid hexadecimal"
            return out
        out["details"]["payload_source"] = "payload_hex"
    elif proto_hint:
        library = _tcp_payload_library(ip)
        resolved = library.get(proto_hint.strip().lower())
        if resolved is None:
            out["error"] = (f"proto_hint '{proto_hint}' is not in the TCP library "
                            f"({sorted(library)}); pass payload_hex with the "
                            "protocol bytes")
            return out
        payload = resolved
        out["details"]["payload_source"] = f"library:{proto_hint.strip().lower()}"
    else:
        # Sin payload: banner-grab puro (válido en TCP, a diferencia de UDP).
        out["details"]["payload_source"] = "none:banner_grab"

    if len(payload) > 4096:
        out["error"] = "payload demasiado grande (>4096 bytes)"
        return out
    if payload:
        out["details"]["payload_sent_hex"] = payload.hex()

    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        out["details"]["tcp_connect"] = True
        if payload:
            sock.sendall(payload)
        data = b""
        while len(data) < 4096:
            try:
                chunk = sock.recv(2048)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        if data:
            out["protocol_confirmed"] = True  # algo escucha y contestó bytes
            out["ok"] = True
            out["details"]["response_len"] = len(data)
            out["details"]["response_hex"] = data[:512].hex()
            out["details"]["response_ascii"] = "".join(
                chr(b) if 32 <= b < 127 else "." for b in data[:512])
            out["details"]["note"] = (
                "Respuesta TCP recibida: hay un servicio hablando en este puerto. "
                "Interpreta la evidencia para identificar el protocolo y confirma "
                "cualquier hallazgo aparte (esta sonda no marca vulnerabilidades)."
            )
        else:
            # Conexión aceptada pero mudo: alcanzabilidad, NO confirmación.
            out["details"]["note"] = (
                "Port open but no answer to this payload. That is "
                "REACHABILITY, not a confirmed service: try the payload of the "
                "protocol you suspect before concluding anything."
            )
    except socket.timeout:
        out["error"] = "connection timeout (filtered port or slow host)"
    except ConnectionRefusedError:
        out["error"] = "connection refused (closed port)"
    except OSError as e:
        out["error"] = str(e)
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
    return out


# =============================================================================
# TR-069 / CWMP
# =============================================================================
def probe_cwmp(ip: str, port: int = 7547, timeout: int = 5) -> Dict[str, Any]:
    """TR-069/CWMP: banner HTTP + chequeo CVE-2017-17215 (RomPager / Mirai)."""
    out: Dict[str, Any] = {
        "ok": False, "ip": ip, "port": port, "service": "cwmp",
        "protocol_confirmed": False,
        "vulnerabilities": [], "details": {}, "error": None,
    }
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        req = (
            f"GET / HTTP/1.0\r\n"
            f"Host: {ip}:{port}\r\n"
            f"User-Agent: IoTSafeGuard-Probe/1.0\r\n\r\n"
        ).encode("ascii")
        sock.sendall(req)
        data = b""
        while True:
            try:
                chunk = sock.recv(2048)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if len(data) > 8192:
                break
        if data:
            out["protocol_confirmed"] = True
            text = data.decode("latin-1", errors="replace")
            server = _extract_header(data, "Server") or ""
            out["details"]["raw_banner"] = text[:400]
            out["details"]["server"] = server
            out["details"]["status_line"] = text.split("\r\n", 1)[0]

            srv_low = server.lower()
            # RomPager → Misfortune Cookie (CVE-2014-9222)
            if "rompager" in srv_low:
                out["vulnerabilities"].append({
                    "id": "CWMP-ROMPAGER-CVE-2014-9222",
                    "severity": "CRITICAL",
                    "description": (
                        f"Servidor RomPager detectado en {ip}:{port} ('{server}'). "
                        f"Vulnerable a Misfortune Cookie (CVE-2014-9222)."
                    ),
                    "score": 9.8,
                    "source": "cwmp_probe",
                })
            # Allegro RomPager < 4.34 / Huawei HG532 → Mirai (CVE-2017-17215)
            if "huawei" in srv_low or "hg532" in srv_low or "allegro" in srv_low:
                out["vulnerabilities"].append({
                    "id": "CWMP-MIRAI-CVE-2017-17215",
                    "severity": "CRITICAL",
                    "description": (
                        f"Banner sospechoso en {ip}:{port} ('{server}'). "
                        f"Posible Huawei HG532 vulnerable a SOAP injection (CVE-2017-17215, Mirai)."
                    ),
                    "score": 9.8,
                    "source": "cwmp_probe",
                })
            # Cualquier endpoint en 7547 sin auth ya es señal
            if "200 ok" in text.lower().split("\r\n", 1)[0] or "401" in text[:20]:
                out["vulnerabilities"].append({
                    "id": "CWMP-EXPOSED",
                    "severity": "MEDIUM",
                    "description": (
                        f"Endpoint TR-069/CWMP expuesto en {ip}:{port}. "
                        f"Históricamente vector ISP (Mirai 2016)."
                    ),
                    "score": 5.0,
                    "source": "cwmp_probe",
                })
        out["ok"] = True
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        out["error"] = str(e)
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
    return out


# =============================================================================
# Telnet (23)
# =============================================================================
TELNET_BANNER_SIGNATURES = {
    "MIRAI-IOT-DVR": re.compile(r"(dvr login|hi3520|xc3511)", re.I),
    "MIRAI-HIKVISION": re.compile(r"hikvision", re.I),
    "MIRAI-BUSYBOX": re.compile(r"busybox", re.I),
    "ROUTER-LINUX": re.compile(r"(openwrt|dd-wrt|tomato)", re.I),
    "DRAYTEK-VIGOR": re.compile(r"draytek", re.I),
    "ZYXEL": re.compile(r"zyxel", re.I),
}


def _looks_like_telnet(raw: bytes, text: str) -> bool:
    """¿La respuesta es realmente telnet? Evita falsos positivos cuando se sondea
    telnet sobre un puerto que habla OTRO protocolo (caso real: SOCKS5 en 1080
    devolvía `05ff` y el probe lo tomaba por telnet).

    Telnet legítimo se reconoce por:
      - Negociación IAC al inicio: 0xFF seguido de comando WILL/WONT/DO/DONT/SB.
      - Un prompt de login/usuario/password en el texto.
      - Un banner mayoritariamente imprimible (bienvenida telnet).
    Una respuesta binaria corta (p. ej. SOCKS5 `05 ff`) no cumple ninguna.
    """
    if len(raw) >= 2 and raw[0] == 0xFF and raw[1] in (0xFB, 0xFC, 0xFD, 0xFE, 0xFA):
        return True
    low = text.lower()
    if any(p in low for p in ("login:", "password:", "username:", "user:", "passwd:")):
        return True
    if len(text) >= 8:
        printable = sum(1 for c in text if 32 <= ord(c) < 127 or c in "\r\n\t")
        if printable / len(text) >= 0.8:
            return True
    return False


def _strip_telnet_iac(data: bytes) -> bytes:
    """Elimina secuencias IAC (255) básicas para extraer texto plano del banner."""
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 0xFF:
            if i + 1 < len(data):
                cmd = data[i + 1]
                if cmd in (0xFB, 0xFC, 0xFD, 0xFE) and i + 2 < len(data):
                    i += 3
                    continue
                i += 2
                continue
            i += 1
            continue
        out.append(data[i])
        i += 1
    return bytes(out)


# Tabla Mirai original — ataque 2016, todas las creds del leak
TELNET_DEFAULT_CREDS: Tuple[Tuple[str, str], ...] = (
    ("root", "root"),
    ("root", "xc3511"),       # XiongMai DVRs (Mirai)
    ("root", "vizxv"),        # Dahua DVRs
    ("root", "admin"),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", ""),
    ("root", ""),
    ("root", "12345"),
    ("root", "888888"),
    ("ubnt", "ubnt"),         # Ubiquiti default
    ("default", ""),          # genérico
)


def _telnet_read_until(sock: socket.socket, prompts: Tuple[bytes, ...],
                       max_bytes: int = 4096, timeout: float = 3.0) -> bytes:
    """Lee del socket hasta ver uno de los prompts o agotar timeout/buffer."""
    sock.settimeout(timeout)
    buf = bytearray()
    end_at = time.time() + timeout
    while time.time() < end_at and len(buf) < max_bytes:
        try:
            chunk = sock.recv(1024)
        except socket.timeout:
            break
        if not chunk:
            break
        buf.extend(chunk)
        low = bytes(buf).lower()
        if any(p in low for p in prompts):
            break
    return bytes(buf)


def _telnet_attempt_login(ip: str, port: int, user: str, password: str,
                          timeout: float = 3.0) -> Optional[str]:
    """Intenta login telnet. Devuelve indicio de éxito ('shell_prompt' / banner postlogin)
    o None si falla. Heurísticas: ve un shell prompt ($/#/>) sin volver a 'login:'."""
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        # Negociación mínima (decir DONT a todo lo que pida)
        try:
            sock.sendall(b"\xff\xfc\x01")
        except OSError:
            pass

        # Esperar prompt de login
        data = _telnet_read_until(sock, (b"login:", b"username:"), timeout=timeout)
        if not data:
            return None
        sock.sendall(user.encode("ascii", errors="replace") + b"\r\n")
        data = _telnet_read_until(sock, (b"password:",), timeout=timeout)
        sock.sendall(password.encode("ascii", errors="replace") + b"\r\n")

        # Tras enviar password, esperar shell prompt o nuevo login (= fallo)
        data = _telnet_read_until(sock, (b"#", b"$", b">", b"login:", b"incorrect"),
                                  timeout=timeout)
        cleaned = _strip_telnet_iac(data).decode("latin-1", errors="replace").lower()
        if not cleaned:
            return None
        # Fallo detectado
        if "login:" in cleaned[-200:] or "incorrect" in cleaned or "denied" in cleaned:
            return None
        # Éxito heurístico: shell prompt al final
        last_chunk = cleaned[-50:]
        if any(p in last_chunk for p in ("# ", "$ ", "> ", ":/", ":~")):
            return cleaned[-200:]
        return None
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


def probe_telnet(ip: str, port: int = 23, timeout: int = 5,
                 try_default_creds: bool = True,
                 max_creds_attempts: int = 6) -> Dict[str, Any]:
    """Telnet: banner + match firmas + intento de creds default Mirai.

    Si `try_default_creds=True`, prueba hasta `max_creds_attempts` pares user/password
    de la tabla TELNET_DEFAULT_CREDS. Si alguno funciona → vulnerability CRITICAL
    `TELNET-DEFAULT-CRED`.
    """
    out: Dict[str, Any] = {
        "ok": False, "ip": ip, "port": port, "service": "telnet",
        "protocol_confirmed": False,
        "vulnerabilities": [], "details": {}, "error": None,
    }
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        try:
            sock.sendall(b"\xff\xfb\x01")
        except OSError:
            pass

        data = _telnet_read_until(sock, (b"login:", b"password:"),
                                  max_bytes=4096, timeout=float(timeout))
        text = _strip_telnet_iac(data).decode("latin-1", errors="replace") if data else ""
        # Solo se confirma telnet si la respuesta REALMENTE parece telnet (IAC,
        # prompt o banner imprimible). Recibir bytes sueltos no basta: un puerto
        # con otro protocolo (SOCKS5 → `05ff`) respondería igual y antes generaba
        # un falso TELNET-EXPOSED.
        if data and _looks_like_telnet(data, text):
            out["protocol_confirmed"] = True
            out["details"]["banner"] = text[:500]
            out["details"]["banner_len"] = len(text)

            for vuln_id, regex in TELNET_BANNER_SIGNATURES.items():
                if regex.search(text):
                    out["details"].setdefault("matched_signatures", []).append(vuln_id)
                    out["vulnerabilities"].append({
                        "id": f"TELNET-{vuln_id}",
                        "severity": "HIGH" if "MIRAI" in vuln_id else "MEDIUM",
                        "description": (
                            f"Telnet abierto en {ip}:{port}. Banner coincide con firma "
                            f"{vuln_id}. Vector típico Mirai/IoT botnet."
                        ),
                        "score": 7.0,
                        "source": "telnet_probe",
                    })
            out["vulnerabilities"].append({
                "id": "TELNET-EXPOSED",
                "severity": "MEDIUM",
                "description": (
                    f"Telnet expuesto en {ip}:{port}. Protocolo legacy sin cifrado, "
                    f"creds en claro. Vector primario de Mirai (2016)."
                ),
                "score": 5.5,
                "source": "telnet_probe",
            })
        elif data:
            # Respondió, pero no es telnet → registra la evidencia y NO confirma.
            out["details"]["non_telnet_response_hex"] = data[:32].hex()
            out["details"]["note"] = (
                f"Port {port} answered but does NOT look like telnet (no IAC, no "
                "prompt, not printable). Probably another protocol. Not confirmed.")

        # Cerrar el socket de banner-grab antes de intentar logins (cada intento abre uno nuevo)
        try:
            sock.close()
            sock = None
        except OSError:
            sock = None

        # --- Intento de creds default ---
        if try_default_creds and out["protocol_confirmed"]:
            tried: List[Tuple[str, str]] = []
            for user, password in TELNET_DEFAULT_CREDS[:max_creds_attempts]:
                tried.append((user, password))
                proof = _telnet_attempt_login(ip, port, user, password,
                                              timeout=min(3.0, float(timeout)))
                if proof:
                    out["vulnerabilities"].append({
                        "id": "TELNET-DEFAULT-CRED",
                        "severity": "CRITICAL",
                        "description": (
                            f"Telnet en {ip}:{port} acepta credenciales por defecto: "
                            f"{user}:{password!r}. Acceso shell sin autenticación efectiva."
                        ),
                        "score": 9.5,
                        "source": "telnet_probe",
                        "credentials": {"user": user, "password": password},
                        "shell_evidence": proof,
                        "verification_cmd": f"telnet {ip} {port}",
                    })
                    out["details"]["accepted_creds"] = {"user": user, "password": password}
                    break
            out["details"]["creds_attempted"] = [
                {"user": u, "password": p} for u, p in tried
            ]
        out["ok"] = True
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        out["error"] = str(e)
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
    return out


# =============================================================================
# UPnP IGD (SSDP M-SEARCH + SCPD)
# =============================================================================
def _ssdp_msearch(ip: str, st: str, timeout: int = 3) -> Optional[Dict[str, str]]:
    """Envía M-SEARCH unicast al target. Devuelve headers parseados o None."""
    msg = (
        f"M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {ip}:1900\r\n"
        f"MAN: \"ssdp:discover\"\r\n"
        f"MX: 2\r\n"
        f"ST: {st}\r\n\r\n"
    ).encode("ascii")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(msg, (ip, 1900))
        data, _ = sock.recvfrom(2048)
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()
    headers: Dict[str, str] = {}
    for line in data.decode("latin-1", errors="replace").split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return headers


def _http_get_full(url: str, timeout: int = 5) -> Optional[Dict[str, Any]]:
    """GET HTTP/HTTPS y devuelve {status, headers, body}.

    Variante de `_http_get` que conserva headers (necesario para protocolos
    como DIAL que comunican el endpoint dinámico vía `Application-URL`).
    """
    try:
        parsed = urlparse(url)
        scheme = (parsed.scheme or "http").lower()
        host = parsed.hostname
        if not host:
            return None
        is_https = scheme == "https"
        port = parsed.port or (443 if is_https else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        raw_sock = socket.create_connection((host, port), timeout=timeout)
        raw_sock.settimeout(timeout)
        if is_https:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        req = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: IoTSafeGuard\r\n\r\n"
        sock.sendall(req.encode("ascii"))
        data = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break
        try:
            sock.close()
        except OSError:
            pass

        # Parsear status + headers + body
        if b"\r\n\r\n" not in data:
            return {"status": 0, "headers": {}, "body": data}
        head_b, body = data.split(b"\r\n\r\n", 1)
        head_lines = head_b.decode("latin-1", errors="replace").split("\r\n")
        status_line = head_lines[0] if head_lines else ""
        try:
            status = int(status_line.split(" ", 2)[1])
        except (IndexError, ValueError):
            status = 0
        headers: Dict[str, str] = {}
        for line in head_lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return {"status": status, "headers": headers, "body": body}
    except (OSError, ValueError):
        return None


def _http_get(url: str, timeout: int = 5) -> Optional[bytes]:
    """GET HTTP/HTTPS simple sin librerías. Devuelve body o None.

    Soporta ambos esquemas. Para HTTPS usa ssl con verify=False (acepta self-signed,
    típico en IoT). Sin librerías externas — solo `socket` + `ssl` stdlib.
    """
    try:
        parsed = urlparse(url)
        scheme = (parsed.scheme or "http").lower()
        host = parsed.hostname
        if not host:
            return None
        is_https = scheme == "https"
        port = parsed.port or (443 if is_https else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        raw_sock = socket.create_connection((host, port), timeout=timeout)
        raw_sock.settimeout(timeout)
        if is_https:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        req = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: IoTSafeGuard\r\n\r\n"
        sock.sendall(req.encode("ascii"))
        data = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break
        try:
            sock.close()
        except OSError:
            pass
        if b"\r\n\r\n" in data:
            return data.split(b"\r\n\r\n", 1)[1]
        return data
    except (OSError, ValueError):
        # OSError cubre socket.timeout, ConnectionRefusedError, ssl.SSLError
        return None


def probe_upnp_igd(ip: str, timeout: int = 3) -> Dict[str, Any]:
    """UPnP IGD: M-SEARCH unicast + fetch device description + lista servicios.
    Detecta AddPortMapping/DeletePortMapping abiertos sin auth."""
    out: Dict[str, Any] = {
        "ok": False, "ip": ip, "port": 1900, "service": "upnp_igd",
        "protocol_confirmed": False,
        "vulnerabilities": [], "details": {}, "error": None,
    }
    headers = _ssdp_msearch(ip, "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                            timeout=timeout)
    if not headers:
        out["error"] = "no SSDP response"
        return out

    out["protocol_confirmed"] = True
    out["details"]["ssdp_headers"] = headers
    location = headers.get("location")
    if not location:
        out["ok"] = True
        return out

    body = _http_get(location, timeout=timeout)
    if not body:
        out["ok"] = True
        return out

    text = body.decode("utf-8", errors="replace")
    out["details"]["device_xml_snippet"] = text[:600]

    dangerous_actions = ["AddPortMapping", "DeletePortMapping", "GetExternalIPAddress",
                         "GetStatusInfo", "ForceTermination"]
    found = [a for a in dangerous_actions if a in text]
    if found:
        out["details"]["actions_seen_in_root"] = found

    scpd_match = re.search(r"<SCPDURL>([^<]+)</SCPDURL>", text)
    if scpd_match:
        scpd_url = scpd_match.group(1)
        if scpd_url.startswith("/"):
            base = urlparse(location)
            scpd_url = f"{base.scheme}://{base.hostname}:{base.port or 80}{scpd_url}"
        scpd_body = _http_get(scpd_url, timeout=timeout)
        if scpd_body:
            scpd_text = scpd_body.decode("utf-8", errors="replace")
            scpd_actions = [a for a in dangerous_actions if a in scpd_text]
            if scpd_actions:
                out["details"]["actions_in_scpd"] = scpd_actions

    if found or out["details"].get("actions_in_scpd"):
        out["vulnerabilities"].append({
            "id": "UPNP-IGD-EXPOSED",
            "severity": "HIGH",
            "description": (
                f"UPnP IGD en {ip} responde sin autenticación con acciones peligrosas "
                f"({found or out['details'].get('actions_in_scpd')}). Permite a un "
                f"atacante en la LAN abrir port-forward arbitrario al WAN."
            ),
            "score": 7.5,
            "source": "upnp_probe",
        })
    out["ok"] = True
    return out


# =============================================================================
# WS-Discovery (UDP 3702)
# =============================================================================
WSD_PROBE = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
    'xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
    '<soap:Header>'
    '<wsa:MessageID>urn:uuid:iotsafeguard-probe-001</wsa:MessageID>'
    '<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>'
    '<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>'
    '</soap:Header>'
    '<soap:Body><wsd:Probe/></soap:Body>'
    '</soap:Envelope>'
).encode("utf-8")

WSD_DEVICE_TYPES = {
    "ONVIF-CAMERA": ("dn:NetworkVideoTransmitter", "tdn:NetworkVideoTransmitter"),
    "PRINTER": ("PrintBasic", "PrintAdvanced", "Printer"),
    "DPWS-DEVICE": ("dpws:Device",),
}


def probe_wsdiscovery(ip: str, port: int = 3702, timeout: int = 3) -> Dict[str, Any]:
    """WS-Discovery unicast Probe (UDP 3702). Detecta cámaras ONVIF + impresoras DPWS."""
    out: Dict[str, Any] = {
        "ok": False, "ip": ip, "port": port, "service": "wsdiscovery",
        "protocol_confirmed": False,
        "vulnerabilities": [], "details": {}, "error": None,
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(WSD_PROBE, (ip, port))
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            out["error"] = "timeout"
            return out
        if data:
            out["protocol_confirmed"] = True
            text = data.decode("utf-8", errors="replace")
            out["details"]["xml_snippet"] = text[:600]
            for label, markers in WSD_DEVICE_TYPES.items():
                if any(m in text for m in markers):
                    out["details"].setdefault("matched", []).append(label)
                    out["vulnerabilities"].append({
                        "id": f"WSD-{label}-EXPOSED",
                        "severity": "MEDIUM",
                        "description": (
                            f"WS-Discovery en {ip}:{port} expone dispositivo {label} "
                            f"sin autenticación de descubrimiento."
                        ),
                        "score": 5.0,
                        "source": "wsdiscovery_probe",
                    })
            xaddrs = re.findall(r"<[^>]*XAddrs[^>]*>([^<]+)</[^>]*XAddrs[^>]*>", text)
            if xaddrs:
                out["details"]["xaddrs"] = xaddrs[0].split()[:5]
        out["ok"] = True
    except OSError as e:
        out["error"] = str(e)
    finally:
        sock.close()
    return out


# =============================================================================
# OPC-UA (4840)
# =============================================================================
def _opcua_hello(endpoint_url: str) -> bytes:
    """OPC-UA Hello (HEL) message según OPC-UA Part 6 §7.1.2."""
    url = endpoint_url.encode("utf-8")
    body = struct.pack(
        "<IIIIII",
        0,            # ProtocolVersion
        65536,        # ReceiveBufferSize
        65536,        # SendBufferSize
        0,            # MaxMessageSize (0 = no limit)
        0,            # MaxChunkCount
        len(url),     # EndpointUrl length
    ) + url
    msg_type = b"HEL"
    chunk_type = b"F"
    msg_size = 8 + len(body)
    return msg_type + chunk_type + struct.pack("<I", msg_size) + body


def probe_opcua(ip: str, port: int = 4840, timeout: int = 5) -> Dict[str, Any]:
    """OPC-UA: Hello → Acknowledge handshake. Confirma protocolo industrial expuesto."""
    out: Dict[str, Any] = {
        "ok": False, "ip": ip, "port": port, "service": "opcua",
        "protocol_confirmed": False,
        "vulnerabilities": [], "details": {}, "error": None,
    }
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        endpoint = f"opc.tcp://{ip}:{port}"
        sock.sendall(_opcua_hello(endpoint))
        data = b""
        while len(data) < 28:  # ACK mínimo
            try:
                chunk = sock.recv(1024)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk

        if len(data) >= 8 and data[:3] in (b"ACK", b"ERR"):
            out["protocol_confirmed"] = True
            msg_type = data[:3].decode()
            out["details"]["handshake_response"] = msg_type
            if msg_type == "ACK" and len(data) >= 28:
                # ACK body: ProtoVer(4) + RecvBuf(4) + SendBuf(4) + MaxMsg(4) + MaxChunks(4) = 20
                # Cabecera "ACK" "F" + size = 8 bytes → body comienza en offset 8
                proto_ver, recv_buf, send_buf, max_msg, max_chunks = struct.unpack(
                    "<IIIII", data[8:28]
                )
                out["details"]["protocol_version"] = proto_ver
                out["details"]["receive_buffer"] = recv_buf
                out["details"]["send_buffer"] = send_buf
                out["details"]["max_message_size"] = max_msg
                out["details"]["max_chunk_count"] = max_chunks
            out["vulnerabilities"].append({
                "id": "OPCUA-EXPOSED",
                "severity": "MEDIUM",
                "description": (
                    f"OPC-UA en {ip}:{port} acepta handshake sin filtrado IP. "
                    f"Protocolo industrial expuesto — verificar SecurityPolicy='None' "
                    f"y UserTokenPolicy='Anonymous' con cliente OPC-UA dedicado."
                ),
                "score": 5.5,
                "source": "opcua_probe",
            })
        elif data:
            out["details"]["raw_first_bytes"] = data[:32].hex()
        out["ok"] = True
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        out["error"] = str(e)
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
    return out


# =============================================================================
# TFTP (UDP 69)
# =============================================================================
# Lista corta de archivos comunes — máx ~4s en worst case (4 archivos × 1s timeout)
TFTP_DEFAULT_FILES = ["firmware.bin", "config.bin", "running-config", "startup-config"]


def _tftp_rrq(filename: str) -> bytes:
    """RRQ packet: opcode 0x01 + filename + 0 + 'octet' + 0."""
    return b"\x00\x01" + filename.encode("ascii") + b"\x00octet\x00"


def probe_tftp(ip: str, port: int = 69, timeout: int = 3,
               filenames: Optional[List[str]] = None,
               per_file_timeout: float = 1.0) -> Dict[str, Any]:
    """TFTP: RRQ anónimo de filenames comunes. DATA → firmware extractable.

    timeout = total budget aproximado. per_file_timeout = espera por archivo (default 1s)
    para evitar bloqueos largos cuando el target no escucha. Si llega cualquier respuesta,
    `protocol_confirmed=True` y a partir de ahí podemos seguir probando con timeouts más cortos.
    """
    out: Dict[str, Any] = {
        "ok": False, "ip": ip, "port": port, "service": "tftp",
        "protocol_confirmed": False,
        "vulnerabilities": [], "details": {}, "error": None,
    }
    files_to_try = filenames or TFTP_DEFAULT_FILES
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    accessible: List[str] = []
    deadline = time.time() + timeout
    try:
        for fname in files_to_try:
            if time.time() > deadline:
                break
            sock.settimeout(per_file_timeout)
            try:
                sock.sendto(_tftp_rrq(fname), (ip, port))
                data, _ = sock.recvfrom(516)
            except socket.timeout:
                continue
            except OSError:
                continue
            if len(data) < 2:
                continue
            opcode = struct.unpack("!H", data[:2])[0]
            out["protocol_confirmed"] = True
            if opcode == 3:  # DATA
                accessible.append(fname)
            elif opcode == 5:  # ERROR
                err_code = struct.unpack("!H", data[2:4])[0] if len(data) >= 4 else 0
                out["details"].setdefault("errors", {})[fname] = err_code

        if accessible:
            out["details"]["accessible_files"] = accessible
            out["vulnerabilities"].append({
                "id": "TFTP-ANON-DOWNLOAD",
                "severity": "CRITICAL",
                "description": (
                    f"TFTP en {ip}:{port} permite descarga anónima de archivos sensibles: "
                    f"{accessible}. Vector clásico de extracción de firmware/config."
                ),
                "score": 8.5,
                "source": "tftp_probe",
                "verification_cmd": f"tftp {ip} -c get {accessible[0]}",
            })
        out["ok"] = True
    finally:
        sock.close()
    return out


# =============================================================================
# LG WebOS (3000/3001) — WebSocket + REST endpoints específicos
# =============================================================================
# CVE-2023-6317 PoCs LG WebOS pairing
# =============================================================================
# Payload "ligero" — solo handshake básico (verificación de protocolo)
LG_WEBOS_PAIRING_PAYLOAD = (
    '{"type":"register","id":"register_0",'
    '"payload":{"forcePairing":false,"pairingType":"PROMPT",'
    '"client-key":"","manifest":{"manifestVersion":1,'
    '"appVersion":"1.1","signed":{"created":"20140509",'
    '"appId":"com.lge.test","permissions":[]}}}}'
)


def _build_lg_webos_bypass_payload() -> str:
    """Construye payload PoC real (Bitdefender) con manifest.permissions[]
    escalados. Usado para verificación AUTOMÁTICA del bypass CVE-2023-6317.

    Lazy-import para evitar carga si no se usa.
    """
    import json
    from modules.cve_pocs import LG_WEBOS_BYPASS_PAYLOAD
    return json.dumps(LG_WEBOS_BYPASS_PAYLOAD)

LG_WEBOS_REST_ENDPOINTS = [
    "/",
    "/api/v1/service/register",
    "/api/v2/auth/sign/secured",
    "/api/v2/permissions/getPermissionList",
    "/secondscreen/api",
    "/services",
]


def _websocket_handshake(ip: str, port: int, path: str = "/",
                         timeout: float = 3.0,
                         use_tls: bool = False) -> Tuple[Optional[socket.socket], Optional[str]]:
    """Inicia handshake WebSocket. Soporta TLS si use_tls=True (verify=False).
    Devuelve (socket, response_status_line) o (None, error)."""
    try:
        raw_sock = socket.create_connection((ip, port), timeout=timeout)
    except (OSError, socket.timeout) as e:
        return None, str(e)
    raw_sock.settimeout(timeout)

    if use_tls:
        try:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock: socket.socket = ctx.wrap_socket(raw_sock, server_hostname=ip)
        except (OSError, Exception) as e:
            try:
                raw_sock.close()
            except OSError:
                pass
            return None, f"TLS handshake failed: {e}"
    else:
        sock = raw_sock

    handshake = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {ip}:{port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"User-Agent: IoTSafeGuard\r\n\r\n"
    )
    try:
        sock.sendall(handshake.encode("ascii"))
        data = sock.recv(2048)
    except (OSError, socket.timeout) as e:
        try:
            sock.close()
        except OSError:
            pass
        return None, str(e)
    if not data:
        sock.close()
        return None, "empty handshake response"
    status_line = data.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
    if "101" in status_line and "switching" in status_line.lower():
        return sock, status_line
    sock.close()
    return None, status_line


def _ws_send_text(sock: socket.socket, text: str) -> None:
    """Envía un frame WebSocket text (FIN=1, opcode=1) sin máscara cliente.
    Servidores LG WebOS no validan estrictamente la máscara en sus PoCs públicos.
    """
    payload = text.encode("utf-8")
    if len(payload) < 126:
        header = bytes([0x81, 0x80 | len(payload)])
    elif len(payload) < 65536:
        header = bytes([0x81, 0x80 | 126]) + struct.pack("!H", len(payload))
    else:
        header = bytes([0x81, 0x80 | 127]) + struct.pack("!Q", len(payload))
    mask = b"\x00\x00\x00\x00"  # máscara nula = payload sin XOR
    sock.sendall(header + mask + payload)


def _ws_recv_text(sock: socket.socket, max_bytes: int = 8192) -> Optional[str]:
    try:
        data = sock.recv(max_bytes)
    except (OSError, socket.timeout):
        return None
    if not data or len(data) < 2:
        return None
    payload_len = data[1] & 0x7F
    offset = 2
    if payload_len == 126:
        offset = 4
    elif payload_len == 127:
        offset = 10
    return data[offset:].decode("utf-8", errors="replace")


def _attempt_lg_webos_bypass(ip: str, port: int, scheme: str,
                             timeout: float = 5.0) -> Dict[str, Any]:
    """Intenta el PoC oficial Bitdefender de CVE-2023-6317.

    Abre conexión nueva, envía payload con manifest.permissions[] y espera
    hasta 3 mensajes (handshake + posible registered + diagnóstico). Devuelve
    veredicto estructurado:

      {
        "attempted": True,
        "vulnerable": True|False,
        "client_key": "<extracted>" | None,
        "response_seen": True|False,
        "diagnosis": "...",
        "messages": [str, ...]
      }
    """
    out: Dict[str, Any] = {
        "attempted": True,
        "vulnerable": False,
        "client_key": None,
        "response_seen": False,
        "diagnosis": "no response",
        "messages": [],
    }
    use_tls = scheme == "wss"
    sock, info = _websocket_handshake(ip, port, "/", timeout=timeout, use_tls=use_tls)
    if sock is None:
        out["diagnosis"] = f"handshake failed: {info}"
        return out

    try:
        bypass_payload = _build_lg_webos_bypass_payload()
        _ws_send_text(sock, bypass_payload)
        # Esperar hasta 3 mensajes (pairing flow puede tener handshake + registered)
        end_at = time.time() + timeout
        while time.time() < end_at and len(out["messages"]) < 3:
            try:
                sock.settimeout(min(timeout, end_at - time.time()))
                msg = _ws_recv_text(sock, max_bytes=16384)
            except (OSError, socket.timeout):
                break
            if not msg:
                break
            out["messages"].append(msg[:500])
            out["response_seen"] = True
            # Detección robusta: usar regex tolerantes a whitespace JSON.
            client_key_match = re.search(r'"client-key"\s*:\s*"([^"]+)"', msg)
            registered_match = re.search(r'"type"\s*:\s*"registered"', msg)
            if client_key_match and client_key_match.group(1).strip() and registered_match:
                out["vulnerable"] = True
                out["client_key"] = client_key_match.group(1)
                out["diagnosis"] = "client-key obtained without PIN (bypass works)"
                break
            # Si vemos error explícito, marca diagnóstico y rompe
            if re.search(r'"error"\s*:', msg):
                out["diagnosis"] = f"server rejected: {msg[:120]}"
                break
            # PIN prompt → seguimos esperando un segundo mensaje (registered o timeout)
            if re.search(r'"pairingType"\s*:\s*"PROMPT"', msg) and \
               re.search(r'"returnValue"\s*:\s*true', msg):
                continue
    finally:
        try:
            sock.close()
        except OSError:
            pass

    if out["response_seen"] and not out["vulnerable"] and out["diagnosis"] == "no response":
        out["diagnosis"] = "responses received but no client-key obtained — likely patched"
    return out


def probe_lg_webos(ip: str, port: int = 3000, alt_port: int = 3001,
                   timeout: int = 5) -> Dict[str, Any]:
    """LG WebOS (Smart TV): handshake WebSocket + intento de pairing CVE-2023-6317.

    Estrategia:
    1. Probar puerto principal (3000) y secundario (3001) para WebSocket.
    2. Si el handshake (101 Switching Protocols) tiene éxito: enviar pairing payload
       y observar respuesta. Si llega `client-key`, es vulnerable a CVE-2023-6317.
    3. Como fallback: GET REST endpoints conocidos para detectar firmware.
    """
    out: Dict[str, Any] = {
        "ok": False, "ip": ip, "port": port, "service": "lg_webos",
        "protocol_confirmed": False,
        "vulnerabilities": [], "details": {}, "error": None,
    }

    candidates: List[int] = []
    if port:
        candidates.append(port)
    if alt_port and alt_port != port:
        candidates.append(alt_port)

    ws_results: Dict[int, Dict[str, Any]] = {}
    for p in candidates:
        # Estrategia: probar plain WS primero. Si falla con "empty handshake response"
        # o "Connection reset by peer" (típico LG WebOS moderno requiere TLS), reintenta wss.
        sock, info = _websocket_handshake(ip, p, "/", timeout=float(timeout), use_tls=False)
        scheme_used = "ws"
        if sock is None:
            # Auto-fallback a TLS si el plain WS no respondió
            sock_tls, info_tls = _websocket_handshake(
                ip, p, "/", timeout=float(timeout), use_tls=True
            )
            if sock_tls is not None:
                sock = sock_tls
                info = info_tls
                scheme_used = "wss"
            else:
                # Conservar info de ambos intentos para diagnóstico
                info = f"ws: {info} | wss: {info_tls}"
        ws_results[p] = {
            "handshake": info,
            "scheme_used": scheme_used,
            "upgraded": sock is not None,
        }
        if sock is not None:
            out["protocol_confirmed"] = True
            out["port"] = p
            out["details"]["scheme"] = scheme_used
            try:
                # === Pase 1: handshake básico (verificar protocolo vivo) ===
                _ws_send_text(sock, LG_WEBOS_PAIRING_PAYLOAD)
                resp = _ws_recv_text(sock, max_bytes=16384)
                if resp:
                    ws_results[p]["pairing_response_snippet"] = resp[:500]
                    if '"alert"' in resp.lower() or '"prompt"' in resp.lower():
                        ws_results[p]["pairing_response"] = (
                            "PIN prompt — manual pairing required"
                        )
            finally:
                try:
                    sock.close()
                except OSError:
                    pass

            # === Pase 2: PoC REAL Bitdefender con manifest.permissions[] ===
            # Verificación AUTOMÁTICA del bypass CVE-2023-6317. Si el TV está
            # parcheado responderá con error/PIN prompt; si no, devolverá un
            # client-key válido sin pedir PIN al usuario.
            bypass_result = _attempt_lg_webos_bypass(
                ip, p, scheme_used, timeout=float(timeout)
            )
            ws_results[p]["bypass_attempt"] = bypass_result
            if bypass_result.get("vulnerable"):
                out["vulnerabilities"].append({
                    "id": "LG-WEBOS-CVE-2023-6317",
                    "severity": "CRITICAL",
                    "description": (
                        f"LG WebOS en {ip}:{p} ({scheme_used}://) ES VULNERABLE "
                        f"a CVE-2023-6317 (Bitdefender PoC). El bypass del "
                        f"prompt PIN funcionó: client-key obtenido sin "
                        f"interacción del usuario. Confirmed automáticamente."
                    ),
                    "score": 9.1,
                    "source": "lg_webos_probe",
                    "client_key": bypass_result.get("client_key"),
                    "verification_cmd": (
                        f"execute_websocket(url='{scheme_used}://{ip}:{p}/', "
                        f"payload=<Bitdefender manifest payload>)"
                    ),
                })
            elif bypass_result.get("response_seen"):
                ws_results[p]["bypass_diagnosis"] = bypass_result.get(
                    "diagnosis", "no client-key in response"
                )

    out["details"]["websocket_handshake"] = ws_results

    # Fallback: REST endpoints para detectar versión / firmware
    # Si plain HTTP falla, intentar HTTPS automáticamente (LG WebOS moderno usa TLS).
    rest_findings: Dict[str, Any] = {}
    for endpoint in LG_WEBOS_REST_ENDPOINTS:
        for p in candidates:
            body = None
            scheme = None
            for try_scheme in ("http", "https"):
                url = f"{try_scheme}://{ip}:{p}{endpoint}"
                body = _http_get(url, timeout=int(timeout))
                if body is not None:
                    scheme = try_scheme
                    break
            if body is None:
                continue
            text = body.decode("utf-8", errors="replace")
            entry = rest_findings.setdefault(p, {})
            if any(k in text.lower() for k in ("webos", "lg", "luna", "secondscreen")):
                entry[endpoint] = {"scheme": scheme, "body": text[:300]}
                out["protocol_confirmed"] = True
                if not out["port"]:
                    out["port"] = p
            elif text:
                entry[endpoint] = {"scheme": scheme, "body": f"<{len(text)}B no-LG content>"}
    if rest_findings:
        out["details"]["rest_endpoints"] = rest_findings

    if out["protocol_confirmed"] and not any(
        v["id"].startswith("LG-WEBOS-CVE") for v in out["vulnerabilities"]
    ):
        out["vulnerabilities"].append({
            "id": "LG-WEBOS-EXPOSED",
            "severity": "INFO",
            "description": (
                f"LG WebOS detectado en {ip} (puertos {sorted(ws_results.keys())}). "
                f"Endpoint de pairing requiere interacción del usuario (PIN prompt). "
                f"Para validar CVE-2023-6317-6320 manualmente: websocat ws://{ip}:3000."
            ),
            "score": 1.0,
            "source": "lg_webos_probe",
        })
    out["ok"] = True
    return out


# =============================================================================
# DIAL (Discovery and Launch — Smart TVs, set-top boxes)
# =============================================================================
DIAL_COMMON_APPS = ["YouTube", "Netflix", "Prime", "Twitch", "Spotify", "DIAL"]
DIAL_MARKERS = (b"DIAL", b"dial-multiscreen-org", b"urn:dial:",
                b"<friendlyName>", b"<modelName>")


def probe_dial(ip: str, ports: Optional[List[int]] = None,
               timeout: int = 5) -> Dict[str, Any]:
    """DIAL Discovery and Launch — Smart TVs / set-top boxes.

    Flujo según la especificación oficial DIAL v1.7:

      1. GET <ip>:<port>/dd.xml → device descriptor (XML).
         La RESPUESTA HTTP contiene un header `Application-URL` que indica el
         endpoint dinámico real del REST DIAL. Algunos TVs (LG, Samsung) lo
         exponen en un puerto efímero distinto del estático del UPnP.
      2. GET <Application-URL>/<app_name> → estado de cada app candidata.
      3. POST <Application-URL>/<app_name> → lanzamiento remoto (sin auth en
         implementaciones vulnerables; observado en LG WebOS, Samsung Tizen).

    Si /dd.xml no existe en los puertos canónicos, fallback a `/apps` directo
    (Chromecast, Roku Externals usan ese endpoint plano).
    """
    out: Dict[str, Any] = {
        "ok": False, "ip": ip, "port": 0, "service": "dial",
        "protocol_confirmed": False,
        "vulnerabilities": [], "details": {}, "error": None,
    }
    ports = ports or [1664, 1755, 8060, 8008]  # 8060=Roku, 8008=Chromecast
    apps_status: Dict[str, Dict[str, str]] = {}
    dial_root_found = False
    application_url: Optional[str] = None  # endpoint dinámico DIAL si lo expone

    # Paso 1: descubrir /dd.xml + capturar Application-URL header
    for port in ports:
        resp = _http_get_full(f"http://{ip}:{port}/dd.xml", timeout=timeout)
        if not resp:
            continue
        body = resp.get("body") or b""
        if not any(m in body for m in DIAL_MARKERS):
            continue

        out["protocol_confirmed"] = True
        out["port"] = port
        dial_root_found = True
        text = body.decode("utf-8", errors="replace")
        out["details"]["dd_xml_snippet"] = text[:600]

        # Header Application-URL (spec DIAL §6.1.2): endpoint REST dinámico
        app_url_header = resp["headers"].get("application-url")
        if app_url_header:
            application_url = app_url_header.rstrip("/")
            out["details"]["application_url"] = application_url

        # Metadatos extraídos del descriptor XML
        friendly = re.search(r"<friendlyName>([^<]+)</friendlyName>", text)
        model = re.search(r"<modelName>([^<]+)</modelName>", text)
        manufacturer = re.search(r"<manufacturer>([^<]+)</manufacturer>", text)
        if friendly:
            out["details"]["friendly_name"] = friendly.group(1)
        if model:
            out["details"]["model_name"] = model.group(1)
        if manufacturer:
            out["details"]["manufacturer"] = manufacturer.group(1)
        break

    # Paso 1b: si no había /dd.xml, intentar /apps plano (Chromecast/Roku)
    if not dial_root_found:
        for port in ports:
            resp = _http_get_full(f"http://{ip}:{port}/apps", timeout=timeout)
            if not resp or not resp.get("body"):
                continue
            out["protocol_confirmed"] = True
            out["port"] = port
            out["details"]["apps_root_response"] = (
                resp["body"][:300].decode("utf-8", errors="replace")
            )
            dial_root_found = True
            app_url_header = resp["headers"].get("application-url")
            if app_url_header:
                application_url = app_url_header.rstrip("/")
                out["details"]["application_url"] = application_url
            break

    # Paso 2: enumerar apps. Usa Application-URL si está disponible
    # (canónico spec DIAL); si no, fallback a /apps en los puertos estáticos.
    if dial_root_found:
        app_endpoints: List[str] = []
        if application_url:
            app_endpoints.append(application_url)
        for port in ports:
            app_endpoints.append(f"http://{ip}:{port}/apps")

        for app in DIAL_COMMON_APPS:
            for endpoint in app_endpoints:
                resp = _http_get_full(f"{endpoint}/{app}", timeout=timeout)
                if not resp:
                    continue
                status = resp.get("status", 0)
                if status == 0:
                    continue
                body_text = (resp.get("body") or b"").decode("utf-8", errors="replace")
                state = "unknown"
                state_match = re.search(r"<state>([^<]+)</state>", body_text)
                if state_match:
                    state = state_match.group(1)
                apps_status[app] = {
                    "endpoint": endpoint,
                    "status": str(status),
                    "state": state,
                }
                if status in (200, 201):
                    break  # app encontrada, siguiente

        if apps_status:
            out["details"]["apps"] = apps_status
            installed = [a for a, s in apps_status.items()
                         if s["status"] in ("200", "201")]
            description_parts = [
                f"DIAL en {ip}:{out['port']} expone descripción y "
                f"enumeración de apps sin autenticación.",
            ]
            if application_url:
                description_parts.append(
                    f"Endpoint dinámico real: {application_url}."
                )
            if installed:
                description_parts.append(
                    f"Apps lanzables remotamente vía POST: {installed}."
                )
            launch_endpoint = application_url or f"http://{ip}:{out['port']}/apps"
            out["vulnerabilities"].append({
                "id": "DIAL-EXPOSED",
                "severity": "MEDIUM",
                "description": " ".join(description_parts),
                "score": 5.5,
                "source": "dial_probe",
                "verification_cmd": (
                    f"curl -X POST {launch_endpoint}/YouTube"
                    if installed else None
                ),
            })
    out["ok"] = True
    return out


# =============================================================================
# Chromecast / Eureka (8008/8443)
# =============================================================================
CHROMECAST_INFO_PATHS = [
    "/setup/eureka_info?options=detail",
    "/setup/eureka_info",
    "/setup/get_app_state",
    "/setup/scan_results",
    "/setup/connectivity_check",
    "/setup/configured_networks",
    "/ssdp/device-desc.xml",
]


def probe_chromecast(ip: str, port: int = 8008, timeout: int = 5) -> Dict[str, Any]:
    """Chromecast/Eureka API: enumera /setup/* paths con info sin auth.

    El API de Chromecast (Eureka) expone build_version, MAC, locale, ssid actual,
    redes WiFi configuradas (sin password pero con SSID — fingerprinting LAN).
    """
    out: Dict[str, Any] = {
        "ok": False, "ip": ip, "port": port, "service": "chromecast",
        "protocol_confirmed": False,
        "vulnerabilities": [], "details": {}, "error": None,
    }
    found: Dict[str, Dict[str, Any]] = {}
    for path in CHROMECAST_INFO_PATHS:
        body = _http_get(f"http://{ip}:{port}{path}", timeout=timeout)
        if not body:
            continue
        text = body.decode("utf-8", errors="replace")
        if not text.strip():
            continue
        # Marcadores de Eureka/Chromecast
        if any(m in text for m in ('"build_version"', '"cast_build_revision"',
                                   "Chromecast", "Eureka", "Google Cast")):
            out["protocol_confirmed"] = True
            found[path] = {"snippet": text[:400], "size": len(text)}
        elif text.startswith("{") and len(text) < 800:
            # JSON pequeño no identificado pero respondió
            found[path] = {"snippet": text[:400], "size": len(text)}

    out["details"]["paths"] = found

    if found:
        # Heurística de severidad según qué se haya filtrado
        sensitive_paths = [p for p in found if "scan_results" in p
                           or "configured_networks" in p
                           or "eureka_info" in p]
        if sensitive_paths:
            out["vulnerabilities"].append({
                "id": "CHROMECAST-INFO-DISCLOSURE",
                "severity": "MEDIUM",
                "description": (
                    f"Chromecast/Eureka en {ip}:{port} expone información de dispositivo "
                    f"sin autenticación: {sensitive_paths}. Filtra MAC, build, SSID, "
                    f"redes vecinas. Mitigado pero histórico."
                ),
                "score": 5.0,
                "source": "chromecast_probe",
            })

        # Chromecast SDK puerto 8009 (no en este probe) acepta comandos sin auth
        out["vulnerabilities"].append({
            "id": "CHROMECAST-EXPOSED",
            "severity": "INFO",
            "description": (
                f"Chromecast detectado en {ip}:{port}. API Eureka responde a "
                f"{len(found)} paths sin auth. Revisar puerto 8009 (cast control) "
                f"si presente para inyección de URLs."
            ),
            "score": 1.0,
            "source": "chromecast_probe",
        })
    out["ok"] = True
    return out


# =============================================================================
# SSH (22) — banner + version detection
# =============================================================================
SSH_VULN_PATTERNS = {
    # OpenSSH versiones con CVEs notables
    "OpenSSH-OLD-CVE": re.compile(r"OpenSSH_([0-6]\.|7\.[0-3])", re.I),
    "DROPBEAR-OLD": re.compile(r"dropbear[_ ](2014|2015|2016|2017|2018|2019)", re.I),
    "LIBSSH-OLD": re.compile(r"libssh[_ -]0\.[0-7]", re.I),
}


def probe_ssh(ip: str, port: int = 22, timeout: int = 5) -> Dict[str, Any]:
    """SSH (22): banner grab + match contra versiones vulnerables conocidas.

    No intenta auth: SSH bloquea/lockea cuentas tras N fallos. Banner-only es
    suficiente para correlacionar con CVEs (OpenSSH < 7.4 tiene varios criticals).
    """
    out: Dict[str, Any] = {
        "ok": False, "ip": ip, "port": port, "service": "ssh",
        "protocol_confirmed": False,
        "vulnerabilities": [], "details": {}, "error": None,
    }
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        # SSH server envía banner inmediatamente al conectarse
        banner = b""
        end_at = time.time() + timeout
        while time.time() < end_at and b"\r\n" not in banner and len(banner) < 512:
            try:
                chunk = sock.recv(256)
            except socket.timeout:
                break
            if not chunk:
                break
            banner += chunk
        if banner.startswith(b"SSH-"):
            out["protocol_confirmed"] = True
            text = banner.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
            out["details"]["banner"] = text
            out["details"]["protocol_version"] = text.split("-", 2)[1] if "-" in text else "?"

            # Match versiones vulnerables
            for vuln_id, regex in SSH_VULN_PATTERNS.items():
                if regex.search(text):
                    out["vulnerabilities"].append({
                        "id": f"SSH-{vuln_id}",
                        "severity": "MEDIUM",
                        "description": (
                            f"SSH banner '{text}' coincide con firma {vuln_id}. "
                            f"Versión potencialmente vulnerable a CVEs históricos."
                        ),
                        "score": 5.0,
                        "source": "ssh_probe",
                    })
            # Marca informativa SSH expuesto
            out["vulnerabilities"].append({
                "id": "SSH-EXPOSED",
                "severity": "INFO",
                "description": (
                    f"SSH expuesto en {ip}:{port} (banner: {text}). Para comprobar "
                    f"credenciales por defecto usa probe_ssh_credentials (fase exploit, "
                    f"auth real con tope anti-lockout)."
                ),
                "score": 0.5,
                "source": "ssh_probe",
            })
        out["ok"] = True
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        out["error"] = str(e)
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
    return out


# Credenciales por defecto/débiles de IoT/embebidos. Lista CORTA a propósito:
# es una comprobación de credenciales por defecto, NO un brute-force. Mantenerla
# breve evita bloquear cuentas / disparar fail2ban en el objetivo.
_SSH_DEFAULT_CREDS: List[Tuple[str, str]] = [
    ("root", "root"), ("root", ""), ("root", "admin"), ("root", "toor"),
    ("admin", "admin"), ("admin", "password"), ("admin", ""), ("admin", "1234"),
    ("support", "support"), ("user", "user"),
]


# Opciones de crypto LEGADA: los dispositivos IoT/embebidos (Dropbear/OpenSSH
# viejos) solo ofrecen algoritmos que los clientes modernos rechazan por defecto
# (host key `ssh-rsa`/SHA-1, kex group1/group14-sha1, cifrados CBC/3des). Sin
# estos `-o ...+legacy`, ni el ssh del sistema ni paramiko 5.x pueden conectar —
# justo los objetivos que más interesan. paramiko ELIMINÓ `ssh-rsa`, por eso se
# usa el cliente `ssh` del sistema, que sí permite reactivarlo.
_SSH_LEGACY_OPTS: List[str] = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "GlobalKnownHostsFile=/dev/null",
    "-o", "PreferredAuthentications=password,keyboard-interactive",
    "-o", "PubkeyAuthentication=no",
    "-o", "NumberOfPasswordPrompts=1",
    "-o", "HostKeyAlgorithms=+ssh-rsa,ssh-dss",
    "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
    "-o", "KexAlgorithms=+diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,"
          "diffie-hellman-group-exchange-sha1",
    "-o", "Ciphers=+aes128-cbc,3des-cbc,aes256-cbc,aes128-ctr",
    "-o", "MACs=+hmac-sha1",
]


def _ssh_command(ip: str, port: int, user: str, timeout: int, verify_cmd: str):
    """Construye el comando `ssh` (con crypto legada) o None si no hay cliente."""
    ssh_bin = shutil.which("ssh")
    if not ssh_bin:
        return None
    return ([ssh_bin] + _SSH_LEGACY_OPTS
            + ["-o", f"ConnectTimeout={int(timeout)}", "-p", str(port),
               f"{user}@{ip}", verify_cmd])


def _ssh_password_login(ip: str, port: int, user: str, pw: str,
                        timeout: int, verify_cmd: str) -> Dict[str, str]:
    """Intenta un login SSH por contraseña con el cliente `ssh` del sistema (vía
    pty, sin sshpass) y crypto legada para IoT. NO hace brute-force: es UN intento.

    Devuelve ``{"status", "evidence"}`` con status:
      ``success`` | ``auth_failed`` | ``unreachable`` | ``no_client``.
    """
    cmd = _ssh_command(ip, port, user, timeout, verify_cmd)
    if cmd is None or _pty is None:
        return {"status": "no_client", "evidence": ""}
    master, slave = _pty.openpty()
    try:
        proc = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave,
                                 start_new_session=True, close_fds=True)
    except OSError as e:
        os.close(master)
        os.close(slave)
        return {"status": "unreachable", "evidence": str(e)}
    os.close(slave)
    buf = b""
    pw_sent = False
    deadline = time.time() + timeout + 6
    try:
        while time.time() < deadline:
            r, _, _ = select.select([master], [], [], 0.4)
            if master in r:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                if not pw_sent and b"assword" in buf.split(b"\n")[-1].lower():
                    os.write(master, (pw + "\n").encode("utf-8", "replace"))
                    pw_sent = True
            elif proc.poll() is not None:
                break
        try:
            rc = proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            rc = -9
    finally:
        try:
            os.close(master)
        except OSError:
            pass
    text = buf.decode("latin-1", "replace")
    low = text.lower()
    if any(s in low for s in ("permission denied", "authentication failed",
                              "too many authentication failures")):
        return {"status": "auth_failed", "evidence": ""}
    if any(s in low for s in ("no matching host key", "no matching key exchange",
                              "no matching cipher", "connection refused",
                              "no route to host", "connection timed out",
                              "operation timed out", "could not resolve")):
        return {"status": "unreachable", "evidence": text.strip()[:200]}
    if rc == 0 and pw_sent:
        return {"status": "success", "evidence": text.strip()[:600]}
    # Sin "permission denied" claro pero sin éxito → conservador: auth fallida.
    return {"status": "auth_failed", "evidence": ""}


def probe_ssh_credentials(
    ip: str,
    port: int = 22,
    usernames: Optional[List[str]] = None,
    passwords: Optional[List[str]] = None,
    pairs: Optional[List[Any]] = None,
    timeout: int = 6,
    max_attempts: int = 8,
    delay: float = 0.4,
    verify_cmd: str = "id; uname -a",
) -> Dict[str, Any]:
    """Prueba de **credenciales SSH** por defecto/débiles con autenticación REAL.

    A diferencia de :func:`probe_ssh` (que solo lee el banner), aquí se **intenta
    autenticación** vía el cliente `ssh` del sistema con **crypto legada** (para
    Dropbear/OpenSSH viejos de IoT) y un **pty** que introduce la contraseña sin
    `sshpass`. Un éxito CONFIRMA acceso con prueba de shell (`id; uname -a`).
    Resuelve el hueco de que el agente no sabía probar credenciales SSH (un pipe a
    `nc`/`telnet` no hace el handshake criptográfico y daba falso negativo).

    Seguridad / anti-lockout:
      * Lista corta de credenciales y `max_attempts` acotan los intentos para no
        bloquear cuentas ni disparar fail2ban. Es *default-credential check*, NO
        un brute-force. Para en el **primer éxito**, pausa `delay` s entre intentos.
      * Si el objetivo es inalcanzable, aborta — no machaca un host caído.
    """
    out: Dict[str, Any] = {
        "ok": False, "ip": ip, "port": port, "service": "ssh",
        "protocol_confirmed": False,
        "vulnerabilities": [], "credentials": [], "details": {}, "error": None,
    }

    # Construir la lista de pares (usuario, contraseña) a probar.
    if pairs:
        cred_list = [(str(p[0]), str(p[1]) if len(p) > 1 else "")
                     for p in pairs if isinstance(p, (list, tuple)) and p]
    elif usernames or passwords:
        us = usernames or ["root", "admin"]
        ps = passwords or ["root", "admin", "", "password"]
        cred_list = [(u, pw) for u in us for pw in ps]
    else:
        cred_list = list(_SSH_DEFAULT_CREDS)
    cred_list = cred_list[:max(1, max_attempts)]

    attempts = 0
    for user, pw in cred_list:
        attempts += 1
        res = _ssh_password_login(ip, port, user, pw, timeout, verify_cmd)
        status = res.get("status")
        if status == "no_client":
            out["error"] = "cliente 'ssh' del sistema no disponible (o sin soporte de pty)"
            break
        if status == "unreachable":
            out["error"] = res.get("evidence") or "SSH inaccesible"
            break
        out["protocol_confirmed"] = True  # respondió (auth aceptada o rechazada)
        if status == "success":
            out["credentials"].append(
                {"service": "ssh", "username": user, "password": pw, "port": port})
            out["vulnerabilities"].append({
                "id": "SSH-DEFAULT-CREDS",
                "severity": "CRITICAL",
                "score": 9.8,
                "impact": "REMOTE_SHELL",
                "description": (
                    f"SSH en {ip}:{port} acepta credenciales por defecto "
                    f"'{user}:{pw or '(contraseña vacía)'}' — acceso a shell remoto."
                ),
                "evidence": (res.get("evidence") or "")[:600],
                "source": "ssh_credentials_probe",
            })
            out["details"] = {"attempts": attempts, "matched": f"{user}:{pw}"}
            out["ok"] = True
            return out  # para en el primer éxito
        if delay:
            time.sleep(delay)

    out["ok"] = out["error"] is None          # error (inalcanzable/sin cliente) → ok=False
    out["details"]["attempts"] = attempts
    if out["ok"] and out["protocol_confirmed"] and not out["vulnerabilities"]:
        out["details"]["result"] = (
            f"none of the {attempts} credentials tried worked "
            f"(SSH answers, authentication rejected)"
        )
    return out


# =============================================================================
# FTP (21) — banner + anonymous login
# =============================================================================
def _ftp_send(sock: socket.socket, line: str, timeout: float = 3.0) -> bytes:
    """Envía línea FTP y lee respuesta hasta CRLF terminal."""
    sock.sendall(line.encode("ascii", errors="replace") + b"\r\n")
    sock.settimeout(timeout)
    buf = b""
    end_at = time.time() + timeout
    while time.time() < end_at and len(buf) < 4096:
        try:
            chunk = sock.recv(1024)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        # Respuesta multi-línea termina con "XXX " (3 dígitos + espacio)
        last_line = buf.split(b"\r\n")[-2:]
        if last_line and len(last_line[-1]) == 0:
            preceding = last_line[-2] if len(last_line) >= 2 else b""
            if len(preceding) >= 4 and preceding[3:4] == b" " and preceding[:3].isdigit():
                break
    return buf


def probe_ftp(ip: str, port: int = 21, timeout: int = 5) -> Dict[str, Any]:
    """FTP (21): banner + intento anonymous login + LIST raíz si tiene éxito."""
    out: Dict[str, Any] = {
        "ok": False, "ip": ip, "port": port, "service": "ftp",
        "protocol_confirmed": False,
        "vulnerabilities": [], "details": {}, "error": None,
    }
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        banner = b""
        end_at = time.time() + timeout
        while time.time() < end_at and len(banner) < 1024:
            try:
                chunk = sock.recv(512)
            except socket.timeout:
                break
            if not chunk:
                break
            banner += chunk
            if banner.startswith(b"220") and b"\r\n" in banner:
                break

        if not banner.startswith(b"220"):
            out["error"] = f"unexpected banner: {banner[:64]!r}"
            return out

        out["protocol_confirmed"] = True
        text = banner.decode("latin-1", errors="replace")
        out["details"]["banner"] = text[:500].strip()

        # Anonymous login.
        #
        # Se prueban varias contraseñas, no una. El RFC 1635 dice que un
        # servidor anónimo debe aceptar cualquier cosa —de ahí la de estilo
        # correo—, pero en la práctica abundan los servidores con una CUENTA
        # llamada `anonymous` que exige justamente `anonymous` o `ftp` como
        # contraseña. Enviar solo la de correo daba un 530 y se concluía «no
        # hay acceso anónimo» sobre un servidor al que se entra tecleando la
        # palabra que ya venía en el usuario. Detectado al validar el propio
        # laboratorio, cuyo Pure-FTPd está configurado exactamente así.
        resp_user = _ftp_send(sock, "USER anonymous", timeout=float(timeout))
        out["details"]["user_resp"] = resp_user[:200].decode("latin-1", errors="replace")

        resp_pass = b""
        for candidate in ("iotsafeguard@example.com", "anonymous", "ftp", ""):
            resp_pass = _ftp_send(sock, f"PASS {candidate}".rstrip(),
                                  timeout=float(timeout))
            if b"230" in resp_pass:
                out["details"]["anon_password_used"] = candidate or "(empty)"
                break
            # Un 5xx cierra la sesión en muchos servidores: hay que renegociar
            # el USER antes del siguiente intento, o el resto son 503.
            if b"530" in resp_pass or b"421" in resp_pass:
                try:
                    _ftp_send(sock, "USER anonymous", timeout=float(timeout))
                except (OSError, socket.timeout):
                    break
        out["details"]["pass_resp"] = resp_pass[:200].decode("latin-1", errors="replace")

        if b"230" in resp_pass:
            # 230 = login successful
            out["vulnerabilities"].append({
                "id": "FTP-ANON-LOGIN",
                "severity": "HIGH",
                "description": (
                    f"FTP en {ip}:{port} acepta login anónimo. "
                    f"Acceso al filesystem sin credenciales reales."
                ),
                "score": 7.5,
                "source": "ftp_probe",
                "verification_cmd": f"ftp -n {ip} <<< $'user anonymous\\npass test\\nls'",
            })
            out["details"]["anon_login"] = True

            # LIST root
            try:
                # Hay que abrir conexión PASV/PORT — simplificamos solo LIST sin data conn
                resp_list = _ftp_send(sock, "PWD", timeout=float(timeout))
                out["details"]["pwd_resp"] = resp_list[:200].decode("latin-1", errors="replace")
            except (OSError, socket.timeout):
                pass

        out["ok"] = True
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        out["error"] = str(e)
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
    return out


# =============================================================================
# SMB (445) — protocol negotiation + SMBv1 detection
# =============================================================================
# SMBv1 NEGOTIATE PROTOCOL request (cliente)
SMB1_NEGOTIATE_REQ = bytes.fromhex(
    "000000a4"      # NetBIOS Session header: msg_type=0, length=0xa4
    "ff534d42"      # Magic: \xffSMB
    "72"            # SMB_COM_NEGOTIATE
    "00000000"      # NT Status
    "18"            # Flags
    "53c8"          # Flags2
    "0000"          # PID High
    "0000000000000000"  # Signature
    "0000"          # Reserved
    "0000"          # TID
    "2f4b"          # PID
    "0000"          # UID
    "c5fe"          # MID
    "00"            # WCT
    "8100"          # ByteCount = 0x81
    # Dialects
    "024c414e4d414e312e3000"
    "024c414e4d414e322e3100"
    "024e54204c414e4d414e20312e3000"
    "024e54204c4d20302e313200"
    "025357324c4d2e353700"
    "025357324c4d2e353800"
    "025357324c4d2e3539"
)


def probe_smb(ip: str, port: int = 445, timeout: int = 5) -> Dict[str, Any]:
    """SMB (445): negotiate protocol → detectar SMBv1 (deprecated, EternalBlue)."""
    out: Dict[str, Any] = {
        "ok": False, "ip": ip, "port": port, "service": "smb",
        "protocol_confirmed": False,
        "vulnerabilities": [], "details": {}, "error": None,
    }
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(SMB1_NEGOTIATE_REQ)
        data = b""
        end_at = time.time() + timeout
        while time.time() < end_at and len(data) < 4096:
            try:
                chunk = sock.recv(1024)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if len(data) >= 36:  # mínimo NetBIOS + SMB header
                break

        if len(data) < 4 or data[0] != 0x00:
            out["error"] = "no SMB session response"
            return out
        # Verificar magic bytes \xffSMB en offset 4 (NetBIOS) o detectar SMB2 \xfeSMB
        magic = data[4:8]
        if magic == b"\xffSMB":
            out["protocol_confirmed"] = True
            out["details"]["protocol"] = "SMBv1"
            # SMBv1 es deprecated (Microsoft, 2014) y vector EternalBlue
            out["vulnerabilities"].append({
                "id": "SMB-V1-EXPOSED",
                "severity": "HIGH",
                "description": (
                    f"SMBv1 expuesto en {ip}:{port}. Protocolo deprecated por Microsoft "
                    f"desde 2014. Vector primario de EternalBlue (CVE-2017-0144, WannaCry/NotPetya). "
                    f"Bandera obligatoria de remediation."
                ),
                "score": 8.5,
                "source": "smb_probe",
                "verification_cmd": (
                    f"nmap --script smb-protocols -p 445 {ip}  # confirmar dialecto"
                ),
            })
            # Buscar response status
            if len(data) >= 9:
                nt_status = struct.unpack("<I", data[9:13])[0] if len(data) >= 13 else 0
                out["details"]["nt_status"] = f"0x{nt_status:08x}"
        elif magic == b"\xfeSMB":
            out["protocol_confirmed"] = True
            out["details"]["protocol"] = "SMBv2/3"
            out["vulnerabilities"].append({
                "id": "SMB-EXPOSED",
                "severity": "INFO",
                "description": (
                    f"SMBv2/3 expuesto en {ip}:{port}. Protocolo moderno — verificar "
                    f"compartos accesibles con `smbclient -L //{ip}` y null sessions con "
                    f"`smbclient -L //{ip} -N`."
                ),
                "score": 1.0,
                "source": "smb_probe",
            })
        else:
            out["details"]["raw_first_bytes"] = data[:32].hex()
        out["ok"] = True
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        out["error"] = str(e)
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
    return out


# =============================================================================
# DNS (53 UDP) — dnsmasq version assessment + open recursion
# =============================================================================
def _build_dns_query(name: str, qtype: int = 1, txid: int = 0x1234) -> bytes:
    """Builds a minimal DNS query packet (qtype 1=A, 255=ANY)."""
    flags = 0x0100  # RD=1
    hdr = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    qname = b""
    for label in name.rstrip(".").split("."):
        enc = label.encode()
        qname += bytes([len(enc)]) + enc
    qname += b"\x00"
    qname += struct.pack("!HH", qtype, 1)  # QCLASS=IN
    return hdr + qname


def _parse_dns_flags(data: bytes) -> Dict[str, Any]:
    if len(data) < 12:
        return {"valid": False}
    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    return {
        "valid": (flags >> 15) & 1 == 1,
        "rcode": flags & 0xF,        # 0=NOERROR, 2=SERVFAIL, 3=NXDOMAIN, 5=REFUSED
        "answer_count": ancount,
        "recursion_available": (flags >> 7) & 1 == 1,
        "authoritative": (flags >> 10) & 1 == 1,
    }


_DNSMASQ_DNSSEC_MIN = (2, 57)  # DNSSEC support added in dnsmasq 2.57


def _dnsmasq_has_dnssec(version_str: str) -> bool:
    """False when version is too old to have DNSSEC compiled in (< 2.57)."""
    try:
        parts = [int(x) for x in version_str.split(".")[:2]]
        return tuple(parts) >= _DNSMASQ_DNSSEC_MIN
    except (ValueError, TypeError):
        return True  # unknown → conservative


def probe_dns(ip: str, port: int = 53, timeout: int = 5,
              dnsmasq_version: Optional[str] = None) -> Dict[str, Any]:
    """DNS probe: open recursion check + dnsmasq version-based CVE assessment.

    Sends a recursive A query. Checks whether the server forwards external
    queries (open resolver) — prerequisite for upstream-server attacks like
    CVE-2019-14513. Also evaluates dnsmasq version and explicitly marks
    DNSSEC-dependent CVEs as not applicable when version < 2.57.
    """
    out: Dict[str, Any] = {
        "ok": False, "ip": ip, "port": port, "service": "dns",
        "protocol_confirmed": False,
        "vulnerabilities": [], "details": {}, "error": None,
        "_elapsed_ms": 0,
    }
    t0 = time.time()
    sock = None
    try:
        query = _build_dns_query("example.com", qtype=1, txid=0xDEAD)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (ip, port))
        data, _ = sock.recvfrom(512)
        parsed = _parse_dns_flags(data)
        out["protocol_confirmed"] = parsed.get("valid", False)
        out["ok"] = True
        out["details"]["response"] = parsed
        open_recursion = (
            parsed.get("rcode") == 0
            and parsed.get("answer_count", 0) > 0
            and parsed.get("recursion_available", False)
        )
        out["details"]["open_recursion"] = open_recursion

        if open_recursion:
            out["vulnerabilities"].append({
                "id": "DNS-OPEN-RECURSION",
                "severity": "MEDIUM",
                "description": (
                    "DNS server answers recursive queries for external domains. "
                    "Forwards to upstream resolvers — required condition for "
                    "CVE-2019-14513: attacker controlling upstream DNS can send "
                    "crafted oversized responses to trigger dnsmasq bounds failure."
                ),
            })

        if dnsmasq_version:
            out["details"]["dnsmasq_version"] = dnsmasq_version
            has_dnssec = _dnsmasq_has_dnssec(dnsmasq_version)
            out["details"]["dnssec_capable"] = has_dnssec
            try:
                ver_parts = tuple(int(x) for x in dnsmasq_version.split(".")[:2])
            except (ValueError, TypeError):
                ver_parts = (0, 0)

            # CVE-2019-14513: pure bounds issue, no DNSSEC needed, before 2.76
            if ver_parts < (2, 76) and open_recursion:
                out["vulnerabilities"].append({
                    "id": "CVE-2019-14513",
                    "severity": "HIGH",
                    "score": 7.5,
                    "confirmed": False,
                    "version_confirmed": True,
                    "description": (
                        f"dnsmasq {dnsmasq_version} < 2.76: improper bounds checking "
                        "when parsing DNS packets with long names from upstream. "
                        "Open recursion confirmed → upstream attack vector is present."
                    ),
                })

            if not has_dnssec:
                out["details"]["dnssec_cves_not_applicable"] = (
                    f"dnsmasq {dnsmasq_version} predates DNSSEC support (added in 2.57). "
                    "CVE-2020-25681, CVE-2020-25682, CVE-2017-15107 require DNSSEC "
                    "and are NOT applicable to this version."
                )

    except socket.timeout:
        out["error"] = "timeout"
    except (ConnectionRefusedError, OSError) as e:
        out["error"] = str(e)
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
    out["_elapsed_ms"] = int((time.time() - t0) * 1000)
    return out


# =============================================================================
# SOCKS5 (1080) — handshake + prueba de relay
# =============================================================================

# Respuestas del método de autenticación (RFC 1928 §3).
_SOCKS5_NO_AUTH = 0x00
_SOCKS5_NO_ACCEPTABLE = 0xFF

# Códigos de respuesta a CONNECT (RFC 1928 §6).
_SOCKS5_REPLY = {
    0x00: "succeeded", 0x01: "general failure", 0x02: "connection not allowed",
    0x03: "network unreachable", 0x04: "host unreachable",
    0x05: "connection refused", 0x06: "TTL expired",
    0x07: "command not supported", 0x08: "address type not supported",
}


def _socks5_connect(sock: socket.socket, host: str, port: int) -> Tuple[int, bytes]:
    """Envía un CONNECT ya negociado y devuelve (código, respuesta cruda)."""
    request = b"\x05\x01\x00\x01" + socket.inet_aton(host) + struct.pack("!H", port)
    sock.sendall(request)
    reply = sock.recv(262)
    if len(reply) < 2 or reply[0] != 0x05:
        return -1, reply
    return reply[1], reply


def probe_socks5(ip: str, port: int = 1080, timeout: int = 5,
                 relay_port: Optional[int] = None) -> Dict[str, Any]:
    """SOCKS5: negocia autenticación y, si no la pide, comprueba si RELAYA.

    Por qué existe como sonda y no como una tirada de `execute_command`: en
    campo, un altavoz Amazon expuso un SOCKS5 abierto en 1080 y el agente lo
    confirmó a mano con `probe_tcp payload_hex=050100` → `05 00`. Correcto,
    pero insuficiente por tres motivos:

    1. **Se quedaba en LOW.** Un handshake prueba alcanzabilidad, no impacto, y
       el tope de alcanzabilidad lo bajaba —con razón—. Los intentos de
       demostrar el relay (`curl -x socks5://…`, `nc -x …`) chocaban con la
       PolicyEngine, así que el sistema prohibía la única evidencia capaz de
       levantar su propio tope. El informe acababa diciendo «vector de acceso
       crítico» y puntuando NEGLIGIBLE: contradicción interna en la misma página.
    2. **Cada réplica inventaba su identificador**: `SOCKS5-NOAUTH-1080`,
       `SOCKS5-OPEN-PROXY`, `SOCKS5-AUTH-REQUIRED` para el mismo hecho. Sin id
       canónico, ni la KB agrega ni el techo de severidad puede indexar.
    3. **El negativo puntuaba igual que el positivo**: la réplica que recibió
       `05 ff` (proxy que SÍ exige autenticación, o sea buena noticia) registró
       un hallazgo confirmado y sacó el mismo score que la que lo encontró
       abierto de par en par.

    El destino del CONNECT es `127.0.0.1` **del propio objetivo**: no se toca
    ningún tercero, se mantiene dentro del alcance autorizado y además prueba lo
    que de verdad importa —que el proxy alcanza servicios de loopback que no
    están publicados en la red—.
    """
    t0 = time.time()
    out: Dict[str, Any] = {
        "ok": False, "ip": ip, "port": port, "service": "socks5",
        "protocol_confirmed": False,
        "vulnerabilities": [], "details": {}, "error": None,
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        sock.sendall(b"\x05\x01\x00")           # VER=5, 1 método, 0x00 = sin auth
        greeting = sock.recv(2)
        out["details"]["greeting_hex"] = greeting.hex()

        if len(greeting) < 2 or greeting[0] != 0x05:
            out["error"] = "not_socks5"
            out["ok"] = True
            return out

        out["protocol_confirmed"] = True
        method = greeting[1]

        if method == _SOCKS5_NO_ACCEPTABLE:
            # RESULTADO NEGATIVO: el proxy exige autenticación. Se registra como
            # INFO para que quede la comprobación, nunca como vulnerabilidad.
            out["details"]["auth_required"] = True
            out["vulnerabilities"].append({
                "id": "SOCKS5-AUTH-REQUIRED",
                "severity": "INFO",
                "confirmed_negative": True,
                "description": (
                    f"SOCKS5 en {ip}:{port} rechaza el método «sin autenticación» "
                    f"(respuesta 05 ff). Comprobado que NO es un proxy abierto."
                ),
                "score": 0.0,
                "source": "socks5_probe",
                "verification_cmd": f"probe_socks5 ip={ip} port={port}",
            })
            out["ok"] = True
            return out

        if method != _SOCKS5_NO_AUTH:
            out["details"]["auth_method"] = method
            out["ok"] = True
            return out

        # Sin autenticación. Queda por ver si además relaya.
        out["details"]["no_auth_accepted"] = True
        target_port = relay_port or 80
        code, reply = _socks5_connect(sock, "127.0.0.1", target_port)
        out["details"]["connect_reply_hex"] = reply.hex()
        out["details"]["connect_status"] = _SOCKS5_REPLY.get(code, f"unknown ({code})")

        relayed = b""
        if code == 0x00:
            # Túnel concedido: se pide algo mínimo para capturar bytes que
            # vengan DEL OTRO LADO. Sin esto la evidencia seguiría siendo un
            # handshake, y el tope de alcanzabilidad la dejaría en LOW con razón.
            try:
                sock.sendall(b"GET / HTTP/1.0\r\nConnection: close\r\n\r\n")
                relayed = sock.recv(512)
            except OSError:
                relayed = b""
            out["details"]["relayed_response"] = relayed.decode(
                errors="replace")[:300]

        if code == 0x00 and relayed:
            out["vulnerabilities"].append({
                "id": "SOCKS5-OPEN-RELAY",
                "severity": "HIGH",
                "impact": "ACCESS",
                "description": (
                    f"SOCKS5 abierto en {ip}:{port}: acepta el método sin "
                    f"autenticación Y establece el túnel. Se pidió "
                    f"127.0.0.1:{target_port} a través del proxy y el servicio "
                    f"respondió {len(relayed)} bytes. Cualquiera en la LAN puede "
                    f"usar el dispositivo como salto y alcanzar servicios de "
                    f"loopback que no están publicados en la red."
                ),
                "score": 8.0,
                "source": "socks5_probe",
                "evidence": out["details"]["relayed_response"],
                "verification_cmd": f"probe_socks5 ip={ip} port={port}",
            })
        elif code == 0x00:
            # Túnel concedido pero el destino no habló: el relay funciona, no
            # tenemos datos del otro extremo. Se declara como tal.
            out["vulnerabilities"].append({
                "id": "SOCKS5-OPEN-RELAY-NODATA",
                "severity": "MEDIUM",
                "impact": "EXPOSURE",
                "description": (
                    f"SOCKS5 en {ip}:{port} concede el túnel sin autenticación "
                    f"(reply 05 00) pero 127.0.0.1:{target_port} no devolvió "
                    f"datos. El relay se concede; falta demostrar qué alcanza. "
                    f"Reintentar con `relay_port` de un puerto abierto conocido."
                ),
                "score": 5.0,
                "source": "socks5_probe",
                "verification_cmd": f"probe_socks5 ip={ip} port={port} relay_port=…",
            })
        else:
            out["vulnerabilities"].append({
                "id": "SOCKS5-NOAUTH",
                "severity": "MEDIUM",
                "impact": "EXPOSURE",
                "description": (
                    f"SOCKS5 en {ip}:{port} acepta el método «sin autenticación» "
                    f"pero denegó el CONNECT de prueba "
                    f"({out['details']['connect_status']}). Handshake abierto sin "
                    f"relay demostrado."
                ),
                "score": 4.0,
                "source": "socks5_probe",
                "verification_cmd": f"probe_socks5 ip={ip} port={port}",
            })
        out["ok"] = True
    except socket.timeout:
        out["error"] = "timeout"
    except OSError as e:
        out["error"] = str(e)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    out["_elapsed_ms"] = int((time.time() - t0) * 1000)
    return out
