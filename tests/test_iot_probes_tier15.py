"""
Tests Tier 1.5: telnet, upnp_igd, wsdiscovery, opcua, tftp.

Servidor TCP/UDP fake en localhost para cada protocolo.
"""
from __future__ import annotations

import os
import socket
import struct
import sys
import threading
import time


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from modules.iot_probes import (
    _opcua_hello,
    _parse_bacnet_iam,
    _strip_telnet_iac,
    _tftp_rrq,
    probe_bacnet,
    probe_opcua,
    probe_telnet,
    probe_tftp,
    probe_wsdiscovery,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _free_tcp_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _TCPServer:
    def __init__(self, handler):
        self.port = _free_tcp_port()
        self.handler = handler
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.listen(1)
        self._sock.settimeout(5)
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def _run(self):
        try:
            client, _ = self._sock.accept()
            try:
                self.handler(client)
            finally:
                client.close()
        except (socket.timeout, OSError):
            pass
        finally:
            self._sock.close()


class _UDPServer:
    def __init__(self, handler):
        self.port = _free_udp_port()
        self.handler = handler
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.settimeout(3)
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def _run(self):
        try:
            data, addr = self._sock.recvfrom(4096)
            resp = self.handler(data)
            if resp is not None:
                self._sock.sendto(resp, addr)
        except (socket.timeout, OSError):
            pass
        finally:
            self._sock.close()


# ---------------------------------------------------------------------------
# BACnet vendor_id parser (fix #1)
# ---------------------------------------------------------------------------
class TestBACnetIamParser:

    def test_full_apdu_extracts_all_fields(self):
        # ObjectId: type=8, instance=12345 → raw = (8 << 22) | 12345
        raw_oid = (8 << 22) | 12345
        apdu = (
            b"\xc4" + struct.pack("!I", raw_oid)  # 0xC4 + 4B object id
            + b"\x22\x04\x00"                       # 0x22 + max_apdu=1024
            + b"\x91\x00"                           # 0x91 + segmentation=0
            + b"\x21\x07"                           # 0x21 + vendor_id=7
        )
        parsed = _parse_bacnet_iam(apdu)
        assert parsed["object_type"] == 8
        assert parsed["object_instance"] == 12345
        assert parsed["max_apdu"] == 1024
        assert parsed["segmentation"] == 0
        assert parsed["vendor_id"] == 7

    def test_vendor_id_2_bytes(self):
        raw_oid = (8 << 22) | 1
        apdu = (
            b"\xc4" + struct.pack("!I", raw_oid)
            + b"\x22\x04\x00"
            + b"\x91\x00"
            + b"\x22\x01\xf4"   # vendor_id 2-byte = 500
        )
        parsed = _parse_bacnet_iam(apdu)
        assert parsed["vendor_id"] == 500

    def test_short_apdu_returns_partial(self):
        assert _parse_bacnet_iam(b"\x00") == {}


# ---------------------------------------------------------------------------
# probe_bacnet — vendor_id end-to-end
# ---------------------------------------------------------------------------
class TestProbeBACnetVendorId:

    def test_iam_response_extracts_vendor_id(self):
        def handler(req):
            raw_oid = (8 << 22) | 1234
            apdu = (
                b"\xc4" + struct.pack("!I", raw_oid)
                + b"\x22\x04\x00"
                + b"\x91\x00"
                + b"\x21\x2a"  # vendor_id=42
            )
            return b"\x81\x0a" + struct.pack("!H", 4 + 2 + 2 + len(apdu)) + b"\x01\x00\x10\x00" + apdu

        srv = _UDPServer(handler).start()
        result = probe_bacnet("127.0.0.1", port=srv.port, timeout=2)
        assert result["protocol_confirmed"] is True
        assert result["details"]["vendor_id"] == 42
        assert result["details"]["object_instance"] == 1234


# ---------------------------------------------------------------------------
# Telnet helpers
# ---------------------------------------------------------------------------
class TestTelnetHelpers:

    def test_strip_iac_removes_negotiation(self):
        # IAC WILL ECHO + "Login: "
        data = b"\xff\xfb\x01Login: "
        cleaned = _strip_telnet_iac(data)
        assert cleaned == b"Login: "

    def test_strip_iac_handles_double_iac(self):
        data = b"\xff\xfd\x18\xff\xfb\x03BusyBox v1.0\r\n"
        cleaned = _strip_telnet_iac(data)
        assert b"BusyBox v1.0" in cleaned


# ---------------------------------------------------------------------------
# probe_telnet
# ---------------------------------------------------------------------------
class TestProbeTelnet:

    def test_connection_refused(self):
        port = _free_tcp_port()
        result = probe_telnet("127.0.0.1", port=port, timeout=1)
        assert result["protocol_confirmed"] is False

    def test_busybox_banner_triggers_mirai_match(self):
        def handler(client):
            client.settimeout(2)
            try:
                client.recv(64)  # consume IAC del cliente
            except socket.timeout:
                pass
            client.sendall(b"\r\nBusyBox v1.20.2 () built-in shell\r\nLogin: ")

        srv = _TCPServer(handler).start()
        result = probe_telnet("127.0.0.1", port=srv.port, timeout=2)
        assert result["protocol_confirmed"] is True
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "TELNET-MIRAI-BUSYBOX" in ids
        assert "TELNET-EXPOSED" in ids

    def test_hikvision_banner_triggers_match(self):
        def handler(client):
            client.settimeout(2)
            try:
                client.recv(64)
            except socket.timeout:
                pass
            client.sendall(b"Hikvision DS-7204HQHI login: ")

        srv = _TCPServer(handler).start()
        result = probe_telnet("127.0.0.1", port=srv.port, timeout=2,
                              try_default_creds=False)
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "TELNET-MIRAI-HIKVISION" in ids

    def test_default_creds_disabled_skips_login_attempts(self):
        """Cuando try_default_creds=False, no se hacen intentos de login."""
        def handler(client):
            client.settimeout(2)
            try:
                client.recv(64)
            except socket.timeout:
                pass
            client.sendall(b"BusyBox login: ")

        srv = _TCPServer(handler).start()
        result = probe_telnet("127.0.0.1", port=srv.port, timeout=2,
                              try_default_creds=False)
        assert "creds_attempted" not in result["details"]
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "TELNET-DEFAULT-CRED" not in ids

    def test_default_creds_success_marks_critical(self):
        """Servidor que acepta admin/password y devuelve shell prompt → CRITICAL vuln."""
        # Servidor multi-conexión: una conexión para banner-grab, varias para login attempts.
        port = _free_tcp_port()
        listening = socket.socket()
        listening.bind(("127.0.0.1", port))
        listening.listen(8)
        listening.settimeout(8)
        # Admin/password aparece en posición 6 de TELNET_DEFAULT_CREDS, así que
        # max_creds_attempts=8 lo cubre.

        def server_loop():
            for _ in range(8):
                try:
                    client, _ = listening.accept()
                except (socket.timeout, OSError):
                    return
                try:
                    client.settimeout(2)
                    try:
                        client.sendall(b"Welcome\r\nlogin: ")
                    except (BrokenPipeError, OSError):
                        client.close()
                        continue
                    user = b""
                    end_at = time.time() + 1.5
                    while time.time() < end_at and b"\n" not in user:
                        try:
                            chunk = client.recv(64)
                        except (socket.timeout, OSError):
                            break
                        if not chunk:
                            break
                        user += chunk
                    if not user:
                        client.close()
                        continue
                    try:
                        client.sendall(b"Password: ")
                    except (BrokenPipeError, OSError):
                        client.close()
                        continue
                    pw = b""
                    end_at = time.time() + 1.5
                    while time.time() < end_at and b"\n" not in pw:
                        try:
                            chunk = client.recv(64)
                        except (socket.timeout, OSError):
                            break
                        if not chunk:
                            break
                        pw += chunk
                    user_clean = _strip_telnet_iac(user).strip().decode("ascii", errors="replace")
                    pw_clean = _strip_telnet_iac(pw).strip().decode("ascii", errors="replace")
                    try:
                        if user_clean == "admin" and pw_clean == "password":
                            client.sendall(b"\r\nroot@iot:~# ")
                        else:
                            client.sendall(b"\r\nLogin incorrect\r\nlogin: ")
                    except (BrokenPipeError, OSError):
                        pass
                finally:
                    try:
                        client.close()
                    except OSError:
                        pass

        t = threading.Thread(target=server_loop, daemon=True)
        t.start()

        try:
            result = probe_telnet("127.0.0.1", port=port, timeout=3,
                                  try_default_creds=True, max_creds_attempts=8)
        finally:
            try:
                listening.close()
            except OSError:
                pass
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "TELNET-DEFAULT-CRED" in ids
        accepted = result["details"].get("accepted_creds", {})
        assert accepted.get("user") == "admin"
        assert accepted.get("password") == "password"

    def test_socks5_response_not_confirmed_as_telnet(self):
        """Regresión (Echo 192.168.1.34): sondar telnet sobre un puerto SOCKS5
        devolvía `05 ff` y el probe lo tomaba por telnet → falso TELNET-EXPOSED.
        Ahora una respuesta binaria que no parece telnet NO se confirma."""
        def handler(client):
            client.settimeout(2)
            try:
                client.recv(64)  # recibe la negociación IAC del probe
            except socket.timeout:
                pass
            client.sendall(b"\x05\xff")  # respuesta SOCKS5 "no acceptable methods"

        srv = _TCPServer(handler).start()
        result = probe_telnet("127.0.0.1", port=srv.port, timeout=2,
                              try_default_creds=False)
        assert result["protocol_confirmed"] is False
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "TELNET-EXPOSED" not in ids
        assert "non_telnet_response_hex" in result["details"]

    def test_binary_non_printable_not_confirmed(self):
        """Otra respuesta binaria (no IAC, no prompt, no imprimible) → no telnet."""
        def handler(client):
            client.settimeout(2)
            try:
                client.recv(64)
            except socket.timeout:
                pass
            client.sendall(bytes([0x00, 0x01, 0x02, 0x03, 0x99, 0xAB]))

        srv = _TCPServer(handler).start()
        result = probe_telnet("127.0.0.1", port=srv.port, timeout=2,
                              try_default_creds=False)
        assert result["protocol_confirmed"] is False
        assert "TELNET-EXPOSED" not in [v["id"] for v in result["vulnerabilities"]]


# ---------------------------------------------------------------------------
# probe_wsdiscovery
# ---------------------------------------------------------------------------
class TestProbeWSDiscovery:

    def test_no_response(self):
        port = _free_udp_port()
        result = probe_wsdiscovery("127.0.0.1", port=port, timeout=1)
        assert result["protocol_confirmed"] is False

    def test_onvif_camera_match(self):
        def handler(req):
            return (
                b"<soap:Envelope>"
                b"<wsd:Types>tdn:NetworkVideoTransmitter</wsd:Types>"
                b"<wsd:XAddrs>http://192.168.1.10/onvif/device_service</wsd:XAddrs>"
                b"</soap:Envelope>"
            )

        srv = _UDPServer(handler).start()
        result = probe_wsdiscovery("127.0.0.1", port=srv.port, timeout=2)
        assert result["protocol_confirmed"] is True
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "WSD-ONVIF-CAMERA-EXPOSED" in ids
        assert "ONVIF-CAMERA" in result["details"]["matched"]

    def test_printer_match(self):
        def handler(req):
            return b"<wsd:Types>PrintBasic</wsd:Types>"

        srv = _UDPServer(handler).start()
        result = probe_wsdiscovery("127.0.0.1", port=srv.port, timeout=2)
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "WSD-PRINTER-EXPOSED" in ids


# ---------------------------------------------------------------------------
# OPC-UA hello frame builder
# ---------------------------------------------------------------------------
class TestOPCUAHello:

    def test_hello_frame_format(self):
        f = _opcua_hello("opc.tcp://127.0.0.1:4840")
        # MessageType "HEL" + chunk type "F" + size + body
        assert f[:3] == b"HEL"
        assert f[3:4] == b"F"
        size = struct.unpack("<I", f[4:8])[0]
        assert size == len(f)


# ---------------------------------------------------------------------------
# probe_opcua
# ---------------------------------------------------------------------------
class TestProbeOPCUA:

    def test_connection_refused(self):
        port = _free_tcp_port()
        result = probe_opcua("127.0.0.1", port=port, timeout=1)
        assert result["protocol_confirmed"] is False

    def test_ack_response_marks_protocol(self):
        def handler(client):
            client.settimeout(2)
            client.recv(2048)  # consume HEL
            # ACK: "ACK" + "F" + size + ProtoVer + RecvBuf + SendBuf + MaxMsg + MaxChunks
            body = struct.pack("<IIIII", 0, 65536, 65536, 1048576, 100)
            ack = b"ACK" + b"F" + struct.pack("<I", 8 + len(body)) + body
            client.sendall(ack)

        srv = _TCPServer(handler).start()
        result = probe_opcua("127.0.0.1", port=srv.port, timeout=2)
        assert result["protocol_confirmed"] is True
        assert result["details"]["handshake_response"] == "ACK"
        assert result["details"]["receive_buffer"] == 65536
        assert result["details"]["send_buffer"] == 65536
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "OPCUA-EXPOSED" in ids


# ---------------------------------------------------------------------------
# TFTP
# ---------------------------------------------------------------------------
class TestTFTP:

    def test_rrq_packet_format(self):
        p = _tftp_rrq("config.bin")
        assert p == b"\x00\x01config.bin\x00octet\x00"

    def test_no_server_returns_no_files(self):
        port = _free_udp_port()
        result = probe_tftp("127.0.0.1", port=port, timeout=1, filenames=["x.bin"])
        # Sin servidor: no error fatal, simplemente no hay archivos accesibles
        assert result["details"].get("accessible_files") in (None, [])

    def test_data_response_marks_critical_vuln(self):
        def handler(req):
            # Si la solicitud es RRQ válida, devolver DATA opcode
            if len(req) > 2 and req[1] == 1:
                # DATA: opcode=3, block=1, payload "FIRMWARE"
                return b"\x00\x03\x00\x01FIRMWARE"
            return None

        srv = _UDPServer(handler).start()
        result = probe_tftp("127.0.0.1", port=srv.port, timeout=2,
                            filenames=["firmware.bin"])
        assert result["protocol_confirmed"] is True
        assert "firmware.bin" in result["details"].get("accessible_files", [])
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "TFTP-ANON-DOWNLOAD" in ids

    def test_error_response_recorded(self):
        def handler(req):
            # ERROR opcode 5, code 1 = file not found
            return b"\x00\x05\x00\x01not found\x00"

        srv = _UDPServer(handler).start()
        result = probe_tftp("127.0.0.1", port=srv.port, timeout=2,
                            filenames=["missing.bin"])
        assert result["protocol_confirmed"] is True
        # No vuln pero registró el error
        assert result["details"].get("errors", {}).get("missing.bin") == 1
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "TFTP-ANON-DOWNLOAD" not in ids


# ---------------------------------------------------------------------------
# UPnP IGD — probamos solo el path "no SSDP response" porque la M-SEARCH va
# unicast a 1900 y no podemos servir UDP en localhost:1900 sin root + sin colisión
# ---------------------------------------------------------------------------
class TestProbeUPnPIGD:

    def test_no_ssdp_response_marks_error(self):
        from modules.iot_probes import probe_upnp_igd
        # IP sin servicio SSDP escuchando
        result = probe_upnp_igd("127.0.0.2", timeout=1)
        assert result["protocol_confirmed"] is False
        assert "SSDP" in (result.get("error") or "")
