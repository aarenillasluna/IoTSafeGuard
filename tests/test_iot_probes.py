"""
Tests unitarios para modules/iot_probes.py — Modbus, RTSP, BACnet, CWMP.

Estrategia: levantamos servidores TCP/UDP fake en localhost que devuelven frames
controlados. Sin depender de red externa.
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
    _modbus_frame,
    _parse_mbap,
    _parse_rtsp_status,
    _extract_header,
    probe_bacnet,
    probe_cwmp,
    probe_ftp,
    probe_miio,
    probe_udp_raw,
    probe_modbus,
    probe_rtsp,
    probe_smb,
    probe_ssh,
)


# ---------------------------------------------------------------------------
# Helpers: fake TCP/UDP servers
# ---------------------------------------------------------------------------
def _free_port() -> int:
    """Pide al SO un puerto TCP libre."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# Alias usado por las clases de probes consolidadas aquí (SSH/FTP/SMB).
_free_tcp_port = _free_port


def _free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _TCPServer:
    """Servidor TCP de un solo cliente que ejecuta `handler(client_sock)`."""

    def __init__(self, handler):
        self.port = _free_port()
        self.handler = handler
        self.thread = threading.Thread(target=self._run, daemon=True)
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.listen(1)
        self._sock.settimeout(5)

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
        except socket.timeout:
            pass
        except OSError:
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
            data, addr = self._sock.recvfrom(1500)
            resp = self.handler(data)
            if resp is not None:
                self._sock.sendto(resp, addr)
        except socket.timeout:
            pass
        finally:
            self._sock.close()


# ---------------------------------------------------------------------------
# Helpers de bajo nivel
# ---------------------------------------------------------------------------
class TestModbusHelpers:

    def test_modbus_frame_fc17(self):
        f = _modbus_frame(unit_id=1, function_code=0x11, trans_id=42)
        # MBAP: trans_id(2) + proto_id(2)=0 + length(2) + unit_id(1) + fc(1)
        trans, proto, length, unit, fc = struct.unpack("!HHHBB", f)
        assert trans == 42
        assert proto == 0
        assert length == 2  # unit + fc
        assert unit == 1
        assert fc == 0x11

    def test_parse_mbap_well_formed(self):
        # Construye respuesta válida FC17 con byte_count=2 y datos "AB"
        pdu = bytes([0x11, 0x02, 0x41, 0x42])  # fc=17, byte_count=2, slave_id="AB"
        mbap = struct.pack("!HHHB", 1, 0, len(pdu) + 1, 1) + pdu
        parsed = _parse_mbap(mbap)
        assert parsed is not None
        assert parsed["function_code"] == 0x11
        assert parsed["unit_id"] == 1

    def test_parse_mbap_short_returns_none(self):
        assert _parse_mbap(b"\x00\x01") is None


# ---------------------------------------------------------------------------
# probe_modbus
# ---------------------------------------------------------------------------
class TestProbeModbus:

    def test_connection_refused(self):
        port = _free_port()  # nadie escucha
        result = probe_modbus("127.0.0.1", port=port, timeout=1)
        assert result["ok"] is False
        assert result["error"]
        assert result["protocol_confirmed"] is False

    def test_responds_fc17_marks_protocol_confirmed(self):
        def handler(client):
            client.settimeout(2)
            req = client.recv(64)
            mbap = _parse_mbap(req)
            assert mbap is not None
            # Respuesta válida: byte_count=4, slave_id="LAB1"
            pdu = bytes([0x11, 0x04]) + b"LAB1"
            resp = struct.pack("!HHHB", mbap["trans_id"], 0, len(pdu) + 1, mbap["unit_id"]) + pdu
            client.sendall(resp)
            # Segunda petición FC1 — devolvemos exception para abortar el ciclo
            try:
                client.recv(64)
                exc = struct.pack("!HHHBBB", 2, 0, 3, mbap["unit_id"], 0x81, 0x01)
                client.sendall(exc)
            except socket.timeout:
                pass

        srv = _TCPServer(handler).start()
        result = probe_modbus("127.0.0.1", port=srv.port, timeout=2,
                              unit_ids=[1])
        assert result["ok"] is True
        assert result["protocol_confirmed"] is True
        # FC17 sin auth → vulnerability MEDIUM/HIGH
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "MODBUS-NO-AUTH-FC17" in ids


# ---------------------------------------------------------------------------
# probe_rtsp
# ---------------------------------------------------------------------------
class TestProbeRTSP:

    def test_helpers_extract_status_and_header(self):
        data = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: TestCam/1.0\r\n\r\n"
        assert _parse_rtsp_status(data) == 200
        assert _extract_header(data, "Server") == "TestCam/1.0"

    def test_unknown_response_returns_none(self):
        assert _parse_rtsp_status(b"garbage data") is None
        assert _extract_header(b"no headers", "Server") is None

    def test_connection_refused(self):
        port = _free_port()
        result = probe_rtsp("127.0.0.1", ports=[port], timeout=1)
        assert result["protocol_confirmed"] is False

    def test_unauth_describe_marks_vuln(self):
        def handler(client):
            client.settimeout(3)
            # OPTIONS
            client.recv(2048)
            client.sendall(
                b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n"
                b"Public: OPTIONS, DESCRIBE, SETUP\r\n"
                b"Server: FakeCam/2.0\r\n\r\n"
            )
            # DESCRIBE primer path → 200 OK
            client.recv(2048)
            client.sendall(
                b"RTSP/1.0 200 OK\r\nCSeq: 2\r\n"
                b"Content-Type: application/sdp\r\n\r\nv=0\r\n"
            )
            # cerrar
            try:
                while True:
                    chunk = client.recv(2048)
                    if not chunk:
                        break
            except socket.timeout:
                pass

        srv = _TCPServer(handler).start()
        result = probe_rtsp("127.0.0.1", ports=[srv.port], timeout=2)
        assert result["protocol_confirmed"] is True
        assert result["details"]["server"] == "FakeCam/2.0"
        vuln_ids = [v["id"] for v in result["vulnerabilities"]]
        assert "RTSP-NO-AUTH" in vuln_ids

    def test_airplay_audio_describe_not_flagged(self):
        """AirTunes/AirPlay (RAOP) responde 200 a DESCRIBE por diseño: es el
        handshake de audio, NO un stream de vídeo sin auth. No debe ser vuln.
        (Caso real: LG TV puerto 7000 marcado como 'RTSP-NO-AUTH' falso positivo.)"""
        def handler(client):
            client.settimeout(3)
            client.recv(2048)  # OPTIONS
            client.sendall(
                b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n"
                b"Server: AirTunes/377.40.00\r\n\r\n"
            )
            client.recv(2048)  # DESCRIBE → 200 con SDP de audio (m=audio)
            client.sendall(
                b"RTSP/1.0 200 OK\r\nCSeq: 2\r\n"
                b"Content-Type: application/sdp\r\n\r\n"
                b"v=0\r\nm=audio 0 RTP/AVP 96\r\n"
            )
            try:
                while client.recv(2048):
                    pass
            except socket.timeout:
                pass

        srv = _TCPServer(handler).start()
        result = probe_rtsp("127.0.0.1", ports=[srv.port], timeout=2)
        vuln_ids = [v["id"] for v in result["vulnerabilities"]]
        assert "RTSP-NO-AUTH" not in vuln_ids
        assert result["details"].get("airplay_paths")  # registrado como AirPlay legítimo

    def test_airplay_banner_but_real_video_still_flagged(self):
        """Si tras el banner AirPlay hay SDP con m=video, sí es exposición real."""
        def handler(client):
            client.settimeout(3)
            client.recv(2048)
            client.sendall(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: AirTunes/1.0\r\n\r\n")
            client.recv(2048)
            client.sendall(
                b"RTSP/1.0 200 OK\r\nCSeq: 2\r\n"
                b"Content-Type: application/sdp\r\n\r\n"
                b"v=0\r\nm=video 0 RTP/AVP 96\r\n"
            )
            try:
                while client.recv(2048):
                    pass
            except socket.timeout:
                pass

        srv = _TCPServer(handler).start()
        result = probe_rtsp("127.0.0.1", ports=[srv.port], timeout=2)
        vuln_ids = [v["id"] for v in result["vulnerabilities"]]
        assert "RTSP-NO-AUTH" in vuln_ids


# ---------------------------------------------------------------------------
# probe_bacnet
# ---------------------------------------------------------------------------
class TestProbeBACnet:

    def test_no_response_timeout(self):
        port = _free_udp_port()  # nadie responde
        result = probe_bacnet("127.0.0.1", port=port, timeout=1)
        assert result["ok"] is False
        assert "timeout" in (result.get("error") or "")
        assert result["protocol_confirmed"] is False

    def test_iam_response_confirms_protocol(self):
        def handler(req):
            # I-Am: BVLC + NPDU + APDU(0x10 0x00) + datos
            return (b"\x81\x0a\x00\x14"
                    b"\x01\x00"
                    b"\x10\x00"
                    b"\xc4\x02\x00\x00\x01"  # device id
                    b"\x22\x04\x00"           # max_apdu
                    b"\x91\x00"               # segmentation
                    b"\x21\x07")              # vendor_id

        srv = _UDPServer(handler).start()
        result = probe_bacnet("127.0.0.1", port=srv.port, timeout=2)
        assert result["ok"] is True
        assert result["protocol_confirmed"] is True
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "BACNET-NO-AUTH-WHOIS" in ids


# ---------------------------------------------------------------------------
# probe_cwmp
# ---------------------------------------------------------------------------
class TestProbeCWMP:

    def test_connection_refused(self):
        port = _free_port()
        result = probe_cwmp("127.0.0.1", port=port, timeout=1)
        assert result["protocol_confirmed"] is False

    def test_rompager_banner_triggers_misfortune_cookie(self):
        def handler(client):
            client.settimeout(3)
            client.recv(2048)
            client.sendall(
                b"HTTP/1.0 401 Unauthorized\r\n"
                b"Server: RomPager/4.07 UPnP/1.0\r\n"
                b"WWW-Authenticate: Basic realm=\"Broadband\"\r\n\r\n"
            )

        srv = _TCPServer(handler).start()
        result = probe_cwmp("127.0.0.1", port=srv.port, timeout=2)
        assert result["protocol_confirmed"] is True
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "CWMP-ROMPAGER-CVE-2014-9222" in ids

    def test_huawei_banner_triggers_mirai(self):
        def handler(client):
            client.settimeout(3)
            client.recv(2048)
            client.sendall(
                b"HTTP/1.0 200 OK\r\n"
                b"Server: Huawei HG532\r\n\r\nbody"
            )

        srv = _TCPServer(handler).start()
        result = probe_cwmp("127.0.0.1", port=srv.port, timeout=2)
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "CWMP-MIRAI-CVE-2017-17215" in ids


# ---------------------------------------------------------------------------
# probe_ssh / probe_ftp / probe_smb
# (consolidados aquí desde test_critical_improvements.py — iter_08)
# ---------------------------------------------------------------------------
class TestProbeSSH:

    def test_connection_refused(self):
        port = _free_tcp_port()
        result = probe_ssh("127.0.0.1", port=port, timeout=1)
        assert result["protocol_confirmed"] is False

    def test_old_openssh_banner_triggers_vuln(self):
        def handler(client):
            client.sendall(b"SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2\r\n")
            time.sleep(0.5)

        srv = _TCPServer(handler).start()
        result = probe_ssh("127.0.0.1", port=srv.port, timeout=2)
        assert result["protocol_confirmed"] is True
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "SSH-OpenSSH-OLD-CVE" in ids
        assert "SSH-EXPOSED" in ids

    def test_modern_openssh_only_marks_exposed(self):
        def handler(client):
            client.sendall(b"SSH-2.0-OpenSSH_9.6p1\r\n")
            time.sleep(0.5)

        srv = _TCPServer(handler).start()
        result = probe_ssh("127.0.0.1", port=srv.port, timeout=2)
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "SSH-EXPOSED" in ids
        assert "SSH-OpenSSH-OLD-CVE" not in ids


class TestProbeFTP:

    def test_connection_refused(self):
        port = _free_tcp_port()
        result = probe_ftp("127.0.0.1", port=port, timeout=1)
        assert result["protocol_confirmed"] is False

    def test_anonymous_login_marks_high_vuln(self):
        def handler(client):
            client.settimeout(3)
            client.sendall(b"220 Welcome to vsftpd 3.0.3\r\n")
            try:
                client.recv(512)  # USER anonymous
                client.sendall(b"331 Please specify the password.\r\n")
                client.recv(512)  # PASS
                client.sendall(b"230 Login successful.\r\n")
                # PWD opcional
                try:
                    client.recv(512)
                    client.sendall(b'257 "/" is the current directory\r\n')
                except (socket.timeout, OSError):
                    pass
            except (socket.timeout, OSError):
                pass

        srv = _TCPServer(handler).start()
        result = probe_ftp("127.0.0.1", port=srv.port, timeout=2)
        assert result["protocol_confirmed"] is True
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "FTP-ANON-LOGIN" in ids
        assert result["details"]["anon_login"] is True

    def test_anonymous_rejected_no_vuln(self):
        def handler(client):
            client.settimeout(3)
            client.sendall(b"220 Pure-FTPd\r\n")
            try:
                client.recv(512)
                client.sendall(b"331 User name okay, need password.\r\n")
                client.recv(512)
                client.sendall(b"530 Login authentication failed.\r\n")
            except (socket.timeout, OSError):
                pass

        srv = _TCPServer(handler).start()
        result = probe_ftp("127.0.0.1", port=srv.port, timeout=2)
        assert result["protocol_confirmed"] is True
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "FTP-ANON-LOGIN" not in ids


class TestProbeSMB:

    def test_connection_refused(self):
        port = _free_tcp_port()
        result = probe_smb("127.0.0.1", port=port, timeout=1)
        assert result["protocol_confirmed"] is False

    def test_smbv1_response_marks_high_vuln(self):
        def handler(client):
            client.settimeout(3)
            try:
                client.recv(512)  # consume NEGOTIATE PROTOCOL request
            except (socket.timeout, OSError):
                pass
            # Respuesta SMBv1: NetBIOS header + \xffSMB + dialect index 5 (NT LM 0.12)
            resp = (
                bytes([0x00, 0x00, 0x00, 0x55])  # NetBIOS length=85
                + b"\xffSMB"                       # SMBv1 magic
                + bytes([0x72])                    # cmd NEGOTIATE
                + bytes(72)                        # status + flags + padding
            )
            client.sendall(resp)

        srv = _TCPServer(handler).start()
        result = probe_smb("127.0.0.1", port=srv.port, timeout=2)
        assert result["protocol_confirmed"] is True
        assert result["details"]["protocol"] == "SMBv1"
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "SMB-V1-EXPOSED" in ids

    def test_smbv2_response_marks_info(self):
        def handler(client):
            client.settimeout(3)
            try:
                client.recv(512)
            except (socket.timeout, OSError):
                pass
            # SMBv2 magic \xfeSMB
            resp = bytes([0x00, 0x00, 0x00, 0x40]) + b"\xfeSMB" + bytes(60)
            client.sendall(resp)

        srv = _TCPServer(handler).start()
        result = probe_smb("127.0.0.1", port=srv.port, timeout=2)
        assert result["protocol_confirmed"] is True
        assert result["details"]["protocol"] == "SMBv2/3"
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert "SMB-EXPOSED" in ids
        assert "SMB-V1-EXPOSED" not in ids


# ---------------------------------------------------------------------------
# probe_miio (Xiaomi miIO UDP 54321)
# ---------------------------------------------------------------------------
class TestMiio:

    def _hello_reply(self, did: bytes, stamp: int, token: bytes) -> bytes:
        # Cabecera miIO de 32 bytes: magic 0x2131, len 0x0020, unknown 0,
        # did(4), stamp(4), token(16).
        return (bytes.fromhex("21310020") + b"\x00\x00\x00\x00"
                + did + struct.pack(">I", stamp) + token)

    def test_connection_no_response_timeout(self):
        # Puerto UDP cerrado/silencioso → sin respuesta → no confirmado.
        result = probe_miio("127.0.0.1", port=_free_udp_port(), timeout=1)
        assert result["protocol_confirmed"] is False
        assert result["ok"] is False

    def test_modern_firmware_token_blanked_is_info(self):
        did = bytes.fromhex("0a1b2c3d")
        reply = self._hello_reply(did, stamp=12345, token=b"\xff" * 16)
        srv = _UDPServer(lambda data: reply).start()
        result = probe_miio("127.0.0.1", port=srv.port, timeout=2)
        assert result["protocol_confirmed"] is True
        assert result["ok"] is True
        assert result["details"]["did_hex"] == "0a1b2c3d"
        assert result["details"]["stamp"] == 12345
        ids = [v["id"] for v in result["vulnerabilities"]]
        assert ids == ["MIIO-DEVICE-EXPOSED"]
        assert result["vulnerabilities"][0]["severity"] == "INFO"

    def test_old_firmware_token_in_clear_is_critical(self):
        did = bytes.fromhex("deadbeef")
        token = bytes.fromhex("00112233445566778899aabbccddeeff")
        reply = self._hello_reply(did, stamp=99, token=token)
        srv = _UDPServer(lambda data: reply).start()
        result = probe_miio("127.0.0.1", port=srv.port, timeout=2)
        assert result["protocol_confirmed"] is True
        vuln = result["vulnerabilities"][0]
        assert vuln["id"] == "MIIO-TOKEN-EXPOSED"
        assert vuln["severity"] == "CRITICAL"
        assert token.hex() in result["details"]["token_hex"]

    def test_non_miio_response_not_confirmed(self):
        # Respuesta que no empieza por el magic 0x2131 → ignorada.
        srv = _UDPServer(lambda data: b"\x00\x00garbage").start()
        result = probe_miio("127.0.0.1", port=srv.port, timeout=2)
        assert result["protocol_confirmed"] is False


# ---------------------------------------------------------------------------
# probe_udp_raw (UDP genérico de descubrimiento)
# ---------------------------------------------------------------------------
class TestUdpRaw:

    def test_requires_payload(self):
        result = probe_udp_raw("127.0.0.1", port=9999)
        assert result["ok"] is False
        assert "payload" in result["error"].lower()

    def test_invalid_hex_rejected(self):
        result = probe_udp_raw("127.0.0.1", port=9999, payload_hex="zzzz")
        assert result["ok"] is False
        assert "hex" in result["error"].lower()

    def test_unknown_proto_hint_rejected(self):
        result = probe_udp_raw("127.0.0.1", port=9999, proto_hint="nonexistent")
        assert result["ok"] is False
        assert "librería" in result["error"] or "library" in result["error"].lower()

    def test_no_response_timeout(self):
        result = probe_udp_raw("127.0.0.1", port=_free_udp_port(),
                               payload_hex="deadbeef", timeout=1)
        assert result["ok"] is False
        assert result["protocol_confirmed"] is False
        assert "timeout" in result["error"].lower()

    def test_response_returned_as_evidence(self):
        # Servidor que hace echo: confirma que llega la respuesta cruda.
        srv = _UDPServer(lambda data: b"PONG:" + data).start()
        result = probe_udp_raw("127.0.0.1", port=srv.port,
                               payload_hex="01020304", timeout=2)
        assert result["ok"] is True
        assert result["protocol_confirmed"] is True
        assert result["details"]["response_hex"].startswith(b"PONG:".hex())
        assert "PONG:" in result["details"]["response_ascii"]
        # No inventa vulnerabilidades: es descubrimiento puro.
        assert result["vulnerabilities"] == []

    def test_proto_hint_uses_library_payload(self):
        captured = {}

        def handler(data):
            captured["sent"] = data
            return b"ok"

        srv = _UDPServer(handler).start()
        result = probe_udp_raw("127.0.0.1", port=srv.port,
                               proto_hint="ssdp", timeout=2)
        assert result["ok"] is True
        assert result["details"]["payload_source"] == "library:ssdp"
        assert b"M-SEARCH" in captured["sent"]

    def test_proto_hint_snmp_in_library(self):
        # Regresión: el agente probó proto_hint='snmp' y antes no estaba.
        captured = {}

        def handler(data):
            captured["sent"] = data
            return b"ok"

        srv = _UDPServer(handler).start()
        result = probe_udp_raw("127.0.0.1", port=srv.port,
                               proto_hint="snmp", timeout=2)
        assert result["ok"] is True
        assert result["details"]["payload_source"] == "library:snmp"
        assert b"public" in captured["sent"]  # community SNMP en la payload

    def test_proto_hint_isakmp_in_library(self):
        # Regresión (Echo run 20260613): el agente probó proto_hint='isakmp'
        # (puerto 500) y antes no estaba en la librería.
        captured = {}

        def handler(data):
            captured["sent"] = data
            return b"ok"

        srv = _UDPServer(handler).start()
        result = probe_udp_raw("127.0.0.1", port=srv.port,
                               proto_hint="isakmp", timeout=2)
        assert result["ok"] is True
        assert result["details"]["payload_source"] == "library:isakmp"
        sent = captured["sent"]
        import struct
        # ISAKMP bien formado: exchange type Main Mode (2) y length consistente.
        assert sent[18] == 0x02
        assert struct.unpack(">I", sent[24:28])[0] == len(sent)
