"""Unit tests for packet_probes dispatcher and builder helpers."""
import os
import socket
import sys
import struct


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import packet_probes


class TestDispatcher:

    def test_unknown_probe_returns_error(self):
        result = packet_probes.run_probe("does_not_exist", "127.0.0.1")
        assert result["success"] is False
        assert result["error_type"] == "UNKNOWN"

    def test_registry_keys(self):
        expected = {
            "dnsmasq_dns", "dnsmasq_dhcp",
            "snmp_community", "ftp_anon", "telnet_creds",
        }
        assert expected.issubset(set(packet_probes.PROBE_REGISTRY.keys()))

    def test_exception_in_probe_is_caught(self, monkeypatch):
        def boom(*args, **kwargs):
            raise RuntimeError("kaboom")
        monkeypatch.setitem(packet_probes.PROBE_REGISTRY, "snmp_community", boom)
        out = packet_probes.run_probe("snmp_community", "127.0.0.1")
        assert out["success"] is False
        assert "kaboom" in out["output"]


class TestDHCPBuilder:
    """Sanity-check DHCP packet layout — correct BOOTP field offsets."""

    def test_bootp_field_offsets(self):
        pkt = packet_probes._build_dhcp_discover_with_oversized_client_id(100)
        assert pkt[0] == 1              # op = BOOTREQUEST
        assert pkt[1] == 1              # htype = Ethernet
        assert pkt[2] == 6              # hlen = 6
        # xid at offset 4-7
        xid = struct.unpack(">I", pkt[4:8])[0]
        assert xid == 0xDEADBEEF
        # flags at offset 10-11 (broadcast)
        flags = struct.unpack(">H", pkt[10:12])[0]
        assert flags == 0x8000
        # ciaddr at offset 12-15 (all zeros in DISCOVER)
        assert pkt[12:16] == b"\x00" * 4
        # DHCP magic cookie at offset 236
        assert pkt[236:240] == b"\x63\x82\x53\x63"

    def test_oversized_client_id_in_options(self):
        pkt = packet_probes._build_dhcp_discover_with_oversized_client_id(100)
        # Option 61 (Client Identifier) should appear somewhere after magic cookie
        options = pkt[240:]
        assert bytes([61]) in options     # option type 61 present

    def test_option_53_discover_type(self):
        pkt = packet_probes._build_dhcp_discover_with_oversized_client_id(10)
        options = pkt[240:]
        # Option 53 length 1 value 1 (DISCOVER)
        assert bytes([53, 1, 1]) in options


class TestDNSBuilder:
    """Sanity-check the DNS question builder (no network I/O)."""

    def test_builds_valid_header(self):
        pkt = packet_probes._build_dns_query("example.com", txid=0x1234)
        # First 2 bytes are the transaction ID, big-endian
        assert struct.unpack(">H", pkt[:2])[0] == 0x1234
        # Flags RD=1 standard query
        assert struct.unpack(">H", pkt[2:4])[0] == 0x0100
        # QDCOUNT=1
        assert struct.unpack(">H", pkt[4:6])[0] == 1

    def test_query_trailer_is_qtype_a_qclass_in(self):
        pkt = packet_probes._build_dns_query("a.b")
        qtype, qclass = struct.unpack(">HH", pkt[-4:])
        assert qtype == 1      # A
        assert qclass == 1     # IN


class TestSNMPBuilder:
    """SNMPv1 BER packet builder must produce well-formed TLV sequences."""

    def test_packet_starts_with_sequence_tag(self):
        pkt = packet_probes._build_snmpv1_get("public", packet_probes._OID_SYSDESCR)
        assert pkt[0] == 0x30  # SEQUENCE tag

    def test_community_string_embedded(self):
        pkt = packet_probes._build_snmpv1_get("topsecret", packet_probes._OID_SYSDESCR)
        assert b"topsecret" in pkt

    def test_different_communities_produce_different_packets(self):
        a = packet_probes._build_snmpv1_get("public", packet_probes._OID_SYSDESCR)
        b = packet_probes._build_snmpv1_get("private", packet_probes._OID_SYSDESCR)
        assert a != b


class TestFTPProbe:
    """FTP anonymous probe — socket is always closed, even on errors."""

    def test_unreachable_port_returns_network_error(self, monkeypatch):
        """When port is not reachable, probe returns NETWORK without raising."""
        monkeypatch.setattr(packet_probes, "_tcp_reachable", lambda *a, **k: False)
        result = packet_probes.probe_ftp_anonymous("127.0.0.1", ftp_port=9999)
        assert result["success"] is False
        assert result["error_type"] == "NETWORK"

    def test_socket_closed_on_timeout(self, monkeypatch):
        """Socket is closed even when recv raises socket.timeout."""
        closed = []

        class FakeSocket:
            def settimeout(self, t): pass
            def connect(self, addr): pass
            def recv(self, n): raise socket.timeout("timed out")
            def sendall(self, data): pass
            def close(self): closed.append(True)

        monkeypatch.setattr(packet_probes, "_tcp_reachable", lambda *a, **k: True)
        monkeypatch.setattr(socket, "socket", lambda *a, **k: FakeSocket())

        result = packet_probes.probe_ftp_anonymous("127.0.0.1", ftp_port=21)
        assert result["success"] is False
        assert closed, "Socket was not closed after timeout"

    def test_socket_closed_on_os_error(self, monkeypatch):
        """Socket is closed even when connect raises OSError."""
        closed = []

        class FakeSocket:
            def settimeout(self, t): pass
            def connect(self, addr): raise OSError("refused")
            def close(self): closed.append(True)

        monkeypatch.setattr(packet_probes, "_tcp_reachable", lambda *a, **k: True)
        monkeypatch.setattr(socket, "socket", lambda *a, **k: FakeSocket())

        result = packet_probes.probe_ftp_anonymous("127.0.0.1", ftp_port=21)
        assert result["success"] is False
        assert closed, "Socket was not closed after OSError"


class TestSNMPCommunityLogic:
    """SNMP community probe: fallback guard prevents infinite recursion."""

    def test_fallback_community_returns_immediately(self, monkeypatch):
        """If called with a fallback community and no response, returns FAIL without retrying."""
        calls = []

        def fake_udp(ip, port, pkt, timeout=3.0):
            calls.append(True)
            return b""  # no response

        monkeypatch.setattr(packet_probes, "_udp_send_recv", fake_udp)
        result = packet_probes.probe_snmp_community("127.0.0.1", community="private")
        assert result["success"] is False
        assert result["error_type"] == "FAIL"
        # Only one UDP call (no auto-retry) because 'private' is in fallback_communities
        assert len(calls) == 1

    def test_public_community_retries_with_private(self, monkeypatch):
        """When called with 'public' and it fails, a second attempt with 'private' is made."""
        calls = []

        def fake_udp(ip, port, pkt, timeout=3.0):
            calls.append(True)
            return b""  # always fail

        monkeypatch.setattr(packet_probes, "_udp_send_recv", fake_udp)
        result = packet_probes.probe_snmp_community("127.0.0.1", community="public")
        assert result["success"] is False
        # Two UDP calls: public attempt + private auto-retry
        assert len(calls) == 2
