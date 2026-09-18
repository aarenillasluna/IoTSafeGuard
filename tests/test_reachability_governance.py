"""Gobernanza: alcanzabilidad ≠ explotación.

Reproduce los 3 falsos positivos de un run real (Amazon 192.168.1.34) donde el
agente marcó `confirmed=true` HIGH/CRITICAL con impacto ACCESS/EXFIL sobre
evidencia que era SOLO puerto abierto. El backstop determinista en
`effective_severity` debe degradarlos a LOW. Y NO debe degradar hallazgos con
interacción real.
"""
from core.tools import (
    effective_severity,
    _is_reachability_only,
    _has_real_interaction,
    compute_risk_score,
)


# --- Falsos positivos que DEBEN degradarse a LOW -------------------------------

def test_socks5_nc_connect_only_capped_low():
    """nc -zv conecta → 'expuesto sin auth' ACCESS CRITICAL → tope LOW."""
    f = {
        "confirmed": True, "severity": "HIGH", "impact": "ACCESS",
        "raw_output": "Connection to 192.168.1.34 1080 port [tcp/socks] succeeded!",
    }
    assert _is_reachability_only(f)
    assert effective_severity(f) == "LOW"


def test_socks5_handshake_rejected_capped_low():
    """SOCKS5 responde 05 ff (rechaza método) = EXIGE auth, no 'sin auth'."""
    f = {
        "confirmed": True, "severity": "CRITICAL", "impact": "ACCESS",
        "raw_output": "SOCKS5 handshake response: 0x05 0xFF (no auth methods accepted)",
    }
    assert effective_severity(f) == "LOW"


def test_tftp_protocol_not_confirmed_capped_low():
    """TFTP puerto abierto pero protocol_confirmed: false → EXFIL CRITICAL → LOW."""
    f = {
        "confirmed": True, "severity": "CRITICAL", "impact": "EXFIL",
        "raw_output": "TFTP port 69 UDP open - protocol_confirmed: false (no response to RRQ)",
    }
    assert effective_severity(f) == "LOW"


def test_nagios_nsca_connect_only_capped_low():
    f = {
        "confirmed": True, "severity": "HIGH", "impact": "ACCESS",
        "raw_output": "Connection to 192.168.1.34 4070 port [tcp/*] succeeded!",
    }
    assert effective_severity(f) == "LOW"


def test_open_filtered_timeout_capped_low():
    f = {
        "confirmed": True, "severity": "HIGH", "impact": "CRASH",
        "raw_output": "137/udp open|filtered netbios-ns ... Command timed out",
    }
    assert effective_severity(f) == "LOW"


# --- Parafraseo: el agente reescribe la evidencia y esquivaba el cap -----------
# Caso real (Echo 192.168.1.34, run 20260613): el agente escribió la evidencia
# del puerto SOCKS5 con sus palabras ("(open)", "Connection succeeded", "nc -zv",
# "HTTP/0.9") en vez de la salida literal de la tool ("succeeded!", "open|filtered").
# Esos tokens no casaban con el regex de alcanzabilidad, así que un puerto abierto
# quedaba como HIGH/ACCESS. El regex ahora cubre esas paráfrasis → se detecta como
# alcanzabilidad y se topa a LOW. (No tocamos los confirmados con evidencia de
# protocolo real —Modbus/MQTT del lab—, que no casan estos patrones y conservan
# su severidad.)

def test_paraphrased_socks5_access_capped_low():
    f = {
        "confirmed": True, "severity": "HIGH", "impact": "ACCESS",
        "raw_output": (
            "Port 1080/tcp: SOCKS5 proxy (open)\n"
            "Connection test: nc -zv 192.168.1.34 1080 -> Connection succeeded\n"
            "HTTP test: curl http://192.168.1.34:1080/ -> Received HTTP/0.9"
        ),
    }
    assert _is_reachability_only(f)        # detectado pese al parafraseo
    assert not _has_real_interaction(f)    # no hay prueba de proxy real
    assert effective_severity(f) == "LOW"


def test_paraphrased_tcpwrapped_open_capped_low():
    f = {
        "confirmed": True, "severity": "MEDIUM", "impact": "ACCESS",
        "raw_output": "Puerto 8888 abierto (tcpwrapped), acepta conexión pero no responde.",
    }
    assert effective_severity(f) == "LOW"


# --- Hallazgos REALES que NO deben degradarse ----------------------------------

def test_real_rce_shell_output_not_capped():
    """EXEC con output de comando real (uid=) → respeta CRITICAL."""
    f = {
        "confirmed": True, "severity": "CRITICAL", "impact": "EXEC",
        "raw_output": "$ id\nuid=0(root) gid=0(root) groups=0(root)",
    }
    assert not _is_reachability_only(f)
    assert effective_severity(f) == "CRITICAL"


def test_real_access_http_body_not_capped():
    """ACCESS con 200 + cuerpo tras 401 → respeta HIGH."""
    f = {
        "confirmed": True, "severity": "HIGH", "impact": "ACCESS",
        "raw_output": "HTTP/1.1 200 OK\nSet-Cookie: session=abc\n<html>admin panel</html>",
    }
    assert effective_severity(f) == "HIGH"


def test_real_exfil_credentials_not_capped():
    f = {
        "confirmed": True, "severity": "CRITICAL", "impact": "EXFIL",
        "raw_output": "GET /etc/passwd → root:x:0:0:root:/root:/bin/bash\nadmin:password=admin123",
    }
    assert effective_severity(f) == "CRITICAL"


# --- Invariantes -----------------------------------------------------------------

def test_unconfirmed_not_touched():
    """No confirmado → se respeta severidad declarada (la regla no aplica)."""
    f = {
        "confirmed": False, "severity": "HIGH", "impact": "ACCESS",
        "raw_output": "port 1080 succeeded!",
    }
    assert effective_severity(f) == "HIGH"


def test_empty_evidence_not_reachability():
    assert not _is_reachability_only({"raw_output": "", "evidence": ""})


def test_risk_score_not_inflated_by_open_ports():
    """Los 3 falsos positivos juntos NO inflan el score por encima de LOW-band."""
    findings = [
        {"confirmed": True, "severity": "HIGH", "impact": "ACCESS",
         "raw_output": "Connection to x 1080 succeeded!"},
        {"confirmed": True, "severity": "HIGH", "impact": "ACCESS",
         "raw_output": "Connection to x 4070 succeeded!"},
        {"confirmed": True, "severity": "CRITICAL", "impact": "EXFIL",
         "raw_output": "port 69 open - protocol_confirmed: false"},
    ]
    risk = compute_risk_score(findings)
    # 3× LOW efectivo → score muy por debajo del HIGH 60 inflado original.
    assert risk["risk_score"] < 30
    assert risk["risk_label"] in ("NEGLIGIBLE", "LOW", "MEDIUM")
