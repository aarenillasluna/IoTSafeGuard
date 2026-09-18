"""
Tests para los critical improvements (parte no-probe):
- HTTPS support en _http_get
- Smart retry 401 → web_login hint
- Risk score global + heurística de vendor
- recommend_probes para SSH/FTP/SMB
- Estructura del docker-compose lab

NOTA: los tests de probe_ssh / probe_ftp / probe_smb se consolidaron en
`test_iot_probes.py` (iter_08) junto al resto de probes de protocolo.
"""
from __future__ import annotations

import os
import socket
import sys
import yaml


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core import tools as toolbox
from core.tools import compute_risk_score, _detect_auth_required


# ----------------------------------------------------------------- helpers
def _free_tcp_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ----------------------------------------------------------------- HTTPS in _http_get
class TestHTTPSSupport:
    """No podemos levantar un servidor HTTPS auto-firmado simple sin más overhead.
    Verificamos que _http_get acepta scheme=https sin romper, y que retorna None
    limpiamente cuando no hay servidor."""

    def test_https_no_server_returns_none(self):
        from modules.iot_probes import _http_get
        # Puerto sin servidor
        port = _free_tcp_port()
        result = _http_get(f"https://127.0.0.1:{port}/", timeout=1)
        assert result is None  # sin crash

    def test_http_no_server_returns_none(self):
        from modules.iot_probes import _http_get
        port = _free_tcp_port()
        result = _http_get(f"http://127.0.0.1:{port}/", timeout=1)
        assert result is None


# ----------------------------------------------------------------- 401/403 hint
class TestAuthHint:

    def test_401_in_output_returns_hint(self):
        out = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=admin\r\n\r\nUnauthorized"
        hint = _detect_auth_required(out)
        assert hint is not None
        assert "401" in hint
        assert "web_login" in hint
        assert "Cookie" in hint

    def test_403_in_output_returns_hint(self):
        out = "HTTP/1.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
        hint = _detect_auth_required(out)
        assert hint is not None
        assert "403" in hint

    def test_200_no_hint(self):
        out = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
        assert _detect_auth_required(out) is None

    def test_empty_output_no_hint(self):
        assert _detect_auth_required("") is None
        assert _detect_auth_required(None) is None  # type: ignore


# ----------------------------------------------------------------- Risk score
class TestRiskScore:

    def test_no_findings_zero_score(self):
        r = compute_risk_score([])
        assert r["risk_score"] == 0
        assert r["risk_label"] == "NEGLIGIBLE"

    def test_single_critical_confirmed_low_score(self):
        # CRITICAL confirmado CON impacto demostrado (EXEC) → no se topa.
        findings = [{"severity": "CRITICAL", "confirmed": True, "impact": "EXEC"}]
        r = compute_risk_score(findings)
        # weight=10 / 0.4 = 25 → LOW (un único CRITICAL no debe disparar HIGH/CRITICAL)
        assert r["risk_score"] == 25
        assert r["risk_label"] == "LOW"

    def test_multiple_critical_max_score(self):
        # 4 CRITICAL confirmed (con impacto) = 40/0.4 = 100 → CRITICAL exacto
        findings = [{"severity": "CRITICAL", "confirmed": True, "impact": "EXEC"}] * 4
        r = compute_risk_score(findings)
        assert r["risk_score"] == 100
        assert r["risk_label"] == "CRITICAL"

    def test_unconfirmed_does_not_drive_score(self):
        confirmed = compute_risk_score([{"severity": "HIGH", "confirmed": True}])
        unconfirmed = compute_risk_score([{"severity": "HIGH", "confirmed": False}])
        # confirmed→18 (LOW), unconfirmed→0 (NEGLIGIBLE)
        assert confirmed["risk_score"] > 0
        assert unconfirmed["risk_score"] == 0
        assert unconfirmed["risk_label"] == "NEGLIGIBLE"

    def test_confirmed_high_without_impact_capped_to_low(self):
        # Política de impacto: confirmado HIGH/CRITICAL SIN clase de impacto
        # demostrado → se topa a LOW (no infla el score). Consistencia entre runs.
        no_impact = compute_risk_score([{"severity": "HIGH", "confirmed": True}])
        exposure = compute_risk_score(
            [{"severity": "HIGH", "confirmed": True, "impact": "EXPOSURE"}])
        hygiene = compute_risk_score(
            [{"severity": "CRITICAL", "confirmed": True, "impact": "HYGIENE"}])
        for r in (no_impact, exposure, hygiene):
            assert r["confirmed_severity_counts"]["LOW"] == 1
            assert r["confirmed_severity_counts"]["HIGH"] == 0
            assert r["confirmed_severity_counts"]["CRITICAL"] == 0
            assert r["risk_label"] == "NEGLIGIBLE"  # 1/0.4 = 2.5 → 3

    def test_confirmed_with_demonstrated_impact_not_capped(self):
        # Impacto demostrado (EXEC/ACCESS/EXFIL) → respeta severidad declarada.
        for imp in ("EXEC", "ACCESS", "EXFIL"):
            r = compute_risk_score(
                [{"severity": "CRITICAL", "confirmed": True, "impact": imp}])
            assert r["confirmed_severity_counts"]["CRITICAL"] == 1
        # DISCLOSURE topa a MEDIUM (info no sensible sin auth).
        r = compute_risk_score(
            [{"severity": "HIGH", "confirmed": True, "impact": "DISCLOSURE"}])
        assert r["confirmed_severity_counts"]["MEDIUM"] == 1
        assert r["confirmed_severity_counts"]["HIGH"] == 0

    def test_many_unconfirmed_critical_stays_negligible(self):
        # Regresión empírica: 28 CVEs descartados como "no aplica al modelo" no
        # deben llevar el target a CRITICAL si no hay nada confirmado.
        findings = [{"severity": "CRITICAL", "confirmed": False}] * 28
        r = compute_risk_score(findings)
        assert r["risk_score"] == 0
        assert r["risk_label"] == "NEGLIGIBLE"

    def test_severity_counts(self):
        findings = [
            {"severity": "CRITICAL", "confirmed": True, "impact": "EXEC"},
            {"severity": "HIGH", "confirmed": False},
            {"severity": "HIGH", "confirmed": True, "impact": "ACCESS"},
            {"severity": "INFO", "confirmed": False},
        ]
        r = compute_risk_score(findings)
        assert r["severity_counts"]["CRITICAL"] == 1
        assert r["severity_counts"]["HIGH"] == 2
        assert r["severity_counts"]["INFO"] == 1
        assert r["confirmed_count"] == 2
        # Nuevo: confirmed_severity_counts debe distinguir lo confirmado del ruido
        assert r["confirmed_severity_counts"]["CRITICAL"] == 1
        assert r["confirmed_severity_counts"]["HIGH"] == 1
        assert r["confirmed_severity_counts"]["INFO"] == 0

    def test_vendor_heuristic_skips_unconfirmed_findings(self):
        """Regresión empírica: un run contra router Movistar terminó con vendor=TP-Link
        porque la heurística leía la descripción de un CVE de TP-Link que el agente
        ya había descartado como "no aplica al modelo".
        """
        from core.tools import _heuristic_vendor_from_findings
        findings = [
            {  # CVE descartado por el agente
                "evidence": "CVE-2018-12575 afecta a TP-Link TL-WR841N v13, no aplica.",
                "confirmed": False,
                "severity": "CRITICAL",
            },
            {  # Hallazgo real del propio dispositivo
                "evidence": "HTTPS cert CN='PKI Root TG Telefonica', title='movistar'",
                "interpretation": "Router Telefonica/Movistar HGU",
                "confirmed": True,
                "severity": "INFO",
            },
        ]
        vendor = _heuristic_vendor_from_findings(findings)
        # Debe encontrar Telefonica/Movistar, NUNCA TP-Link
        assert vendor in ("Telefonica", "Movistar")

    def test_vendor_heuristic_returns_none_when_only_unconfirmed(self):
        from core.tools import _heuristic_vendor_from_findings
        findings = [
            {"evidence": "CVE para NETGEAR Nighthawk RAX30, no aplica",
             "confirmed": False},
            {"evidence": "CVE para Cisco IOS XE, no aplica", "confirmed": False},
        ]
        assert _heuristic_vendor_from_findings(findings) is None

    def test_vendor_heuristic_word_boundary_avoids_lg_in_algoritmo(self):
        """Regresión empírica: la reflexión hallucinó 'dispositivo LG IoT'
        para un router Movistar porque la heurística hacía substring naïf:
        `'lg' in 'algoritmo'.lower()` es True. Word boundary lo previene.
        """
        from core.tools import _heuristic_vendor_from_findings
        findings = [
            {
                "evidence": "SSH dropbear 2019.78 con Algoritmo ssh-rsa antiguo",
                "interpretation": "El algoritmo de host key es viejo",
                "confirmed": True,
                "severity": "MEDIUM",
            },
        ]
        # LG no debe matchear dentro de "algoritmo"
        assert _heuristic_vendor_from_findings(findings) is None

    def test_vendor_heuristic_matches_real_lg_token(self):
        """Y al revés: LG con word boundaries reales SÍ debe matchear."""
        from core.tools import _heuristic_vendor_from_findings
        findings = [
            {"evidence": "Dispositivo LG WebOS detectado",
             "confirmed": True, "severity": "INFO"},
        ]
        assert _heuristic_vendor_from_findings(findings) == "LG"

    def test_vendor_in_text_handles_punctuation(self):
        """TP-Link con guión interno, Cisco después de coma, etc."""
        from core.tools import _vendor_in_text
        assert _vendor_in_text("TP-Link", "Affects TP-Link routers")
        assert _vendor_in_text("Cisco", "Vulnerable: Cisco, Juniper")
        assert _vendor_in_text("D-Link", "(D-Link DIR-815)")
        # No matchea como substring arbitraria
        assert not _vendor_in_text("LG", "algoritmo de cifrado")
        assert not _vendor_in_text("LG", "logging output")

    def test_done_tool_includes_risk(self):
        toolbox.build_registry()
        toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))
        toolbox.dispatch("record_finding", {
            "cve_id": "X", "severity": "HIGH", "confirmed": True,
            # La evidencia muestra la sesión obtenida. Decir `impact: ACCESS`
            # con evidencia "e" ya no puntúa: un acceso afirmado y no mostrado
            # se registra como candidato, así que el fixture tiene que probar
            # lo que declara igual que se le exige al agente en campo.
            "impact": "ACCESS", "title": "t",
            "evidence": "$ id\nuid=0(root) gid=0(root)",
        })
        r = toolbox.dispatch("done", {"summary": "test"})
        assert "risk_score" in r
        assert r["risk_score"] > 0
        assert r["risk_label"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


# ----------------------------------------------------------------- recommend_probes con SSH/FTP/SMB
class TestRecommendProbesNewProtocols:

    def setup_method(self):
        toolbox.build_registry()
        toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))

    def test_ssh_ftp_smb_recommended(self):
        ports = [
            {"port": 22, "proto": "tcp"},
            {"port": 21, "proto": "tcp"},
            {"port": 445, "proto": "tcp"},
            {"port": 139, "proto": "tcp"},
        ]
        r = toolbox.dispatch("recommend_probes", {"ports": ports})
        probes = {rec["probe"] for rec in r["recommendations"]}
        assert "probe_ssh" in probes
        assert "probe_ftp" in probes
        assert "probe_smb" in probes


# ----------------------------------------------------------------- Docker compose lab estructura
class TestIoTLabComposeFile:

    def test_compose_file_parses(self):
        path = os.path.join(ROOT, "docker-compose.iot-lab.yml")
        assert os.path.isfile(path), "docker-compose.iot-lab.yml no existe"
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        services = data.get("services", {})
        # Servicios mínimos esperados
        for svc in ("mqtt", "modbus", "rtsp", "ftp", "rompager", "telnet",
                    "vulnhttp", "tftp"):
            assert svc in services, f"Servicio {svc} falta en compose"

    def test_lab_dir_structure(self):
        lab_dir = os.path.join(ROOT, "lab")
        assert os.path.isdir(lab_dir)
        for required in ("mosquitto.conf", "rompager-default.conf",
                         "vulnhttp-default.conf"):
            assert os.path.isfile(os.path.join(lab_dir, required)), \
                f"Falta lab/{required}"
        for d in ("vulnhttp-content", "tftp-content"):
            assert os.path.isdir(os.path.join(lab_dir, d))
