"""Consistencia de severidad run-to-run (iter_12).

Reproduce la inconsistencia observada en dos runs consecutivos del MISMO
dispositivo (LG 65QNED826RE, 192.168.1.36) con escaneo de puertos idéntico:

    run 15:54 → risk LOW  · mDNS-EXPOSED MEDIUM · RTSP-NO-AUTH presente
    run 16:06 → NEGLIGIBLE · mDNS-EXPOSED INFO   · RTSP-NO-AUTH ausente

Tres causas, tres fixes deterministas:
  1. Techo canónico por tipo de hallazgo: la tool declara la severidad de
     MDNS-EXPOSED (INFO); el LLM no puede inflarla a MEDIUM al re-registrar.
  2. probe_rtsp sobre AirTunes/AirPlay (puerto 7000): un DESCRIBE 200 sin
     `m=video` es el handshake de audio esperado, no un stream sin auth.
  3. Superficie UDP `open|filtered`: conjetura de nmap, no confirmación; no
     debe inflar surface_services ni la cobertura.
"""
import core.tools as toolbox
from core.tools import (
    effective_severity,
    is_confirmed_vuln,
    compute_risk_score,
)
from core.telemetry import TelemetryCollector


def setup_function():
    toolbox.build_registry()
    toolbox.bind_session(toolbox.AgentSession(target_ip="192.168.1.36"))


# --- Fix 1: techo canónico por tipo de hallazgo -------------------------------

def test_canonical_ceiling_caps_llm_inflation():
    """MDNS-EXPOSED que el LLM infló a MEDIUM → severidad efectiva INFO."""
    f = {
        "cve_id": "MDNS-EXPOSED", "confirmed": True,
        "severity": "MEDIUM", "impact": "DISCLOSURE",
        "canonical_severity": "INFO",
        "raw_output": '{"model": "OLED65", "firmware": "p20.33.31.23"}',
    }
    assert effective_severity(f) == "INFO"
    # ...y por tanto NO cuenta como vulnerabilidad confirmada (es una nota info).
    assert not is_confirmed_vuln(f)


def test_canonical_ceiling_applies_unconfirmed_too():
    f = {
        "cve_id": "MDNS-EXPOSED", "confirmed": False,
        "severity": "MEDIUM", "canonical_severity": "INFO",
    }
    assert effective_severity(f) == "INFO"


def test_canonical_ceiling_does_not_raise():
    """El techo solo topa hacia abajo: si el LLM pone INFO no lo sube a la canónica."""
    f = {
        "cve_id": "SOME-EXPOSED", "confirmed": True,
        "severity": "INFO", "canonical_severity": "LOW",
    }
    assert effective_severity(f) == "INFO"


def test_no_canonical_field_behaves_as_before():
    """Sin canonical_severity, un CVE real con impacto EXEC conserva CRITICAL."""
    f = {
        "cve_id": "CVE-2024-1234", "confirmed": True,
        "severity": "CRITICAL", "impact": "EXEC",
        "raw_output": "uid=0(root) gid=0(root)",
    }
    assert effective_severity(f) == "CRITICAL"


def test_two_identical_runs_same_risk_label():
    """El corazón del bug: mismo device, la severidad libre del LLM difiere entre
    runs, pero la efectiva (y el risk label) debe ser idéntica."""
    run_a = [{"cve_id": "MDNS-EXPOSED", "confirmed": True, "severity": "MEDIUM",
              "impact": "DISCLOSURE", "canonical_severity": "INFO",
              "raw_output": "model=OLED"}]
    run_b = [{"cve_id": "MDNS-EXPOSED", "confirmed": True, "severity": "INFO",
              "impact": "DISCLOSURE", "canonical_severity": "INFO",
              "raw_output": "model=OLED"}]
    ra, rb = compute_risk_score(run_a), compute_risk_score(run_b)
    assert ra["risk_label"] == rb["risk_label"] == "NEGLIGIBLE"
    assert ra["risk_score"] == rb["risk_score"] == 0


def test_merge_preserves_canonical_ceiling():
    """El auto-registro fija la canónica; un record_finding manual del LLM que la
    infla a MEDIUM la mergea en `severity` pero NO borra el techo → efectiva INFO."""
    # 1) Auto-registro de la tool (INFO + canonical INFO)
    toolbox._record_finding({
        "cve_id": "MDNS-EXPOSED", "title": "mDNS", "severity": "INFO",
        "confirmed": True, "canonical_severity": "INFO", "raw_output": "model=X",
    })
    # 2) El LLM re-registra el mismo hallazgo inflado a MEDIUM (sin canonical)
    toolbox._record_finding({
        "cve_id": "MDNS-EXPOSED", "title": "mDNS expuesto", "severity": "MEDIUM",
        "confirmed": True, "impact": "DISCLOSURE", "raw_output": "model=X device leak",
    })
    findings = toolbox.get_session().findings
    mdns = [f for f in findings if f.get("cve_id") == "MDNS-EXPOSED"]
    assert len(mdns) == 1                              # mergeado, no duplicado
    assert mdns[0].get("canonical_severity") == "INFO"  # techo conservado
    assert effective_severity(mdns[0]) == "INFO"        # infló severity, no efectiva


# --- Fix 3: superficie UDP open|filtered no infla ------------------------------

def test_open_filtered_udp_is_unconfirmed_surface():
    tel = TelemetryCollector()
    tel.record_surface([
        {"port": 3001, "protocol": "tcp", "service_name": "http"},           # confirmado
        {"port": 5353, "protocol": "udp", "service_name": "zeroconf",
         "state_confidence": "open"},                                         # confirmado
        {"port": 161, "protocol": "udp", "service_name": "snmp",
         "state_confidence": "open|filtered"},                               # conjetura
        {"port": 69, "protocol": "udp", "service_name": "tftp",
         "state_confidence": "open|filtered"},                               # conjetura
    ])
    assert "snmp" not in tel.surface_services
    assert "tftp" not in tel.surface_services
    assert "http" in tel.surface_services
    assert "zeroconf" in tel.surface_services
    assert tel.surface_services_unconfirmed == {"snmp", "tftp"}
    assert 161 in tel.surface_ports_unconfirmed
    assert 3001 in tel.surface_ports


def test_unconfirmed_surface_not_in_coverage_denominator():
    """La cobertura no se penaliza por puertos open|filtered no testables."""
    tel = TelemetryCollector()
    tel.record_surface([
        {"port": 3001, "service_name": "http"},
        {"port": 161, "service_name": "snmp", "state_confidence": "open|filtered"},
    ])
    # Superficie real = {3001, http}. Probado http+3001 → cobertura 1.0
    cov = tel.surface_coverage(tested_ports=[3001], tested_services=["http"])
    assert cov == 1.0


# --------------------------------------------------- clase declarada ⇒ evidencia exigida
#
# Campo, 2026-08-13, cinco réplicas contra un D-Link DIR-815. Una de ellas
# registró SIETE CVE de dnsmasq como confirmados con `impact` EXEC/CRASH cuya
# evidencia era la DESCRIPCIÓN del fallo, y cuya propia interpretación decía
# «candidatos … requieren verificación de aplicabilidad». Coincidencia de
# versión ascendida a ejecución remota: 100/100 CRITICAL sobre nada.
#
# La guarda existía desde iter_22 pero solo miraba identificadores de la tabla
# de sondas, así que un CVE cualquiera la esquivaba. Lo que se declara es lo que
# hay que demostrar, venga el identificador de donde venga.

def test_clase_de_impacto_declarada_exige_evidencia_aunque_el_id_sea_desconocido():
    from core.severity import asserts_unproven_action
    f = {"cve_id": "CVE-2017-14492", "impact": "EXEC", "confirmed": True,
         "raw_output": "dnsmasq 2.45 is vulnerable to CVE-2017-14492: "
                       "heap-based buffer overflow in IPv6 router advertisement."}
    assert asserts_unproven_action(f)


def test_crash_declarado_sin_evidencia_tambien_se_degrada():
    from core.severity import asserts_unproven_action
    f = {"cve_id": "CVE-2015-8899", "impact": "CRASH", "confirmed": True,
         "raw_output": "dnsmasq 2.45 is vulnerable to CVE-2015-8899: DoS via empty DNS address."}
    assert asserts_unproven_action(f)


def test_respuesta_citada_con_marcado_cuenta_como_interaccion_real():
    """El agente recorta la respuesta a su gusto; el recorte no decide.

    Dos réplicas confirmaron el mismo CVE-2015-0152. Una pegó el volcado con su
    prólogo `<?xml …>`; la otra citó solo `<name>admin</name><password></password>`
    dentro de una frase. Sin esto, la segunda se contaba como afirmación sin
    prueba y el mismo hallazgo puntuaba distinto según cómo se hubiera pegado.
    """
    from core.severity import asserts_unproven_action
    f = {"cve_id": "CVE-2015-0152", "impact": "EXFIL", "confirmed": True,
         "raw_output": "GET /getcfg.php?a=%0a_POST_SERVICES%3DDEVICE.ACCOUNT\n"
                       "Respuesta XML contiene:\n<name>admin</name>\n<password></password>"}
    assert not asserts_unproven_action(f)


def test_peticion_citada_no_basta_por_si_sola():
    """Un `GET` pegado prueba lo que se pidió, nunca lo que contestó el aparato."""
    from core.severity import asserts_unproven_action
    f = {"cve_id": "CVE-2015-0150", "impact": "ACCESS", "confirmed": True,
         "raw_output": "GET /getcfg.php?a=%0a_POST_SERVICES%3DDEVICE.ACCOUNT\n\n"
                       "Respuesta: acceso sin autenticación, revelando cuentas administrativas."}
    assert asserts_unproven_action(f)


def test_las_sondas_deterministas_quedan_exentas():
    """Una sonda no narra: su salida ES la observación. Sin esta exención, las
    confirmaciones del laboratorio (MQTT anónimo, telnet por defecto) caerían."""
    from core.severity import asserts_unproven_action
    f = {"cve_id": "MQTT-ANON-ACCESS", "impact": "ACCESS", "confirmed": True,
         "_from_probe": True, "raw_output": "connected, subscribed to #"}
    assert not asserts_unproven_action(f)


def test_la_procedencia_se_persiste_en_el_hallazgo():
    """`_from_probe` viaja al informe: sin él, un criterio nuevo no puede
    revaluar el corpus ya escrito sin degradar también a las sondas."""
    import core.tools as toolbox
    toolbox.build_registry()
    toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))
    toolbox.dispatch("record_finding", {
        "cve_id": "TELNET-DEFAULT-CRED", "severity": "CRITICAL", "confirmed": True,
        "impact": "ACCESS", "title": "t", "_from_probe": True,
        "evidence": "login ok",
    })
    hallazgos = toolbox._SESSION.findings
    assert hallazgos and hallazgos[-1]["_from_probe"] is True


# ------------------------------------------------- confirmado sin evidencia alguna
#
# Campo, 2026-08-14, cinco réplicas contra el firmware Netgear. En tres de ellas
# el modelo registró el MISMO hecho dos veces: `HTTP-DEFAULT-CRED` con el volcado
# de la sesión, y `WEAK-CREDENTIALS` con los tres campos de evidencia en blanco.
# El cascarón contaba como confirmado. Son 20 de los 435 confirmados del corpus.

def test_confirmado_sin_ninguna_evidencia_se_degrada_a_candidato():
    import core.tools as toolbox
    toolbox.build_registry()
    toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))
    toolbox.dispatch("record_finding", {
        "cve_id": "WEAK-CREDENTIALS", "severity": "CRITICAL", "confirmed": True,
        "impact": "ACCESS", "title": "t",
    })
    assert toolbox._SESSION.findings[-1]["confirmed"] is False


def test_el_cascaron_cae_aunque_declare_una_clase_inofensiva():
    """La guarda de acción-no-demostrada no llega a DISCLOSURE/HYGIENE; esta sí."""
    import core.tools as toolbox
    toolbox.build_registry()
    toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))
    toolbox.dispatch("record_finding", {
        "cve_id": "HTTP-CONFIG-EXPOSED", "severity": "MEDIUM", "confirmed": True,
        "impact": "DISCLOSURE", "title": "t", "raw_output": "   ",
    })
    assert toolbox._SESSION.findings[-1]["confirmed"] is False


def test_una_evidencia_minima_pero_real_sigue_contando():
    import core.tools as toolbox
    toolbox.build_registry()
    toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))
    toolbox.dispatch("record_finding", {
        "cve_id": "MDNS-EXPOSED", "severity": "INFO", "confirmed": True,
        "impact": "EXPOSURE", "title": "t", "raw_output": "_googlecast._tcp.local",
    })
    assert toolbox._SESSION.findings[-1]["confirmed"] is True


# ------------------------------------------------- el modelo no sale de una cabecera

def test_una_codificacion_no_es_un_modelo():
    """Campo: un Netgear se publicó 5/5 como modelo «ISO-8859», leído de
    `charset=ISO-8859-1`. Mismo accidente que «CURVE25519», otro vocabulario."""
    from modules.fingerprint import _extract_model_from_text as extraer
    assert extraer("Content-Type: text/html; charset=ISO-8859-1") is None
    assert extraer("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=windows-1252") is None


def test_el_prefijo_comercial_es_parte_del_modelo():
    """`TL-WR841N` se publicaba truncado a `WR841N`, y con eso se consultaba la
    NVD y se indexaba la KB: dos letras tras el guion, no una."""
    from modules.fingerprint import _extract_model_from_text as extraer
    assert extraer("TP-Link TL-WR841N v9") == "TL-WR841N"
    assert extraer("D-Link DIR-815 WAP http config 1.04") == "DIR-815"
    assert extraer("NETGEAR WNAP320 Wireless Access Point") == "WNAP320"


def test_las_credenciales_por_defecto_de_http_son_un_solo_hallazgo():
    """Campo: cuatro réplicas de cinco confirmaron admin:password y la métrica
    las contaba como dos hallazgos (3/5 `HTTP-DEFAULT-CRED` + 1/5
    `WEAK-CREDENTIALS`) porque el modelo alternaba el nombre."""
    from core.finding_ids import canonicalize_finding_id as canon
    for variante in ("HTTP-DEFAULT-CRED", "WEB-DEFAULT-CRED", "HTTP-WEAK-CRED",
                     "DEFAULT-CREDENTIALS", "WEAK-CREDENTIALS"):
        assert canon(variante) == "WEAK-CREDENTIALS", variante


def test_pero_telnet_y_ssh_conservan_su_servicio():
    """Mismo concepto, servicio distinto: remediación distinta, hallazgo distinto."""
    from core.finding_ids import canonicalize_finding_id as canon
    assert canon("TELNET-DEFAULT-CRED") == "TELNET-DEFAULT-CRED"
    assert canon("SSH-DEFAULT-CREDS") == "SSH-DEFAULT-CREDS"
    assert canon("HTTP-AUTH-REQUIRED") == "HTTP-AUTH-REQUIRED"
