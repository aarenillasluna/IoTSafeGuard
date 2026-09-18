"""iter_21 — el mismo hecho tiene que llamarse igual en cada ejecución.

Al revisar 26 informes de campo apareció un patrón limpio: **donde el
identificador lo emite una sonda es estable —`SOCKS5-NOAUTH` 10 veces de 10,
`SSH-DROPBEAR-OLD` 9— y donde lo inventa el modelo no se repite nunca**. El
televisor LG acumuló cinco hallazgos confirmados en ocho ejecuciones con cinco
identificadores distintos, tres de ellos para el MISMO descriptor UPnP.

La consecuencia no es estética. El índice de estabilidad de §5.10.2 es
|∩|/|∪| sobre los conjuntos de confirmados: si el mismo hecho lleva un nombre
distinto cada vez, la intersección es vacía **por construcción** y la métrica
publica 0.000 para un agente que encontró lo mismo. Estaba midiendo la libertad
léxica del modelo, no su consistencia.

Se cubren aquí las tres piezas: la canonización, la severidad fija por tipo, y
las dos causas —distintas— de un índice bajo.
"""
import json

import pytest

from core.finding_ids import canonicalize_finding_id, looks_like_free_text
from core.severity import (
    _CANONICAL_SEVERITY,
    _CONFIRMED_NEGATIVE_IDS,
    _PROBE_IMPACT_CLASS,
    effective_severity,
)


# ── Canonización ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("variantes", [
    # Los tres nombres del mismo descriptor UPnP, de tres ejecuciones reales.
    ["UPNP-DESCRIPTOR-EXPOSURE", "UPNP-DEVICE-DESCRIPTOR-EXPOSURE"],
    # El mismo dato de Chromecast, dos ejecuciones.
    ["CHROMECAST-EUREKA-INFO-DISCLOSURE", "CHROMECAST-EUREKA-INFO-EXPOSURE"],
    # El mismo acceso sin autenticar, dos ejecuciones del router.
    ["WEB-UNAUTH-ACCESS", "WEB-UNAUTHENTICATED-ACCESS"],
])
def test_las_variantes_del_mismo_hecho_convergen(variantes):
    canonicos = {canonicalize_finding_id(v) for v in variantes}
    assert len(canonicos) == 1, f"{variantes} deberían dar un solo id: {canonicos}"


def test_hallazgos_distintos_NO_se_fusionan():
    """El riesgo de normalizar es pasarse. `CHROMECAST-EXPOSED` (puerto
    alcanzable, clase EXPOSURE) y `CHROMECAST-INFO-DISCLOSURE` (datos legibles,
    clase DISCLOSURE) son cosas distintas con topes distintos, y una versión de
    este módulo las colapsó por declarar `INFO` como relleno."""
    parejas = [
        ("CHROMECAST-EXPOSED", "CHROMECAST-INFO-DISCLOSURE"),
        ("SOCKS5-NOAUTH", "SOCKS5-OPEN-RELAY"),
        ("SSH-EXPOSED", "SSH-DEFAULT-CREDS"),
        ("TELNET-EXPOSED", "TELNET-DEFAULT-CRED"),
    ]
    for a, b in parejas:
        assert canonicalize_finding_id(a) != canonicalize_finding_id(b), (a, b)


def test_los_cve_reales_no_se_tocan():
    """Reescribir un CVE rompería el emparejamiento con la NVD."""
    for cve in ("CVE-2023-6317", "cve-2021-44228", "CVE-2014-0160"):
        assert canonicalize_finding_id(cve) == cve.upper()


def test_es_idempotente():
    """Canonizar dos veces no puede dar algo distinto: el identificador pasa por
    aquí al registrarse y otra vez al leerlo el arnés de varianza."""
    for raw in ("UPnP-DEVICE-DISCLOSURE", "socks5_noauth", "WEB-UNAUTHENTICATED-ACCESS",
                "CVE-2023-6317", "HTTP-4070-EXPOSED"):
        una = canonicalize_finding_id(raw)
        assert canonicalize_finding_id(una) == una, raw


def test_una_frase_se_detecta_como_texto_libre():
    """Caso real: `Puerto 4070 - Servicio HTTP sin identificación` llegó a un
    informe como identificador. Se acepta —perder el hallazgo sería peor— pero
    hay que poder avisar al modelo."""
    assert looks_like_free_text("Puerto 4070 - Servicio HTTP sin identificación")
    assert not looks_like_free_text("SOCKS5-NOAUTH")
    assert not looks_like_free_text("CVE-2023-6317")
    # Y aun así produce un identificador válido, sin acentos ni espacios.
    salida = canonicalize_finding_id("Puerto 4070 - Servicio HTTP sin identificación")
    assert " " not in salida and salida.isupper()
    assert "Ó" not in salida and "ó" not in salida


def test_el_vocabulario_no_tiene_colisiones():
    """Dos identificadores del vocabulario que normalicen a la misma clave son
    un fallo del vocabulario, no del normalizador: uno de los dos dejaría de
    poder distinguirse. Es la prueba que detecta el caso `CHROMECAST-*`."""
    from core.finding_ids import _clave
    visto = {}
    for cid in (list(_PROBE_IMPACT_CLASS) + list(_CANONICAL_SEVERITY)
                + list(_CONFIRMED_NEGATIVE_IDS)):
        k = _clave(cid)
        assert visto.get(k, cid) == cid, (
            f"colisión de vocabulario: {visto[k]} y {cid} normalizan igual")
        visto[k] = cid


def test_las_claves_de_severidad_canonica_son_canonicas():
    """Si una clave no canoniza a sí misma, la búsqueda nunca acierta y la tabla
    es decorativa. Pasó con `SSH-DEFAULT-CRED` frente a `SSH-DEFAULT-CREDS`."""
    for cid in _CANONICAL_SEVERITY:
        assert canonicalize_finding_id(cid) == cid, cid


# ── Severidad fija por tipo ────────────────────────────────────────────────

def _hallazgo(cid, sev):
    return {"cve_id": cid, "severity": sev, "confirmed": True, "impact": "DISCLOSURE",
            "raw_output": "GET /desc.xml → 200, friendlyName=LG, modelName=65QNED826RE"}


def test_la_severidad_deja_de_depender_de_la_replica():
    """El mismo descriptor UPnP del mismo televisor salió LOW en una ejecución y
    MEDIUM en otra, con idéntica evidencia. El tope por clase de impacto acotaba
    por arriba y por debajo el modelo elegía."""
    for cid in ("UPNP-DESCRIPTOR-EXPOSURE", "UPNP-DEVICE-DESCRIPTOR-EXPOSURE"):
        salidas = {effective_severity(_hallazgo(cid, s))
                   for s in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")}
        assert salidas == {"LOW"}, f"{cid} sigue oscilando: {salidas}"


def test_un_id_desconocido_sigue_rigiendose_por_el_tope():
    """No se puede fijar la severidad de algo cuyo significado no está
    declarado: ahí manda el tope por clase de impacto, como siempre."""
    f = _hallazgo("ALGO-QUE-NADIE-DECLARO", "CRITICAL")
    assert effective_severity(f) == "MEDIUM"  # tope de DISCLOSURE


def test_la_severidad_fija_tambien_baja_no_solo_topa():
    """Es un valor, no un límite: si fuera solo techo, seguiría oscilando por
    debajo, que es exactamente el defecto que se corrige."""
    assert effective_severity(_hallazgo("SOCKS5-NOAUTH", "INFO")) == "LOW"
    assert effective_severity(_hallazgo("SOCKS5-NOAUTH", "HIGH")) == "LOW"


# ── El registro escribe el identificador ya canonizado ─────────────────────

def test_record_finding_canoniza_al_escribir(monkeypatch):
    """En el punto de ESCRITURA, que es por donde pasan las dos fuentes —lo que
    registra el modelo y lo que auto-registran las sondas—."""
    from core import tools as toolbox
    s = toolbox.AgentSession(target_ip="192.0.2.7")
    toolbox.bind_session(s)
    toolbox._record_finding({"cve_id": "UPnP-DEVICE-DESCRIPTOR-EXPOSURE",
                             "title": "descriptor legible", "severity": "MEDIUM",
                             "confirmed": True, "impact": "DISCLOSURE"})
    assert s.findings[0]["cve_id"] == "UPNP-DESCRIPTOR-EXPOSURE"


def test_dos_grafias_del_mismo_hallazgo_se_deduplican(monkeypatch):
    """El identificador es la clave de deduplicación. Antes, dos nombres del
    mismo hecho producían dos hallazgos y el informe contaba dos."""
    from core import tools as toolbox
    s = toolbox.AgentSession(target_ip="192.0.2.8")
    toolbox.bind_session(s)
    for cid in ("WEB-UNAUTH-ACCESS", "WEB-UNAUTHENTICATED-ACCESS"):
        toolbox._record_finding({"cve_id": cid, "title": "panel sin auth",
                                 "severity": "MEDIUM", "confirmed": True,
                                 "impact": "ACCESS"})
    assert len(s.findings) == 1, [f["cve_id"] for f in s.findings]


def test_un_identificador_en_prosa_recibe_el_formato_esperado(monkeypatch):
    from core import tools as toolbox
    s = toolbox.AgentSession(target_ip="192.0.2.9")
    toolbox.bind_session(s)
    r = toolbox._record_finding({"cve_id": "Puerto 4070 - Servicio HTTP sin identificación",
                                 "title": "puerto raro", "severity": "LOW",
                                 "confirmed": True})
    assert "_hint" in r and "PROTOCOL-WHAT-OUTCOME" in r["_hint"]


# ── El informe declara cómo terminó, también en la ruta feliz ──────────────

def test_done_sella_el_desenlace_en_el_informe_ya_escrito(tmp_path):
    """El modelo llama a `save_report` y DESPUÉS a `done()`, así que al escribir
    el artefacto aún no se sabía cómo iba a terminar: los 26 informes completos
    de la jornada de campo salieron con `finish_reason: null`, y el único que lo
    declaraba era el rescatado —el anómalo—."""
    from core import tools as toolbox
    base = tmp_path / "audit_report_X"
    base.with_suffix(".json").write_text(json.dumps(
        {"findings": [{"target_ip": "192.0.2.1", "run_metadata": {"model": "m"}}]}),
        encoding="utf-8")
    s = toolbox.AgentSession(target_ip="192.0.2.1")
    s.report_saved_path = str(base)
    s.turns_completed = 40
    toolbox.bind_session(s)
    toolbox._done({"summary": "fin"})

    meta = json.loads(base.with_suffix(".json").read_text(encoding="utf-8"))
    meta = meta["findings"][0]["run_metadata"]
    assert meta["finish_reason"] == "done_called"
    assert meta["turns"] == 40
    assert meta["interrupted"] is False
    assert meta["model"] == "m", "no puede pisar lo que ya había"


# ── Recortar la salida deja de costar turnos ───────────────────────────────

def test_head_y_tail_se_permiten_al_final_de_una_tuberia():
    """Catorce rechazos en quince ejecuciones, en seis auditorías distintas, por
    pedir `| head -20`. Truncar no es una capacidad nueva —el contenido ya lo
    tenía— y no toca red ni disco: negarlo solo compraba turnos perdidos."""
    from core.policy_engine import PolicyEngine
    p = PolicyEngine()
    for cmd in ("curl -sk http://192.0.2.1/ | head -20",
                "curl -sk http://192.0.2.1/ | tail -n 5",
                "curl -sk http://192.0.2.1/ | head -c 400"):
        assert p.validate_and_parse(cmd), cmd


@pytest.mark.parametrize("cmd", [
    "head /etc/shadow",
    "tail -n 5 /var/log/auth.log",
    "curl -sk http://192.0.2.1/ | head /etc/passwd",
    "curl -sk http://192.0.2.1/ | head -n 5 /etc/hosts",
])
def test_head_y_tail_NO_pueden_leer_ficheros(cmd):
    """La regla general de la política acepta como «dato» cualquier operando que
    no encaje en un patrón —correcto para una URL o un host—. Para un truncador
    el operando es un fichero LOCAL, así que esa misma regla lo convertía en un
    lector de `/etc/shadow`. Sin este recorte, permitirlos abría un agujero."""
    from core.policy_engine import PolicyEngine, PolicyViolation
    with pytest.raises(PolicyViolation):
        PolicyEngine().validate_and_parse(cmd)


def test_la_tuberia_de_envio_sigue_funcionando():
    """El recorte no puede haber roto la forma que ya existía."""
    from core.policy_engine import PolicyEngine
    assert PolicyEngine().validate_and_parse("echo 'ping' | nc 192.0.2.1 23")


# ── La revisita solo cuenta si hay racha ───────────────────────────────────

def test_re_sondear_tras_cambiar_de_fase_no_es_bucle():
    """Saltó en campo con `probe_tcp(80)` al pasar a explotación: en exploit hay
    rutas que en recon no existían, así que repetir la sonda es trabajo normal.
    Decirle «estás dando vueltas» a un agente que avanza es ruido."""
    from core.agent_guards import SterileStreakDetector
    seco = {"ok": False, "error_type": "FAIL", "output": ""}
    det = SterileStreakDetector(threshold=10, hard_limit=25)
    args = {"ip": "192.0.2.1", "port": 80}
    assert det.observe("probe_tcp", args, seco, gained_finding=False) is None
    det.observe("probe_http", {"ip": "x"}, {"ok": True, "output": "algo útil"},
                gained_finding=True)
    det.reset()
    assert det.observe("probe_tcp", args, seco, gained_finding=False) is None


def test_la_revisita_sigue_detectandose_dentro_de_una_racha():
    """Lo que sí es síntoma: volver a una ruta ya descartada mientras se lleva
    rato sin obtener nada. Es el caso del run de 274 turnos."""
    from core.agent_guards import SterileStreakDetector
    seco = {"ok": True, "error_type": "FAIL", "output": "404 Not Found"}
    det = SterileStreakDetector(threshold=50, hard_limit=200)
    repetida = {"cmd": "curl http://h/te_block.asp"}
    det.observe("execute_command", repetida, seco, gained_finding=False)
    for i in range(8):
        det.observe("execute_command", {"cmd": f"curl http://h/x{i}"}, seco,
                    gained_finding=False)
    assert det.observe("execute_command", repetida, seco, gained_finding=False) == "warn"
    assert det.last_reason == "revisit"


# ── `audit_count` cuenta auditorías, no guardados ─────────────────────────

def test_audit_count_no_cuenta_los_guardados_de_una_misma_auditoria(tmp_path):
    """Tras la jornada de campo los TRES aparatos marcaban 47, que es el número
    total de ejecuciones del sistema, no el de auditorías de cada uno: el tope
    por `runs_total` se había convertido en el valor. Y ese campo viaja al
    prompt del run siguiente dentro de `kb_context`."""
    from core.knowledge_base import KnowledgeBase
    kb = KnowledgeBase(path=str(tmp_path / "kb.json"))
    scan = {"mac": "14:7F:67:11:22:33", "vendor": "ACME", "ports": [{"port": 80}]}
    for _ in range(5):           # una sola auditoría que guarda cinco veces
        kb.upsert_device("192.0.2.5", scan, [])
        kb.save()
    registro = json.loads((tmp_path / "kb.json").read_text(encoding="utf-8"))
    dev = next(iter(registro["devices_seen"].values()))
    assert dev["audit_count"] == 1, dev.get("audit_runs")


def test_fusionar_dos_veces_el_mismo_historial_no_infla(tmp_path):
    """La unión de conjuntos es idempotente, que es justo lo que la aritmética
    de contadores no era: sumar duplicaba en cada guardado (2³⁰ en quince
    ejecuciones) y tomar el máximo hacía irreparable el valor corrupto."""
    from core.knowledge_base import _merge_device_records
    a = {"audit_runs": ["r1", "r2"], "audit_count": 2}
    b = {"audit_runs": ["r2", "r3"], "audit_count": 2}
    una = _merge_device_records(a, b)
    dos = _merge_device_records(una, _merge_device_records(a, b))
    assert una["audit_count"] == 3
    assert dos["audit_count"] == 3


# ── Un identificador que afirma una acción exige evidencia de la acción ─────

def test_un_id_que_afirma_una_accion_sin_evidencia_baja_a_candidato():
    """Caso de campo: `TFTP-ANON-DOWNLOAD` —el nombre afirma que se descargó un
    fichero— registrado con la evidencia «probe_tftp: protocol_confirmed=false».
    La sonda decía explícitamente que no confirmó nada. La severidad lo dejaba en
    LOW, así que la puntuación aguantaba; pero el informe publicaba una descarga
    que no ocurrió, y el nombre de un hallazgo es parte de lo que el informe
    afirma."""
    from core import tools as toolbox
    s = toolbox.AgentSession(target_ip="192.0.2.20")
    toolbox.bind_session(s)
    r = toolbox._record_finding({
        "cve_id": "TFTP-ANON-DOWNLOAD", "title": "tftp", "severity": "HIGH",
        "confirmed": True, "impact": "EXFIL",
        "raw_output": "nmap: 69/udp open|filtered tftp. probe_tftp: protocol_confirmed=false."})
    assert r.get("downgraded_to_candidate") is True
    assert s.findings[0]["confirmed"] is False
    assert "_hint" in r


def test_con_la_evidencia_de_la_accion_si_se_confirma():
    from core import tools as toolbox
    s = toolbox.AgentSession(target_ip="192.0.2.21")
    toolbox.bind_session(s)
    r = toolbox._record_finding({
        "cve_id": "TFTP-ANON-DOWNLOAD", "title": "tftp", "severity": "HIGH",
        "confirmed": True, "impact": "EXFIL",
        "raw_output": "RRQ /conf/config.bin → 8192 bytes; contiene admin_passwd=1234"})
    assert not r.get("downgraded_to_candidate")
    assert s.findings[0]["confirmed"] is True


def test_la_guarda_no_degrada_lo_que_emite_una_sonda():
    """La sonda ejecutó la interacción: su emisión ES la evidencia. Aplicarle la
    guarda degradaría la capa determinista en favor de la no determinista, que
    es exactamente lo contrario de la tesis del trabajo."""
    from core import tools as toolbox
    toolbox.bind_session(toolbox.AgentSession(target_ip="192.0.2.22"))
    toolbox._auto_register_probe_findings(
        "probe_modbus", {"ip": "192.0.2.22"},
        {"ip": "192.0.2.22", "vulnerabilities": [
            {"id": "MODBUS-NO-AUTH-READCOILS", "severity": "CRITICAL",
             "description": "coils legibles"}]})
    assert toolbox.get_session().findings[0]["confirmed"] is True


# ── Detección y confirmación son dos preguntas distintas ───────────────────

def test_el_lab_sigue_detectando_los_vectores_que_ya_no_cuentan_como_vuln():
    """El F1 de §5.2.4 mide COBERTURA DE DETECCIÓN contra vectores plantados;
    el contador de confirmados mide qué se demostró explotable. Reutilizar el
    filtro de confirmados para lo primero convertía en falso negativo un vector
    correctamente detectado —el endpoint CWMP del laboratorio— por el mero hecho
    de haber dejado de contar como vulnerabilidad."""
    import sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
    from lab_scoring import _detected_signatures
    informe = {"findings": [{"attack_results": [
        {"cve_id": "CWMP-EXPOSED", "vuln_found": True, "severity": "INFO"},
        {"cve_id": "SOCKS5-AUTH-REQUIRED", "vuln_found": True, "severity": "INFO"},
        {"cve_id": "ALGO-INFORMATIVO", "vuln_found": True, "severity": "INFO"},
    ]}]}
    sigs = _detected_signatures(informe)
    assert "CWMP-EXPOSED" in sigs, "la presencia del vector plantado SÍ es detección"
    assert "SOCKS5-AUTH-REQUIRED" not in sigs, "un negativo comprobado no detecta nada"
    assert "ALGO-INFORMATIVO" not in sigs, "una nota informativa tampoco"


# ── Cobertura de la superficie: un hueco no es un negativo ─────────────────

def _sesion_con_superficie(puertos):
    from core import tools as toolbox
    s = toolbox.AgentSession(target_ip="192.168.1.1")
    s.scan_cache = {"ports": puertos}
    toolbox.bind_session(s)
    return toolbox, s


def test_un_puerto_nunca_tocado_se_distingue_de_uno_probado_sin_exito():
    """El caso de campo: el agente atacó el 22 y el 80 del router y dejó el 443
    sin un solo intento en las tres ejecuciones — justo el puerto donde el
    escáner clásico de referencia sí encontraba algo (§5.9). El informe no
    distinguía «no lo intenté» de «lo intenté y no había nada»."""
    toolbox, s = _sesion_con_superficie([
        {"port": 22, "protocol": "tcp", "service_name": "ssh"},
        {"port": 80, "protocol": "tcp", "service_name": "http"},
        {"port": 443, "protocol": "tcp", "service_name": "https"},
    ])
    toolbox._note_attempted_ports("probe_ssh_credentials", {"ip": "192.168.1.1", "port": 22})
    toolbox._note_attempted_ports("execute_command", {"cmd": "curl -sk http://192.168.1.1/"})
    cob = toolbox._surface_coverage(s)
    assert cob["tcp_ports"] == 3 and cob["attempted"] == 2
    assert [p["port"] for p in cob["untouched"]] == [443]


def test_el_escaneo_no_cuenta_como_intento():
    """Si `nmap_scan` contara, todo puerto descubierto quedaría marcado como
    probado por el mero hecho de haber sido descubierto, y la métrica diría
    siempre 100 %."""
    toolbox, s = _sesion_con_superficie(
        [{"port": 8080, "protocol": "tcp", "service_name": "http"}])
    toolbox._note_attempted_ports("nmap_scan", {"ip": "192.168.1.1"})
    toolbox._note_attempted_ports("fingerprint_consensus", {})
    assert toolbox._surface_coverage(s)["attempted"] == 0


def test_los_udp_conjeturados_no_entran_en_la_cuenta():
    """`open|filtered` es la forma que tiene nmap de decir que no sabe. Exigir un
    intento contra una conjetura sería invitar a disparar a ciegas, que es la
    patología que la guarda de esterilidad existe para cortar."""
    toolbox, s = _sesion_con_superficie([
        {"port": 22, "protocol": "tcp", "service_name": "ssh"},
        {"port": 161, "protocol": "udp", "service_name": "snmp"},
        {"port": 1900, "protocol": "udp", "service_name": "upnp"},
    ])
    toolbox._note_attempted_ports("probe_ssh", {"ip": "192.168.1.1", "port": 22})
    cob = toolbox._surface_coverage(s)
    assert cob["tcp_ports"] == 1 and cob["coverage"] == 1.0


def test_un_puerto_de_un_tercero_no_cuenta_como_cobertura():
    """La IP tiene que ser la del objetivo: si no, una URL a un tercero que
    aparezca en la línea marcaría un puerto del objetivo como cubierto."""
    toolbox, s = _sesion_con_superficie(
        [{"port": 9999, "protocol": "tcp", "service_name": "?"}])
    toolbox._note_attempted_ports("execute_command", {"cmd": "curl -sk http://8.8.8.8:9999/"})
    assert toolbox._surface_coverage(s)["attempted"] == 0


def test_done_avisa_de_la_superficie_sin_explorar():
    toolbox, s = _sesion_con_superficie([
        {"port": 22, "protocol": "tcp", "service_name": "ssh"},
        {"port": 443, "protocol": "tcp", "service_name": "https"},
    ])
    toolbox._note_attempted_ports("probe_ssh", {"ip": "192.168.1.1", "port": 22})
    r = toolbox._done({"summary": "fin"})
    assert "443/https" in r.get("warning_untouched_ports", "")


def test_el_aviso_no_empuja_a_enumerar():
    """El aviso informa, no obliga. Empujar a «cubrir» puertos a toda costa
    reabriría la enumeración a ciegas que costó una ejecución de 274 turnos."""
    toolbox, s = _sesion_con_superficie(
        [{"port": 443, "protocol": "tcp", "service_name": "https"}])
    aviso = next(h for h in toolbox._audit_status({})["next_actions"] if "TCP" in h)
    assert "Do NOT brute-force" in aviso
    assert "dismiss it explicitly" in aviso


def test_una_url_con_puerto_explicito_no_anota_ademas_el_del_esquema():
    """`http://<ip>:8080/` es el 8080, no el 8080 y el 80. Anotar los dos daría
    por cubierto un puerto que nadie tocó, que es justo lo contrario de lo que
    la métrica existe para medir."""
    toolbox, s = _sesion_con_superficie([
        {"port": 80, "protocol": "tcp", "service_name": "http"},
        {"port": 8080, "protocol": "tcp", "service_name": "http-alt"},
    ])
    toolbox._note_attempted_ports(
        "execute_command", {"cmd": "curl -sk http://192.168.1.1:8080/admin"})
    cob = toolbox._surface_coverage(s)
    assert [p["port"] for p in cob["untouched"]] == [80]


def test_el_puerto_separado_por_espacios_cuenta_como_intento():
    """Caso de campo: el agente tocó el puerto 6668 del robot aspirador con
    `nc -zv <ip> 6668` y trajo la respuesta cruda del servicio, pero la métrica
    lo publicó como puerto sin tocar porque solo reconocía `ip:puerto`. El
    hueco no estaba en el agente sino en cómo se leía lo que había hecho."""
    toolbox, s = _sesion_con_superficie([
        {"port": 22, "protocol": "tcp", "service_name": "ssh"},
        {"port": 6668, "protocol": "tcp", "service_name": "?"},
    ])
    toolbox._note_attempted_ports("probe_ssh", {"ip": "192.168.1.1", "port": 22})
    toolbox._note_attempted_ports(
        "execute_command", {"cmd": "nc -zv 192.168.1.1 6668"})
    assert toolbox._surface_coverage(s)["coverage"] == 1.0


def test_el_puerto_de_la_opcion_p_cuenta_como_intento():
    toolbox, s = _sesion_con_superficie(
        [{"port": 443, "protocol": "tcp", "service_name": "https"}])
    toolbox._note_attempted_ports(
        "execute_command", {"cmd": "nmap -p 443 --script ssl-enum-ciphers 192.168.1.1"})
    assert toolbox._surface_coverage(s)["attempted"] == 1


def test_un_rango_de_puertos_no_cuenta_como_intento_dirigido():
    """`-p 1-1000` es una enumeración, no un intento contra un puerto concreto.
    Contarla marcaría como cubierta toda la superficie de golpe, que es la
    misma patología por la que `nmap_scan` no cuenta."""
    toolbox, s = _sesion_con_superficie([
        {"port": 22, "protocol": "tcp", "service_name": "ssh"},
        {"port": 443, "protocol": "tcp", "service_name": "https"},
    ])
    toolbox._note_attempted_ports(
        "execute_command", {"cmd": "nmap -p 1-1000 192.168.1.1"})
    assert toolbox._surface_coverage(s)["attempted"] == 0


def test_el_puerto_por_espacios_exige_la_ip_del_objetivo():
    """Misma invariante que para `ip:puerto`: un `nc 8.8.8.8 9999` en la línea
    no puede dar por cubierto el 9999 del objetivo."""
    toolbox, s = _sesion_con_superficie(
        [{"port": 9999, "protocol": "tcp", "service_name": "?"}])
    toolbox._note_attempted_ports("execute_command", {"cmd": "nc -zv 8.8.8.8 9999"})
    assert toolbox._surface_coverage(s)["attempted"] == 0


# ── La superficie se reconoce por su FORMA, no por una lista de nombres ────

@pytest.mark.parametrize("inventado", [
    "HTTPS-ACCESSIBLE",   # caso real de campo
    "HTTP-REACHABLE",
    "MQTT-DETECTED",
    "UPNP-EXPOSURE",
    "TR069-EXPOSED",
    "COAP-LISTENING",
])
def test_la_superficie_se_detecta_aunque_el_nombre_sea_nuevo(inventado):
    """Una lista cerrada de nombres siempre va por detrás de la imaginación del
    modelo. En la tanda del 2026-08-11 escribió `HTTPS-ACCESSIBLE` para decir
    exactamente lo que la tabla de puertos abiertos ya decía, y la lista no lo
    contemplaba: contó como vulnerabilidad confirmada. La FORMA del
    identificador —familia de protocolo más «está ahí»— sí es estable."""
    from core.severity import is_confirmed_vuln, is_surface_only
    canon = canonicalize_finding_id(inventado)
    assert is_surface_only(canon), f"{inventado} → {canon}"
    assert not is_confirmed_vuln({"cve_id": inventado, "severity": "HIGH",
                                  "confirmed": True, "impact": "EXPOSURE",
                                  "raw_output": "puerto abierto"})


def test_la_tabla_manda_sobre_la_forma_del_nombre():
    """`DIAL-EXPOSED` tiene forma de superficie pero el vocabulario lo declara
    DISCLOSURE porque lee el descriptor del servicio. Cuando hay declaración
    explícita, manda la declaración: la regla por forma solo decide sobre lo que
    nadie ha clasificado."""
    from core.severity import is_surface_only
    assert not is_surface_only(canonicalize_finding_id("DIAL-EXPOSED"))


@pytest.mark.parametrize("variantes", [
    # La familia web se nombra de tres maneras para el mismo plano; en campo
    # aparecieron `WEB-UNAUTH-ACCESS` y `HTTP-UNAUTH-ACCESS` en dos réplicas del
    # mismo router, para el mismo panel sin autenticar.
    ["WEB-UNAUTH-ACCESS", "HTTP-UNAUTH-ACCESS", "HTTPS-UNAUTH-ACCESS",
     "WEB-UNAUTHENTICATED-ACCESS"],
])
def test_la_familia_web_converge(variantes):
    assert len({canonicalize_finding_id(v) for v in variantes}) == 1


def test_accesible_y_acceso_no_son_lo_mismo():
    """`ACCESSIBLE` dice que el servicio responde; `ACCESS`, que se entró en él.
    Colapsarlos convertiría un puerto abierto en un acceso demostrado, que es el
    error que toda la gobernanza de severidad existe para impedir."""
    from core.severity import is_surface_only
    assert is_surface_only(canonicalize_finding_id("HTTP-ACCESSIBLE"))
    assert not is_surface_only(canonicalize_finding_id("WEB-UNAUTH-ACCESS"))


# ── La superficie también varía, y no es varianza del agente ───────────────

def test_el_arnes_separa_la_volatilidad_de_la_superficie():
    """Dos diagnósticos opuestos daban el mismo número. En la tanda del
    2026-08-11 el altavoz Amazon mantuvo **estabilidad 1,0 sobre una superficie
    que cambió un 50 %** (aparecían y desaparecían tres puertos efímeros),
    mientras el televisor dio **0,0 sobre catorce puertos idénticos en las tres
    réplicas**. En el primero el agente es consistente pese a que el objetivo
    cambia; en el segundo el objetivo es el mismo y lo que varía está en otro
    sitio. Sin esta columna, ambos casos se leían como «inestabilidad»."""
    import sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
    from variance_harness import analyze_group

    estable = [{"confirmed_count": 1, "risk_label": "LOW", "has_set": True,
                "confirmed_set": {"X"}, "surface": frozenset({22, 80})} for _ in range(3)]
    volatil = [{"confirmed_count": 1, "risk_label": "LOW", "has_set": True,
                "confirmed_set": {"X"}, "surface": frozenset(s)}
               for s in ({22, 80}, {22, 80, 9999}, {22, 80, 5541})]

    assert analyze_group(estable)["surface_volatility"] == 0.0
    v = analyze_group(volatil)
    assert v["surface_volatility"] > 0.4, v
    # La estabilidad de hallazgos es 1,0 en AMBOS: es la otra pregunta.
    assert analyze_group(estable)["stability_index"] == 1.0
    assert v["stability_index"] == 1.0


# ── El OUI resuelto deja de tirarse ────────────────────────────────────────

def test_el_oui_resuelto_llega_al_consenso_y_al_informe():
    """Había dos resoluciones de OUI que no se hablaban. La herramienta del
    agente resuelve en cuatro capas —librería local, actualización de la base,
    tabla curada y una API pública— y el consenso de fingerprinting consultaba
    SOLO la librería local. Para cualquier prefijo ausente de esa librería, el
    agente sabía el fabricante y el informe publicaba «Fabricante Genérico»: la
    respuesta determinista se obtenía y se tiraba."""
    from core import tools as toolbox
    from modules.fingerprint import DeviceFingerprinter

    s = toolbox.AgentSession(target_ip="192.0.2.30")
    toolbox.bind_session(s)
    # Se simula la capa de respaldo: el tool resolvió algo que la librería no sabe.
    s.scan_cache = {"oui_vendor": "Fabricante De Modulo S.L.",
                    "oui_vendor_source": "oui_online_api"}

    f = DeviceFingerprinter(timeout=1, lazy_mac_lookup=True)
    con_respaldo = f.get_real_manufacturer("3C:1A:CC:80:B1:59",
                                           oui_vendor=s.scan_cache["oui_vendor"])
    sin_respaldo = f.get_real_manufacturer("3C:1A:CC:80:B1:59")
    # Si la librería local YA lo conoce, el respaldo es irrelevante y no se usa.
    if "Genérico" in (sin_respaldo.get("vendor") or ""):
        assert con_respaldo["vendor"] == "Fabricante De Modulo S.L."
        assert con_respaldo["note"] == "oui_resuelto_por_el_llamante"


def test_el_respaldo_de_oui_no_resucita_la_identidad_de_una_mac_sintetica():
    """La salvaguarda de §4.7 manda sobre el respaldo: una MAC de QEMU no puede
    acabar etiquetada con un fabricante porque alguien traiga un nombre. Si esta
    prueba cae, el caso del firmware emulado vuelve a mis-etiquetarse."""
    from modules.fingerprint import DeviceFingerprinter
    f = DeviceFingerprinter(timeout=1, lazy_mac_lookup=True)
    r = f.get_real_manufacturer("52:54:00:12:34:56", oui_vendor="Netgear Inc.")
    assert r["reliable"] is False
    assert "Virtualizado" in r["vendor"], r
    assert "Netgear" not in r["vendor"]


def test_el_oui_se_guarda_aparte_y_no_como_vendor():
    """Un OUI identifica al fabricante del MÓDULO de red, no siempre a la marca
    del producto. Escribirlo directamente en `vendor` mis-etiquetaría el
    dispositivo con quien le fabrica la radio, que es el mismo error que la
    regla de identidad emulada evita por otro camino."""
    from core import tools as toolbox
    toolbox.build_registry()
    s = toolbox.AgentSession(target_ip="192.0.2.31")
    toolbox.bind_session(s)
    toolbox.dispatch("mac_vendor_lookup", {"mac": "14:7F:67:AF:0C:6A"})
    cache = s.scan_cache or {}
    assert cache.get("oui_vendor"), "el OUI resuelto debe persistirse"
    assert not cache.get("vendor"), "pero NO como identidad del producto"


# ── El negativo comprobado también se reconoce por su forma ────────────────

@pytest.mark.parametrize("negativo", [
    "HTTP-AUTH-REQUIRED",        # caso real: el panel del router EXIGE autenticación
    "SOCKS5-AUTH-REQUIRED",      # el que sí estaba en la lista
    "TELNET-REQUIRES-AUTH",
    "MQTT-AUTH-ENFORCED",
    "CVE-2023-6317-NOT-VULNERABLE",
])
def test_un_negativo_comprobado_no_es_un_hallazgo(negativo):
    """La lista cerrada contemplaba `SOCKS5-AUTH-REQUIRED`; cuando el mismo hecho
    ocurrió sobre HTTP el modelo escribió `HTTP-AUTH-REQUIRED` —«el panel requiere
    autenticación», con las credenciales por defecto rechazadas— y volvió a contar
    como confirmado. Un identificador que dice que el dispositivo EXIGE
    autenticación está reportando que está bien configurado: es información
    valiosa, y no es un hallazgo."""
    from core.severity import effective_severity, is_confirmed_negative, is_confirmed_vuln
    assert is_confirmed_negative(negativo)
    f = {"cve_id": negativo, "severity": "HIGH", "confirmed": True,
         "impact": "ACCESS", "raw_output": "POST /login → 401 credenciales rechazadas"}
    assert effective_severity(f) == "INFO"
    assert is_confirmed_vuln(f) is False


def test_lo_que_si_es_un_hallazgo_no_se_confunde_con_un_negativo():
    """`WEB-UNAUTH-ACCESS` dice justo lo contrario que `HTTP-AUTH-REQUIRED`, y
    ambos contienen la palabra AUTH: la regla mira el final del identificador,
    no la presencia del token."""
    from core.severity import is_confirmed_negative
    for cid in ("WEB-UNAUTH-ACCESS", "SOCKS5-NOAUTH", "SSH-DEFAULT-CREDS",
                "TELNET-DEFAULT-CRED"):
        assert not is_confirmed_negative(cid), cid
