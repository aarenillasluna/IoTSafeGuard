"""
Registro central de tools que el agente expone al modelo.

Cada tool:
- `parameters`: JSON Schema del contrato de la tool.
- `impl`: callable(args: dict) -> dict serializable a JSON.
- `requires_confirmation`: bool — si True, el loop pide OK humano antes de ejecutar.

El agente recibe la lista `FUNCTION_DECLARATIONS` y llama por nombre; `dispatch`
ejecuta la implementación correspondiente.
"""
from __future__ import annotations

import concurrent.futures
import json
import os
import re
import time
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from loguru import logger

# Gobernanza de severidad — vive en `core/severity.py`, sin dependencias del
# registro, para que la KB, la reflexión y los arneses de evaluación puedan
# aplicarla sin importar todo el catálogo de sondas. Se reexporta aquí porque
# `tools.effective_severity` / `tools.compute_risk_score` son rutas públicas
# usadas por el reporter, los agentes y la suite de pruebas.
#
# La lista se limita a lo que alguien consume por esta vía. Reexportar «por si
# acaso» crea dos nombres para lo mismo y hace que un cambio en `severity` haya
# que buscarlo en dos módulos; quien necesite un detector interno lo importa de
# donde vive.
from core.severity import (  # noqa: F401  (reexportación deliberada)
    _IMPACT_MAX_SEVERITY,
    _PROBE_IMPACT_CLASS,
    _PROBE_IMPACT_PREFIXES,
    _SEVERITY_RANK,
    _has_real_interaction,
    _is_reachability_only,
    _probe_impact_class,
    compute_risk_score,
    effective_severity,
    is_confirmed_vuln,
)


# =====================================================================
# Registro
# =====================================================================

PHASES = ("recon", "exploit")


@dataclass
class Tool:
    name: str
    description: str
    parameters: Dict[str, Any]
    impl: Callable[[Dict[str, Any]], Dict[str, Any]]
    requires_confirmation: bool = False
    phases: tuple = PHASES  # default: disponible en todas las fases

_REGISTRY: Dict[str, Tool] = {}


def register(tool: Tool) -> None:
    _REGISTRY[tool.name] = tool


def list_claude_tools(phase: Optional[str] = None) -> List[Dict[str, Any]]:
    """Devuelve tools en formato Anthropic ({name, description, input_schema}).

    El campo `input_schema` es idéntico al `parameters` de cada Tool, que ya
    usa JSON Schema ({type: object, properties: {...}, required: []}).
    """
    return [
        {
            "name": t.name,
            "description": t.description,
            "input_schema": t.parameters,
        }
        for t in _REGISTRY.values()
        if phase is None or phase in t.phases
    ]


def list_tools(phase: Optional[str] = None) -> List["Tool"]:
    """Los objetos `Tool` completos, filtrados por fase igual que `list_claude_tools`."""
    if phase is None:
        return list(_REGISTRY.values())
    return [t for t in _REGISTRY.values() if phase in t.phases]


_TRACKED_PROBES_PREFIX = ("probe_",)
_TRACKED_PROBES_EXTRA = frozenset({"nmap_scan", "http_interrogate", "mac_vendor_lookup"})


def _is_probe(tool_name: str) -> bool:
    """Identifica tools de recon que cuentan para coverage tracking."""
    return tool_name.startswith(_TRACKED_PROBES_PREFIX) or tool_name in _TRACKED_PROBES_EXTRA


def _cache_ws_endpoints_from_result(tool_name: str, result: Dict[str, Any]) -> None:
    """Detecta probes que confirmaron handshake WebSocket exitoso y cachea el
    endpoint (host, port) en la sesión.

    Hoy soporta `probe_lg_webos` (formato: result.details.websocket_handshake
    contiene un dict {port: {upgraded: bool, ...}}). Otros probes WS pueden
    enchufarse aquí sin tocar la lógica de execute_command.
    """
    if _SESSION is None or not isinstance(result, dict):
        return
    if tool_name != "probe_lg_webos":
        return
    details = result.get("details") or {}
    handshakes = details.get("websocket_handshake") or {}
    if not isinstance(handshakes, dict):
        return
    ip = result.get("ip") or _SESSION.target_ip
    for port, info in handshakes.items():
        if isinstance(info, dict) and info.get("upgraded"):
            try:
                endpoint = (ip, int(port))
            except (TypeError, ValueError):
                continue
            if endpoint not in _SESSION.ws_confirmed_endpoints:
                _SESSION.ws_confirmed_endpoints.append(endpoint)


def _extract_raw_output(vuln: Dict[str, Any], probe_details: Dict[str, Any],
                        tool_name: str) -> Dict[str, Any]:
    """Extrae los DATOS REALES que el dispositivo respondió (no la interpretación).

    Output estructurado (dict) con solo hechos verificables:
      - banners de servicio
      - apps detectadas (DIAL)
      - mensajes interceptados (MQTT)
      - handshake responses (LG WebOS)
      - paths con códigos HTTP (RTSP)
      - signatures match (Telnet)
      - protocol versions (SMB)
      - archivos accesibles (TFTP)

    Esto es lo que un auditor humano vería con curl/nc/wireshark. La narrativa
    "DIAL expone apps" es interpretación y va aparte.
    """
    raw: Dict[str, Any] = {}

    # Datos directos de la vuln (capturados por el probe en su ejecución)
    if vuln.get("path"):
        raw["path"] = vuln["path"]
    if vuln.get("credentials"):
        creds = vuln["credentials"]
        if isinstance(creds, dict):
            raw["credentials_accepted"] = f"{creds.get('user', '?')}:{creds.get('password', '?')}"
        else:
            raw["credentials_accepted"] = str(creds)
    if vuln.get("client_key"):
        raw["client_key_extracted"] = vuln["client_key"]
    if vuln.get("shell_evidence"):
        raw["shell_evidence"] = str(vuln["shell_evidence"])[:200]
    if vuln.get("pre_auth_status"):
        raw["http_status_pre_auth"] = vuln["pre_auth_status"]

    # Datos del probe details (contextuales por servicio)
    if not probe_details:
        return raw

    # DIAL — descriptor + apps
    if "apps" in probe_details and isinstance(probe_details["apps"], dict):
        raw["apps_detected"] = {
            app: {"status": info.get("status", "?"), "state": info.get("state", "?")}
            for app, info in list(probe_details["apps"].items())[:8]
        }
    if "application_url" in probe_details:
        raw["application_url"] = probe_details["application_url"]
    if "friendly_name" in probe_details:
        raw["friendly_name"] = probe_details["friendly_name"]
    if "model_name" in probe_details:
        raw["model_name"] = probe_details["model_name"]
    if "manufacturer" in probe_details:
        raw["manufacturer"] = probe_details["manufacturer"]

    # MQTT — mensajes
    msgs = probe_details.get("messages_intercepted") or []
    if msgs:
        raw["messages_intercepted_count"] = len(msgs)
        raw["messages_sample"] = [
            {"topic": m.get("topic", "?"),
             "payload": (m.get("payload_preview", "") or "")[:80]}
            for m in msgs[:3]
        ]
    if probe_details.get("anonymous_access") is not None:
        raw["anonymous_access"] = probe_details["anonymous_access"]
    if probe_details.get("wildcard_subscribe") is not None:
        raw["wildcard_subscribe"] = probe_details["wildcard_subscribe"]

    # RTSP — banner + paths
    if "server" in probe_details:
        raw["server_banner"] = probe_details["server"]
    if "options_status" in probe_details:
        raw["options_status_code"] = probe_details["options_status"]
    if "auth_required_paths" in probe_details:
        raw["auth_required_paths"] = probe_details["auth_required_paths"][:5]

    # LG WebOS — handshake info
    if "websocket_handshake" in probe_details:
        ws_summary = {}
        for port, info in (probe_details["websocket_handshake"] or {}).items():
            if not isinstance(info, dict):
                continue
            entry = {"upgraded": info.get("upgraded", False)}
            if info.get("scheme_used"):
                entry["scheme"] = info["scheme_used"]
            if info.get("pairing_response_snippet"):
                entry["pairing_response"] = info["pairing_response_snippet"][:200]
            bypass = info.get("bypass_attempt") or {}
            if bypass:
                entry["bypass_attempt"] = {
                    "vulnerable": bypass.get("vulnerable", False),
                    "diagnosis": bypass.get("diagnosis", ""),
                }
            ws_summary[str(port)] = entry
        if ws_summary:
            raw["websocket_handshake"] = ws_summary

    # Telnet — banner + signatures
    if tool_name == "probe_telnet":
        if "banner" in probe_details:
            raw["telnet_banner"] = probe_details["banner"][:300]
        if "matched_signatures" in probe_details:
            raw["matched_signatures"] = probe_details["matched_signatures"]

    # SSH — banner
    if tool_name == "probe_ssh" and "banner" in probe_details:
        raw["ssh_banner"] = probe_details["banner"]

    # FTP — banner
    if tool_name == "probe_ftp" and "banner" in probe_details:
        raw["ftp_banner"] = (probe_details["banner"] or "")[:200]

    # SMB — protocol
    if tool_name == "probe_smb" and "protocol" in probe_details:
        raw["smb_protocol"] = probe_details["protocol"]
        if "nt_status" in probe_details:
            raw["nt_status"] = probe_details["nt_status"]

    # TFTP — files
    if "accessible_files" in probe_details:
        raw["accessible_files"] = probe_details["accessible_files"]

    # CWMP — status line + raw banner
    if tool_name == "probe_cwmp":
        if "status_line" in probe_details:
            raw["http_status_line"] = probe_details["status_line"]
        if "server" in probe_details:
            raw["server_banner"] = probe_details["server"]

    # BACnet — vendor_id, object_instance
    if tool_name == "probe_bacnet":
        for k in ("vendor_id", "object_instance", "object_type", "max_apdu"):
            if k in probe_details:
                raw[k] = probe_details[k]

    # Modbus — slave_id, coils
    if tool_name == "probe_modbus":
        for k, v in probe_details.items():
            if k.startswith("unit_") and isinstance(v, dict):
                raw[k] = v

    return raw


def _auto_register_probe_findings(tool_name: str, args: Dict[str, Any],
                                  result: Dict[str, Any]) -> None:
    """Auto-registra vulnerabilities[] devueltas por probes como findings.

    Las probes (probe_*, http_interrogate, etc.) reportan hallazgos verificados
    en `result["vulnerabilities"]`. Sin este auto-registro, el modelo tendría que
    transcribir manualmente cada vuln a `record_finding`, gastando turnos y
    olvidando entradas (bug observado en runs reales).

    Mapea formato probe → formato finding y delega en `_record_finding` para
    aprovechar el dedupe por cve_id existente.

    No-op si el resultado no contiene vulnerabilities, si la sesión no está
    bound, o si la lista está vacía.
    """
    if _SESSION is None or not isinstance(result, dict):
        return
    vulns = result.get("vulnerabilities")
    if not isinstance(vulns, list) or not vulns:
        return

    ip = result.get("ip") or args.get("ip") or _SESSION.target_ip
    port = result.get("port") or args.get("port")
    target_ref = f"{ip}:{port}" if port else str(ip)

    # Detalles del probe que enriquecen evidencia (apps DIAL, banners RTSP, etc.)
    probe_details = result.get("details") or {}

    auto_registered: List[str] = []
    for v in vulns:
        if not isinstance(v, dict):
            continue
        vuln_id = v.get("id")
        if not vuln_id:
            continue

        description = v.get("description", "") or ""
        # Title corto pero significativo: primer trozo de la descripción
        title = description[:120].rsplit(" ", 1)[0] if len(description) > 120 else description
        if not title:
            title = vuln_id

        # ── Separación de datos vs interpretación ──
        # raw_output: dict estructurado de hechos (banner, apps, status codes...)
        # interpretation: descripción narrativa del probe (qué significa el output)
        raw_output_dict = _extract_raw_output(v, probe_details, tool_name)
        # Renderizamos el dict como JSON-like compacto en string para el field
        # (el reporter lo parsea/embeleza luego).
        raw_output_str = ""
        if raw_output_dict:
            raw_output_str = json.dumps(raw_output_dict, ensure_ascii=False, indent=2)

        interpretation = description

        # Reproducción: verification_cmd > tool name fallback
        cmd_label = v.get("verification_cmd") or f"{tool_name}({target_ref})"

        # Las probes reportan vulnerabilidades VERIFICADAS en el dispositivo
        # (protocol_confirmed=True), por tanto confirmed=True por defecto.
        _record_finding({
            "cve_id": vuln_id,
            "title": title,
            "severity": v.get("severity", "INFO"),
            "confirmed": True,
            "raw_output": raw_output_str,
            "interpretation": interpretation,
            "cmd": cmd_label,
            # Clase de impacto DEMOSTRADA por la sonda. Sin esto, `effective_severity`
            # topaba a LOW todo hallazgo auto-registrado —incluido un shell obtenido
            # con credenciales por defecto— y la severidad efectiva dependía de que el
            # LLM re-registrase el hallazgo. La sonda sabe mejor que el modelo qué
            # demostró: lo declara aquí, de forma determinista.
            "impact": _probe_impact_class(v, vuln_id),
            # Emitido por una SONDA, no escrito por el modelo. La guarda que
            # degrada a candidato un identificador que afirma más de lo que su
            # evidencia muestra existe porque el modelo puede redactar el nombre
            # y la prueba por separado. Una sonda no: ejecutó la interacción, y
            # su emisión es la evidencia. Aplicarle la guarda degradaría
            # justamente la capa determinista en favor de la no determinista.
            "_from_probe": True,
            # Techo canónico: la severidad que declara la PROPIA tool para este
            # tipo de hallazgo (higiene/exposición). El LLM puede reescribir
            # `severity` al re-registrar el finding, pero no puede inflarlo por
            # encima de este techo (ver effective_severity). Fija la deriva de
            # severidad run-to-run: mismo device → misma severidad efectiva.
            "canonical_severity": (v.get("severity") or "INFO").upper(),
        })
        auto_registered.append(vuln_id)

    if auto_registered:
        # Marcar en el resultado para trazabilidad/debug; no rompe contrato
        result["_auto_registered_findings"] = auto_registered


def _safety_precheck(name: str) -> Optional[Dict[str, Any]]:
    """SafetyMonitor pre-check antes de ejecutar tool.
    Devuelve None si OK; dict de error si el kill-switch está activo o el
    budget de req/min se agotó (el agente debe interpretarlo como signal de
    cooldown, no como fallo del tool).
    """
    if _SESSION is None or _SESSION.safety is None:
        return None
    if name in _SAFETY_EXEMPT_TOOLS:
        return None
    safety = _SESSION.safety
    if safety._kill_switch_triggered:
        reason = getattr(safety, "kill_switch_reason", None) or "target degraded or unreachable"
        return {
            "ok": False,
            "error_type": "safety_kill_switch",
            "error": (f"SafetyMonitor kill-switch active — {reason}. "
                      "Stop operating against this IP and call save_report/done."),
        }
    if not safety.consume_budget():
        return {
            "ok": False,
            "error_type": "safety_rate_limit",
            "error": (f"Budget exhausted ({safety.requests_per_minute} req/min). "
                      "Wait ~30s before retrying — this protects the IoT device."),
        }
    return None


def _feed_safety_open_ports(result: Dict[str, Any]) -> None:
    """Entrega al SafetyMonitor los puertos TCP que acaba de descubrir nmap.

    El monitor se instancia en `run.py` ANTES del primer escaneo, así que nacía
    con `open_ports=[]` y nadie se los rellenaba después. Consecuencia: el
    fallback TCP —añadido precisamente para los objetivos que filtran ICMP—
    salía por `if not self.open_ports: return False` y nunca llegaba a
    ejecutarse. Era un camino muerto que pasó inadvertido mientras la única
    consecuencia era que `is_degraded()` no viera nada.
    """
    if _SESSION is None or _SESSION.safety is None:
        return
    ports = result.get("ports")
    if not isinstance(ports, list):
        return
    tcp = [p.get("port") for p in ports
           if isinstance(p, dict) and p.get("port")
           and (p.get("proto") or "tcp") == "tcp"
           and "open" in str(p.get("state") or "open")]
    if not tcp:
        return
    known = _SESSION.safety.open_ports
    added = [p for p in tcp if p not in known]
    if added:
        known.extend(added)
        logger.info(f"[SAFETY] fallback TCP operativo — puertos vigilados: {known}")


def _telemetry_record_surface_from_nmap(result: Dict[str, Any]) -> None:
    """Si el resultado viene de nmap_scan, alimenta TelemetryCollector con la
    superficie detectada (puertos + servicios)."""
    if _SESSION is None or _SESSION.telemetry is None:
        return
    ports = result.get("ports")
    if isinstance(ports, list):
        # Formato compacto de _nmap_scan: [{port, proto, service, ...}, ...]
        normalized = [
            {"port": p.get("port"), "service_name": p.get("service") or p.get("service_name")}
            for p in ports if isinstance(p, dict) and p.get("port")
        ]
        _SESSION.telemetry.record_surface(normalized)


_HEALTH_CHECK_EVERY_N_CALLS = 10
_dispatch_call_counter = 0


# Argumentos que SOLO puede fijar el propio sistema (auto-registro de probes),
# nunca el modelo. No están declarados en ningún schema, pero un LLM puede
# emitir campos no declarados: si `canonical_severity` llegase desde el modelo,
# el techo de severidad —que es precisamente la pieza que impide inflar un
# hallazgo de higiene a MEDIUM/HIGH— quedaría fijado por quien debe estar
# sometido a él. `dispatch` los descarta antes de llegar a la implementación;
# el auto-registro interno llama a `_record_finding` directamente y sí los pasa.
_INTERNAL_ONLY_ARGS = frozenset({"canonical_severity"})

# Valor de `cmd` con el que `record_cve_findings` marca un candidato aún no
# probado. Nombrado en un único sitio porque de él dependen dos lecturas
# (`done()` y `audit_status`) y una escritura (el merge de `_record_finding`).
_BATCH_CVE_CMD_MARKER = "cve_search"


def _strip_internal_args(args: Dict[str, Any]) -> Dict[str, Any]:
    """Elimina de los args del modelo los campos reservados al sistema.

    Devuelve el mismo dict si no hay nada que quitar (caso normal, sin coste).
    """
    if not args:
        return args or {}
    intruders = _INTERNAL_ONLY_ARGS.intersection(args.keys())
    if not intruders:
        return args
    logger.warning(f"[TOOL] args internos descartados del modelo: {sorted(intruders)}")
    return {k: v for k, v in args.items() if k not in _INTERNAL_ONLY_ARGS}


# Herramientas que constituyen un INTENTO DIRIGIDO contra un servicio: piden
# algo al objetivo esperando una respuesta que confirme o descarte. Se excluyen
# a propósito el escaneo y el fingerprinting, que construyen la superficie en vez
# de atacarla — si `nmap_scan` contara como intento, todo puerto descubierto
# quedaría marcado como probado por el mero hecho de haber sido descubierto.
_ATTEMPT_TOOLS = frozenset({
    "execute_command", "execute_chain", "execute_websocket", "web_login",
    "probe_ssh_credentials", "probe_telnet", "probe_ftp", "probe_mqtt",
    "probe_rtsp", "probe_socks5", "probe_tftp", "probe_snmp", "probe_coap",
    "probe_modbus", "probe_miio", "probe_upnp_igd", "probe_tcp", "probe_udp",
    "probe_bacnet", "probe_ssh", "probe_dial", "probe_chromecast",
})

_PUERTO_EXPLICITO_RE = re.compile(r":(\d{1,5})\b")
_ESQUEMA_PUERTO = (("https://", 443), ("http://", 80), ("wss://", 443), ("ws://", 80))
# `-p 6668` / `--port=6668`. Se descartan los rangos (`-p 1-1000`, `-p-`): un
# rango es una enumeración, no un intento dirigido contra un puerto concreto.
_PUERTO_FLAG_RE = re.compile(r"(?:^|\s)(?:-p|--port|--dport)[=\s]+([\d,]+)(?=\s|$)")


def _note_attempted_ports(name: str, args: Dict[str, Any]) -> None:
    """Anota contra qué puertos del objetivo se ha intentado algo.

    Existe para responder a una pregunta que el informe no sabía contestar: de
    la superficie que se publica, ¿cuánta se llegó a tocar? En una tanda de
    campo el agente atacó 2 de los 3 puertos TCP del router y 6 de los 14 del
    televisor, y el puerto que dejó sin tocar —el 443 del router— era justo
    donde el escáner clásico de referencia sí encontraba algo (§5.9). No es que
    fallara al intentarlo: es que no lo intentó, y el informe no lo distinguía
    de «se intentó y no había nada».

    Solo registra la INTENCIÓN, no el resultado. Un intento fallido es
    información —el dispositivo resistió— y un puerto sin intentar es un hueco;
    confundirlos es lo que se quiere evitar.

    La atribución se hace por la FORMA en que el puerto aparece, y no por una
    lista de comandos, porque la lista siempre va por detrás: la primera versión
    solo reconocía `ip:puerto` y el esquema de la URL, de modo que un
    `nc -zv <ip> 6668` —que es como el agente tocó de hecho el puerto Tuya del
    robot aspirador, con la respuesta cruda del servicio en el informe— quedaba
    contado como puerto sin tocar. Las formas reconocidas son tres: `ip:puerto`,
    el puerto implícito del esquema y el puerto separado por espacios tras la IP
    del objetivo, más el `-p`/`--port` de la línea cuando la IP del objetivo
    aparece en ella.
    """
    if name not in _ATTEMPT_TOOLS or _SESSION is None:
        return
    objetivo = _SESSION.target_ip
    puertos = set()
    valor = args.get("port")
    if isinstance(valor, (int, str)) and str(valor).isdigit():
        puertos.add(int(valor))
    for clave in ("cmd", "url", "command"):
        texto = str(args.get(clave) or "")
        if not texto:
            continue
        # `ip:puerto` explícito. Se exige la IP del objetivo para no anotar el
        # puerto de un tercero que aparezca en la línea.
        for m in _PUERTO_EXPLICITO_RE.finditer(texto):
            if objetivo and f"{objetivo}:{m.group(1)}" in texto:
                puertos.add(int(m.group(1)))
        # Puerto implícito del esquema: `http://<ip>/algo` es el 80. Se exige
        # que tras la IP venga `/` o el final de la cadena, para no confundir
        # `http://<ip>:8080/` —que ya se anotó arriba con su puerto— con el 80.
        if objetivo:
            for esquema, defecto in _ESQUEMA_PUERTO:
                base = f"{esquema}{objetivo}"
                if f"{base}/" in texto or texto.rstrip().endswith(base):
                    puertos.add(defecto)
            # `nc <ip> <puerto>`, `telnet <ip> <puerto>`: la sintaxis separada por
            # espacios es tan corriente como `ip:puerto`.
            for m in re.finditer(rf"{re.escape(objetivo)}\s+(\d{{1,5}})\b", texto):
                puertos.add(int(m.group(1)))
            # `nmap -p 443 <ip>`: el puerto va en la opción, no junto a la IP. Se
            # exige que la IP del objetivo esté en la línea para no anotar el
            # puerto de un tercero.
            if objetivo in texto:
                for m in _PUERTO_FLAG_RE.finditer(texto):
                    for token in m.group(1).split(","):
                        if token.isdigit():
                            puertos.add(int(token))
    for p in puertos:
        if 0 < p < 65536:
            _SESSION.attempted_ports.add(p)


def dispatch(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Despacha una tool por nombre.

    Side effects deterministas tras la ejecución exitosa:
      - SafetyMonitor pre-check (rate limit + kill-switch) para tools de red.
      - Tracking de probes ejecutadas (para coverage enforcement en transition_phase)
      - Auto-registro de vulnerabilities[] como findings (evita pérdida por
        olvido del modelo)
      - Telemetry: registra latencia y superficie cuando aplica.

    NOTA importante sobre SafetyMonitor: el elapsed_ms del TOOL no es señal de
    degradación del target (nmap_scan tarda 30-60s legítimamente). La
    degradación se mide vía health check ICMP/TCP periódico, cada
    N=_HEALTH_CHECK_EVERY_N_CALLS dispatches, que es lo único que mide
    latencia REAL del dispositivo respondiendo a un paquete.
    """
    tool = _REGISTRY.get(name)
    if not tool:
        return {"error": f"unknown tool '{name}'", "available": list(_REGISTRY.keys())}

    # 0) SafetyMonitor pre-check (rate limit + kill-switch)
    safety_block = _safety_precheck(name)
    if safety_block is not None:
        return safety_block

    args = _strip_internal_args(args or {})
    _note_attempted_ports(name, args)

    try:
        t0 = time.time()
        result = tool.impl(args or {})
        elapsed_ms = int((time.time() - t0) * 1000)
        result.setdefault("_elapsed_ms", elapsed_ms)
        _post_dispatch(name, args or {}, result)
        return result
    except Exception as e:
        logger.exception(f"[TOOL] {name} crashed: {e}")
        return {"error": f"tool '{name}' raised {type(e).__name__}: {e}"}


def _run_probes(args: Dict[str, Any]) -> Dict[str, Any]:
    """Ejecuta varias **probes de protocolo independientes en paralelo**, en UN
    solo turno del modelo.

    Motivación (rendimiento): el agente suele lanzar cada probe en un turno LLM
    distinto (media ~30 turnos/auditoría), y las probes UDP son lentas
    (p. ej. `probe_snmp` puede tardar 20-25 s). Como son I/O independiente, se
    paralelizan: la parte pura de cada probe corre en un `ThreadPoolExecutor`, y
    los *side-effects* (auto-registro de findings, cobertura, telemetría) se
    aplican **después, en el hilo principal y en serie**, evitando *races* sobre
    el estado compartido. Resultado: menos turnos → menos coste y latencia LLM.

    Solo se admiten probes `probe_*` (I/O puras que no tocan la sesión). Para
    `http_interrogate`, `cve_search` o `execute_*` (con estado/efectos propios)
    úsese `dispatch` normal.

    args:
      - `ip`: IP objetivo (se inyecta en cada probe que no traiga la suya).
      - `probes`: lista de `{"probe": "probe_snmp", "args": {...opcional...}}`
                  (o simplemente `{"probe": "probe_snmp"}`).
    """
    ip = args.get("ip")
    items = args.get("probes") or []
    if not isinstance(items, list) or not items:
        return {"ok": False, "error": "probes must be a non-empty list of {probe, args}"}

    # Normaliza + valida cada item ANTES de lanzar nada.
    planned: List[Tuple[str, Dict[str, Any]]] = []
    rejected: Dict[str, str] = {}
    for it in items:
        name = (it.get("probe") if isinstance(it, dict) else str(it)) or ""
        if not name.startswith("probe_"):
            rejected[name or "?"] = "only 'probe_*' probes are accepted in a batch"
            continue
        if name not in _REGISTRY:
            rejected[name] = "unknown probe"
            continue
        p_args = dict(it.get("args") or {}) if isinstance(it, dict) else {}
        # Mismo saneado que `dispatch`: el batch tampoco es una puerta trasera
        # para que el modelo fije argumentos reservados al sistema.
        p_args = _strip_internal_args(p_args)
        if ip and "ip" not in p_args:
            p_args["ip"] = ip
        planned.append((name, p_args))

    if not planned:
        return {"ok": False, "error": "no valid probe in the batch", "rejected": rejected}

    # Pre-check de seguridad por probe (rate-limit/kill-switch), serializado.
    runnable: List[Tuple[str, Dict[str, Any]]] = []
    skipped: Dict[str, Any] = {}
    for name, p_args in planned:
        block = _safety_precheck(name)
        if block is not None:
            skipped[name] = block
        else:
            runnable.append((name, p_args))

    # Ejecución PARALELA de la parte pura (sin tocar _SESSION).
    t0 = time.time()
    raw: List[Tuple[str, Dict[str, Any], Dict[str, Any]]] = []

    def _call(name: str, p_args: Dict[str, Any]) -> Dict[str, Any]:
        try:
            r = _REGISTRY[name].impl(p_args)
            if not isinstance(r, dict):
                r = {"ok": False, "error": "probe returned a non-dict type"}
            return r
        except Exception as e:  # una probe que peta no tumba el batch
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    max_workers = min(8, len(runnable)) or 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(_call, n, a) for n, a in runnable]
        # Recoge en el ORDEN del plan, no en orden de finalización: así los
        # side-effects (auto-registro de findings) y el array de resultados son
        # deterministas entre runs, independientemente de qué probe acabe antes.
        for (n, a), fut in zip(runnable, futures):
            raw.append((n, a, fut.result()))

    # Side-effects SERIALIZADOS en el hilo principal (sin races).
    results: List[Dict[str, Any]] = []
    for name, p_args, result in raw:
        result.setdefault("_elapsed_ms", 0)
        _post_dispatch(name, p_args, result)
        entry = {"probe": name}
        entry.update(result)
        results.append(entry)

    return {
        "ok": True,
        "executed": [n for n, _, _ in raw],
        "results": results,
        "skipped": skipped or None,
        "rejected": rejected or None,
        "_elapsed_ms": int((time.time() - t0) * 1000),
        "note": (
            f"{len(results)} probes run in parallel in a single turn. "
            "Any findings detected have already been auto-recorded."
        ),
    }


def _post_dispatch(name: str, args: Dict[str, Any], result: Dict[str, Any]) -> None:
    """Side-effects deterministas tras ejecutar una tool. Se ejecuta SIEMPRE en
    el hilo principal (también desde `run_probes`, que paraleliza solo la parte
    pura de I/O de cada probe), de modo que el estado compartido —`_SESSION`,
    auto-registro de findings, telemetría— se toca de forma serializada y sin
    *races*."""
    global _dispatch_call_counter

    # 1) Coverage tracking
    if _SESSION is not None and _is_probe(name):
        if name not in _SESSION.executed_probes:
            _SESSION.executed_probes.append(name)

    # 2) Auto-registro de findings desde vulnerabilities[] del probe
    _auto_register_probe_findings(name, args, result)

    # 3) Cachear endpoints WS-only detectados por probes (evita timeouts en
    #    execute_command sucesivos contra puertos que solo hablan WebSocket)
    _cache_ws_endpoints_from_result(name, result)

    # 4) SafetyMonitor: health check ICMP periódico (NO basado en elapsed
    #    del tool). Mide latencia real del target con un ping pequeño.
    if (_SESSION is not None and _SESSION.safety is not None
            and name not in _SAFETY_EXEMPT_TOOLS):
        _dispatch_call_counter += 1
        if _dispatch_call_counter % _HEALTH_CHECK_EVERY_N_CALLS == 0:
            _safety_health_probe()

    # 5) Telemetry: superficie detectada por nmap_scan
    if name == "nmap_scan":
        _telemetry_record_surface_from_nmap(result)
        _feed_safety_open_ports(result)


def _safety_health_probe() -> None:
    """Ejecuta un health check ligero (ICMP + TCP fallback) y mide latencia
    REAL del target. Activa el kill-switch por CUALQUIERA de las dos causas:

      (a) **Inalcanzabilidad** — N sondas consecutivas sin respuesta (ni ICMP ni
          TCP). Se comprueba PRIMERO porque es la señal más grave y porque
          `is_degraded()` es ciega ante ella: un objetivo caído no produce
          muestras de latencia, así que la ventana se queda congelada con los
          valores buenos previos y la media nunca supera el umbral. Sin este
          brazo, el escenario para el que existe la capa —hemos tumbado el
          dispositivo— era justo el que no la disparaba.
      (b) **Degradación** — la latencia media reciente supera el umbral.
    """
    if _SESSION is None or _SESSION.safety is None:
        return
    safety = _SESSION.safety
    try:
        # ICMP primero; si el objetivo bloquea ping (caso real: Amazon Echo y
        # muchos IoT con firewall), el fallback TCP mide la latencia del connect
        # — sin él, _latencies quedaría vacío y la degradación pasaría inadvertida.
        alive = safety._check_icmp()
        if not alive:
            if not safety.can_check_tcp():
                # ICMP filtrado y ningún puerto contra el que probar: el estado
                # del objetivo es DESCONOCIDO, no «caído». Contarlo como fallo
                # declaraba muerto a todo dispositivo que filtra ping antes de
                # que nmap hubiera aportado puertos —el Amazon Echo, que es el
                # ejemplo que la propia memoria usa para justificar el fallback
                # TCP—: el kill-switch saltaba a mitad de auditoría en runs
                # donde el equipo seguía contestando HTTP en 16 ms.
                logger.debug(
                    "[SAFETY] health probe no concluyente (ICMP filtrado y sin "
                    "puertos TCP conocidos) — no cuenta como fallo")
                return
            alive = safety._check_tcp()
        safety.record_health_check(alive)
        if safety.is_unreachable():
            logger.warning(
                f"[SAFETY] objetivo sin respuesta en {safety.ping_failures} sondas "
                f"consecutivas — activando kill-switch"
            )
            safety.trigger_kill_switch(
                f"target unreachable ({safety.ping_failures} consecutive probes with no answer)"
            )
        elif safety.is_degraded():
            logger.warning(
                f"[SAFETY] degradación detectada vía health probe — activando kill-switch"
            )
            safety.trigger_kill_switch("target latency above the threshold")
    except Exception as e:
        logger.debug(f"[SAFETY] health probe error: {e}")


def reset_safety_kill_switch() -> bool:
    """Permite recuperar la sesión tras un kill-switch (manual o por health probe).
    Devuelve True si había kill-switch activo y se reseteó.
    """
    if _SESSION is None or _SESSION.safety is None:
        return False
    if _SESSION.safety._kill_switch_triggered:
        _SESSION.safety._kill_switch_triggered = False
        _SESSION.safety.kill_switch_reason = None
        _SESSION.safety.ping_failures = 0
        _SESSION.safety._latencies.clear()
        logger.warning("[SAFETY] kill-switch RESETEADO manualmente")
        return True
    return False


def requires_confirmation(name: str) -> bool:
    t = _REGISTRY.get(name)
    return bool(t and t.requires_confirmation)


# =====================================================================
# Sesión compartida (acumulador de hallazgos, credenciales, vars)
# =====================================================================

@dataclass
class AgentSession:
    target_ip: str
    # Fase activa del agente ("recon" | "exploit"). La mantiene el bucle del
    # agente al transicionar; las tools la consultan para aplicar restricciones
    # deterministas por fase (p. ej. `execute_command` es de solo lectura en
    # recon). Sin esto, la regla "solo GET en recon" existía únicamente como
    # texto en el prompt, es decir, no existía.
    phase: str = "recon"
    findings: List[Dict[str, Any]] = field(default_factory=list)
    credentials: List[Dict[str, str]] = field(default_factory=list)
    vars: Dict[str, str] = field(default_factory=dict)
    scan_cache: Optional[Dict[str, Any]] = None
    # Coverage tracking (recommend_probes guarda aquí; dispatch wrapper marca ejecutadas)
    recommended_probes: List[str] = field(default_factory=list)
    executed_probes: List[str] = field(default_factory=list)
    # Endpoints (host, port) confirmados como WebSocket-only (ej. LG WebOS 3001).
    # Poblados por probes que detectan handshake WS exitoso. _execute_cmd/chain
    # rechazan curl HTTP a estos endpoints (deterministicamente, evita timeouts
    # de 60-120s mientras el servidor espera el WS upgrade).
    ws_confirmed_endpoints: List[Tuple[str, int]] = field(default_factory=list)
    # Path al reflection report del run actual (si fue generado por el agente)
    reflection_report_path: Optional[str] = None
    # Path base del audit report ya guardado este run (set por _save_report).
    # _done() lo usa para auto-guardar si el LLM se saltó save_report.
    report_saved_path: Optional[str] = None
    # CVEs registrados via record_cve_findings (batch); usado en _done() para avisar de no testeados
    batch_registered_cves: List[str] = field(default_factory=list)
    # SafetyMonitor + TelemetryCollector — opcionales, se instancian en run.py si
    # están habilitados. Cuando son None, los hooks en dispatch() son no-ops.
    safety: Optional[Any] = None       # core.safety_monitor.SafetyMonitorV2
    telemetry: Optional[Any] = None    # core.telemetry.TelemetryCollector
    # Cache de evidencia HTTP/interrogator para reutilizar en fingerprint_consensus
    # sin re-ejecutar http_interrogate. Poblado por el wrapper de _http_interrogate.
    interrogator_evidence: Dict[str, Any] = field(default_factory=dict)
    # Identidad del LLM que conduce el run — queda registrada en el informe
    # (run_metadata) para que cada artefacto sea atribuible a un modelo concreto.
    model_name: Optional[str] = None
    provider: Optional[str] = None
    # Veces que el proveedor devolvió 429 durante el run. Sale en `run_metadata`
    # porque explica diferencias de duración y de recorrido entre réplicas que,
    # de otro modo, se atribuirían al agente: una réplica estrangulada visita
    # menos herramientas en el mismo presupuesto de reloj.
    provider_rate_limit_hits: int = 0
    # Cómo acabó el run y en qué turno. Los escribe el bucle del agente (y
    # `_done`), y salen en `run_metadata` porque distinguen un informe COMPLETO
    # de uno RESCATADO: sin el campo, un run cortado a los siete turnos produce
    # un artefacto indistinguible de uno que recorrió el pipeline entero, y
    # entra en las estadísticas de estabilidad deprimiéndolas sin dejar rastro.
    finish_reason: Optional[str] = None
    turns_completed: int = 0
    # Puertos del objetivo contra los que se ha dirigido algún intento. Mide
    # COBERTURA de la superficie: un puerto publicado en el informe y nunca
    # tocado no es lo mismo que uno probado sin éxito, y hasta ahora el informe
    # no los distinguía. Ver `_note_attempted_ports`.
    attempted_ports: Set[int] = field(default_factory=set)


def _safety_posture() -> Dict[str, Any]:
    """Configuración de las capas de contención ACTIVAS en este run.

    Va al `run_metadata` del informe. Un artefacto que no declara con qué
    salvaguardas se produjo no es comparable con otro: un run con
    `--no-policy` (shell directo) y otro con la política activa no ejercitan el
    mismo sistema, y hasta ahora los dos generaban informes indistinguibles.
    Declararlo convierte una nota al pie en un dato del propio artefacto.
    """
    session = _SESSION
    safety = session.safety if session is not None else None
    return {
        "policy_engine": not _NO_POLICY,
        "safety_monitor": safety is not None,
        "safety_requests_per_minute": (
            safety.requests_per_minute if safety is not None else None),
        "kill_switch_triggered": (
            bool(safety._kill_switch_triggered) if safety is not None else False),
        "kill_switch_reason": (
            getattr(safety, "kill_switch_reason", None) if safety is not None else None),
    }


# Session is attached lazily by run.py; tools look it up.
_SESSION: Optional[AgentSession] = None
_NO_POLICY: bool = False

# Tools que NO consumen del budget de SafetyMonitor (no tocan red).
# Las demás (probes, execute_*, cve_search) sí consumen.
_SAFETY_EXEMPT_TOOLS = frozenset({
    "record_finding", "record_cve_findings", "record_findings_batch_unconfirmed",
    "transition_phase", "recommend_probes", "save_report", "done",
    "audit_status",  # solo lee el estado de la sesión, no toca el objetivo
    "mac_vendor_lookup",  # lookup local de OUI, sin red
    "fingerprint_consensus",  # solo agrega evidencia previa
    "run_probes",  # wrapper: cada sub-probe hace su propio pre-check (evita doble cobro)
})


def bind_session(session: AgentSession) -> None:
    global _SESSION
    _SESSION = session


@lru_cache(maxsize=1)
def _code_revision() -> Optional[str]:
    """Hash corto del commit de código que produjo el informe (reproducibilidad,
    OE3). Devuelve None fuera de un repositorio git. Cacheado: no cambia en un run."""
    import subprocess as _sp
    try:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        out = _sp.check_output(
            ["git", "-C", root, "rev-parse", "--short", "HEAD"],
            stderr=_sp.DEVNULL, timeout=3,
        )
        rev = out.decode().strip()
        # Marca de árbol sucio: el informe no corresponde a un commit limpio.
        dirty = _sp.call(
            ["git", "-C", root, "diff", "--quiet"],
            stdout=_sp.DEVNULL, stderr=_sp.DEVNULL, timeout=3,
        )
        return f"{rev}-dirty" if dirty != 0 else rev
    except Exception:
        return None


def set_no_policy(value: bool) -> None:
    global _NO_POLICY
    _NO_POLICY = value


def get_session() -> AgentSession:
    if _SESSION is None:
        raise RuntimeError("AgentSession not bound — call bind_session first")
    return _SESSION


def set_phase(phase: str) -> None:
    """Registra la fase activa en la sesión (no-op si no hay sesión bound).

    La llaman el bucle del agente al arrancar y `transition_phase` al cambiar,
    de modo que las restricciones por fase se apliquen en la capa determinista y
    no dependan de que el modelo obedezca el prompt.
    """
    if _SESSION is not None and phase in PHASES:
        _SESSION.phase = phase


def attach_safety_monitor(open_ports: Optional[List[int]] = None,
                          requests_per_minute: int = 60,
                          latency_threshold_ms: float = 2000.0) -> None:
    """Inicializa SafetyMonitor sobre la sesión activa. Idempotente.

    El umbral se aplica a la latencia REAL del objetivo (ping ICMP, con fallback
    a `connect` TCP), no al tiempo de ejecución de las tools. 2000 ms es el valor
    documentado del sistema y el mismo que trae `SafetyMonitorV2` por defecto:
    este wrapper lo sobreescribía con 5000 ms, de modo que el umbral efectivo era
    2,5× el declarado y el kill-switch toleraba degradaciones que debía cortar.
    Exigir un mínimo de 3 muestras evita que un blip puntual aborte la auditoría.
    """
    from core.safety_monitor import SafetyMonitorV2
    session = get_session()
    if session.safety is not None:
        return
    session.safety = SafetyMonitorV2(
        target_ip=session.target_ip,
        open_ports=open_ports or [],
        requests_per_minute=requests_per_minute,
        latency_threshold_ms=latency_threshold_ms,
    )
    logger.info(f"[SAFETY] monitor activo — target={session.target_ip} "
                f"budget={requests_per_minute} req/min  "
                f"icmp_threshold={latency_threshold_ms}ms")


def attach_telemetry(session_id: Optional[str] = None) -> None:
    """Inicializa TelemetryCollector sobre la sesión activa. Idempotente."""
    from core.telemetry import TelemetryCollector
    session = get_session()
    if session.telemetry is not None:
        return
    session.telemetry = TelemetryCollector(session_id=session_id)
    logger.info(f"[TELEMETRY] collector activo — session={session.telemetry.session_id}")


# =====================================================================
# Implementaciones (adaptadores finos sobre modules/*)
# =====================================================================

def _merge_scan(prev: Optional[Dict[str, Any]], new: Dict[str, Any],
                ip: str) -> Tuple[Dict[str, Any], Optional[str]]:
    """Fusiona un nuevo escaneo con el previo del MISMO target (unión de puertos).

    Un rescan nunca debe *perder* puertos ya descubiertos: los dispositivos IoT
    frágiles (p. ej. ESP) dejan de responder ante un escaneo de rango completo
    `-sV -T4` y devuelven 0 puertos, lo que NO es la verdad de campo. Se conserva
    la unión por `(port, proto)`, se prefiere la identidad (OS/MAC) no vacía, y se
    devuelve una advertencia si el rescan encontró menos puertos que el previo
    (señal de degradación del objetivo bajo el escaneo).
    """
    if not isinstance(prev, dict) or prev.get("ip") != ip:
        return new, None
    prev_ports = prev.get("ports", []) or []
    new_ports = new.get("ports", []) or []
    by_key: Dict[Tuple[Any, Any], Dict[str, Any]] = {}
    for p in prev_ports:
        by_key[(p.get("port"), p.get("protocol"))] = p
    for p in new_ports:  # el nuevo enriquece, pero no borra
        by_key[(p.get("port"), p.get("protocol"))] = p
    merged = dict(new)
    merged["ports"] = list(by_key.values())
    # Identidad: preferir valores no vacíos (el rescan ahogado puede venir sin OS/MAC)
    for k in ("mac", "os_match", "os_cpe"):
        if not merged.get(k) or merged.get(k) == "Unknown":
            if prev.get(k) and prev.get(k) != "Unknown":
                merged[k] = prev[k]
    warning = None
    if len(new_ports) < len(prev_ports):
        warning = (f"The rescan returned {len(new_ports)} ports against "
                   f"{len(prev_ports)} in the previous scan; the target may be "
                   f"rate-limiting or saturating under the scan. The union is kept "
                   f"({len(merged['ports'])} ports); do not relaunch a full-range "
                   f"scan against this device.")
    return merged, warning


# Sistemas embebidos frágiles (pila TCP minúscula): se escanean en modo suave
# para no saturar su stack (que se cuelga y devuelve 0 puertos falsos).
_FRAGILE_OS_RE = re.compile(
    r"lwip|esp8266|esp32|espressif|freertos|micropython|contiki|mbed\s*os|nucleus|embedded",
    re.IGNORECASE)


def _is_fragile_os(os_match: Optional[str]) -> bool:
    return bool(os_match and _FRAGILE_OS_RE.search(os_match))


def _is_large_port_range(ports: Optional[str]) -> bool:
    """¿`ports` es un rango amplio (coste alto / riesgo de saturar)?"""
    if not ports or not isinstance(ports, str):
        return False
    if "65535" in ports:
        return True
    m = re.match(r"\s*(\d+)\s*-\s*(\d+)\s*$", ports)
    if m:
        return (int(m.group(2)) - int(m.group(1))) > 2000
    return ports.count(",") >= 50


def _nmap_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.recon import ReconScanner
    ip = args.get("ip") or get_session().target_ip
    ports = args.get("ports")  # optional explicit range
    prev = get_session().scan_cache
    # ¿El escaneo previo identificó un objetivo embebido frágil?
    fragile = (isinstance(prev, dict) and prev.get("ip") == ip
               and _is_fragile_os(prev.get("os_match")))
    pre_warn = None
    if fragile and _is_large_port_range(ports):
        prev_n = len(prev.get("ports", []) or [])
        pre_warn = (
            f"the target is a fragile embedded device ({prev.get('os_match')})"
            f"{' and the previous scan found no ports' if prev_n == 0 else ''}; "
            f"a wide-range scan is slow and may saturate its network stack. "
            f"Running in GENTLE MODE (rate-limited); repeating a full-range scan "
            f"against this device is not advisable.")
    scanner = ReconScanner()
    data = scanner.scan_device(ip, ports=ports, gentle=fragile)
    if not data:
        return {"ok": False, "reason": "scan returned None"}
    data, merge_warn = _merge_scan(prev, data, ip)
    warning = " | ".join(w for w in (pre_warn, merge_warn) if w) or None
    if warning:
        logger.warning(f"[RECON] {warning}")
    get_session().scan_cache = data
    # Compact representation for model context
    compact_ports = [
        {
            "port": p.get("port"), "proto": p.get("protocol"),
            "service": p.get("service_name", ""),
            "product": p.get("product", ""), "version": p.get("version", ""),
            "cpe": p.get("cpe", ""),
        }
        for p in data.get("ports", [])
    ]
    result = {
        "ok": True,
        "ip": data.get("ip"),
        "mac": data.get("mac"),
        "os_match": data.get("os_match"),
        "os_cpe": data.get("os_cpe"),
        "ports": compact_ports,
        "port_count": len(compact_ports),
    }
    if warning:
        result["warning"] = warning
    return result


def _hnap_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.hnap import hnap_probe_any
    ip = args.get("ip") or get_session().target_ip
    ports = args.get("ports") or [80, 8080, 443, 8443]
    timeout = args.get("timeout", 4)
    data = hnap_probe_any(ip, ports, timeout=timeout)
    return {"ok": bool(data), "evidence": data or {}}


def _snmp_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.snmp_probe import snmp_probe
    ip = args.get("ip") or get_session().target_ip
    communities = args.get("communities")
    data = snmp_probe(ip, communities=communities) if communities else snmp_probe(ip)
    return {"ok": bool(data), "evidence": data or {}}


def _mdns_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    """mDNS probe wrapper. Adicionalmente:
      1. Extrae model/firmware/manufacturer de las propiedades AirPlay/Bonjour
         y los inyecta en `session.scan_cache` para que device_identity los capte.
      2. Emite `vulnerabilities[]` con MDNS-EXPOSED INFO para auto-register
         (con datos limpios en raw_output: model, firmware, deviceid, serial).
    """
    from modules.discovery import mdns_probe
    ip = args.get("ip") or get_session().target_ip
    # Un único nombre de parámetro: el que declara el schema. El alias
    # `listen_seconds` no era visible para el modelo, así que era código muerto.
    listen = float(args.get("timeout") or 2.5)
    data = mdns_probe(ip, listen_seconds=listen) or []

    out: Dict[str, Any] = {
        "ok": bool(data),
        "ip": ip,
        "service": "mdns",
        "evidence": data,
        "details": {},
        "vulnerabilities": [],
    }

    # Extraer info de cada servicio mDNS encontrado
    extracted: Dict[str, Any] = {}
    for service_entry in data:
        if not isinstance(service_entry, dict):
            continue
        props = service_entry.get("properties") or {}
        # Claves típicas en AirPlay/Bonjour de devices IoT
        if props.get("model"):
            extracted.setdefault("model", props["model"])
        if props.get("manufacturer"):
            extracted.setdefault("manufacturer", props["manufacturer"])
        if props.get("fv"):  # firmware version (AirPlay)
            extracted.setdefault("firmware", props["fv"])
        if props.get("srcvers"):
            extracted.setdefault("source_version", props["srcvers"])
        if props.get("deviceid"):
            extracted.setdefault("deviceid", props["deviceid"])
        if props.get("serialNumber"):
            extracted.setdefault("serial", props["serialNumber"])
        if service_entry.get("server"):
            extracted.setdefault("hostname", service_entry["server"])
        if service_entry.get("type"):
            extracted.setdefault("service_type", service_entry["type"])
        if service_entry.get("port"):
            extracted.setdefault("service_port", service_entry["port"])

    if extracted:
        out["details"] = extracted
        # Inyectar a scan_cache para que device_identity los capture
        try:
            session = get_session()
            cache = session.scan_cache or {}
            # Solo añadir si el campo no estaba ya
            if extracted.get("model") and not cache.get("model"):
                cache["model"] = extracted["model"]
            if extracted.get("firmware") and not cache.get("firmware"):
                cache["firmware"] = extracted["firmware"]
            if extracted.get("manufacturer") and not cache.get("ssdp_manufacturer"):
                cache["ssdp_manufacturer"] = extracted["manufacturer"]
            session.scan_cache = cache
        except RuntimeError:
            pass  # session no bound (test isolation)

        # Emit vulnerability INFO para auto-register
        out["vulnerabilities"].append({
            "id": "MDNS-EXPOSED",
            "severity": "INFO",
            "description": (
                f"mDNS expone identificación del dispositivo sin auth: "
                f"model={extracted.get('model', 'n/a')} "
                f"firmware={extracted.get('firmware', 'n/a')} "
                f"hostname={extracted.get('hostname', 'n/a')}. "
                f"Útil para fingerprinting del atacante en LAN."
            ),
            "score": 1.0,
            "source": "mdns_probe",
        })
    return out


def _coap_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.discovery import coap_probe
    ip = args.get("ip") or get_session().target_ip
    data = coap_probe(ip)
    return {"ok": bool(data), "evidence": data or {}}


def _mqtt_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.mqtt_probes import MQTTProber
    ip = args.get("ip") or get_session().target_ip
    port = int(args.get("port", 1883))
    timeout = int(args.get("timeout", 5))
    raw = MQTTProber(timeout=timeout).probe_broker(ip, port)

    # Normaliza al shape común de iot_probes:
    #   {ok, ip, port, service, protocol_confirmed, vulnerabilities, details, error}
    details = {
        "anonymous_access": raw.get("anonymous_access", False),
        "wildcard_subscribe": raw.get("wildcard_subscribe", False),
        "publish_allowed": raw.get("publish_allowed", False),
        "messages_intercepted": raw.get("messages_intercepted", []),
    }
    return {
        "ok": raw.get("error") is None,
        "ip": ip,
        "port": port,
        "service": "mqtt",
        "protocol_confirmed": (
            bool(raw.get("anonymous_access"))
            or any(v.get("id") == "MQTT-AUTH-REQUIRED" for v in raw.get("vulnerabilities", []))
        ),
        "vulnerabilities": raw.get("vulnerabilities", []),
        "details": details,
        "error": raw.get("error"),
    }


def _modbus_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.iot_probes import probe_modbus
    ip = args.get("ip") or get_session().target_ip
    return probe_modbus(
        ip,
        port=int(args.get("port", 502)),
        timeout=int(args.get("timeout", 5)),
        unit_ids=args.get("unit_ids"),
    )


def _rtsp_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.iot_probes import probe_rtsp
    ip = args.get("ip") or get_session().target_ip
    return probe_rtsp(
        ip,
        ports=args.get("ports"),
        timeout=int(args.get("timeout", 5)),
    )


def _bacnet_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.iot_probes import probe_bacnet
    ip = args.get("ip") or get_session().target_ip
    return probe_bacnet(
        ip,
        port=int(args.get("port", 47808)),
        timeout=int(args.get("timeout", 3)),
    )


def _miio_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.iot_probes import probe_miio
    ip = args.get("ip") or get_session().target_ip
    return probe_miio(
        ip,
        port=int(args.get("port", 54321)),
        timeout=int(args.get("timeout", 4)),
    )


def _udp_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.iot_probes import probe_udp_raw
    ip = args.get("ip") or get_session().target_ip
    port = args.get("port")
    if not port:
        # Antes esto era `int(None)` → TypeError capturado por dispatch, que
        # devolvía "tool raised TypeError" en vez de decirle al modelo qué falta.
        return {"ok": False, "error": "port is required", "error_type": "VALIDATION"}
    return probe_udp_raw(
        ip,
        port=int(port),
        payload_hex=args.get("payload_hex"),
        proto_hint=args.get("proto_hint"),
        timeout=int(args.get("timeout", 4)),
    )


def _tcp_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.iot_probes import probe_tcp_raw
    ip = args.get("ip") or get_session().target_ip
    port = args.get("port")
    if not port:
        return {"ok": False, "error": "port is required", "error_type": "VALIDATION"}
    return probe_tcp_raw(
        ip,
        port=int(port),
        payload_hex=args.get("payload_hex"),
        proto_hint=args.get("proto_hint"),
        timeout=int(args.get("timeout", 5)),
    )


def _cwmp_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.iot_probes import probe_cwmp
    ip = args.get("ip") or get_session().target_ip
    return probe_cwmp(
        ip,
        port=int(args.get("port", 7547)),
        timeout=int(args.get("timeout", 5)),
    )


def _telnet_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.iot_probes import probe_telnet
    ip = args.get("ip") or get_session().target_ip
    return probe_telnet(
        ip,
        port=int(args.get("port", 23)),
        timeout=int(args.get("timeout", 5)),
        try_default_creds=bool(args.get("try_default_creds", True)),
        max_creds_attempts=int(args.get("max_creds_attempts", 6)),
    )


def _upnp_igd_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.iot_probes import probe_upnp_igd
    ip = args.get("ip") or get_session().target_ip
    return probe_upnp_igd(
        ip,
        timeout=int(args.get("timeout", 3)),
    )


def _wsdiscovery_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.iot_probes import probe_wsdiscovery
    ip = args.get("ip") or get_session().target_ip
    return probe_wsdiscovery(
        ip,
        port=int(args.get("port", 3702)),
        timeout=int(args.get("timeout", 3)),
    )


def _opcua_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.iot_probes import probe_opcua
    ip = args.get("ip") or get_session().target_ip
    return probe_opcua(
        ip,
        port=int(args.get("port", 4840)),
        timeout=int(args.get("timeout", 5)),
    )


def _tftp_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.iot_probes import probe_tftp
    ip = args.get("ip") or get_session().target_ip
    return probe_tftp(
        ip,
        port=int(args.get("port", 69)),
        timeout=int(args.get("timeout", 3)),
        filenames=args.get("filenames"),
    )


def _socks5_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.iot_probes import probe_socks5
    ip = args.get("ip") or get_session().target_ip
    relay_port = args.get("relay_port")
    return probe_socks5(
        ip,
        port=int(args.get("port", 1080)),
        timeout=int(args.get("timeout", 5)),
        relay_port=int(relay_port) if relay_port else None,
    )


def _lg_webos_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.iot_probes import probe_lg_webos
    ip = args.get("ip") or get_session().target_ip
    return probe_lg_webos(
        ip,
        port=int(args.get("port", 3000)),
        alt_port=int(args.get("alt_port", 3001)),
        timeout=int(args.get("timeout", 5)),
    )


def _dial_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.iot_probes import probe_dial
    ip = args.get("ip") or get_session().target_ip
    return probe_dial(
        ip,
        ports=args.get("ports"),
        timeout=int(args.get("timeout", 5)),
    )


def _chromecast_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.iot_probes import probe_chromecast
    ip = args.get("ip") or get_session().target_ip
    return probe_chromecast(
        ip,
        port=int(args.get("port", 8008)),
        timeout=int(args.get("timeout", 5)),
    )


def _ssh_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.iot_probes import probe_ssh
    ip = args.get("ip") or get_session().target_ip
    return probe_ssh(
        ip,
        port=int(args.get("port", 22)),
        timeout=int(args.get("timeout", 5)),
    )


def _ssh_credentials_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.iot_probes import probe_ssh_credentials
    ip = args.get("ip") or get_session().target_ip
    return probe_ssh_credentials(
        ip,
        port=int(args.get("port", 22)),
        usernames=args.get("usernames"),
        passwords=args.get("passwords"),
        pairs=args.get("pairs"),
        timeout=int(args.get("timeout", 6)),
        max_attempts=int(args.get("max_attempts", 8)),
    )


def _ftp_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.iot_probes import probe_ftp
    ip = args.get("ip") or get_session().target_ip
    return probe_ftp(
        ip,
        port=int(args.get("port", 21)),
        timeout=int(args.get("timeout", 5)),
    )


def _smb_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.iot_probes import probe_smb
    ip = args.get("ip") or get_session().target_ip
    return probe_smb(
        ip,
        port=int(args.get("port", 445)),
        timeout=int(args.get("timeout", 5)),
    )


def _dns_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.iot_probes import probe_dns
    ip = args.get("ip") or get_session().target_ip
    # Auto-extract dnsmasq version from scan_cache if not provided
    dnsmasq_version = args.get("dnsmasq_version") or ""
    if not dnsmasq_version:
        cache_ports = (get_session().scan_cache or {}).get("ports", [])
        for p in cache_ports:
            if isinstance(p, dict) and "dnsmasq" in (p.get("product") or "").lower():
                dnsmasq_version = p.get("version", "")
                break
    return probe_dns(
        ip,
        port=int(args.get("port", 53)),
        timeout=int(args.get("timeout", 5)),
        dnsmasq_version=dnsmasq_version or None,
    )


def _http_interrogate(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.interrogator import IoTInterrogator
    ip = args.get("ip") or get_session().target_ip
    raw_ports = args.get("ports") or [80, 443, 8080, 8443]
    # IoTInterrogator.interrogate espera List[Dict] con 'port' y 'protocol'.
    # Prioriza el cache del scan previo si existe.
    cached = (get_session().scan_cache or {}).get("ports") or []
    if cached:
        port_dicts = cached
    else:
        port_dicts = [
            {"port": int(p), "protocol": "tcp"} if isinstance(p, int) else p
            for p in raw_ports
        ]
    data = IoTInterrogator(timeout=4).interrogate(ip, port_dicts)

    # Propagar vendor identificado por http_title a scan_cache para que KB lo persista
    if data:
        title = (data.get("http_title") or "").strip()
        _TITLE_VENDORS = (
            "Netgear", "TP-Link", "D-Link", "Asus", "Linksys", "Belkin",
            "Zyxel", "MikroTik", "Ubiquiti", "Cisco", "Hikvision", "Dahua",
            "Huawei", "Tenda", "Xiaomi", "Synology", "QNAP",
        )
        detected_vendor = next(
            (v for v in _TITLE_VENDORS if v.lower() in title.lower()), None
        )
        try:
            session = get_session()
            # Cachear evidencia HTTP completa para que fingerprint_consensus la reutilice
            # sin re-ejecutar interrogator (ahorra ~4s y carga sobre el target).
            session.interrogator_evidence = data
            if detected_vendor:
                cache = session.scan_cache or {}
                if not cache.get("vendor"):
                    cache["vendor"] = detected_vendor
                session.scan_cache = cache
        except RuntimeError:
            pass  # sin sesión activa (tests)

    # Un volcado de configuración con credenciales EN CLARO se emite como
    # hallazgo por la capa determinista, no se deja a criterio del modelo.
    #
    # `unauth_data_endpoints` se devolvía solo como dato, para que el agente
    # verificase cada uno y decidiera. Es lo correcto para la mayoría —«datos
    # sin autenticación» exige juzgar si son sensibles—, pero NO para el tipo
    # `config_dump`, que por construcción del clasificador significa «una clave
    # con carga (pass/psk/secret/token) y un valor detrás». Ahí no hay nada que
    # juzgar: es exfiltración demostrada.
    #
    # Dejarlo en manos del LLM ponía la evidencia MÁS FUERTE que produce el
    # sistema —el `/config.cfg` del laboratorio sirve usuario, contraseña de
    # administrador y PSK del wifi— a merced de que se acordara de registrarla.
    # Es el mismo argumento del cuarto principio de §4.8.5.
    vulns: List[Dict[str, Any]] = []
    for endpoint in (data or {}).get("unauth_data_endpoints") or []:
        if endpoint.get("type") != "config_dump":
            continue
        vulns.append({
            "id": "HTTP-CONFIG-EXPOSED",
            "severity": "CRITICAL",
            "impact": "EXFIL",
            "description": (
                f"{endpoint.get('url')} sirve un volcado de configuración con "
                f"credenciales en claro, sin autenticación."
            ),
            "score": 9.1,
            "source": "http_interrogate",
            "url": endpoint.get("url"),
            "evidence": (endpoint.get("data_preview") or "")[:400],
        })

    result: Dict[str, Any] = {"ok": bool(data), "evidence": data or {}}
    if vulns:
        result["vulnerabilities"] = vulns
    return result


def _fingerprint_consensus(args: Dict[str, Any]) -> Dict[str, Any]:
    """Fusiona evidencia ya recolectada en un veredicto de identidad con
    confianza ponderada por fuente. Determinista (no LLM, no más probes)."""
    from modules.fingerprint import DeviceFingerprinter

    session = get_session()
    scan_cache = session.scan_cache or {}
    mac = args.get("mac") or scan_cache.get("mac")
    evidence = args.get("evidence") or session.interrogator_evidence or {}
    scan_results = args.get("scan_results") or {
        "ip": session.target_ip,
        "ports": scan_cache.get("ports", []),
        "os_match": scan_cache.get("os_match"),
        "os_cpe": scan_cache.get("os_cpe"),
        "mac": mac,
    }

    fingerprinter = DeviceFingerprinter(timeout=3, lazy_mac_lookup=True)
    consensus = fingerprinter.consensus_only(
        mac_address=mac,
        scan_results=scan_results,
        evidence=evidence,
        # OUI ya resuelto por `mac_vendor_lookup` (que tiene más capas de
        # respaldo que la librería local del fingerprinter). Solo se usa si esa
        # librería no conoce el prefijo.
        oui_vendor=scan_cache.get("oui_vendor"),
    )

    # Propagar identidad determinista al scan_cache si vendor/model están vacíos
    det = consensus.get("deterministic") or {}
    cache_updated = False
    if not scan_cache.get("vendor") and det.get("manufacturer"):
        scan_cache["vendor"] = det["manufacturer"]
        cache_updated = True
    if not scan_cache.get("model") and det.get("model"):
        scan_cache["model"] = det["model"]
        cache_updated = True
    if not scan_cache.get("firmware") and det.get("firmware_version"):
        scan_cache["firmware"] = det["firmware_version"]
        cache_updated = True
    if cache_updated:
        session.scan_cache = scan_cache

    consensus["ok"] = True
    return consensus


# OUI mini-cache para vendors IoT comunes — fallback cuando mac_vendor_lookup falla
_OUI_FALLBACK = {
    "00:1A:11": "Google",
    "F4:F5:D8": "Google",
    "FA:8F:CA": "Google (Chromecast)",
    "14:7F:67": "LG Innotek",
    "B4:E6:2D": "LG Electronics",
    "CC:2D:8C": "LG Electronics",
    "60:E3:AC": "LG Electronics",
    "00:1C:62": "LG Electronics",
    "00:5A:13": "LG Electronics",
    "00:14:C2": "Samsung",
    "00:21:19": "Samsung",
    "78:1F:DB": "Samsung",
    "C8:14:79": "Samsung",
    "28:39:5E": "Samsung",
    "00:50:F2": "Microsoft",
    "00:11:50": "Belkin",
    "C0:56:27": "Belkin (Wemo)",
    "00:17:88": "Philips Hue",
    "EC:B5:FA": "Philips Hue",
    "B0:C5:54": "D-Link",
    "00:1B:11": "D-Link",
    "00:23:69": "Cisco-Linksys",
    "C8:D7:19": "Cisco",
    "F0:9F:C2": "Ubiquiti",
    "B4:FB:E4": "Ubiquiti",
    "44:D9:E7": "Ubiquiti",
    "00:0E:C6": "ASIX (TP-Link OEM)",
    "60:E3:27": "TP-Link",
    "98:DA:C4": "TP-Link",
    "98:DE:D0": "TP-Link",
    "DC:9F:DB": "Hikvision",
    "00:0E:8E": "Hikvision",
    "44:19:B6": "Hikvision",
    "C0:51:7E": "Hikvision",
    "AC:CB:51": "Dahua",
    "3C:EF:8C": "Dahua",
    "00:80:A1": "BACnet (various)",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "98:F0:7B": "ESP / Espressif",
    "84:0D:8E": "Espressif",
    "AC:67:B2": "Espressif",
    "EC:FA:BC": "Espressif",
    "F4:CF:A2": "Espressif",
}


def _oui_fallback_lookup(mac: str) -> Optional[str]:
    if not mac or len(mac) < 8:
        return None
    prefix = mac.upper().replace("-", ":")[:8]
    return _OUI_FALLBACK.get(prefix)


_OUI_ONLINE_CACHE: Dict[str, Optional[str]] = {}


def _oui_online_lookup(mac: str) -> Optional[str]:
    """Resuelve la OUI a fabricante vía API pública, como último recurso cuando
    la base local falla. Muchas OUI de IoT muy comunes (p. ej. Tuya `B8:06:0D`)
    no están en la lib local y, sin vendor, el agente se fía del fingerprint de
    SO de nmap —que para IoT es poco fiable y puede misidentificar el dispositivo
    por completo—. Cachea por ejecución, timeout corto y tolera fallos de red."""
    if not mac or len(mac) < 8:
        return None
    prefix = mac.upper().replace("-", ":")[:8]
    if prefix in _OUI_ONLINE_CACHE:
        return _OUI_ONLINE_CACHE[prefix]
    vendor: Optional[str] = None
    try:
        import urllib.request
        req = urllib.request.Request(
            f"https://api.macvendors.com/{prefix}",
            headers={"User-Agent": "IoTSafeGuard-Agent"},
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            if getattr(resp, "status", 200) == 200:
                txt = resp.read().decode("utf-8", "replace").strip()
                # Respuesta válida = nombre corto sin marcadores de error/HTML.
                if txt and len(txt) < 200 and "<" not in txt and "error" not in txt.lower():
                    vendor = txt
    except Exception as e:  # red caída, 404, rate-limit, etc.
        logger.debug(f"[MAC] lookup online falló para {prefix}: {e}")
    _OUI_ONLINE_CACHE[prefix] = vendor
    return vendor


_MAC_VENDORS_UPDATED = False


def _mac_vendor(args: Dict[str, Any]) -> Dict[str, Any]:
    """Resuelve OUI a vendor. Si la lib local falla, intenta:
    1. update_vendors (una vez por ejecución)
    2. fallback al OUI mini-cache hardcoded
    """
    global _MAC_VENDORS_UPDATED
    from mac_vendor_lookup import MacLookup
    mac = args.get("mac")
    if not mac:
        return {"error": "mac required"}

    def _persistir(vendor: str, source: str) -> Dict[str, Any]:
        """Deja el OUI resuelto en la sesión, además de devolverlo.

        Sin esto, la resolución se entregaba al modelo y se perdía: el consenso
        de fingerprinting hace su propia consulta —solo contra la librería
        local— y el informe y la KB leen del `scan_cache`, de modo que un
        fabricante correctamente resuelto por las capas de respaldo no llegaba a
        ninguno de los tres. Se guarda bajo su propia clave, no como `vendor`,
        porque un OUI identifica al fabricante del MÓDULO de red y no siempre a
        la marca del producto: es evidencia débil (peso 0,25 en el consenso) y
        debe seguir siéndolo.
        """
        if _SESSION is not None:
            cache = _SESSION.scan_cache or {}
            cache.setdefault("oui_vendor", vendor)
            cache.setdefault("oui_vendor_source", source)
            _SESSION.scan_cache = cache
        return {"ok": True, "mac": mac, "vendor": vendor, "source": source}

    lookup = MacLookup()
    try:
        vendor = lookup.lookup(mac)
        return _persistir(vendor, "mac_vendor_lookup")
    except Exception:
        pass

    # Primer fallo: actualizar la base local una sola vez
    if not _MAC_VENDORS_UPDATED:
        try:
            lookup.update_vendors()
            _MAC_VENDORS_UPDATED = True
            try:
                vendor = lookup.lookup(mac)
                return _persistir(vendor, "mac_vendor_lookup_updated")
            except Exception:
                pass
        except Exception as e:
            logger.debug(f"[MAC] update_vendors falló: {e}")

    # Fallback al OUI hardcoded (curado, instantáneo)
    fallback = _oui_fallback_lookup(mac)
    if fallback:
        return _persistir(fallback, "oui_static_fallback")

    # Último recurso: API pública de OUI (cubre OUI de IoT ausentes en la lib).
    online = _oui_online_lookup(mac)
    if online:
        return _persistir(online, "oui_online_api")

    return {
        "ok": False, "mac": mac,
        "error": f"vendor not found for OUI {mac[:8]}",
        "source": "exhausted",
    }


# ── Local CVE family knowledge base ──────────────────────────────────────────
# Groups related CVEs that must be tested together. When any member of a family
# is found via NVD, all siblings are injected into the results automatically.
_CVE_FAMILIES: List[Dict[str, Any]] = [
    {
        "family": "LG WebOS Auth Bypass + RCE (CVE-2023-6317 to 6320)",
        "keywords": ["lg", "webos", "lgtv", "65qned", "secondscreen"],
        "members": [
            {
                "id": "CVE-2023-6317",
                "severity": "HIGH",
                "score": 7.2,
                "description": (
                    "LG WebOS 4–7: Unauthorized account addition via secondscreen.gateway "
                    "service (port 3001). Allows bypassing PIN verification to add a privileged "
                    "account. Proof: POST /api/v1/service/register returns 200 with duid."
                ),
                "poc_hint": "POST http://<TARGET_IP>:3001/api/v1/service/register with JSON body",
            },
            {
                "id": "CVE-2023-6318",
                "severity": "HIGH",
                "score": 9.1,
                "description": (
                    "LG WebOS 4–7: Command injection via processLGTVMsg after auth bypass "
                    "(CVE-2023-6317). Injects OS commands through the msg parameter. "
                    "Requires a valid client-key obtained from 6317."
                ),
                "poc_hint": "POST http://<TARGET_IP>:3001/api/v1/service/processLGTVMsg with client-key header",
            },
            {
                "id": "CVE-2023-6319",
                "severity": "HIGH",
                "score": 9.1,
                "description": (
                    "LG WebOS 4–7: OS command injection via luna-service2 (com.webos.service.appstatus). "
                    "Exploitable after auth bypass. Commands injected via JSON parameters."
                ),
                "poc_hint": "luna-send or WebSocket to com.webos.service.appstatus after obtaining client-key",
            },
            {
                "id": "CVE-2023-6320",
                "severity": "HIGH",
                "score": 9.1,
                "description": (
                    "LG WebOS 4–7: Authenticated command injection via "
                    "com.webos.service.connectionmanager/tv/setVlanStaticAddress. "
                    "Requires valid client-key from CVE-2023-6317."
                ),
                "poc_hint": "POST to connectionmanager/tv/setVlanStaticAddress with injected network params",
            },
        ],
    },
]


def _enrich_with_families(cves: List[Dict], keyword: str, cpe: Optional[str]) -> List[Dict]:
    """Inject full CVE family when any family keyword or member CVE matches."""
    needle = (keyword or "").lower() + " " + (cpe or "").lower()
    injected_ids = {c["id"] for c in cves}
    extras: List[Dict] = []

    for family in _CVE_FAMILIES:
        # Match by keyword OR by finding an existing member in results
        member_ids = {m["id"] for m in family["members"]}
        keyword_hit = any(kw in needle for kw in family["keywords"])
        member_hit = bool(injected_ids & member_ids)

        if keyword_hit or member_hit:
            member_by_id = {m["id"]: m for m in family["members"]}
            for m in family["members"]:
                if m["id"] not in injected_ids:
                    extras.append({
                        "id": m["id"],
                        "severity": m["severity"],
                        "score": m["score"],
                        "description": m["description"],
                        "poc_hint": m.get("poc_hint", ""),
                        "source": "local_kb",
                    })
                    injected_ids.add(m["id"])
            for cve in cves:
                if cve["id"] in member_ids and "poc_hint" not in cve:
                    cve["poc_hint"] = member_by_id[cve["id"]].get("poc_hint", "")
                    cve["source"] = "nvd+local_kb"

    return cves + extras


def _web_login_success_side_effects(
    ip: str, port: int, username: str, password: str, cookie: str, result: Dict[str, Any]
) -> None:
    """Al autenticar con éxito: guarda credencial en session + emite WEAK-CREDENTIALS finding."""
    try:
        sess = get_session()
        sess.credentials.append({
            "ip": ip, "port": str(port), "service": "http",
            "username": username, "password": password,
        })
    except RuntimeError:
        pass  # test isolation

    result["vulnerabilities"] = [{
        "id": "WEAK-CREDENTIALS",
        "severity": "CRITICAL",
        "score": 9.8,
        "description": (
            f"Web interface authenticated with default credentials "
            f"({username}:{password}) on {ip}:{port}. "
            f"Full admin session obtained (session_cookie present)."
        ),
        "source": "web_login",
    }]


def _web_login(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Intenta autenticación en la interfaz web del dispositivo.

    Flujo (en orden):
      1. GET /login.php?username=X&password=Y  → "loginok" | "sessionexists" | "restricted"
         - sessionexists → GET /recreate.php para terminar la sesión previa → reintenta
      2. POST /login.php con form-data (fallback)
      3. POST /login con form-data (fallback genérico)

    Devuelve session_cookie lista para usar en curl: -H "Cookie: PHPSESSID=..."
    """
    import random
    import requests as _req

    ip = args.get("ip") or get_session().target_ip
    username = args.get("username", "admin")
    password = args.get("password", "password")
    port = int(args.get("port", 80))
    scheme = args.get("scheme", "https" if port in (443, 8443) else "http")
    timeout = int(args.get("timeout", 10))
    base = f"{scheme}://{ip}:{port}"

    session = _req.Session()
    session.verify = False

    def _cookie_str() -> str:
        phpsessid = session.cookies.get("PHPSESSID", "")
        if phpsessid:
            return f"PHPSESSID={phpsessid}"
        # Return all cookies as a flat string for non-PHP stacks
        return "; ".join(f"{k}={v}" for k, v in session.cookies.items())

    rand_id = random.randint(10000, 99999)

    # ── Strategy 1: Netgear-style GET /login.php ─────────────────────────────
    try:
        r = session.get(
            f"{base}/login.php",
            params={"username": username, "password": password, "id": rand_id},
            timeout=timeout,
            allow_redirects=False,
        )
        body = r.text.strip()

        if body == "loginok":
            cookie = _cookie_str()
            result = {
                "ok": True,
                "method": "GET /login.php",
                "session_cookie": cookie,
                "note": f"Authenticated as {username}. Use: curl -H 'Cookie: {cookie}'",
            }
            _web_login_success_side_effects(ip, port, username, password, cookie, result)
            return result

        if body == "sessionexists":
            # Kill the old session and get a fresh auth cookie
            r2 = session.get(
                f"{base}/recreate.php",
                params={"username": username, "password": password, "id": rand_id + 1},
                timeout=timeout,
            )
            if r2.text.strip() == "recreateok":
                cookie = _cookie_str()
                result = {
                    "ok": True,
                    "method": "GET /login.php + recreate.php",
                    "session_cookie": cookie,
                    "note": (
                        f"Previous session terminated. Authenticated as {username}. "
                        f"Use: curl -H 'Cookie: {cookie}'"
                    ),
                }
                _web_login_success_side_effects(ip, port, username, password, cookie, result)
                return result
            return {
                "ok": False,
                "method": "GET /login.php",
                "session_cookie": "",
                "note": f"sessionexists; recreate.php returned: {r2.text.strip()[:80]}",
            }

        if body == "restricted":
            return {
                "ok": False,
                "method": "GET /login.php",
                "session_cookie": "",
                "note": "Admin already logged in — access restricted. Try later.",
            }

    except _req.RequestException:
        pass  # fall through to generic strategies

    # ── Strategy 2: POST /login.php (common PHP form) ─────────────────────────
    for endpoint in ("/login.php", "/login", "/admin/login", "/cgi-bin/login"):
        try:
            r = session.post(
                f"{base}{endpoint}",
                data={"username": username, "password": password},
                timeout=timeout,
                allow_redirects=True,
            )
            body = r.text.strip()
            # Heuristic: if we were redirected away from the login page, auth likely succeeded
            final_url = r.url
            if r.status_code == 200 and "login" not in final_url.lower() and len(body) > 100:
                cookie = _cookie_str()
                if cookie:
                    return {
                        "ok": True,
                        "method": f"POST {endpoint}",
                        "session_cookie": cookie,
                        "note": f"POST login may have succeeded. Use: curl -H 'Cookie: {cookie}'",
                    }
        except _req.RequestException:
            continue

    # Agotadas las estrategias conocidas, el sistema hace por su cuenta lo que
    # antes se le PEDÍA al modelo: bajar la raíz, leer los formularios y minar
    # el JavaScript en busca del endpoint real de autenticación. La instrucción
    # se emitía aquí mismo y en el prompt, y en la tanda del 2026-08-08 el
    # modelo la ignoró en las 4 ejecuciones en que se dio la condición. Un paso
    # mecánico omitido de forma sistemática no es una decisión: es código que
    # falta. Devuelve datos observados; qué hacer con ellos lo sigue eligiendo
    # el agente.
    discovery: Dict[str, Any] = {}
    try:
        from modules.interrogator import discover_login_mechanism
        discovery = discover_login_mechanism(base, timeout=timeout)
    except Exception as e:
        logger.debug(f"[WEB_LOGIN] descubrimiento de login omitido: {e}")

    forms = discovery.get("login_forms") or []
    endpoints = discovery.get("login_endpoints") or []
    if forms or endpoints:
        note = (
            "Could not authenticate with any known strategy, so the page and its "
            "JavaScript were fetched and parsed for you — see `login_discovery`. "
            "Build the request against `action`/`login_endpoints` with the field "
            "names given, via execute_command in exploit phase. The parse is "
            "regex-based: `html_evidence` carries what was actually served, so "
            "check it if the extracted fields look wrong."
        )
    else:
        note = (
            "Could not authenticate with any known strategy. The page and its "
            "JavaScript were fetched, but the deterministic parser found no login "
            "form or auth endpoint. That is a HINT, NOT a verdict — it misses "
            "unquoted attributes, unusual attribute order and JS-rendered panels. "
            "Read `login_discovery.html_evidence` yourself: if there is a form in "
            "there, drive it. Only conclude there is no web login once YOU have "
            "looked at that evidence."
        )

    return {
        "ok": False,
        "method": "all_failed",
        "session_cookie": "",
        "login_discovery": discovery or None,
        "note": note,
    }


def _enrich_with_pocs(cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Inyecta poc_template + verification_hint del KB local en cada CVE.

    Dos secciones complementarias:

    * `poc_template` — descripción estructurada (protocol, endpoint, payload,
      success/failure indicators) para validación programática.
    * `verification_hint` — receta narrativa que el agente sigue para evitar
      "redescubrir" la verificación con vectores distintos en cada run. Incluye
      `verification_steps`, `implies_cves` (CVEs que se confirman con la misma
      evidencia) e `implied_by` (CVE padre cuya confirmación basta).

    El agente debe seguir `verification_hint.verification_steps` cuando esté
    presente, en lugar de improvisar — esto neutraliza la variabilidad LLM
    observada empíricamente entre runs.
    """
    from modules.cve_pocs import get_poc
    enriched: List[Dict[str, Any]] = []
    for c in cves:
        poc = get_poc(c.get("id", ""))
        if poc:
            c = dict(c)
            template = {
                "protocol": poc.get("protocol"),
                "endpoint": poc.get("endpoint"),
                "default_port": poc.get("default_port"),
                "method": poc.get("method"),
                "query_string": poc.get("query_string"),
                "payload": poc.get("payload"),
                "payload_template": poc.get("payload_template"),
                "expect_n_messages": poc.get("expect_n_messages"),
                "success_indicators": poc.get("success_indicators"),
                "failure_indicators": poc.get("failure_indicators"),
                "depends_on": poc.get("depends_on"),
                "reference": poc.get("reference"),
            }
            c["poc_template"] = {k: v for k, v in template.items() if v is not None}

            hint = {
                "verification_steps": poc.get("verification_steps"),
                "implies_cves": poc.get("implies_cves"),
                "implied_by": poc.get("implied_by"),
            }
            hint = {k: v for k, v in hint.items() if v}
            if hint:
                c["verification_hint"] = hint

            c["poc_available"] = True
        enriched.append(c)
    return enriched


def _parse_version_tuple(v: str):
    """Convierte "2016.74" o "1.4.18" a tupla comparable (2016, 74, 0) / (1, 4, 18)."""
    import re
    parts = re.split(r"[.\-]", v.strip().lstrip("v"))
    result = []
    for p in parts[:4]:
        try:
            result.append(int(p))
        except ValueError:
            break
    return tuple(result) if result else None


def _extract_model_hint(description: str) -> Optional[str]:
    """Extrae el primer código de modelo específico de una descripción CVE.

    Busca tokens que parezcan números de modelo de hardware: 2-6 letras mayúsculas
    seguidas de 3+ dígitos (ej: WNR2000v5, DGN2200, WNDR4700, MR1100, WNAP320).
    Excluye siglas técnicas comunes para evitar falsos positivos.

    Agnostico de vendor: el mismo patrón funciona para Netgear, TP-Link, D-Link,
    Hikvision, Dahua, etc.
    """
    import re
    _TECH_SIGLAS = frozenset({
        "HTTP", "HTTPS", "SSH", "CGI", "PHP", "SQL", "XML", "API", "URL",
        "LAN", "WAN", "VPN", "DNS", "NTP", "UDP", "TCP", "MAC", "OID",
        "CVSS", "NVD", "CVE", "CWE", "CPE", "RCE", "XSS", "XXE", "SSRF",
        "CSRF", "CORS", "TLS", "SSL", "FTP", "SFTP", "SMTP", "SNMP",
        "HNAP", "UPNP", "SSDP", "DHCP", "ICMP", "OSPF", "BGP",
    })
    pat = re.compile(r'\b([A-Z]{2,6}\d{3,}[a-zA-Z0-9]*)\b')
    for m in pat.finditer(description):
        token = m.group(1)
        if token.upper() not in _TECH_SIGLAS:
            return token
    return None


def _annotate_model_specificity(cves: list) -> list:
    """Añade `model_hint` y `model_specific` a CVEs que nombran un modelo concreto.

    Si la descripción menciona un código de modelo hardware específico, el CVE
    probablemente solo afecta a ese modelo. El agente debe verificar si el
    dispositivo objetivo coincide antes de intentar el exploit.
    """
    annotated = []
    for cve in cves:
        desc = cve.get("description") or ""
        hint = _extract_model_hint(desc)
        c = dict(cve)
        if hint:
            c["model_hint"] = hint
            c["model_specific"] = True
        annotated.append(c)
    return annotated


def _annotate_version_applicability(cves: list, device_version: str) -> list:
    """Añade `likely_patched` y `version_note` a CVEs cuya descripción indica
    que la versión del dispositivo ya no es vulnerable.

    Patrones reconocidos en descripción:
      - "before X.Y.Z"  / "prior to X.Y.Z"  → device_version >= X.Y.Z → parcheado
      - "through X.Y.Z" / "up to X.Y.Z"     → device_version <= X.Y.Z → VULNERABLE
      - "X.Y.Z and earlier"                  → device_version <= X.Y.Z → VULNERABLE
    """
    import re
    if not device_version:
        return cves

    dev_ver = _parse_version_tuple(device_version)
    if not dev_ver:
        return cves

    # Patrones "before/prior to" — si device >= fixed_ver → parcheado
    pat_before = re.compile(
        r"(?:before|prior to|earlier than)\s+v?([\d][\d.\-]+[\d])",
        re.IGNORECASE,
    )
    # Patrones "through/up to/and earlier" — si device <= vuln_ver → vulnerable
    pat_through = re.compile(
        r"(?:through|up to|and earlier|and before)\s+v?([\d][\d.\-]+[\d])",
        re.IGNORECASE,
    )

    annotated = []
    for cve in cves:
        desc = cve.get("description") or ""
        note = None
        patched = False

        for m in pat_before.finditer(desc):
            fixed_ver = _parse_version_tuple(m.group(1))
            if fixed_ver and dev_ver >= fixed_ver:
                patched = True
                note = (
                    f"PATCHED VERSION: the description says 'before {m.group(1)}', "
                    f"the device has {device_version} (>= the fixed version). "
                    f"Confirm with a PoC before recording it."
                )
                break

        if not patched:
            for m in pat_through.finditer(desc):
                vuln_ver = _parse_version_tuple(m.group(1))
                if vuln_ver and dev_ver <= vuln_ver:
                    note = (
                        f"POTENTIALLY VULNERABLE VERSION: the description says 'through {m.group(1)}', "
                        f"the device has {device_version} (<= the affected version). "
                        f"Prioritise testing it."
                    )
                    break

        c = dict(cve)
        if patched:
            c["likely_patched"] = True
        if note:
            c["version_note"] = note
        annotated.append(c)
    return annotated


_GENERIC_CVE_KEYWORD_TOKENS = frozenset({
    # Palabras genéricas (no product/vendor): producen CVEs de vendors aleatorios.
    "router", "vulnerability", "vulnerabilities", "credentials", "device",
    "embedded", "exploit", "rce", "default", "interface", "web", "iot",
    "firmware", "authentication", "auth", "bypass", "hardcoded",
    "injection", "command", "disclosure", "information",
    "remote", "code", "execution", "overflow", "buffer", "stack", "memory",
    "dos", "denial", "service", "amplification", "spoofing", "attack",
    "unauthenticated", "open", "proxy", "server", "network", "string",
    "community", "protocol", "linux", "kernel", "embedded",
    # Acrónimos de PROTOCOLO (no son productos: la implementación sí lo es —
    # net-snmp, ntpd, libcoap…). Buscar el protocolo a secas = ruido cross-vendor.
    "snmp", "tftp", "ntp", "netbios", "l2tp", "ipsec", "isakmp", "ike",
    "coap", "ssdp", "mdns", "upnp", "dhcp", "socks", "socks5", "smb",
    "telnet", "ftp", "http", "https", "dns", "mqtt", "rtsp",
})


def _is_generic_cve_keyword(keyword: str) -> bool:
    """True si el keyword no contiene ningún token product/vendor-específico.

    Heurística: si TODOS los tokens del keyword están en _GENERIC_CVE_KEYWORD_TOKENS,
    la búsqueda devolverá CVEs de vendors aleatorios (TP-Link, NETGEAR, Cisco…) y
    el agente acabará registrando hallazgos para vendors que no son el target.
    Empíricamente observado: "router default credentials", "router web interface
    vulnerability", "hardcoded credentials device" → 30+ findings basura por run.
    """
    if not keyword:
        return False
    tokens = [t for t in keyword.lower().split() if t]
    if not tokens:
        return False
    return all(t in _GENERIC_CVE_KEYWORD_TOKENS for t in tokens)


_OS_KERNEL_RE = re.compile(r"\b(linux\s+kernel|linux_kernel|kernel)\b", re.IGNORECASE)
_OS_RANGE_RE = re.compile(r"(\d+(?:\.\d+)*)\s*-\s*(\d+(?:\.\d+)*)")


def _reject_os_range_kernel_search(keyword: str, version: str,
                                   nmap_cpe: Optional[str]) -> Optional[Dict[str, Any]]:
    """Rechaza buscar CVEs del kernel cuando la versión sale del RANGO de nmap.

    La detección de SO de nmap no devuelve una versión, devuelve un intervalo:
    `Linux 3.2 - 4.9`, `Linux 2.6.31 - 2.6.35`. Tomar un extremo como si fuera
    «la versión» y barrer el kernel entero produjo, en campo, entre 15 y 23 CVEs
    de 2009 probados de uno en uno. Cero confirmados en 38 intentos, porque son
    fallos locales del kernel y aquí solo hay acceso remoto — cosa que el propio
    agente razonaba bien antes de descartarlos en bloque.

    El coste no era el acierto sino la consistencia: ese barrido solo se dispara
    en algunas réplicas, y es el causante principal de la varianza medida (mismo
    router: 4, 4, 8, 8 y 23 hallazgos; mismo televisor: 6 y 34).

    La regla es general y honesta: **un rango de fingerprint no es una versión**.
    Un kernel leído de un banner o de `sysDescr` por SNMP sí lo es, y ese sigue
    pasando: solo se rechaza cuando la versión pedida coincide con un extremo
    del rango que nmap dejó en el `scan_cache`.
    """
    if not _OS_KERNEL_RE.search(f"{keyword} {nmap_cpe or ''}"):
        return None
    os_match = ((get_session().scan_cache or {}).get("os_match") or "")
    m = _OS_RANGE_RE.search(os_match)
    if not m:
        return None
    lo, hi = m.group(1), m.group(2)
    pedido = (version or "").strip() or keyword
    if not any(pedido.startswith(v) or v.startswith(pedido) for v in (lo, hi) if v):
        return None
    return {
        "ok": False,
        "keyword": keyword,
        "count": 0,
        "cves": [],
        "error": "os_fingerprint_range_is_not_a_version",
        "note": (
            f"nmap did not report a kernel version, it reported the RANGE "
            f"'{os_match}'. Taking '{pedido}' out of it is a guess, and sweeping "
            f"kernel CVEs from a guess yields dozens of local-privilege findings "
            f"that no remote test can confirm. If a probe gives you a REAL kernel "
            f"version (SNMP sysDescr, an HTTP banner, a config dump), search for "
            f"that one instead. Otherwise spend the turns on the services that "
            f"are actually exposed."
        ),
    }


def _cve_search(args: Dict[str, Any]) -> Dict[str, Any]:
    import re as _re
    from modules.cve_api import NVDCVEClient
    keyword = args.get("keyword")
    version = args.get("version") or ""
    nmap_cpe = args.get("cpe") or None
    if not keyword and not nmap_cpe:
        return {"error": "keyword or cpe required"}

    # Guard contra keywords genéricos que solo generan ruido vendor-spray.
    if keyword and not nmap_cpe and _is_generic_cve_keyword(keyword):
        return {
            "ok": False,
            "keyword": keyword,
            "count": 0,
            "cves": [],
            "error": "generic_keyword_rejected",
            "note": (
                f"'{keyword}' is too generic: it would return CVEs from random "
                "vendors. Refine it with the exact vendor/product detected by nmap "
                "(e.g. 'D-Link DIR-815', 'Dropbear SSH 2019.78', 'dnsmasq 2.45'). "
                "If you need to explore further, use the CPE from scan_cache (the "
                "`cpe` field on each port)."
            ),
        }

    # Guard contra el barrido de CVEs del kernel a partir del rango de nmap.
    rejected = _reject_os_range_kernel_search(keyword or "", version, nmap_cpe)
    if rejected:
        return rejected

    client = NVDCVEClient(api_key=os.getenv("NVD_API_KEY"))
    raw = client.get_cves_for_product(keyword or "", version, nmap_cpe=nmap_cpe) or []

    # Auto-broaden: if 0 results and keyword embeds a version number (e.g. "dnsmasq 2.45"),
    # retry with just the product name. This prevents non-deterministic behaviour where the
    # agent independently invents broader queries in some runs but not others.
    if not raw and keyword and not version:
        _ver_suffix = _re.search(r"\s+[\d][\d.]*$", keyword)
        if _ver_suffix:
            broader = keyword[: _ver_suffix.start()].strip()
            if len(broader) >= 4:
                raw = client.get_cves_for_product(broader, "", nmap_cpe=nmap_cpe) or []
                if raw:
                    keyword = broader  # reflect actual search term in response

    cves = [
        {
            "id": c.get("id"),
            "severity": c.get("severity"),
            "score": c.get("score"),
            "description": (c.get("description") or "")[:400],
        }
        for c in raw[:20]
    ]
    cves = _enrich_with_families(cves, keyword or "", nmap_cpe)
    cves = _enrich_with_pocs(cves)
    cves = _annotate_version_applicability(cves, version)
    cves = _annotate_model_specificity(cves)

    hinted = [c["id"] for c in cves if "verification_hint" in c]
    model_specific = [c["id"] for c in cves if c.get("model_specific")]
    response: Dict[str, Any] = {
        "ok": True,
        "keyword": keyword,
        "version": version,
        "cpe": nmap_cpe,
        "count": len(cves),
        "cves": cves,
        "note": "Includes local CVE family knowledge base entries (source=local_kb).",
    }
    instructions: List[str] = []
    if hinted:
        instructions.append(
            f"{len(hinted)} CVE(s) have a verification_hint in the local KB "
            f"({hinted}). You MUST follow verification_hint.verification_steps "
            "literally before improvising other vectors: those steps are documented "
            "because alternative vectors produce false negatives. If the evidence "
            "confirms a CVE listed in another one's implies_cves, record them all "
            "with the same raw_output."
        )
    if model_specific:
        instructions.append(
            f"{len(model_specific)} CVE(s) carry a `model_hint` (a specific HW model "
            f"different from the target): {model_specific}. "
            "Do NOT record them with record_finding: they are out of scope. Only "
            "record findings when (a) the CVE matches the target's vendor/model, or "
            "(b) you ran a test and obtained evidence (positive or negative)."
        )
    # Enriquecimiento Exploit-DB: por cada CVE encontrado por NVD, buscar PoCs
    # publicados en Exploit-DB via searchsploit. Adjunta el resultado en
    # `exploit_db_pocs` dentro de cada CVE individual. NVD encuentra la
    # vulnerabilidad, Exploit-DB aporta el código de explotación.
    cves = _enrich_with_exploit_db_pocs(cves)
    pocs_count = sum(len(c.get("exploit_db_pocs") or []) for c in cves)
    if pocs_count > 0:
        instructions.append(
            f"{pocs_count} external PoC(s) found in Exploit-DB (the "
            "`exploit_db_pocs` field on each CVE). They have lower coverage than the "
            "local KB (`verification_hint`): use them when the CVE has NO "
            "verification_hint, or when the KB steps fail."
        )

    if instructions:
        response["instruction"] = " ".join(instructions)
    return response


_CVE_VER_SLASH = re.compile(r"([A-Za-z][A-Za-z0-9_+\-]{1,30})/(\d+(?:\.\d+)+)")
_CVE_VER_WORD = re.compile(
    r"\b([A-Za-z][A-Za-z0-9_+\-]{1,30})\s+(?:v(?:ersion)?\.?\s*)?(\d+\.\d+(?:\.\d+)*)\b",
    re.IGNORECASE,
)


def _components_for_cve_scan(ports: List[Dict[str, Any]], http_server: str) -> List[Dict[str, Any]]:
    """Extrae componentes software CVE-relevantes del scan, DESCARTANDO los guesses
    de servicio de nmap sin versión (`nagios-nsca`, `mbap`, `IDentifier NameTracer
    Pro httpd`, `nginx` a secas…) que solo generan ruido.

    Regla: un componente entra SOLO si tiene CPE o una versión concreta. Eso hace el
    barrido preciso y reproducible. Además parsea el header `Server:` (http_server),
    que delata el stack web versionado (RomPager/4.07, Boa/0.94.13) que nmap no pone
    en los campos por-puerto.
    """
    comps: List[Dict[str, Any]] = []
    seen: set = set()

    # Tokens que parecen "producto/versión" pero son protocolos/genéricos → no CVE-buscables.
    _NON_PRODUCT = {"upnp", "http", "https", "dlna", "mime", "ssl", "tls", "tcp", "udp"}

    def add(product: str, version: str, cpe: Optional[str], port, source: str) -> None:
        prod = (product or "").strip()
        # Filtro clave: sin CPE y sin (producto + versión) → ruido, se descarta.
        if not cpe and not (prod and version):
            return
        if prod.lower() in _NON_PRODUCT:
            return
        key = (prod.lower(), version or "", cpe or "")
        if key in seen:
            return
        seen.add(key)
        comps.append({"product": prod or None, "version": version or None,
                      "cpe": cpe, "port": port, "source": source})

    for p in ports:
        if not isinstance(p, dict):
            continue
        cpe = p.get("cpe")
        product = p.get("product") or ""
        version = p.get("version") or ""
        if cpe:
            add(product or p.get("service") or "", version, cpe, p.get("port"), "nmap_cpe")
            continue
        if product and version:
            add(product, version, None, p.get("port"), "nmap_product")
            continue
        # Extraer "name/X.Y" o "name version X.Y" del blob producto/servicio (p. ej.
        # nmap a veces mete "mosquitto version 2.1.2" en el campo service).
        blob = product or p.get("service") or ""
        m = _CVE_VER_SLASH.search(blob) or _CVE_VER_WORD.search(blob)
        if m:
            add(m.group(1), m.group(2), None, p.get("port"), "nmap_banner")

    # Header Server: "nginx, RomPager/4.07 UPnP/1.0, Boa/0.94.13" → componentes versionados.
    for m in _CVE_VER_SLASH.finditer(http_server or ""):
        add(m.group(1), m.group(2), None, None, "http_server")

    return comps


def _cve_scan_recon(args: Dict[str, Any]) -> Dict[str, Any]:
    """Búsqueda CVE DETERMINISTA desde el `scan_cache`.

    Extrae los componentes software con CPE o versión concreta (descartando los
    guesses de servicio sin versión de nmap, que solo dan ruido) y busca CVEs por
    CPE/versión vía virtualMatchString — SIN que el LLM elija keywords. Mismo scan →
    mismo set de CVEs (reproducible). Deduplica por cve_id. Complementa `cve_search`.
    """
    from modules.cve_api import NVDCVEClient
    session = get_session()
    scan = session.scan_cache or {}
    ports = scan.get("ports") or []
    if not ports:
        return {"ok": False, "error": "no scan_cache; run nmap_scan first",
                "cves": [], "total_cves": 0}

    http_server = (session.interrogator_evidence or {}).get("http_server") or ""
    components = _components_for_cve_scan(ports, http_server)
    if not components:
        return {"ok": True, "deterministic": True, "components_scanned": 0,
                "total_cves": 0, "cves": [], "by_component": [],
                "note": ("No component with a reliable CPE or version in the scan "
                         "(nmap only produced service guesses). Use a targeted "
                         "cve_search with the product+version the probes confirm.")}

    client = NVDCVEClient(api_key=os.getenv("NVD_API_KEY"))
    seen: Dict[str, Dict[str, Any]] = {}
    by_component: List[Dict[str, Any]] = []
    for comp in components:
        # allow_broad_keyword=False: barrido determinista solo por CPE o producto+versión
        # concretos. Evita el keyword versionless (nginx → ruido de ecosistema).
        raw = client.get_cves_for_product(
            comp["product"] or "", comp["version"] or "", nmap_cpe=comp["cpe"],
            allow_broad_keyword=False) or []
        ids: List[str] = []
        for c in raw:
            cid = c.get("id")
            if cid and cid not in seen:
                seen[cid] = c
                ids.append(cid)
        by_component.append({**comp, "cve_ids": ids})

    cves = sorted(seen.values(), key=lambda c: c.get("score", 0) or 0, reverse=True)
    # Enriquecer con el KB local (verification_hint) — mismo enriquecimiento que
    # cve_search. Sin esto, los CVEs del barrido determinista llegan SIN la receta
    # de verificación y el agente improvisa rutas (p.ej. CVE-2021-33558 → curleaba
    # /cgi-bin/webproc en vez de /backup.html, descartándolo en falso).
    cves = _enrich_with_pocs(cves)
    return {
        "ok": True,
        "deterministic": True,
        "components_scanned": len(components),
        "components": [f"{c['product']} {c['version'] or ''}".strip() for c in components],
        "total_cves": len(cves),
        "cves": cves[:40],
        "by_component": by_component,
        "note": ("Deterministic CPE/version sweep from scan_cache (reproducible, with no "
                 "noise from services that carry no version). Record candidates with "
                 "record_cve_findings and test them in the exploit phase."),
    }


# Cache de detección del binario para no spammear warnings cuando no está instalado
_SEARCHSPLOIT_AVAILABLE: Optional[bool] = None


def _searchsploit_is_available() -> bool:
    """Cachea la primera detección: si el binario no está, evitamos los 20
    subprocess.run que generarían 20 warnings idénticos."""
    global _SEARCHSPLOIT_AVAILABLE
    if _SEARCHSPLOIT_AVAILABLE is not None:
        return _SEARCHSPLOIT_AVAILABLE
    import shutil
    _SEARCHSPLOIT_AVAILABLE = shutil.which("searchsploit") is not None
    if not _SEARCHSPLOIT_AVAILABLE:
        logger.info("[CVE] searchsploit no encontrado — enriquecimiento Exploit-DB "
                    "desactivado. Instala con: sudo apt install exploitdb")
    return _SEARCHSPLOIT_AVAILABLE


def _enrich_with_exploit_db_pocs(cves: List[Dict[str, Any]],
                                  max_lookups: int = 10,
                                  max_pocs_per_cve: int = 3) -> List[Dict[str, Any]]:
    """Por cada CVE en la lista (top `max_lookups`), consulta searchsploit por
    su cve_id y adjunta los PoCs encontrados como `exploit_db_pocs`.

    Diseño:
      • Solo busca por `CVE-XXXX-YYYY` directo (no por keyword/cpe) — esto
        garantiza que cada PoC esté realmente asociado a esa vulnerabilidad.
      • No-op silencioso si searchsploit no está instalado (caché por proceso).
      • Cap de `max_lookups` para no disparar 20 subprocess.run en cve_search
        que devuelve 20 resultados. Los top CVEs (más relevantes según NVD)
        son los que más interés tienen en explotarse.
      • Cap de `max_pocs_per_cve` para no inflar el contexto del LLM.
    """
    if not cves or not _searchsploit_is_available():
        return cves
    try:
        from modules.searcher import SearchsploitClient
    except ImportError:
        return cves

    client = SearchsploitClient(timeout=6)
    for cve in cves[:max_lookups]:
        cve_id = cve.get("id") or ""
        if not cve_id.startswith("CVE-"):
            continue
        try:
            # Buscar por el CVE ID exacto — searchsploit indexa el campo "CVE"
            # de cada exploit, así que un match aquí es por relación directa.
            pocs = client.search(cpe=None, keywords=[cve_id], limit=max_pocs_per_cve) or []
        except Exception as e:
            logger.debug(f"[CVE] exploit-db lookup falló para {cve_id}: {e}")
            continue
        if pocs:
            # Compactar: solo metadatos útiles para que el LLM decida si descargar
            # el exploit completo via execute_command + curl.
            cve["exploit_db_pocs"] = [
                {
                    "edb_id": p.get("edb_id"),
                    "title": p.get("title"),
                    "path": p.get("path"),
                    "date": p.get("date"),
                    "match_score": p.get("match_score"),
                }
                for p in pocs
            ]
    return cves


_HTTP_401_PATTERNS = (
    "HTTP/1.1 401", "HTTP/1.0 401", "401 Unauthorized",
    "WWW-Authenticate:", "401 Authorization Required",
)
_HTTP_403_PATTERNS = (
    "HTTP/1.1 403", "HTTP/1.0 403", "403 Forbidden",
)
# Default creds para auto-retry post-401. Solo las más comunes para no lockear cuentas.
_AUTO_LOGIN_CREDS = (
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
)


def _detect_auth_required(output: str) -> Optional[str]:
    """Inspecciona output de curl/etc. y devuelve hint si detecta 401/403."""
    if not output:
        return None
    head = output[:1024]
    if any(p in head for p in _HTTP_401_PATTERNS):
        return (
            "The endpoint returned HTTP 401 Unauthorized. "
            "ACTION: the agent already tried an auto-retry with default credentials; "
            "if it did not, or it failed, call "
            "`web_login(ip, username='admin', password='password')` (also try "
            "admin/admin, root/root) and retry with `-H 'Cookie: <session_cookie>'`."
        )
    if any(p in head for p in _HTTP_403_PATTERNS):
        return (
            "The endpoint returned HTTP 403 Forbidden. "
            "ACTION: if you already have a session from web_login, try a different "
            "user. If you have no session, call web_login first. Also consider "
            "referer headers or the legitimate client's specific User-Agent."
        )
    return None


_CURL_URL_RE = re.compile(r"https?://([0-9a-zA-Z\-_.]+)(?::(\d+))?(/[^\s'\"]*)?")


def _extract_curl_target(cmd: str) -> Optional[Tuple[str, int]]:
    """Extrae (host, port) de un comando curl/nc. Devuelve None si no se puede."""
    m = _CURL_URL_RE.search(cmd)
    if m:
        host = m.group(1)
        port_s = m.group(2)
        scheme_https = cmd.lower().split(host, 1)[0].rstrip(":/").endswith("https")
        try:
            port = int(port_s) if port_s else (443 if scheme_https else 80)
            return host, port
        except ValueError:
            return None
    return None


def _check_ws_endpoint_guard(cmd: str) -> Optional[Dict[str, Any]]:
    """Pre-flight: si el cmd targets un endpoint confirmado como WebSocket-only,
    rechaza inmediatamente con redirect a `execute_websocket`.

    Evita timeouts de 60-120s donde curl HTTP/HTTPS queda colgado esperando
    respuesta de un servidor que solo habla WebSocket Upgrade.
    """
    if _SESSION is None or not _SESSION.ws_confirmed_endpoints:
        return None
    target = _extract_curl_target(cmd)
    if not target:
        return None
    if target in _SESSION.ws_confirmed_endpoints:
        host, port = target
        scheme = "wss" if any(t in cmd for t in ("https://", " --insecure", " -k")) else "ws"
        return {
            "ok": False,
            "error_type": "WS_ENDPOINT_NOT_HTTP",
            "error": (
                f"Endpoint {host}:{port} was confirmed WebSocket-only by "
                f"probe_lg_webos (successful WS upgrade handshake). An HTTP/HTTPS "
                f"curl would hang until the timeout. It is NOT executed."
            ),
            "_hint": (
                f"Use `execute_websocket(url='{scheme}://{host}:{port}/', "
                f"payload='<json>', timeout=8)` instead. That tool sends a real "
                f"WebSocket frame with a full handshake."
            ),
            "skipped_cmd": cmd[:200],
        }
    return None


# Formas de pedir una escritura HTTP: método mutante explícito o cualquier flag
# que implique cuerpo/subida. Se comprueba sobre el comando ya normalizado.
_HTTP_WRITE_RE = re.compile(
    r"(?:^|\s)(?:-X|--request)\s*(?:POST|PUT|DELETE|PATCH)\b"
    r"|(?:^|\s)(?:-d|--data|--data-binary|--data-raw|--data-urlencode"
    r"|-F|--form|-T|--upload-file)(?:\s|=|$)",
    re.IGNORECASE)


def _recon_readonly_guard(cmd: str) -> Optional[Dict[str, Any]]:
    """En fase recon, `execute_command` es de SOLO LECTURA.

    El prompt de reconocimiento siempre prometió "solo HTTP GET en esta fase; no
    POST/PUT/DELETE", pero nada lo comprobaba: la promesa vivía en el texto que el
    modelo puede ignorar. Este guard la traslada a la capa determinista, que es la
    tesis del trabajo (OE2): reconocimiento no modifica el estado del dispositivo.

    Devuelve None si el comando puede ejecutarse; dict de error si hay que
    bloquearlo. Se respeta `--no-policy` (bypass explícito del operador).
    """
    if _NO_POLICY or _SESSION is None or _SESSION.phase != "recon":
        return None
    if not _HTTP_WRITE_RE.search(cmd or ""):
        return None
    return {
        "ok": False,
        "error_type": "RECON_READ_ONLY",
        "error": (
            "Recon phase: `execute_command` is read-only (GET/HEAD). A mutating "
            "method (POST/PUT/DELETE/PATCH) or a body flag (-d/--data/-F/-T) "
            "would modify the state of the audited device."
        ),
        "instruction": (
            "If you need to write in order to prove a vector, call "
            "`transition_phase(phase='exploit')` first and repeat the command there."
        ),
    }


_NON_PRINTABLE_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def _render_binary_output(output: str) -> Tuple[str, Optional[str]]:
    """Devuelve (texto imprimible, volcado hex) para una salida con bytes crudos.

    Dos problemas que resuelve de una vez:

    · **El agente no podía ver los bytes.** Contra servicios binarios (SOCKS5,
      NSCA, miIO) la respuesta llega con bytes de control y el modelo recibía
      texto mutilado. Su reacción natural —`… | xxd`, `… | od -A x -t x1z`— la
      rechazaba la PolicyEngine: nueve intentos bloqueados en quince
      ejecuciones, por querer *mirar* unos bytes que sí se le permite enviar.
      Renderizando aquí, el `| xxd` deja de hacer falta y no hay que ampliar la
      tubería ni lanzar otro proceso.

    · **La salida cruda corrompía el log.** Es el mismo fallo que el banner SSH:
      unos pocos NUL bastan para que `file` clasifique el `.log` como `data` y
      `grep`/`tail` lo traten como binario, con el dashboard transmitiéndolo
      línea a línea.

    El hex solo se adjunta cuando aporta algo; una salida de texto normal sale
    intacta y sin campo extra.
    """
    if not output or not _NON_PRINTABLE_RE.search(output):
        return output, None
    crudo = output.encode("utf-8", errors="surrogateescape")
    limpio = _NON_PRINTABLE_RE.sub(".", output)
    return limpio, crudo[:512].hex()


def _execute_cmd(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.exploiter import ActiveExploiter
    cmd = args.get("cmd")
    if not cmd:
        return {"error": "cmd required"}

    # Fix curl HEAD: `curl -X HEAD` deja a curl esperando un body que un HEAD nunca
    # envía → cuelga hasta el timeout (30s desperdiciados). El método HEAD correcto
    # en curl es `-I`. Reescribimos de forma transparente.
    if "-X HEAD" in cmd or "-XHEAD" in cmd:
        cmd = re.sub(r"-X\s*HEAD\b", "-I", cmd)

    # `2>&1` sin shell no redirige nada: llega como un operando literal más. El
    # modelo lo añade por costumbre (observado en la tanda del 2026-08-08) y la
    # validación de operandos lo rechazaba por contener metacaracteres, con lo
    # que se perdía el turno por un fragmento que era inocuo Y no operativo. Se
    # elimina en silencio: el ejecutor ya captura stderr y lo une a stdout, así
    # que el modelo obtiene exactamente lo que pedía.
    cmd = re.sub(r"\s+2>&1\b", "", cmd)

    # Fix `echo -e` en /bin/sh (dash): imprime "-e" literal en vez de interpretar \n,
    # rompiendo la enumeración telnet (`echo -e 'cmd1\ncmd2\nexit' | nc`). Reescribimos
    # a `printf '...\n'` (mismo efecto, + newline final para que se ejecute el último
    # comando). Solo el caso single-quote y sin '%' (printf trataría % como format spec).
    if "echo -e '" in cmd and "%" not in cmd:
        cmd = re.sub(r"echo -e '([^']*)'", r"printf '\1\n'", cmd)

    # Guard determinista: rechazar curl HTTP a endpoints WS-only conocidos
    ws_guard = _check_ws_endpoint_guard(cmd)
    if ws_guard is not None:
        return ws_guard

    # Guard determinista: en recon no se modifica el estado del objetivo.
    readonly_guard = _recon_readonly_guard(cmd)
    if readonly_guard is not None:
        return readonly_guard

    target = args.get("target_ip") or get_session().target_ip
    timeout = int(args.get("timeout", 30))
    cve_id = args.get("cve_id", "agent")
    auto_retry_login = bool(args.get("auto_retry_login", True))
    ex = ActiveExploiter(bypass_policy=_NO_POLICY)
    result = ex.execute_poc(cmd, target, timeout=timeout, cve_id=cve_id)
    creds = result.get("discovered_credentials") or []
    if creds:
        get_session().credentials.extend(creds)
    output = (result.get("output") or "")[:2000]
    output, output_hex = _render_binary_output(output)
    error_type = result.get("error_type")
    ran = error_type not in ("POLICY_VIOLATION", "POLICY_MISSING", "CRASH", "MANUAL")
    # TIMEOUT no es un crash — el servicio sigue en pie (p. ej. SSH esperando password)
    ok = result.get("success") or (ran and bool(output.strip()))

    response: Dict[str, Any] = {
        "ok": ok,
        "error_type": error_type,
        "output": output,
        "credentials": creds,
        "requires_manual_verification": result.get("requires_manual_verification", False),
    }
    if output_hex:
        response["output_hex"] = output_hex

    # Smart auto-retry: si vemos 401 → intentar web_login con default creds y reintentar
    head = output[:1024]
    if auto_retry_login and any(p in head for p in _HTTP_401_PATTERNS):
        target_info = _extract_curl_target(cmd)
        if target_info:
            host, port = target_info
            session_cookie: Optional[str] = None
            login_attempts: List[Dict[str, Any]] = []
            for user, pw in _AUTO_LOGIN_CREDS:
                # Cada intento consume presupuesto del SafetyMonitor. Esta rama
                # llama a `_web_login` DIRECTAMENTE, sin pasar por `dispatch`, y
                # por tanto se saltaba el rate-limit: una ráfaga de cinco logins
                # contra un panel web frágil que el monitor ni veía. Es
                # exactamente el tipo de carga que la capa existe para acotar, y
                # además puede bloquear cuentas en dispositivos con lockout.
                budget_block = _safety_precheck("web_login")
                if budget_block is not None:
                    login_attempts.append({
                        "user": user, "skipped": True,
                        "reason": budget_block.get("error_type"),
                    })
                    break
                login_result = _web_login({
                    "ip": host, "username": user, "password": pw, "port": port,
                })
                login_attempts.append({
                    "user": user, "password": pw,
                    "ok": login_result.get("ok"),
                    "method": login_result.get("method"),
                })
                if login_result.get("ok") and login_result.get("session_cookie"):
                    session_cookie = login_result["session_cookie"]
                    get_session().credentials.append({
                        "service": "web", "user": user, "password": pw,
                        "discovered_via": "auto_retry_post_401",
                    })
                    break
            response["auto_login_attempts"] = login_attempts
            if session_cookie:
                # Reinyectar Cookie en el cmd y reintentar UNA vez
                if "-H 'Cookie:" not in cmd and '-H "Cookie:' not in cmd:
                    retry_cmd = cmd + f" -H 'Cookie: {session_cookie}'"
                else:
                    retry_cmd = re.sub(
                        r"-H ['\"]Cookie: [^'\"]*['\"]",
                        f"-H 'Cookie: {session_cookie}'",
                        cmd,
                    )
                logger.info(f"[AUTO-RETRY] post-401 con cookie de {host}")
                retry_res = ex.execute_poc(retry_cmd, target, timeout=timeout,
                                           cve_id=f"{cve_id}_retry")
                retry_out = (retry_res.get("output") or "")[:2000]
                response["auto_retry"] = {
                    "executed": True,
                    "session_cookie_used": True,
                    "output": retry_out,
                    "error_type": retry_res.get("error_type"),
                }
                # Si el retry tiene status diferente, considerarlo el output principal
                retry_head = retry_out[:1024]
                if retry_out and not any(p in retry_head for p in _HTTP_401_PATTERNS):
                    response["output"] = retry_out
                    response["ok"] = retry_res.get("success") or bool(retry_out.strip())
                    response["error_type"] = retry_res.get("error_type")

    # Hint sigue presente para 401 sin éxito o 403
    auth_hint = _detect_auth_required(response["output"])
    if auth_hint:
        response["_auth_hint"] = auth_hint

    return response


def _execute_chain(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.exploiter import ActiveExploiter
    chain = args.get("chain")
    if not isinstance(chain, dict) or not isinstance(chain.get("steps"), list):
        return {"error": "chain must be dict with 'steps' list"}

    # Guard determinista: si CUALQUIER step de la cadena targets un endpoint
    # WS-only conocido, rechazamos toda la cadena (evita timeouts en cascada).
    for step in chain["steps"]:
        if not isinstance(step, dict):
            continue
        step_cmd = step.get("cmd", "")
        if not isinstance(step_cmd, str):
            continue
        ws_guard = _check_ws_endpoint_guard(step_cmd)
        if ws_guard is not None:
            ws_guard["error"] = (
                f"Step '{step.get('name', '?')}' apunta a un endpoint WS-only. "
                + ws_guard["error"]
            )
            return ws_guard

    target = args.get("target_ip") or get_session().target_ip
    timeout = int(args.get("timeout", 60))
    cve_id = args.get("cve_id", "agent")
    ex = ActiveExploiter(bypass_policy=_NO_POLICY)
    result = ex.execute_reactive_chain(chain, target, timeout=timeout, cve_id=cve_id)
    creds = result.get("discovered_credentials") or []
    if creds:
        get_session().credentials.extend(creds)
    chain_vars = result.get("chain_vars") or {}
    get_session().vars.update(chain_vars)
    return {
        "ok": result.get("success"),
        "error_type": result.get("error_type"),
        "output": (result.get("output") or "")[:2000],
        "credentials": creds,
        "vars": chain_vars,
    }


def _derive_cve_id_from_title(title: str) -> Optional[str]:
    """Cuando el LLM pasa record_finding sin cve_id pero con title descriptivo,
    intentamos derivar el ID estándar del remediation KB para evitar duplicados.

    Ejemplos:
      "DIAL Exposed - App Enumeration"  → "DIAL-EXPOSED"
      "LG WebOS Detected - Pairing"     → "LG-WEBOS-EXPOSED"
      "mDNS Service Discovery"          → "MDNS-EXPOSED" (heurística)
      "Hikvision magic cookie auth..."  → "CVE-2017-7921"

    Estrategia:
      1. Buscar CVE-YYYY-NNNN explícito en el title (regex).
      2. Match contra IDs conocidos del KB por keywords.
      3. None si no hay match seguro (no inventamos IDs).
    """
    if not title or not isinstance(title, str):
        return None
    # 1. CVE explícito en title
    m = re.search(r"\bCVE-\d{4}-\d{4,7}\b", title, re.IGNORECASE)
    if m:
        return m.group(0).upper()

    # 2. Mapping fuzzy de keywords → ID conocido en KB
    title_low = title.lower()
    keyword_map = [
        # (keywords obligatorios, finding_id)
        (("dial", "expos"), "DIAL-EXPOSED"),
        (("dial", "enum"), "DIAL-EXPOSED"),
        (("dial", "app"), "DIAL-EXPOSED"),
        (("webos", "pair"), "LG-WEBOS-EXPOSED"),
        (("webos", "detect"), "LG-WEBOS-EXPOSED"),
        (("lg webos",), "LG-WEBOS-EXPOSED"),
        (("mqtt", "anon"), "MQTT-ANON-ACCESS"),
        (("mqtt", "wildcard"), "MQTT-WILDCARD-SUB"),
        (("modbus", "fc17"), "MODBUS-NO-AUTH-FC17"),
        (("modbus", "coil"), "MODBUS-NO-AUTH-READCOILS"),
        (("rtsp", "default"), "RTSP-DEFAULT-CRED"),
        (("rtsp", "no auth"), "RTSP-NO-AUTH"),
        (("rtsp", "auth"), "RTSP-NO-AUTH"),
        (("telnet", "expos"), "TELNET-EXPOSED"),
        (("telnet", "default"), "TELNET-DEFAULT-CRED"),
        (("telnet", "mirai", "busybox"), "TELNET-MIRAI-BUSYBOX"),
        (("ftp", "anon"), "FTP-ANON-LOGIN"),
        (("smb", "v1"), "SMB-V1-EXPOSED"),
        (("tftp", "anon"), "TFTP-ANON-DOWNLOAD"),
        (("rompager",), "CWMP-ROMPAGER-CVE-2014-9222"),
        (("huawei", "hg532"), "CWMP-MIRAI-CVE-2017-17215"),
        (("bacnet", "auth"), "BACNET-NO-AUTH-WHOIS"),
        (("chromecast", "info"), "CHROMECAST-INFO-DISCLOSURE"),
        (("upnp", "igd"), "UPNP-IGD-EXPOSED"),
        (("opcua", "expos"), "OPCUA-EXPOSED"),
        (("mdns", "device"), "MDNS-EXPOSED"),
        (("mdns", "discov"), "MDNS-EXPOSED"),
        (("mdns", "ident"), "MDNS-EXPOSED"),
        (("mdns",), "MDNS-EXPOSED"),
        (("airplay", "mdns"), "MDNS-EXPOSED"),
        (("zeroconf",), "MDNS-EXPOSED"),
        (("hikvision", "magic"), "CVE-2017-7921"),
        (("hikvision", "cookie"), "CVE-2017-7921"),
        (("misfortune", "cookie"), "CVE-2014-9222"),
        (("default", "credential"), "WEAK-CREDENTIALS"),
        (("default", "cred"), "WEAK-CREDENTIALS"),
        (("weak", "credential"), "WEAK-CREDENTIALS"),
        (("weak", "password"), "WEAK-CREDENTIALS"),
        (("admin", "password"), "WEAK-CREDENTIALS"),
        (("dropbear", "old"), "SSH-DROPBEAR-OLD"),
        (("dropbear",), "SSH-DROPBEAR-OLD"),
    ]
    for keywords, finding_id in keyword_map:
        if all(kw.lower() in title_low for kw in keywords):
            return finding_id
    return None


_RAW_OUTPUT_ADMIN_KEYS = frozenset({
    # Metadata interna del dispatch — NO son datos del dispositivo
    "_auto_registered_findings", "_elapsed_ms",
    "ok", "error", "error_type",
    "ip", "port", "service", "protocol_confirmed",
    # `vulnerabilities[]` ya es interpretación del probe (description campo)
    # — la mantenemos fuera de raw_output para no duplicar con interpretation.
    "vulnerabilities",
})


def _clean_raw_output(raw: str) -> str:
    """Filtra claves administrativas del JSON raw_output.

    Cuando el LLM (o legacy code) pasa el resultado completo del dispatch como
    raw_output, contiene metadata del agente (`_elapsed_ms`, `ok`, etc.) que
    NO son datos del dispositivo. Este helper limpia el JSON manteniendo solo
    los datos que un auditor humano hubiera obtenido con curl/nc.

    Si el raw_output no es JSON parseable, se devuelve tal cual (best-effort).
    """
    if not raw or not isinstance(raw, str):
        return raw or ""
    raw_strip = raw.strip()
    if not raw_strip.startswith("{"):
        return raw  # No es JSON, no tocar
    try:
        parsed = json.loads(raw_strip)
    except json.JSONDecodeError:
        return raw
    if not isinstance(parsed, dict):
        return raw

    cleaned = {k: v for k, v in parsed.items() if k not in _RAW_OUTPUT_ADMIN_KEYS}
    # Si el cleanup deja solo `details`, promovemos el contenido de details
    # al nivel raíz (suele ser donde están los datos verdaderos del probe)
    if list(cleaned.keys()) == ["details"] and isinstance(cleaned["details"], dict):
        cleaned = cleaned["details"]
    if not cleaned:
        return raw  # Si filtramos todo, devolver original (mejor algo que nada)
    return json.dumps(cleaned, ensure_ascii=False, indent=2)


def _raw_output_quality_score(raw: str) -> int:
    """Heurística de calidad del raw_output. Mayor = más limpio.

    Penaliza la presencia de claves administrativas. Útil para decidir merge:
    cuando hay dos versiones del mismo finding, preferimos la más limpia
    (mayor score) sobre la más larga.
    """
    if not raw or not raw.strip().startswith("{"):
        return 0  # No JSON, score neutral
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return 0
    if not isinstance(parsed, dict):
        return 0
    admin_keys_present = sum(1 for k in parsed if k in _RAW_OUTPUT_ADMIN_KEYS)
    # Score = mil puntos por estar limpio − 100 por cada clave admin
    return 1000 - (admin_keys_present * 100)


def _record_finding(args: Dict[str, Any]) -> Dict[str, Any]:
    """Registra hallazgo. Si cve_id ya existe, actualiza el entry previo.

    Schema actualizado — separación entre datos crudos y reasoning:
      - `raw_output`: lo que el dispositivo realmente respondió (banner, JSON,
        códigos HTTP, mensajes WS, etc.). Hechos verificables.
      - `interpretation`: lo que el agente interpreta (conclusiones, hipótesis,
        razonamiento sobre la evidencia). Texto narrativo.
      - `evidence` (legacy): si solo se pasa este, se trata como interpretation.

    Política de merge cuando se actualiza un finding:
      - confirmed: True gana sobre False (una vez confirmado, no se desconfirma)
      - severity: la más alta entre la previa y la nueva
      - raw_output / interpretation: si la nueva es más larga, sustituye
      - title: la nueva sustituye si es más descriptiva (más larga)

    **Retractación explícita (`retract=true`).** El merge anterior es un
    trinquete: `confirmed`, `severity` e `impact` solo podían SUBIR. En un
    sistema cuya tesis es que manda la evidencia, eso deja una asimetría
    incómoda —la evidencia solo puede agravar un hallazgo, nunca corregirlo— y
    un error queda grabado para siempre. El flujo real que lo destapa: el agente
    registra un candidato como HIGH, lo prueba después y descubre que el modelo
    no aplica; su `record_finding(confirmed=false, severity="INFO")` se
    descartaba en silencio y el informe seguía publicando el HIGH.

    `retract=true` invierte el trinquete para esa llamada concreta: la nueva
    severidad, `confirmed` e `impact` SUSTITUYEN a los previos. No es una puerta
    trasera para inflar —lo que se escriba sigue pasando por `effective_severity`
    y por el techo canónico— sino la vía para que una comprobación posterior
    pese tanto como la primera. Se exige que sea explícita para que rebajar un
    hallazgo sea siempre un acto deliberado y quede registrado en el log.

    Dedupe inteligente:
      - Si cve_id es null/empty pero title sugiere un ID conocido del KB,
        derivamos cve_id automáticamente (DIAL-EXPOSED, LG-WEBOS-EXPOSED, etc.)
      - Esto evita duplicados cuando el LLM llama record_finding sin cve_id
        pero el agente ya lo había auto-registrado del probe.
    """
    # Backward compat: si no pasaron los nuevos campos pero sí evidence,
    # ponemos evidence en interpretation (eso es lo que el LLM solía escribir).
    raw_output = args.get("raw_output") or ""
    interpretation = args.get("interpretation") or ""
    legacy_evidence = args.get("evidence", "") or ""
    if not raw_output and not interpretation and legacy_evidence:
        interpretation = legacy_evidence

    # Cleanup raw_output: quitar claves administrativas (_elapsed_ms, ok, etc.)
    # Esto fixes el bug donde el LLM pasaba el dispatch result completo como raw.
    raw_output = _clean_raw_output(raw_output)

    # Dedupe fuzzy: si no hay cve_id, intentar derivarlo del title
    cve_id_raw = args.get("cve_id")
    if not cve_id_raw:
        derived = _derive_cve_id_from_title(args.get("title", "") or "")
        if derived:
            cve_id_raw = derived
            logger.info(
                f"[FINDING] cve_id null derivado de title → {derived} "
                f"(evita duplicado vs auto-register)"
            )

    # Identificador CANÓNICO. Va aquí, en el punto de ESCRITURA, por el mismo
    # motivo que la reparación de invariantes de la KB: es el único sitio por el
    # que pasan todas las fuentes —lo que registra el modelo y lo que
    # auto-registran las sondas— y el único donde normalizar tiene efecto sobre
    # todo lo que se guarda después (informe, KB, arnés de varianza).
    #
    # En campo, el mismo descriptor UPnP del mismo televisor se registró como
    # `UPNP-DESCRIPTOR-EXPOSURE`, `UPnP-DEVICE-DISCLOSURE` y
    # `UPNP-DEVICE-DESCRIPTOR-EXPOSURE` en tres ejecuciones distintas, y el
    # índice de estabilidad de §5.10.2 —que es |∩|/|∪| sobre los conjuntos de
    # confirmados— publicaba 0.000 para un agente que había encontrado lo mismo.
    _texto_libre = False
    if cve_id_raw:
        from core.finding_ids import canonicalize_finding_id, looks_like_free_text
        _texto_libre = looks_like_free_text(cve_id_raw)
        canonico = canonicalize_finding_id(cve_id_raw)
        if canonico and canonico != cve_id_raw:
            logger.info(f"[FINDING] id canonizado: {cve_id_raw!r} → {canonico}")
            cve_id_raw = canonico

    # Un identificador que AFIRMA UNA ACCIÓN exige evidencia de esa acción.
    #
    # En campo se registró `TFTP-ANON-DOWNLOAD` —cuyo nombre afirma que se
    # descargó un fichero de forma anónima— con esta evidencia literal:
    # «nmap: 69/udp open|filtered tftp. probe_tftp: protocol_confirmed=false».
    # La sonda decía explícitamente que NO había confirmado nada. La gobernanza
    # de severidad lo dejó en LOW, así que la puntuación no se resintió; pero el
    # informe publicaba una descarga que no ocurrió, y el nombre de un hallazgo
    # es parte de lo que el informe afirma.
    #
    # No se rechaza —perder la observación sería peor— sino que se degrada a
    # candidato: es exactamente lo que es. La distinción candidato/confirmado ya
    # vertebra el trabajo; aquí se aplica al único sitio donde faltaba.
    _degradado = False
    if (cve_id_raw and bool(args.get("confirmed", False))
            and not args.get("_from_probe")):
        from core.severity import asserts_unproven_action
        _degradado = asserts_unproven_action(
            {"cve_id": cve_id_raw, "raw_output": raw_output,
             "impact": (args.get("impact") or "").upper(),
             "evidence": legacy_evidence, "interpretation": interpretation})
        if _degradado:
            logger.warning(
                f"[FINDING] {cve_id_raw} afirma una acción que su evidencia no "
                f"muestra; se registra como CANDIDATO")

        # Y el caso límite del mismo principio: confirmado SIN evidencia de
        # ninguna clase. No es que la evidencia no respalde la afirmación —es
        # que no hay evidencia. En campo el modelo registró `WEAK-CREDENTIALS`
        # con los tres campos en blanco y, por separado, `HTTP-DEFAULT-CRED`
        # con el volcado de la sesión: el mismo hecho dos veces, una de ellas
        # como cascarón. Sin esta comprobación el cascarón contaba como
        # hallazgo confirmado siempre que declarase una clase inofensiva
        # (`DISCLOSURE`, `HYGIENE`), a las que la guarda anterior no llega.
        # Son 20 de los 435 confirmados del corpus acumulado.
        if not _degradado and not any(
                (x or "").strip() for x in (raw_output, interpretation, legacy_evidence)):
            _degradado = True
            logger.warning(
                f"[FINDING] {cve_id_raw} se confirma sin evidencia de ninguna "
                f"clase; se registra como CANDIDATO")

    # Title sano: si el cve_id está en el KB, preferir el título oficial del KB
    # antes que la NVD description truncada a mitad de palabra.
    title_raw = args.get("title") or ""
    if cve_id_raw:
        try:
            from modules.remediation_kb import get_remediation
            kb_entry = get_remediation(cve_id_raw)
            if kb_entry and kb_entry.get("title"):
                # Solo override si el title actual es claramente NVD-truncated:
                # cortado a mitad de palabra (no termina en . ni espacio)
                # o si simplemente no hay title.
                if not title_raw or (
                    len(title_raw) >= 70 and not title_raw.rstrip().endswith(("...", ".", "!"))
                ):
                    title_raw = kb_entry["title"]
        except ImportError:
            pass

    incoming = {
        "cve_id": cve_id_raw,
        "title": title_raw,
        "severity": args.get("severity", "INFO"),
        "confirmed": bool(args.get("confirmed", False)) and not _degradado,
        # Clase de impacto demostrado (gobierna el tope de severidad efectiva).
        "impact": (args.get("impact") or "").upper(),
        # Techo canónico por tipo de hallazgo (lo declara la tool en el
        # auto-registro; el LLM no lo pasa al re-registrar). effective_severity
        # nunca supera este techo → severidad reproducible entre runs.
        "canonical_severity": (args.get("canonical_severity") or "").upper() or None,
        # Quién afirma el hallazgo: una sonda determinista o el modelo. Se
        # persiste porque sin él una regla nueva NO puede aplicarse al corpus
        # ya escrito: la guarda de acción-no-demostrada exime a las sondas, y
        # sin esta marca revaluar informes antiguos degradaría por igual las
        # confirmaciones deterministas del laboratorio. Guardar la procedencia
        # es lo que hace la evidencia re-auditable cuando el criterio cambia.
        "_from_probe": bool(args.get("_from_probe")),
        # Campos separados (nueva arquitectura)
        "raw_output": raw_output,
        "interpretation": interpretation,
        # Legacy combinado para compatibilidad con código que lee `evidence`
        "evidence": " | ".join(p for p in (raw_output, interpretation) if p) or legacy_evidence,
        "cmd": args.get("cmd", "") or "",
    }
    findings = get_session().findings
    cve_id = incoming["cve_id"]

    retract = bool(args.get("retract", False))

    if cve_id:
        for existing in findings:
            if existing.get("cve_id") == cve_id:
                if retract:
                    # Corrección explícita: la comprobación posterior sustituye a
                    # la anterior en lugar de sumarse a ella. Sin esta rama, un
                    # candidato registrado HIGH que luego se demuestra inaplicable
                    # seguía publicándose como HIGH.
                    # GOBERNANZA-OK: traza del estado ANTES y DESPUÉS de la
                    # corrección. Se registra el campo tal cual está almacenado
                    # —no su lectura gobernada— porque el objeto de la línea es
                    # documentar qué se sobrescribió.
                    logger.info(
                        f"[FINDING] retractación de {cve_id}: "
                        f"{existing.get('severity')}/confirmed={existing.get('confirmed')} → "
                        f"{incoming['severity']}/confirmed={incoming['confirmed']}"
                    )
                    existing["confirmed"] = incoming["confirmed"]
                    existing["severity"] = incoming["severity"]
                    existing["impact"] = incoming.get("impact") or ""
                    existing["retracted"] = True
                else:
                    if incoming["confirmed"]:
                        existing["confirmed"] = True
                    old_rank = _SEVERITY_RANK.get(existing.get("severity", "INFO"), 0)
                    new_rank = _SEVERITY_RANK.get(incoming["severity"], 0)
                    if new_rank > old_rank:
                        existing["severity"] = incoming["severity"]
                    # Impacto: adoptar la clase que otorgue mayor tope (la prueba
                    # más fuerte manda; no degradar si la nueva llamada lo omite).
                    inc_impact = incoming.get("impact") or ""
                    if inc_impact:
                        old_cap = _SEVERITY_RANK.get(
                            _IMPACT_MAX_SEVERITY.get((existing.get("impact") or "").upper(), "LOW"), 1)
                        new_cap = _SEVERITY_RANK.get(
                            _IMPACT_MAX_SEVERITY.get(inc_impact.upper(), "LOW"), 1)
                        if new_cap >= old_cap or not existing.get("impact"):
                            existing["impact"] = inc_impact.upper()
                # Techo canónico: lo fija el primer auto-registro de la tool.
                # Un re-registro manual del LLM (sin canonical_severity) NO puede
                # borrarlo — así el LLM no esquiva el techo re-emitiendo el hallazgo.
                if incoming.get("canonical_severity") and not existing.get("canonical_severity"):
                    existing["canonical_severity"] = incoming["canonical_severity"]
                if incoming["title"] and len(incoming["title"]) > len(existing.get("title") or ""):
                    existing["title"] = incoming["title"]
                # `cmd` no se fusionaba, y de él depende la detección de candidatos
                # sin probar (marca `cmd == "cve_search"`). Consecuencia: un CVE
                # registrado en lote y luego probado de verdad seguía apareciendo en
                # `warning_untested_cves`, y el agente gastaba turnos re-probando lo
                # ya probado. Cualquier registro manual posterior lo da por atendido.
                inc_cmd = incoming.get("cmd") or ""
                if inc_cmd and inc_cmd != _BATCH_CVE_CMD_MARKER:
                    existing["cmd"] = inc_cmd
                elif not inc_cmd and existing.get("cmd") == _BATCH_CVE_CMD_MARKER:
                    existing["cmd"] = ""
                # Merge raw_output: prioriza calidad (limpio) > tamaño.
                # Si existing está limpio (sin claves admin) y new tiene admin
                # keys, mantenemos existing aunque new sea más largo.
                new_raw = incoming.get("raw_output", "") or ""
                if new_raw:
                    existing_raw = existing.get("raw_output", "") or ""
                    new_score = _raw_output_quality_score(new_raw)
                    existing_score = _raw_output_quality_score(existing_raw)
                    # Reemplazar si: mayor calidad, O misma calidad y mayor info útil
                    if (new_score > existing_score or
                        (new_score == existing_score and len(new_raw) > len(existing_raw))):
                        existing["raw_output"] = new_raw

                # Interpretation: tamaño = más completo (textos descriptivos)
                new_interp = incoming.get("interpretation", "") or ""
                if new_interp and len(new_interp) > len(existing.get("interpretation") or ""):
                    existing["interpretation"] = new_interp
                # Reconstruir evidence combinada
                existing["evidence"] = " | ".join(
                    p for p in (existing.get("raw_output", ""),
                                existing.get("interpretation", "")) if p
                ) or existing.get("evidence", "")
                if incoming["cmd"] and not existing.get("cmd"):
                    existing["cmd"] = incoming["cmd"]
                # Telemetry: re-attempt sobre el mismo CVE
                _telemetry_record_attempt(cve_id, incoming["confirmed"])
                return {
                    "ok": True,
                    "merged": True,
                    "retracted": retract or None,
                    "cve_id": cve_id,
                    "effective_severity": effective_severity(existing),
                    "total_findings": len(findings),
                }

    findings.append(incoming)
    # Telemetry: nuevo intento de explotación registrado
    if cve_id:
        _telemetry_record_attempt(cve_id, incoming["confirmed"])
    salida = {"ok": True, "merged": False, "cve_id": cve_id,
              "total_findings": len(findings)}
    if _degradado:
        salida["downgraded_to_candidate"] = True
        salida["_hint"] = (
            f"`{cve_id}` names a demonstrated action (access/extraction), but the "
            f"evidence you provided shows no such interaction — it reads as a port "
            f"state or a probe that did not confirm. It was recorded as a CANDIDATE, "
            f"not a confirmed finding. To confirm it, supply in `raw_output` what the "
            f"device actually returned (retrieved bytes, a session, a shell). If the "
            f"probe did not confirm, say so with a reachability id instead."
        )
    if _texto_libre:
        # Caso real: `Puerto 4070 - Servicio HTTP sin identificación` como
        # identificador. Se acepta —perder el hallazgo sería peor que aceptar un
        # nombre feo— pero se le enseña el formato, porque una frase no se
        # repite igual en la siguiente ejecución y rompe la agregación.
        salida["_hint"] = (
            f"The `cve_id` you passed reads as a sentence, not an identifier; it was "
            f"stored as `{cve_id}`. Use a CVE id when there is one, or a SHORT "
            f"uppercase slug of the form PROTOCOL-WHAT-OUTCOME "
            f"(e.g. `HTTP-CONFIG-EXPOSED`, `SOCKS5-NOAUTH`, `TELNET-DEFAULT-CRED`). "
            f"The same fact must get the same id on every run, or the finding "
            f"cannot be correlated across audits."
        )
    return salida


def _telemetry_record_attempt(cve_id: str, confirmed: bool) -> None:
    """Reporta a TelemetryCollector si está activo. No-op si no."""
    if _SESSION is None or _SESSION.telemetry is None:
        return
    error_type = "CONFIRMED" if confirmed else "NOT_VULNERABLE"
    _SESSION.telemetry.record_exploit_attempt(
        cve_id=cve_id, success=confirmed, error_type=error_type
    )




_COMMON_VENDORS = (
    "LG", "Samsung", "Sony", "Hikvision", "Dahua", "Philips",
    "Google", "Mikrotik", "TP-Link", "D-Link", "Ubiquiti", "Cisco",
    "Netgear", "Asus", "Linksys", "Belkin", "Zyxel", "Huawei",
    "Tenda", "Xiaomi", "Synology", "QNAP",
    "Telefonica", "Movistar", "FiberHome", "Technicolor", "Alcatel",
    "Sagem", "Sagemcom", "Mitrastar", "Comtrend", "ZTE",
)


def _vendor_in_text(vendor: str, text: str) -> bool:
    """Match con word boundaries reales — evita el bug de substring que
    detectaba 'LG' dentro de palabras como 'algoritmo' o 'old'.

    Acepta separadores comunes en banners/CVE descriptions: espacio,
    guiones, punto, slash, comilla, paréntesis. No es una regex \\b porque
    'TP-Link' (con guión interno) debe matchear pero no formar parte de
    otra palabra.
    """
    import re as _re
    # Escapamos el vendor por si contiene caracteres especiales (TP-Link).
    pattern = r"(?:^|[\s\-/.,;:()\"'\[\]])" + _re.escape(vendor) + r"(?:[\s\-/.,;:()\"'\[\]]|$)"
    return bool(_re.search(pattern, text, _re.IGNORECASE))


def _heuristic_vendor_from_findings(findings: List[Dict[str, Any]]) -> Optional[str]:
    """Extrae vendor de la evidencia de findings cuando scan_cache no lo tiene.

    Sólo considera findings con `confirmed=True`. Findings descartados
    (típicamente "CVE para vendor X, no aplica a este target") mencionan
    nombres de vendor en su descripción/evidence pero esos nombres son
    PRECISAMENTE los que el agente acaba de declarar irrelevantes — usarlos
    para clasificar el target invierte la lógica.

    No es autoritativo: scan_cache tiene prioridad. Devuelve None si ningún
    finding confirmado menciona un vendor conocido.

    El match usa word boundaries reales (`_vendor_in_text`) — vendors cortos
    como 'LG' no matchearán dentro de palabras como 'algoritmo' u 'older'.
    """
    for f in findings:
        # GOBERNANZA-OK: excepción deliberada al criterio `is_confirmed_vuln`
        # que rige en el resto del sistema. Aquí se pregunta «¿verificó el
        # agente este dato?», no «¿es esto una vulnerabilidad?». La evidencia de
        # IDENTIDAD es casi siempre INFO —«dispositivo LG WebOS detectado» es
        # una nota, no un fallo— y `is_confirmed_vuln` la descartaría justo por
        # serlo, dejando ciega la heurística de fabricante. El campo crudo es el
        # criterio correcto en este único punto.
        if not f.get("confirmed"):
            continue
        text = (f.get("evidence") or "") + " " + (f.get("interpretation") or "")
        for v in _COMMON_VENDORS:
            if _vendor_in_text(v, text):
                return v
    return None


def _resolve_device_identity(
    scan: Dict[str, Any], kb_prev: Dict[str, Any],
    findings: List[Dict[str, Any]],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Resuelve la identidad del dispositivo (vendor/model/firmware/mac).

    Regla de identidad del proyecto: **por MAC, nunca por IP**. El registro
    previo de la KB se busca por IP (las IPs se reutilizan), de modo que si su
    MAC difiere de la del escaneo actual es **otro dispositivo** que heredó la
    IP (p. ej. un Xiaomi/ESP8266 en la IP que antes tenía la LG TV). En ese caso
    NO se hereda su identidad ni su histórico: se descarta `kb_prev`.

    Devuelve `(device_identity, kb_prev_efectivo)` — el segundo, ya saneado,
    para que el `previous_audit` del informe tampoco muestre el dispositivo
    equivocado.
    """
    from modules.fingerprint import normalize_mac
    scan_mac = normalize_mac(scan.get("mac"))
    prev_mac = normalize_mac(kb_prev.get("mac"))
    if scan_mac and prev_mac and scan_mac != prev_mac:
        logger.info(
            f"[REPORT] el registro KB de esta IP tiene MAC {prev_mac} ≠ {scan_mac} "
            f"del escaneo actual: es otro dispositivo (IP reutilizada). No se "
            f"hereda identidad por IP.")
        kb_prev = {}
    vendor = (
        scan.get("ssdp_manufacturer")
        or scan.get("vendor")
        or kb_prev.get("vendor")
        or _heuristic_vendor_from_findings(findings)
    )
    model = scan.get("ssdp_model") or scan.get("model") or kb_prev.get("model")
    firmware = scan.get("firmware") or kb_prev.get("firmware")
    identity = {
        "vendor": vendor,
        "model": model,
        "firmware": firmware,
        "mac": scan.get("mac") or kb_prev.get("mac"),
    }
    return identity, kb_prev


def _save_report(args: Dict[str, Any]) -> Dict[str, Any]:
    from modules.reporter import Reporter
    s = get_session()
    out_dir = args.get("out_dir", "reports")
    reporter = Reporter(report_dir=out_dir)
    attack_results = [
        {
            "service": f.get("cve_id") or f.get("title") or "UNKNOWN",
            "cve_id": f.get("cve_id", ""),
            "title": f.get("title", ""),
            # Severidad EFECTIVA (tras política de impacto) — fuente de verdad
            # para conteos/score del reporter. La declarada se conserva aparte.
            "severity": effective_severity(f),
            "severity_claimed": (f.get("severity") or "INFO").upper(),
            "impact": (f.get("impact") or "").upper(),
            "vuln_found": is_confirmed_vuln(f),
            # `repro_cmd`, no `executed_cmd`: este campo es el comando que
            # REPRODUCE el hallazgo (a veces solo el nombre de la sonda que lo
            # emitió), no una prueba de que se ejecutase. En un informe cuya
            # disciplina es separar la prueba de la interpretación, el nombre
            # anterior afirmaba más de lo que el dato sostiene. Los lectores
            # aceptan ambas claves para no romper los informes ya generados.
            "repro_cmd": f.get("cmd", ""),
            # Pasar campos separados al reporter (nueva arquitectura)
            "raw_output": f.get("raw_output", "") or "",
            "interpretation": f.get("interpretation", "") or "",
            # Legacy combinado
            "output_log": f.get("evidence", "") or "",
            # `details` es el campo legado del que el reporter tira como
            # RESPALDO de `severity` (`res.get("severity") or res.get("details")`).
            # Llevaba la severidad DECLARADA mientras `severity` lleva la
            # efectiva, de modo que el respaldo de un campo gobernado era su
            # versión sin gobernar: cualquier ruta que cayera en el fallback
            # publicaba la cifra que la política había topado. Se iguala a la
            # efectiva; la declarada sigue disponible en `severity_claimed`.
            "details": effective_severity(f),
        }
        for f in s.findings
    ]
    scan = s.scan_cache or {}
    risk = compute_risk_score(s.findings)

    # ── KB lookup (previous audit) — needed para fallback de device_identity ─
    kb_prev: Dict[str, Any] = {}
    kb = None
    try:
        from core.knowledge_base import get_kb
        kb = get_kb()
        kb_prev = kb.get_device_record(ip=s.target_ip, mac=scan.get("mac"),
                                       firmware=scan.get("firmware")) or {}
    except Exception as e:
        logger.debug(f"[REPORT] KB lookup skipped: {e}")

    # ── Recopilar contexto enriquecido para el reporter ────────────────────
    # Vendor/modelo: scan_cache > KB.devices_seen (runs previos) > heurísticas.
    # Fallback a KB porque probes como mDNS son flaky (TV en sleep, race timing)
    # y no queremos perder identificación ya conocida. PERO el fallback solo
    # aplica si la MAC coincide — identidad por MAC, nunca por IP (las IPs se
    # reutilizan). `kb_prev` se descarta si es otro dispositivo en la misma IP.
    device_identity, kb_prev = _resolve_device_identity(scan, kb_prev, s.findings)
    vendor = device_identity["vendor"]

    # CVEs efectivamente testeados (cualquier cve_id en findings es candidato testeado)
    tested_cves = sorted({
        f.get("cve_id") for f in s.findings
        if f.get("cve_id") and (f.get("cve_id") or "").startswith("CVE-")
    })

    # KB context del run actual (si KB disponible)
    kb_context: Dict[str, Any] = {}
    if kb is not None:
        try:
            if kb_prev:
                kb_context["previous_audit"] = kb_prev
            if vendor:
                vp = kb.get_vendor_profile(vendor)
                if vp:
                    kb_context["vendor_profile"] = {
                        "vendor": vendor,
                        "patched_cves_known": vp.get("patched_cves", []),
                        "useful_probes_historically": vp.get("useful_probes", []),
                        "device_count_audited": vp.get("device_count", 0),
                    }
        except Exception as e:
            logger.debug(f"[REPORT] KB context skipped: {e}")

    reporter.add_entry(
        ip=s.target_ip,
        os_match=scan.get("os_match") or "unknown",
        ports=scan.get("ports", []),
        attack_plan=f"Autonomous {s.provider or 'LLM'} agent audit",
        attack_results=attack_results,
        system_cves=[],
        # Contexto enriquecido
        device_identity=device_identity,
        risk_summary=risk,
        executed_tools=list(s.executed_probes),
        tested_cves=tested_cves,
        kb_context=kb_context,
        reflection_report_path=getattr(s, "reflection_report_path", None),
        run_metadata={
            # Atribución del run: sin esto, dos proveedores distintos producen
            # informes indistinguibles y la comparación entre modelos es imposible.
            "model": s.model_name,
            "provider": s.provider,
            # Revisión del código que generó el informe → reproducibilidad exacta
            # (cada artefacto es citable a un commit concreto).
            "code_revision": _code_revision(),
            # Capas de contención activas durante ESTE run. Sin este campo, un
            # informe producido en modo investigación (`--no-policy`, shell
            # directo) era indistinguible de uno con la política activa, y las
            # afirmaciones sobre contención no se podían auditar por artefacto.
            "safety_posture": _safety_posture(),
            "provider_rate_limit_hits": s.provider_rate_limit_hits,
            # Cómo terminó el run. `interrupted` es la afirmación que importa:
            # el informe existe, pero el agente NO recorrió el pipeline hasta
            # `done`. Un artefacto rescatado es evidencia válida de lo que se
            # llegó a ver, y a la vez no es comparable con uno completo.
            # Cobertura de la superficie publicada. Sin este campo, un puerto que
            # el agente nunca tocó era indistinguible en el informe de uno que
            # probó sin encontrar nada, y el lector no tenía forma de saber
            # cuánto del objetivo se había examinado de verdad.
            "surface_coverage": _surface_coverage(s),
            "finish_reason": s.finish_reason,
            "turns": s.turns_completed or None,
            "interrupted": bool(s.finish_reason) and s.finish_reason != "done_called",
        },
    )

    try:
        base = reporter.generate_reports(executed_nodes=["agent"])
        # Append risk summary JSON adicional para integración fácil
        try:
            with open(base + "_risk.json", "w", encoding="utf-8") as fh:
                json.dump({
                    "ip": s.target_ip,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    **risk,
                }, fh, indent=2, ensure_ascii=False)
        except OSError:
            pass
        # Persist telemetry junto al reporte: misma ruta base, sufijo _telemetry.json
        telemetry_path: Optional[str] = None
        if s.telemetry is not None:
            try:
                from pathlib import Path as _Path
                telemetry_path = str(s.telemetry.save_report(_Path(base + "_telemetry.json")))
            except Exception as te:
                logger.debug(f"[REPORT] telemetry save skipped: {te}")
        s.report_saved_path = base
        return {
            "ok": True,
            "path": base,
            "findings": len(s.findings),
            "telemetry_path": telemetry_path,
            **risk,
        }
    except Exception as e:
        logger.warning(f"[REPORT] generate_reports failed, JSON fallback: {e}")
        ts = time.strftime("%Y%m%d_%H%M%S")
        os.makedirs(out_dir, exist_ok=True)
        base = os.path.join(out_dir, f"agent_report_{ts}")
        with open(base + ".json", "w", encoding="utf-8") as fh:
            json.dump(reporter.findings, fh, indent=2, ensure_ascii=False)
        with open(base + "_risk.json", "w", encoding="utf-8") as fh:
            json.dump({
                "ip": s.target_ip,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                **risk,
            }, fh, indent=2, ensure_ascii=False)
        s.report_saved_path = base
        return {
            "ok": True,
            "path": base,
            "findings": len(s.findings),
            "fallback": str(e),
            **risk,
        }


def _untested_batch_cves(session: "AgentSession") -> List[str]:
    """CVEs registrados en lote (`record_cve_findings`) que nunca se probaron.

    Marca de "no testeado": el finding conserva `cmd == _BATCH_CVE_CMD_MARKER`, es
    decir nunca lo sobreescribió un `record_finding` posterior con evidencia real.
    Fuente única de verdad para `done()` y para `audit_status`.
    """
    if not session.batch_registered_cves:
        return []
    finding_map = {f.get("cve_id"): f for f in session.findings if f.get("cve_id")}
    return [
        cve_id for cve_id in session.batch_registered_cves
        if (finding_map.get(cve_id) or {}).get("cmd") == _BATCH_CVE_CMD_MARKER
    ]


def _surface_coverage(session: "AgentSession") -> Dict[str, Any]:
    """Cuánta de la superficie publicada se llegó a tocar.

    Solo cuenta **TCP**. Los puertos UDP que nmap devuelve como `open|filtered`
    son una conjetura —el protocolo no distingue «abierto y callado» de
    «filtrado»—, y exigir un intento contra una conjetura convertiría la métrica
    en una invitación a disparar a ciegas, que es justo la patología que la
    guarda de esterilidad existe para cortar.

    Es una medida de COBERTURA, no de éxito: un puerto probado sin resultado
    cuenta como cubierto. La pregunta que responde es la que el informe no sabía
    contestar —de lo que publico como superficie, ¿qué llegué a intentar?— y su
    utilidad es que un hueco deje de parecerse a un negativo.
    """
    scan = session.scan_cache or {}
    tcp: Dict[int, str] = {}
    for op in scan.get("ports") or []:
        if not isinstance(op, dict):
            continue
        proto = (op.get("protocol") or op.get("proto") or "tcp").lower()
        if proto != "tcp":
            continue
        try:
            tcp[int(op["port"])] = op.get("service_name") or op.get("service") or "?"
        except (KeyError, TypeError, ValueError):
            continue
    intentados = sorted(p for p in tcp if p in session.attempted_ports)
    sin_tocar = sorted(p for p in tcp if p not in session.attempted_ports)
    return {
        "tcp_ports": len(tcp),
        "attempted": len(intentados),
        "coverage": round(len(intentados) / len(tcp), 3) if tcp else 1.0,
        "untouched": [{"port": p, "service": tcp[p]} for p in sin_tocar],
    }


def _audit_status(args: Dict[str, Any]) -> Dict[str, Any]:
    """Estado de la auditoría en curso: qué se ha registrado y qué queda pendiente.

    Motivación: hasta ahora el agente no podía consultar su propio progreso. Solo
    descubría los candidatos sin probar cuando `done()` devolvía
    `warning_untested_cves` —al final, cuando ya había decidido terminar— y en
    ejecuciones largas re-registraba hallazgos por haber perdido el hilo del
    historial. Esta tool es de solo lectura (no toca el objetivo ni consume
    presupuesto de SafetyMonitor) y hace explícito el trabajo pendiente.
    """
    s = get_session()
    # Dos conjuntos con propósitos distintos, y confundirlos era el defecto:
    #   · `marked` — todo lo que el modelo marcó `confirmed=True`. Es la base del
    #     diagnóstico `capped`: el agente necesita ver también lo que reclamó y
    #     no le fue reconocido, INFO incluido. GOBERNANZA-OK: la lectura cruda es
    #     aquí el objetivo, no un descuido — se trata precisamente de comparar lo
    #     que el modelo afirmó contra lo que la política reconoce.
    #   · `confirmed` — lo que la gobernanza acepta como vulnerabilidad
    #     (`is_confirmed_vuln`). Es lo que cuenta, y debe coincidir con la cifra
    #     del informe: si `audit_status` dijera 2 y el informe 1, el agente
    #     tomaría decisiones sobre un estado que no existe.
    marked = [f for f in s.findings if f.get("confirmed")]
    confirmed = [f for f in marked if is_confirmed_vuln(f)]
    by_effective: Dict[str, int] = {}
    for f in confirmed:
        sev = effective_severity(f)
        by_effective[sev] = by_effective.get(sev, 0) + 1

    untested = _untested_batch_cves(s)
    # Confirmados cuya severidad EFECTIVA quedó por debajo de la declarada: el
    # agente puede ver así, en vivo, que le falta clase de impacto o prueba.
    capped = [
        {
            "cve_id": f.get("cve_id"),
            "declared_severity": (f.get("severity") or "INFO").upper(),
            "effective_severity": effective_severity(f),
            "impact": (f.get("impact") or "") or None,
        }
        for f in marked
        if _SEVERITY_RANK.get(effective_severity(f), 0)
        < _SEVERITY_RANK.get((f.get("severity") or "INFO").upper(), 0)
    ]

    result: Dict[str, Any] = {
        "ok": True,
        "target_ip": s.target_ip,
        "phase": s.phase,
        "findings_total": len(s.findings),
        # Vulnerabilidades confirmadas SEGÚN LA GOBERNANZA — la misma cifra que
        # publicará el informe. `marked_confirmed` se expone al lado para que la
        # diferencia sea visible y no un misterio: si el agente marcó 5 y solo 3
        # cuentan, debe poder verlo aquí en vez de descubrirlo al final.
        "findings_confirmed": len(confirmed),
        "findings_marked_confirmed": len(marked),
        "confirmed_by_effective_severity": by_effective,
        "recorded_cve_ids": [f.get("cve_id") for f in s.findings if f.get("cve_id")],
        "untested_candidate_cves": untested,
        "severity_capped_findings": capped,
        "probes_recommended": sorted(set(s.recommended_probes)),
        "probes_executed": sorted(set(s.executed_probes)),
        "coverage_pct": _compute_coverage_pct(s),
        # Cobertura de la SUPERFICIE (puertos TCP tocados / publicados), que es
        # una pregunta distinta de la cobertura de sondas recomendadas.
        "surface_coverage": _surface_coverage(s),
        "credentials_found": len(s.credentials),
        "report_saved_path": s.report_saved_path,
    }
    hints: List[str] = []
    if untested:
        hints.append(
            f"{len(untested)} untested candidate(s): {untested}. Test them "
            "individually or dismiss them with record_finding(confirmed=false, "
            "evidence='NOT_VULNERABLE|INCONCLUSIVE: reason') before done()."
        )
    if capped:
        hints.append(
            f"{len(capped)} confirmed finding(s) have an effective severity below "
            "the declared one: either the `impact` class is missing or the proof in "
            "`raw_output` is reachability only. Review them."
        )
    missing_probes = sorted(set(s.recommended_probes) - set(s.executed_probes))
    if missing_probes:
        hints.append(f"Recommended probes still pending: {missing_probes}.")
    sin_tocar = result["surface_coverage"]["untouched"]
    if sin_tocar:
        listado = ", ".join(f"{p['port']}/{p['service']}" for p in sin_tocar[:8])
        hints.append(
            f"{len(sin_tocar)} open TCP port(s) have received NO directed attempt: "
            f"{listado}. A port you never touched is not a negative result — the "
            f"report cannot tell it apart from one you probed and found clean. "
            f"Either send one directed request at each, or dismiss it explicitly "
            f"with record_finding(confirmed=false) stating why it is out of scope. "
            f"Do NOT brute-force paths on them."
        )
    if hints:
        result["next_actions"] = hints
    return result


def _stamp_run_outcome(session: "AgentSession") -> Optional[str]:
    """Sella `finish_reason` / `turns` / `interrupted` en el informe ya escrito.

    Solo toca el **JSON**. Es el artefacto que leen las máquinas —el arnés de
    varianza, el agregador del panel, cualquier recálculo del Capítulo 5— y el
    único donde el campo tiene consecuencias. Regenerar además el HTML, el MD y
    el SARIF exigiría rehacer el informe entero para cambiar tres claves que no
    aparecen en ninguno de los tres.

    Silencioso ante cualquier fallo: sellar metadatos no puede ser el motivo de
    que una auditoría terminada se dé por fallida.
    """
    base = getattr(session, "report_saved_path", None)
    if not base:
        return None
    ruta = f"{base}.json"
    try:
        with open(ruta, "r", encoding="utf-8") as fh:
            datos = json.load(fh)
        for entrada in datos.get("findings") or []:
            meta = entrada.setdefault("run_metadata", {})
            meta["finish_reason"] = session.finish_reason
            meta["turns"] = session.turns_completed or meta.get("turns")
            meta["interrupted"] = (bool(session.finish_reason)
                                   and session.finish_reason != "done_called")
        tmp = f"{ruta}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(datos, fh, indent=2, ensure_ascii=False, default=str)
        os.replace(tmp, ruta)
        return ruta
    except (OSError, json.JSONDecodeError, ValueError) as e:
        logger.debug(f"[REPORT] no se pudo sellar el desenlace en {ruta}: {e}")
        return None


def _done(args: Dict[str, Any]) -> Dict[str, Any]:
    """Finaliza ejecución. Adjunta risk score automático al summary.

    Red de seguridad: si el LLM llamó done() sin haber llamado save_report
    antes (failure mode observado en algunos modelos), generamos el report
    aquí para no perder los artefactos (HTML/JSON/MD/SARIF) de los findings
    ya registrados.
    """
    s = get_session()
    # Antes de guardar nada: este run SÍ llegó al final por su propio pie. El
    # informe se marcará como completo, no como rescatado.
    s.finish_reason = "done_called"
    # Y si el informe YA está escrito, se le sella el desenlace encima. El
    # camino normal es que el modelo llame a `save_report` y DESPUÉS a `done()`,
    # así que en el momento de escribir el artefacto todavía no se sabía cómo
    # iba a terminar el run: los 26 informes de la jornada de campo salieron con
    # `finish_reason: null` pese a haber terminado los 26 correctamente. El
    # rescate lo rellenaba bien por casualidad —porque él sí escribe al final—,
    # de modo que el único informe que declaraba su desenlace era el anómalo.
    _stamp_run_outcome(s)

    auto_saved_report: Optional[str] = None
    if getattr(s, "report_saved_path", None) is None and s.findings:
        logger.warning(
            "[DONE] save_report no fue llamado antes de done(); "
            "auto-guardando report para no perder los findings."
        )
        try:
            saved = _save_report({})
            auto_saved_report = saved.get("path")
            logger.success(f"[DONE] report auto-guardado en {auto_saved_report}")
        except Exception as e:
            logger.error(f"[DONE] auto-save del report falló: {e}")

    risk = compute_risk_score(s.findings)

    # CVEs batch-registrados que nunca se testearon individualmente (misma
    # definición que consulta `audit_status`, para que no divergan).
    untested = _untested_batch_cves(s)

    result: Dict[str, Any] = {
        "ok": True,
        "summary": args.get("summary", ""),
        "_finish": True,
        **risk,
    }
    if auto_saved_report:
        result["auto_saved_report"] = auto_saved_report
    cobertura = _surface_coverage(s)
    if cobertura["untouched"]:
        result["surface_coverage"] = cobertura
        listado = ", ".join(f"{p['port']}/{p['service']}"
                            for p in cobertura["untouched"][:8])
        result["warning_untouched_ports"] = (
            f"⚠️ {len(cobertura['untouched'])} open TCP port(s) reached the end of the "
            f"audit without a single targeted attempt: {listado}. They are recorded in "
            f"the report as unexplored surface, not as a negative result."
        )
    if untested:
        result["warning_untested_cves"] = untested
        result["warning_msg"] = (
            f"⚠️ {len(untested)} CVE(s) recorded as candidates were never tested "
            f"individually: {untested}. Consider testing them before finishing, or "
            "mark them with record_finding(confirmed=false, evidence='reason for the skip')."
        )
    return result


def _record_cve_findings(args: Dict[str, Any]) -> Dict[str, Any]:
    """Registra TODOS los CVEs devueltos por cve_search en una sola llamada.

    Acepta lista de CVEs (output directo de cve_search['cves']) y los registra como
    `confirmed=false` con severidad y descripción. Ahorra N turns que el modelo
    gastaría en llamadas individuales a record_finding.
    """
    cves = args.get("cves") or []
    if not isinstance(cves, list):
        return {
            "ok": False,
            "error": "cves must be a list (the output of cve_search['cves'])",
            "error_type": "VALIDATION",
        }
    confirmed_default = bool(args.get("confirmed", False))
    note = args.get("note", "Candidato del cve_search; pendiente de validación.")

    registered: List[str] = []
    skipped: List[str] = []
    session = get_session()

    for c in cves:
        if not isinstance(c, dict):
            continue
        cve_id = c.get("id") or c.get("cve_id")
        if not cve_id:
            continue
        severity = (c.get("severity") or "MEDIUM").upper()
        description = (c.get("description") or "")[:200]
        title = c.get("title") or description[:80] or cve_id

        # cve_search NO produce raw_output del dispositivo — solo metadata NVD.
        # La descripción del CVE es interpretación canónica de la vuln.
        model_hint = c.get("model_hint")
        model_note = (
            f" ⚠️ CVE específico de modelo '{model_hint}' — verifica que el dispositivo "
            f"sea ese modelo antes de intentar el exploit."
            if model_hint else ""
        )
        result = _record_finding({
            "cve_id": cve_id,
            "title": title,
            "severity": severity,
            "confirmed": confirmed_default,
            # No raw_output — cve_search no toca el target
            "interpretation": f"{note} {description}{model_note}".strip(),
            "cmd": _BATCH_CVE_CMD_MARKER,
        })
        if result.get("merged"):
            skipped.append(cve_id)
        else:
            registered.append(cve_id)

    # Rastrear IDs batch para que _done() pueda detectar los no testeados
    session.batch_registered_cves.extend(registered)

    return {
        "ok": True,
        "registered_new": registered,
        "merged_existing": skipped,
        "total_findings": len(session.findings),
        "note": (
            f"⚠️ Registrados {len(registered)} CVE candidatos. DEBES testear cada uno "
            "individualmente con execute_command + record_finding antes de llamar done()."
        ) if registered else None,
    }


def _record_findings_batch_unconfirmed(args: Dict[str, Any]) -> Dict[str, Any]:
    """Marca varios CVEs como confirmed=false con misma razón en una sola llamada.

    Caso de uso: tras intentar explotar CVE-2023-6317 sin éxito, los CVEs
    dependientes (CVE-2023-6318/6319/6320) heredan la imposibilidad. En vez
    de gastar 1 turno por CVE en `record_finding`, este batch los marca todos
    a la vez con la misma evidencia.

    Reuso del dedupe existente: si los CVEs ya están en findings, los actualiza.
    Si no, los crea con título genérico derivado del cve_id.
    """
    cve_ids = args.get("cve_ids") or []
    reason = args.get("reason") or ""
    severity = args.get("severity", "MEDIUM")

    if not isinstance(cve_ids, list) or not cve_ids:
        return {
            "ok": False,
            "error": "cve_ids must be a non-empty list",
            "error_type": "VALIDATION",
        }
    if not reason:
        return {
            "ok": False,
            "error": "reason is required (shared justification for every CVE)",
            "error_type": "VALIDATION",
        }

    updated: List[str] = []
    created: List[str] = []
    for cve_id in cve_ids:
        if not isinstance(cve_id, str) or not cve_id.strip():
            continue
        # batch_dismiss es interpretación pura (no datos del target).
        # NO populamos raw_output para no contaminar con texto narrativo.
        result = _record_finding({
            "cve_id": cve_id,
            "title": f"{cve_id} (no confirmado)",
            "severity": severity,
            "confirmed": False,
            "interpretation": reason,
            "cmd": "batch_dismiss",
        })
        if result.get("merged"):
            updated.append(cve_id)
        else:
            created.append(cve_id)

    return {
        "ok": True,
        "updated_existing": updated,
        "created_new": created,
        "total_findings": len(get_session().findings),
    }


def _execute_websocket(args: Dict[str, Any]) -> Dict[str, Any]:
    """Ejecuta WebSocket real (no curl con headers fake): connect → send payload → recv.

    Soporta ws:// y wss:// (TLS sin verify, para self-signed típico en IoT).
    Útil para CVEs LG WebOS, Samsung Tizen, etc. que requieren WebSocket genuino.

    Auto-detect de mensajes esperados:
      - Si el payload contiene `"type":"register"` (LG WebOS pairing flow), el server
        envía típicamente 2 mensajes: (1) handshake con pairingType, (2) registered
        con client-key (tras PIN o tras bypass). El default 1 perdería el segundo
        que es donde está la confirmación. Auto-default a 2.
      - Para otros payloads, default 1 sigue siendo correcto.
      - El usuario puede override pasando `expect_n_messages` explícitamente.
    """
    import asyncio
    import ssl

    url = args.get("url")
    if not url:
        return {"ok": False, "error": "url required (ws:// or wss://)"}
    payload = args.get("payload", "")
    timeout = float(args.get("timeout", 8))

    # Auto-detect: pairing flows necesitan 2 mensajes
    if "expect_n_messages" in args:
        expect_n_messages = int(args["expect_n_messages"])
    else:
        expect_n_messages = 2 if isinstance(payload, str) and '"type":"register"' in payload else 1

    try:
        import websockets
        from websockets.exceptions import WebSocketException
    except ImportError:
        return {"ok": False, "error": "websockets library not installed (pip install websockets>=12)"}

    async def _exchange() -> Dict[str, Any]:
        ssl_ctx = None
        if url.startswith("wss://"):
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
        try:
            async with websockets.connect(
                url,
                ssl=ssl_ctx,
                open_timeout=timeout,
                close_timeout=timeout,
                ping_interval=None,
            ) as ws:
                if payload:
                    await ws.send(payload)
                messages: List[str] = []
                try:
                    while len(messages) < expect_n_messages:
                        msg = await asyncio.wait_for(ws.recv(), timeout=timeout)
                        if isinstance(msg, bytes):
                            msg = msg.decode("utf-8", errors="replace")
                        messages.append(msg)
                except asyncio.TimeoutError:
                    pass
                return {
                    "ok": True,
                    "url": url,
                    "messages_received": len(messages),
                    "messages": [m[:2000] for m in messages],
                    "handshake": "ok",
                }
        except WebSocketException as e:
            return {
                "ok": False,
                "url": url,
                "error": f"websocket error: {e}",
                "error_type": "WS_PROTOCOL",
            }
        except (OSError, asyncio.TimeoutError) as e:
            return {
                "ok": False,
                "url": url,
                "error": str(e),
                "error_type": "NETWORK",
            }

    try:
        return asyncio.run(_exchange())
    except RuntimeError as e:
        # asyncio.run falla si ya hay un loop activo (raro en agente, pero por si acaso)
        return {"ok": False, "error": f"asyncio: {e}", "error_type": "RUNTIME"}


def _recommend_probes(args: Dict[str, Any]) -> Dict[str, Any]:
    """Mapea puertos detectados por nmap a probes específicas.
    Devuelve lista priorizada con razón. Ayuda al modelo a no saltarse cobertura.

    Si el modelo no pasa `ports` (o los pasa en un formato que no se puede
    interpretar), se recurre a los puertos del `scan_cache` en lugar de devolver
    un plan vacío: un plan vacío desactivaba en silencio el *coverage enforcement*
    de `transition_phase`, que es justo la salvaguarda contra saltarse las sondas.
    """
    ports_input = args.get("ports") or []
    if not ports_input and _SESSION is not None:
        ports_input = (_SESSION.scan_cache or {}).get("ports") or []
    # Aceptar tanto [{"port":80,"proto":"tcp"}, ...] como [80, 443, ...]
    ports_set = set()
    for p in ports_input:
        if isinstance(p, dict):
            n = p.get("port")
            proto = (p.get("proto") or "tcp").lower()
            if n is not None:
                ports_set.add((int(n), proto))
        elif isinstance(p, (int, str)):
            try:
                ports_set.add((int(p), "tcp"))
            except (ValueError, TypeError):
                pass

    # Tabla puerto → (probe, razón, prioridad). Prioridad menor = más prioritario.
    PORT_MAP = {
        # HTTP/web
        (80, "tcp"): ("http_interrogate", "HTTP — fingerprint + unauth endpoints", 1),
        (443, "tcp"): ("http_interrogate", "HTTPS — TLS cert + banners", 1),
        (8080, "tcp"): ("http_interrogate", "HTTP alt", 1),
        (8443, "tcp"): ("http_interrogate", "HTTPS alt", 1),
        (8888, "tcp"): ("http_interrogate", "HTTP alt", 1),
        # Streaming / cast
        (3000, "tcp"): ("probe_lg_webos", "LG WebOS HTTP control", 2),
        (3001, "tcp"): ("probe_lg_webos", "LG WebOS WebSocket", 2),
        (8008, "tcp"): ("probe_chromecast", "Chromecast/Eureka", 2),
        (1664, "tcp"): ("probe_dial", "DIAL discovery", 2),
        (1755, "tcp"): ("probe_dial", "DIAL alt port", 2),
        (554, "tcp"): ("probe_rtsp", "RTSP stream", 2),
        (8554, "tcp"): ("probe_rtsp", "RTSP alt", 2),
        (7000, "tcp"): ("probe_rtsp", "AirPlay/RTSP — try OPTIONS", 2),
        # Discovery / IoT
        (53, "tcp"): ("probe_dns", "DNS open recursion + dnsmasq CVE assessment", 2),
        (53, "udp"): ("probe_dns", "DNS open recursion + dnsmasq CVE assessment", 2),
        (23, "tcp"): ("probe_telnet", "Telnet — Mirai default creds", 1),
        (161, "udp"): ("probe_snmp", "SNMP community strings", 2),
        (5353, "udp"): ("probe_mdns", "mDNS service discovery", 2),
        (5683, "udp"): ("probe_coap", "CoAP /.well-known/core", 2),
        (1900, "udp"): ("probe_upnp_igd", "UPnP IGD analysis", 2),
        (3702, "udp"): ("probe_wsdiscovery", "WS-Discovery cameras/printers", 2),
        (47808, "udp"): ("probe_bacnet", "BACnet/IP HVAC", 2),
        (69, "udp"): ("probe_tftp", "TFTP firmware download", 2),
        (54321, "udp"): ("probe_miio", "Xiaomi miIO — token/identity", 1),
        # IoT apps
        (1883, "tcp"): ("probe_mqtt", "MQTT broker — anon connect", 1),
        (8883, "tcp"): ("probe_mqtt", "MQTT over TLS", 1),
        (7547, "tcp"): ("probe_cwmp", "TR-069 / CWMP — Mirai vector", 1),
        # Industrial / OT
        (502, "tcp"): ("probe_modbus", "Modbus TCP — PLC/SCADA", 1),
        (4840, "tcp"): ("probe_opcua", "OPC-UA industrial", 1),
        # Banners + auth básico
        (22, "tcp"): ("probe_ssh", "SSH banner + version match CVEs", 1),
        (21, "tcp"): ("probe_ftp", "FTP anonymous login attempt", 1),
        (445, "tcp"): ("probe_smb", "SMB v1 detection (EternalBlue)", 1),
        (139, "tcp"): ("probe_smb", "SMB over NetBIOS (legacy)", 2),
        (25, "tcp"): ("execute_command", "SMTP banner — curl/nc", 3),
        # Prioridad 1: un proxy abierto convierte al aparato en salto hacia sus
        # propios servicios de loopback, y el handshake es barato y concluyente.
        (1080, "tcp"): ("probe_socks5", "SOCKS5 — no-auth? does it relay?", 1),
        (1081, "tcp"): ("probe_socks5", "SOCKS5 alt", 2),
        # Protocolos de fabricante sobre TCP, vía sonda genérica probe_tcp
        (6668, "tcp"): ("probe_tcp", "Tuya — local control protocol", 1),
        (6053, "tcp"): ("probe_tcp", "ESPHome — native API", 1),
        (6379, "tcp"): ("probe_tcp", "Redis — does PING answer without auth?", 2),
    }

    # Sondas genéricas que necesitan argumentos para ser útiles: el plan los da
    # resueltos para que el agente los pase tal cual a run_probes, en vez de
    # tener que adivinar el `proto_hint` correcto (fuente de varianza).
    PROBE_ARGS = {
        (6668, "tcp"): {"port": 6668, "proto_hint": "tuya"},
        (6053, "tcp"): {"port": 6053, "proto_hint": "esphome"},
        (6379, "tcp"): {"port": 6379, "proto_hint": "redis"},
    }

    recommendations = []
    seen_probes = set()
    for (port, proto), (probe_name, reason, prio) in PORT_MAP.items():
        if (port, proto) in ports_set:
            key = (probe_name, port, proto)
            if key in seen_probes:
                continue
            seen_probes.add(key)
            rec: Dict[str, Any] = {
                "probe": probe_name,
                "port": port,
                "proto": proto,
                "reason": reason,
                "priority": prio,
            }
            probe_args = PROBE_ARGS.get((port, proto))
            if probe_args:
                rec["args"] = dict(probe_args)
            recommendations.append(rec)

    recommendations.sort(key=lambda r: (r["priority"], r["port"]))

    # --- Recomendación por IDENTIDAD, no por puerto ---
    # Algunas probes no deben condicionarse a "puerto abierto": el escaneo UDP
    # es poco fiable (open|filtered) y protocolos como Xiaomi miIO (54321) casi
    # nunca aparecen. El disparador correcto es la identidad del dispositivo.
    # Si el OUI/vendor apunta a Xiaomi o el OS a Espressif/ESP8266, sugerimos
    # probe_miio aunque 54321 no se haya detectado abierto.
    _scan_id = (_SESSION.scan_cache or {}) if _SESSION else {}
    _id_blob = " ".join(str(_scan_id.get(k, "")) for k in (
        "vendor", "manufacturer", "ssdp_manufacturer", "os_match", "os_cpe")).lower()
    if ("xiaomi" in _id_blob or "espressif" in _id_blob or "esp8266" in _id_blob
            or "esp32" in _id_blob):
        if not any(r["probe"] == "probe_miio" for r in recommendations):
            recommendations.append({
                "probe": "probe_miio",
                "port": 54321,
                "proto": "udp",
                "reason": ("Xiaomi/ESP identity — miIO usually answers on 54321 even "
                           "when the UDP scan does not mark it open"),
                "priority": 1,
                "identity_driven": True,
            })

    # --- Barrido UDP de descubrimiento cuando el host está vivo pero "callado" ---
    # El escaneo UDP de nmap casi nunca confirma puertos (open|filtered), así que
    # un dispositivo que responde a ping pero muestra 0-2 puertos TCP NO está
    # necesariamente mudo: sus servicios UDP de descubrimiento (mDNS, SSDP, SNMP,
    # CoAP, WS-Discovery) responden a la payload correcta aunque nmap no los viera.
    # Estos probes ya envían el protocolo correcto, así que se recomiendan por
    # cobertura, no por "puerto abierto". Barato y de alto rendimiento.
    tcp_open = sum(1 for (p, proto) in ports_set if proto == "tcp")
    host_alive = bool(_scan_id.get("mac") or _scan_id.get("os_match"))
    if host_alive and tcp_open <= 2:
        UDP_SWEEP = [
            ("probe_mdns", 5353, "mDNS/Bonjour — service identity"),
            ("probe_upnp_igd", 1900, "SSDP/UPnP — discovery"),
            ("probe_snmp", 161, "SNMP default communities"),
            ("probe_coap", 5683, "CoAP /.well-known/core"),
            ("probe_wsdiscovery", 3702, "WS-Discovery — cameras/printers"),
        ]
        for probe_name, port, reason in UDP_SWEEP:
            if not any(r["probe"] == probe_name for r in recommendations):
                recommendations.append({
                    "probe": probe_name,
                    "port": port,
                    "proto": "udp",
                    "reason": f"{reason} (host alive but quiet; the UDP scan is not reliable)",
                    "priority": 2,
                    "identity_driven": True,
                })

    # Probes que SIEMPRE conviene si nmap devolvió MAC
    mandatory: List[Dict[str, Any]] = []
    if ports_set:
        mandatory.append({
            "probe": "mac_vendor_lookup",
            "reason": "Resolver fabricante de MAC (siempre tras nmap)",
        })

    # Persistir lista en sesión para coverage enforcement en transition_phase
    if _SESSION is not None:
        unique_probes: List[str] = []
        seen: set = set()
        for rec in recommendations:
            if rec["probe"] not in seen:
                seen.add(rec["probe"])
                unique_probes.append(rec["probe"])
        # Mandatory tools también deben contarse
        for m in mandatory:
            if m["probe"] not in seen:
                seen.add(m["probe"])
                unique_probes.append(m["probe"])
        _SESSION.recommended_probes = unique_probes

    # ---- Enriquecimiento desde Knowledge Base (si está disponible) ----
    # Si el target IP fue auditado previamente o el vendor es conocido en la KB,
    # añadimos contexto histórico para que el agente no parta de cero.
    kb_context: Dict[str, Any] = {}
    try:
        from core.knowledge_base import get_kb
        kb = get_kb()
        target_ip = _SESSION.target_ip if _SESSION else None

        if target_ip:
            # Lookup por identidad (MAC), nunca por IP — las IPs se reutilizan.
            _scan = (_SESSION.scan_cache or {}) if _SESSION else {}
            previous = kb.get_device_record(ip=target_ip, mac=_scan.get("mac"),
                                            firmware=_scan.get("firmware"))
            # Defensa en profundidad: aunque la KB devolviera (por bug/legado) un
            # registro de otra MAC, no se hereda su identidad.
            from modules.fingerprint import normalize_mac
            scan_mac = normalize_mac(_scan.get("mac"))
            prev_mac = normalize_mac(previous.get("mac")) if previous else None
            if previous and scan_mac and prev_mac and scan_mac != prev_mac:
                logger.info(
                    f"[recommend_probes] el registro KB de {target_ip} tiene MAC "
                    f"{prev_mac} ≠ {scan_mac} del escaneo actual: otro dispositivo "
                    f"(IP reutilizada). No se hereda identidad por IP.")
                previous = None
            if previous:
                kb_context["previous_audit"] = {
                    "first_seen": previous.get("first_seen"),
                    "last_seen": previous.get("last_seen"),
                    "audit_count": previous.get("audit_count", 0),
                    "vendor": previous.get("vendor"),
                    "model": previous.get("model"),
                    "firmware": previous.get("firmware"),
                    "previous_findings_count": previous.get("findings_count_last", 0),
                }
                vendor = previous.get("vendor")
                if vendor:
                    profile = kb.get_vendor_profile(vendor)
                    if profile:
                        kb_context["vendor_profile"] = {
                            "vendor": vendor,
                            "useful_probes_historically": profile.get("useful_probes", []),
                            "patched_cves_known": profile.get("patched_cves", []),
                            "device_count_audited": profile.get("device_count", 0),
                        }
                        # Reordenar recomendaciones: probes ya validados como útiles
                        # para este vendor suben a prioridad 0 (más alta).
                        useful_set = set(profile.get("useful_probes", []))
                        for rec in recommendations:
                            if rec["probe"] in useful_set:
                                rec["priority"] = 0
                                rec["reason"] += " [KB: probe useful for this vendor]"
                        recommendations.sort(key=lambda r: (r["priority"], r["port"]))
    except Exception as e:
        # KB es enhancement, no critical — log y continuar
        logger.debug(f"[recommend_probes] KB enrichment skipped: {e}")

    # ---- Sugerencias de búsqueda CVE por versión de componente ----
    # Lee los puertos del scan_cache (nmap incluye product+version en cada puerto).
    # Genera términos de búsqueda específicos para que el agente no olvide buscar
    # CVEs de lighttpd, Dropbear, PHP, etc. independientemente del vendor del dispositivo.
    cve_searches_suggested: List[Dict[str, str]] = []
    try:
        cache_ports = (_SESSION.scan_cache or {}).get("ports", []) if _SESSION else []
        # También acepta los ports que el agente pasó directamente (pueden tener product/version)
        all_port_dicts = list(cache_ports)
        for p in ports_input:
            if isinstance(p, dict) and p.get("product"):
                all_port_dicts.append(p)

        seen_terms: set = set()
        for port_info in all_port_dicts:
            if not isinstance(port_info, dict):
                continue
            product = (port_info.get("product") or "").strip()
            version = (port_info.get("version") or "").strip()
            if not product:
                continue
            # Construir término: "producto versión_mayor" (ej: "lighttpd 1.4", "dropbear 2016")
            ver_parts = version.split(".")
            ver_short = ".".join(ver_parts[:2]) if len(ver_parts) >= 2 else version
            term = f"{product} {ver_short}".strip() if ver_short else product
            if term.lower() not in seen_terms:
                seen_terms.add(term.lower())
                cve_searches_suggested.append({
                    "keyword": term,
                    "reason": f"Specific version detected by nmap: {product} {version}",
                    "port": port_info.get("port"),
                })

    except Exception as e:
        logger.debug(f"[recommend_probes] cve_searches_suggested skipped: {e}")

    response = {
        "ok": True,
        "input_ports": sorted(p[0] for p in ports_set),
        "recommendations": recommendations,
        "mandatory_after_nmap": mandatory,
        "instruction": (
            "Run ALL the recommended probes you have not called yet. "
            "Only after exhausting this list, call cve_search with the vendor/model "
            "you obtained. transition_phase WILL BLOCK the transition if fewer than "
            "60% of the recommended probes have been run."
        ),
        "_elapsed_ms": 0,
    }
    if cve_searches_suggested:
        response["cve_searches_suggested"] = cve_searches_suggested
        response["instruction"] += (
            " Also search CVEs for every component in cve_searches_suggested "
            "(specific software versions detected by nmap)."
        )
    if kb_context:
        response["kb_context"] = kb_context
        # Si conocemos CVEs ya patcheados, instrucción adicional
        patched = kb_context.get("vendor_profile", {}).get("patched_cves_known", [])
        if patched:
            response["instruction"] += (
                f" The KB reports that these CVEs are consistently patched for "
                f"this vendor: {patched}. Do not spend turns validating them."
            )
    return response


def _transition_phase(args: Dict[str, Any]) -> Dict[str, Any]:
    """Solicita cambiar de fase (recon ↔ exploit).

    Coverage enforcement: si transitamos a 'exploit' y la cobertura de probes
    recomendadas es <60%, bloqueamos la transición y devolvemos lista de probes
    pendientes. El modelo debe ejecutarlas antes de retransicionar.

    Override: pasar `force=true` (escape hatch documentado para casos donde
    una probe recomendada no aplica al target — ej: nmap detectó puerto pero
    el servicio no responde).
    """
    target = (args.get("phase") or "").strip().lower()
    force = bool(args.get("force", False))
    if target not in PHASES:
        return {
            "ok": False,
            "error": f"phase must be one of {list(PHASES)}",
            "error_type": "VALIDATION",
        }

    # Coverage enforcement — solo en recon → exploit
    session = _SESSION
    if target == "exploit" and not force and session is not None and session.recommended_probes:
        recommended = set(session.recommended_probes)
        executed = set(session.executed_probes)
        missing = sorted(recommended - executed)
        # Misma fórmula que _compute_coverage_pct: ratio de RECOMENDADAS cubiertas.
        # No incluye probes ejecutadas extra (ad-hoc) — solo lo planificado.
        coverage_ratio = len(recommended & executed) / len(recommended)
        if coverage_ratio < 0.6:
            return {
                "ok": False,
                "error_type": "COVERAGE_INSUFFICIENT",
                "error": (
                    f"Insufficient probe coverage: "
                    f"{int(coverage_ratio * 100)}% (minimum 60%). "
                    f"Run the pending probes before transitioning."
                ),
                "coverage_pct": round(coverage_ratio * 100, 1),
                "executed": sorted(executed),
                "missing": missing,
                # El mensaje ya no nombra el escape hatch. Antes lo explicaba en
                # la misma respuesta que bloqueaba la transición, con lo que la
                # puerta se abría sola: el modelo leía el bloqueo y el modo de
                # saltárselo a la vez, y la cobertura mínima quedaba en una
                # sugerencia. `force` sigue existiendo y está documentado en el
                # esquema de la tool —para el caso legítimo de una sonda que no
                # aplica— pero usarlo debe ser una decisión del agente, no la
                # salida que el propio sistema le señala.
                "instruction": (
                    f"Run these pending probes first: {missing}. "
                    f"If one does NOT apply to the target, run it anyway and record "
                    f"it as not applicable: a negative result is information, and "
                    f"that way coverage reflects what has actually been checked."
                ),
            }

    # La fase efectiva cambia ya aquí: las restricciones deterministas por fase
    # (solo lectura en recon) deben seguir a la transición sin depender de que el
    # bucle del agente propague el cambio.
    set_phase(target)

    return {
        "ok": True,
        "_transition_to": target,
        # Coverage % representa probes recomendadas que SÍ se ejecutaron.
        # Capeamos a 100 porque executed_probes puede contener probes ad-hoc no
        # recomendadas que no deberían inflar la métrica.
        "coverage_pct": _compute_coverage_pct(session) if session is not None else None,
        "message": (
            f"Transitioned → '{target}' phase. The next turn loads that phase's "
            f"prompt and tools."
            + (" [forced]" if force else "")
        ),
    }


def _compute_coverage_pct(session: "AgentSession") -> Optional[float]:
    """Porcentaje de probes recomendadas que se ejecutaron, capeado a 100%.

    Devuelve None si no se ha llamado recommend_probes (no hay baseline).
    """
    if not session.recommended_probes:
        return None
    recommended = set(session.recommended_probes)
    executed = set(session.executed_probes)
    matched = recommended & executed
    pct = len(matched) / len(recommended) * 100
    return round(min(100.0, pct), 1)


# =====================================================================
# Registro declarativo
# =====================================================================

def _obj(*required: str, **props) -> Dict[str, Any]:
    """Objeto JSON Schema. Los nombres pasados como POSICIONALES van a `required`.

    Ej.: `_obj("cmd", cmd=_str("…"), timeout=_int("…"))`. Que un `required` no
    exista entre las propiedades es un error de programación, así que revienta al
    importar el módulo en lugar de generar un schema silenciosamente inválido.
    """
    unknown = [r for r in required if r not in props]
    if unknown:
        raise ValueError(f"required inexistente(s) en properties: {unknown}")
    return {"type": "object", "properties": props, "required": list(required)}


def _str(desc: str = "") -> Dict[str, Any]:
    return {"type": "string", "description": desc}


def _enum(desc: str, *values: str) -> Dict[str, Any]:
    """String con dominio cerrado. Restringe al modelo en la propia API en vez de
    confiar en que el prompt enumere los valores válidos (menos varianza)."""
    if not values:
        raise ValueError("un enum sin valores no restringe nada")
    return {"type": "string", "description": desc, "enum": list(values)}


def _enum_desc(values: Tuple[str, ...], desc: str) -> Dict[str, Any]:
    """Igual que `_enum` pero con los valores delante, para descripciones largas."""
    return _enum(desc, *values)


def _int(desc: str = "") -> Dict[str, Any]:
    return {"type": "integer", "description": desc}


def _bool(desc: str = "") -> Dict[str, Any]:
    return {"type": "boolean", "description": desc}


def _array(items, desc: str = "") -> Dict[str, Any]:
    return {"type": "array", "items": items, "description": desc}


def _obj_desc(desc: str = "") -> Dict[str, Any]:
    """Object opaco (sin schema interno) usado para evidence/scan_results — el
    agente pasa lo que tenga, el tool lo agrega con defaults."""
    return {"type": "object", "description": desc}


def build_registry() -> None:
    _REGISTRY.clear()

    register(Tool(
        name="nmap_scan",
        description=(
            "Scan TCP ports (top-10000 + extended IoT range) and UDP ports (if "
            "running as root) on the target. Returns open ports with service, "
            "product, version and a per-port **`cpe` field**, plus the OS guess and "
            "the MAC. FIRST tool of every audit: the rest of the plan (probes, CPEs "
            "for CVE lookup, identity) derives from its output. The result is stored "
            "in the session `scan_cache` and merged with previous scans, so "
            "re-scanning never loses already-discovered ports. Caveat: `os_match` is "
            "an unreliable hypothesis on IoT; the MAC OUI overrides it."
        ),
        parameters=_obj(
            ip=_str("Target IP. If omitted, the session target is used."),
            ports=_str("Optional nmap-style range (e.g. '1-65535'). Omit for "
                       "top-10000 + extra IoT ports."),
        ),
        impl=_nmap_scan,
        phases=("recon", "exploit"),  # útil también para re-fingerprint
    ))

    register(Tool(
        name="probe_hnap",
        description=(
            "HNAP1 probe (SOAP over HTTP) for D-Link and similar gear: requests "
            "`GetDeviceSettings` unauthenticated and extracts ModelName and "
            "FirmwareVersion. It is the HIGHEST-weighted identity source in the "
            "fingerprint consensus, because the device declares its own model."
        ),
        parameters=_obj(
            ip=_str("Target IP. If omitted, the session target is used."),
            ports=_array(_int(), "Candidate web ports (default 80, 8080, 443, 8443)."),
            timeout=_int("Per-request timeout in seconds (default 5)."),
        ),
        impl=_hnap_probe,
        phases=("recon",),
    ))

    register(Tool(
        name="probe_snmp",
        description=(
            "Tries the usual SNMP communities (public, private, …) and, if one is "
            "accepted, returns sysDescr and sysObjectID. A sysDescr usually carries "
            "vendor, model and firmware version in the clear: it is first-class "
            "identity evidence and, on top of that, unauthenticated info exposure."
        ),
        parameters=_obj(
            ip=_str("Target IP. If omitted, the session target is used."),
            communities=_array(_str(), "Communities to try (default: public, private, …).")
        ),
        impl=_snmp_probe,
        phases=("recon",),
    ))

    register(Tool(
        name="probe_mdns",
        description=(
            "Listens to mDNS/Bonjour (UDP 5353) and enumerates the services the "
            "target advertises (AirPlay, Cast, HomeKit/HAP, IPP…). From the TXT "
            "properties it extracts model, firmware and serial number, which are "
            "injected into the `scan_cache` for identity. Emits an MDNS-EXPOSED "
            "finding at INFO severity: it is surface/hygiene, not a vulnerability."
        ),
        parameters=_obj(
            ip=_str("Target IP. If omitted, the session target is used."),
            timeout=_int("mDNS listen window in seconds (default 2.5)."),
        ),
        impl=_mdns_probe,
        phases=("recon",),
    ))

    register(Tool(
        name="probe_coap",
        description=(
            "CoAP (UDP 5683): GET /.well-known/core and /oic/res to enumerate the "
            "resources the device publishes without authentication. Common on "
            "low-power sensors and OCF/OneIoTa devices."
        ),
        parameters=_obj(
            ip=_str("Target IP. If omitted, the session target is used."),
        ),
        impl=_coap_probe,
        phases=("recon",),
    ))

    register(Tool(
        name="probe_mqtt",
        description=(
            "MQTT broker probe (1883/8883): attempts anonymous CONNECT, wildcard '#' "
            "SUBSCRIBE and a test PUBLISH. Detects misconfigured IoT brokers (anonymous "
            "access, wildcard subscribe, open publish). Returns vulnerabilities[] with "
            "severity."
        ),
        parameters=_obj(
            ip=_str("Target IP (defaults to the session target)."),
            port=_int("MQTT port (default 1883). Use 8883 for MQTTS."),
            timeout=_int("Timeout in seconds (default 5)."),
        ),
        impl=_mqtt_probe,
        phases=("recon",),
    ))

    register(Tool(
        name="probe_miio",
        description=(
            "Probe for Xiaomi's native protocol (miIO) over UDP 54321. Sends the "
            "unauthenticated 'hello' handshake (read-only, a single datagram) and, if "
            "the device answers, CONFIRMS it is a Xiaomi miIO device and extracts its "
            "device-id and uptime — useful when nmap sees no ports but the OUI/vendor "
            "is Xiaomi. On old firmware it reveals the TOKEN in the clear (full local "
            "control → CRITICAL). "
            "⚠️ USE IT BY IDENTITY, NOT BY PORT: run it WHENEVER the vendor/OUI is "
            "Xiaomi or the OS looks like Espressif/ESP8266, EVEN IF port 54321 does "
            "NOT show up as open — UDP scanning is unreliable (open|filtered) and will "
            "almost never flag it. It is the first resort for an apparently 'mute' "
            "Xiaomi device."
        ),
        parameters=_obj(
            ip=_str("Target IP (defaults to the session target)."),
            port=_int("miIO port (default 54321)."),
            timeout=_int("Timeout in seconds (default 4)."),
        ),
        impl=_miio_probe,
        phases=("recon",),
    ))

    register(Tool(
        name="probe_udp",
        description=(
            "Generic UDP probe for ports WITHOUT a dedicated probe. Sends ONE datagram "
            "and returns the raw response (hex + printable ascii + length). "
            "KEY POINT: a UDP service only answers the CORRECT protocol payload; "
            "sending empty/random bytes yields silence (which is why nmap's UDP scan "
            "fails). You KNOW many protocols from your training: **build the payload "
            "in hex** (`payload_hex`) — e.g. an SSDP M-SEARCH, an mDNS query, an NTP "
            "mode-6 request, a vendor handshake — or use `proto_hint` with a protocol "
            "from the built-in library (ssdp, mdns, coap, ntp, netbios, dns, snmp, isakmp). "
            "Useful when you see an odd UDP port or a 'silent' device you suspect speaks "
            "a protocol with no dedicated probe. "
            "⚠️ This is DISCOVERY, not confirmation: it does NOT flag vulnerabilities on "
            "its own. If the response reveals something exploitable, confirm it afterwards "
            "with the evidence (record_finding with confirmed=true only if you prove it)."
        ),
        parameters=_obj(
            "port",
            ip=_str("Target IP (defaults to the session target)."),
            port=_int("Target UDP port. Required."),
            payload_hex=_str("Hex payload to send (e.g. '21310020ffff…'). Build it "
                             "yourself for the protocol, or use proto_hint."),
            proto_hint=_enum(
                "Protocol from the built-in library, if you do not build payload_hex.",
                "ssdp", "mdns", "coap", "ntp", "netbios", "dns", "snmp", "isakmp", "miio",
            ),
            timeout=_int("Timeout in seconds (default 4)."),
        ),
        impl=_udp_probe,
        phases=("recon",),
    ))

    register(Tool(
        name="probe_tcp",
        description=(
            "Generic TCP probe for ports WITHOUT a dedicated probe — the counterpart "
            "of `probe_udp`, with one key difference: over TCP the `connect` already "
            "proves the port is open and many services GREET you without being asked, "
            "so the payload is OPTIONAL (without it, this does a banner grab). "
            "It covers the TCP IoT protocols no probe handles: **Tuya local (6668)** "
            "and **ESPHome (6053)** are the canonical case of a device that 'exposes "
            "nothing' yet speaks its vendor's protocol. Use `proto_hint` (tuya, "
            "esphome, http, redis) or build the bytes yourself in `payload_hex`. "
            "⚠️ This is DISCOVERY, not confirmation: it returns the raw response and "
            "does NOT flag vulnerabilities. A successful `connect` is reachability, "
            "not access: to confirm anything you need the service to RETURN data."
        ),
        parameters=_obj(
            "port",
            ip=_str("Target IP (defaults to the session target)."),
            port=_int("Target TCP port. Required."),
            payload_hex=_str("Hex payload to send after connecting. Omit for a "
                             "banner grab (just read whatever the service announces)."),
            proto_hint=_enum(
                "Protocol from the built-in library, if you do not build payload_hex.",
                "tuya", "esphome", "http", "redis",
            ),
            timeout=_int("Timeout in seconds (default 5)."),
        ),
        impl=_tcp_probe,
        phases=("recon",),
    ))

    register(Tool(
        name="probe_modbus",
        description=(
            "Modbus TCP probe (port 502, OT/SCADA): Function Code 17 (Report Slave ID) "
            "and FC1 (Read Coils). Detects PLCs and industrial gear with no "
            "authentication. Direct detection of critical exposure on ICS networks."
        ),
        parameters=_obj(
            ip=_str("Target IP (defaults to the session target)."),
            port=_int("Modbus port (default 502)."),
            timeout=_int("Timeout in seconds (default 5)."),
            unit_ids=_array(_int(), "Unit IDs to try (default [1, 0, 255])."),
        ),
        impl=_modbus_probe,
        phases=("recon",),
    ))

    register(Tool(
        name="probe_rtsp",
        description=(
            "RTSP/ONVIF probe (554, 8554) — IP cameras. OPTIONS + DESCRIBE on common "
            "paths (/, /live, /h264, /onvif/snapshot). On a 401 it tries default "
            "credentials (admin/admin, admin/12345, etc.). Detects unauthenticated "
            "streams and weak credentials."
        ),
        parameters=_obj(
            ip=_str("Target IP. If omitted, the session target is used."),
            ports=_array(_int(), "RTSP ports (default [554, 8554])."),
            timeout=_int("Timeout in seconds (default 5)."),
        ),
        impl=_rtsp_probe,
        phases=("recon",),
    ))

    register(Tool(
        name="probe_bacnet",
        description=(
            "BACnet/IP probe (UDP 47808) — building automation / HVAC. Sends a unicast "
            "Who-Is and detects I-Am responses. If it answers, the OT device is exposed "
            "without authentication."
        ),
        parameters=_obj(
            ip=_str("Target IP. If omitted, the session target is used."),
            port=_int("BACnet port (default 47808)."),
            timeout=_int("Timeout in seconds (default 3)."),
        ),
        impl=_bacnet_probe,
        phases=("recon",),
    ))

    register(Tool(
        name="probe_cwmp",
        description=(
            "TR-069/CWMP probe (port 7547) — ISP/router vector. HTTP banner plus checks "
            "for RomPager (CVE-2014-9222 'Misfortune Cookie') and Huawei HG532 "
            "(CVE-2017-17215, Mirai SOAP injection)."
        ),
        parameters=_obj(
            ip=_str("Target IP. If omitted, the session target is used."),
            port=_int("CWMP port (default 7547)."),
            timeout=_int("Timeout in seconds (default 5)."),
        ),
        impl=_cwmp_probe,
        phases=("recon",),
    ))

    register(Tool(
        name="probe_telnet",
        description=(
            "Telnet probe (23) — Mirai's primary vector. Captures the banner, matches "
            "it against signatures (BusyBox/Hikvision/OpenWrt/DD-WRT/DrayTek/Zyxel) and "
            "ATTEMPTS login with Mirai default credentials (root/xc3511, root/vizxv, "
            "admin/admin, …). If one works → CRITICAL TELNET-DEFAULT-CRED vulnerability "
            "with shell proof."
        ),
        parameters=_obj(
            ip=_str("Target IP. If omitted, the session target is used."),
            port=_int("Telnet port (default 23)."),
            timeout=_int("Timeout in seconds (default 5)."),
            try_default_creds=_bool("Try Mirai default credentials (default true)."),
            max_creds_attempts=_int("User/password pairs to try (default 6, max 13)."),
        ),
        impl=_telnet_probe,
        phases=("recon",),
    ))

    register(Tool(
        name="probe_upnp_igd",
        description=(
            "UPnP IGD probe: unicast M-SEARCH (1900) → fetch device.xml → look for "
            "AddPortMapping/DeletePortMapping in the SCPD. Detects routers that allow "
            "arbitrary port forwarding without authentication (LAN→WAN attack)."
        ),
        parameters=_obj(
            ip=_str("Target IP. If omitted, the session target is used."),
            timeout=_int("Timeout in seconds (default 3)."),
        ),
        impl=_upnp_igd_probe,
        phases=("recon",),
    ))

    register(Tool(
        name="probe_wsdiscovery",
        description=(
            "WS-Discovery probe (UDP 3702) — SOAP protocol probe. Detects ONVIF cameras "
            "(NetworkVideoTransmitter), DPWS printers and Microsoft DPWS devices. Useful "
            "for quiet enumeration when the device does not answer other probes."
        ),
        parameters=_obj(
            ip=_str("Target IP. If omitted, the session target is used."),
            port=_int("WS-Discovery port (default 3702)."),
            timeout=_int("Timeout in seconds (default 3)."),
        ),
        impl=_wsdiscovery_probe,
        phases=("recon",),
    ))

    register(Tool(
        name="probe_opcua",
        description=(
            "OPC-UA probe (4840) — industrial protocol. Hello → Acknowledge handshake. "
            "Confirms the service is exposed. Verifying SecurityPolicy/UserToken "
            "requires a dedicated OPC-UA client (not included in this tool)."
        ),
        parameters=_obj(
            ip=_str("Target IP. If omitted, the session target is used."),
            port=_int("OPC-UA port (default 4840)."),
            timeout=_int("Timeout in seconds (default 5)."),
        ),
        impl=_opcua_probe,
        phases=("recon",),
    ))

    register(Tool(
        name="probe_tftp",
        description=(
            "TFTP probe (UDP 69): anonymous RRQ for common filenames (firmware.bin, "
            "config.bin, running-config, etc.). If it receives DATA → firmware/config "
            "extractable without authentication (CRITICAL)."
        ),
        parameters=_obj(
            ip=_str("Target IP. If omitted, the session target is used."),
            port=_int("TFTP port (default 69)."),
            timeout=_int("Timeout in seconds (default 3)."),
            filenames=_array(_str(), "Filenames to try (default: firmware.bin, config.bin, …)."),
        ),
        impl=_tftp_probe,
        phases=("recon",),
    ))

    register(Tool(
        name="probe_socks5",
        description=(
            "SOCKS5 probe (usually 1080): negotiates the authentication method and, "
            "if the proxy accepts 'no authentication', goes one step further and "
            "checks whether it actually RELAYS — it issues a CONNECT to 127.0.0.1 on "
            "the target itself and reads whatever the tunnelled service answers. "
            "Reaching only the handshake proves reachability, not impact; a relayed "
            "response proves the device can be used as a pivot into loopback services "
            "that are not published on the network. Emits canonical ids: "
            "SOCKS5-OPEN-RELAY (relay proven), SOCKS5-NOAUTH (handshake open, CONNECT "
            "denied) and SOCKS5-AUTH-REQUIRED (negative result: the proxy demands "
            "credentials). Prefer it over hand-rolled `curl --socks5` / `nc -x`, which "
            "the policy blocks because they can reach arbitrary third-party hosts."
        ),
        parameters=_obj(
            ip=_str("Target IP. If omitted, the session target is used."),
            port=_int("SOCKS5 port (default 1080)."),
            timeout=_int("Timeout in seconds (default 5)."),
            relay_port=_int(
                "Loopback port to request through the tunnel (default 80). Pass a "
                "port you already know is open to get a stronger relayed response."),
        ),
        impl=_socks5_probe,
        phases=("recon", "exploit"),
    ))

    register(Tool(
        name="probe_lg_webos",
        description=(
            "LG WebOS Smart TV probe (3000/3001): WebSocket handshake plus a pairing "
            "attempt (CVE-2023-6317). If it answers with client-key/registered → "
            "vulnerable. Falls back to REST on /api/v1/service/register, "
            "/api/v2/auth/sign/secured, etc."
        ),
        parameters=_obj(
            ip=_str("Target IP. If omitted, the session target is used."),
            port=_int("Main LG WebOS port (default 3000)."),
            alt_port=_int("Alternate port (default 3001)."),
            timeout=_int("Timeout in seconds (default 5)."),
        ),
        impl=_lg_webos_probe,
        phases=("recon",),
    ))

    register(Tool(
        name="probe_dial",
        description=(
            "DIAL probe (Discovery and Launch — Smart TVs, set-top boxes). GET /dd.xml "
            "for the device descriptor + GET /apps/{YouTube,Netflix,Prime,…} to "
            "enumerate apps launchable without authentication. If it answers, a LAN "
            "attacker can start apps."
        ),
        parameters=_obj(
            ip=_str("Target IP. If omitted, the session target is used."),
            ports=_array(_int(), "DIAL ports (default 1664, 1755, 8060, 8008)."),
            timeout=_int("Timeout in seconds (default 5)."),
        ),
        impl=_dial_probe,
        phases=("recon",),
    ))

    register(Tool(
        name="probe_chromecast",
        description=(
            "Chromecast/Eureka probe (8008): enumerates /setup/eureka_info, "
            "/setup/scan_results and /setup/configured_networks. Leaks MAC, build and "
            "neighbouring SSIDs without authentication. Historical — some firmware "
            "versions already restrict it."
        ),
        parameters=_obj(
            ip=_str("Target IP. If omitted, the session target is used."),
            port=_int("Chromecast port (default 8008)."),
            timeout=_int("Timeout in seconds (default 5)."),
        ),
        impl=_chromecast_probe,
        phases=("recon",),
    ))

    register(Tool(
        name="probe_ssh",
        description=(
            "SSH probe (22): banner grab plus matching against old OpenSSH/Dropbear/"
            "libssh versions with historical CVEs. Does NOT attempt authentication "
            "(banner-only, recon phase). To TEST default credentials use "
            "probe_ssh_credentials (exploit phase)."
        ),
        parameters=_obj(
            ip=_str("Target IP. If omitted, the session target is used."),
            port=_int("SSH port (default 22)."),
            timeout=_int("Timeout in seconds (default 5)."),
        ),
        impl=_ssh_probe,
        phases=("recon",),
    ))

    register(Tool(
        name="probe_ssh_credentials",
        description=(
            "Tests default/weak SSH CREDENTIALS with REAL authentication (the system "
            "ssh client + legacy crypto for old IoT Dropbear/OpenSSH + a pty for the "
            "password, without sshpass) — unlike probe_ssh, which is banner-only. If "
            "one works, it confirms SSH-DEFAULT-CREDS (CRITICAL) with shell proof "
            "(id; uname -a) and returns the credentials. "
            "ANTI-LOCKOUT: a short list plus max_attempts bound the attempts; this is "
            "NOT brute force and it stops at the first success. It is the CORRECT way "
            "to test SSH credentials (piping to nc/telnet does not perform an SSH "
            "handshake). Exploit phase."
        ),
        parameters=_obj(
            ip=_str("Target IP. If omitted, the session target is used."),
            port=_int("SSH port (default 22)."),
            usernames=_array(_str(), "Usernames to try (default: root, admin, …)."),
            passwords=_array(_str(), "Passwords to try (combined with usernames)."),
            pairs=_array(_array(_str()),
                         "Explicit [username, password] pairs; they take precedence "
                         "over usernames/passwords."),
            max_attempts=_int("Anti-lockout attempt cap (default 8)."),
            timeout=_int("Per-attempt timeout in seconds (default 6)."),
        ),
        impl=_ssh_credentials_probe,
        phases=("exploit",),
    ))

    register(Tool(
        name="probe_ftp",
        description=(
            "FTP probe (21): banner plus an anonymous login attempt (USER anonymous + "
            "PASS test). On a 230 response it flags FTP-ANON-LOGIN at HIGH. Classic "
            "vector for firmware/config extraction on old routers and cameras."
        ),
        parameters=_obj(
            ip=_str("Target IP. If omitted, the session target is used."),
            port=_int("FTP port (default 21)."),
            timeout=_int("Timeout in seconds (default 5)."),
        ),
        impl=_ftp_probe,
        phases=("recon",),
    ))

    register(Tool(
        name="probe_smb",
        description=(
            "SMB probe (445): NEGOTIATE PROTOCOL request → detects SMBv1 (deprecated, "
            "the EternalBlue/CVE-2017-0144 vector) versus SMBv2/3. Exposed SMBv1 is "
            "automatically HIGH severity."
        ),
        parameters=_obj(
            ip=_str("Target IP. If omitted, the session target is used."),
            port=_int("SMB port (default 445)."),
            timeout=_int("Timeout in seconds (default 5)."),
        ),
        impl=_smb_probe,
        phases=("recon",),
    ))

    register(Tool(
        name="probe_dns",
        description=(
            "DNS probe (UDP 53): checks for open recursion and evaluates dnsmasq CVEs "
            "by version. If the server forwards external queries (open resolver), it is "
            "vulnerable to upstream attacks such as CVE-2019-14513. Explicitly marks "
            "DNSSEC-dependent CVEs (CVE-2020-25681, -25682, CVE-2017-15107) as NOT "
            "applicable when the dnsmasq version is < 2.57 (no DNSSEC support). "
            "Auto-reads the dnsmasq version from the scan_cache if not provided."
        ),
        parameters=_obj(
            ip=_str("Target IP. If omitted, the session target is used."),
            port=_int("DNS port (default 53)."),
            timeout=_int("Timeout in seconds (default 5)."),
            dnsmasq_version=_str("Detected dnsmasq version (auto if empty)."),
        ),
        impl=_dns_probe,
        phases=("recon",),
    ))

    register(Tool(
        name="http_interrogate",
        description=(
            "Full web interrogation of the target: SSDP/UPnP discovery, *well-known* "
            "and administration paths, banners and headers, TLS certificate and favicon "
            "hash. It also returns **`unauth_data_endpoints`**: URLs serving data "
            "WITHOUT authentication (verify each one with a GET and record the result), "
            "plus `title`/`server`/`body_snippet` with the panel's technology, which "
            "feed `cve_searches_suggested` and the exploitation phase. "
            "Call it with ALL web ports at once, not one per call. "
            "It is also valid in exploit phase to re-interrogate after authenticating: "
            "logging in usually reveals internal paths that were invisible before."
        ),
        parameters=_obj(
            ip=_str("Target IP. If omitted, the session target is used."),
            ports=_array(_int(), "Web ports to interrogate (default 80, 443, 8080, 8443).")
        ),
        impl=_http_interrogate,
        phases=("recon", "exploit"),
    ))

    register(Tool(
        name="web_login",
        description=(
            "Authenticates against an IoT device's web interface and returns the session "
            "cookie. Supports: Netgear (GET /login.php + recreate.php for "
            "'sessionexists'), POST /login.php, /login, /admin/login, /cgi-bin/login. "
            "Returns ok=true + session_cookie for use in execute_command with "
            "-H 'Cookie: …'."
        ),
        parameters=_obj(
            ip=_str("Target IP (defaults to the session target)."),
            username=_str("Username (default 'admin')."),
            password=_str("Password to try (default 'password')."),
            port=_int("Web port (default 80)."),
            scheme=_enum("URL scheme; if omitted it is derived from the port.",
                         "http", "https"),
            timeout=_int("Per-request timeout in seconds (default 10)."),
        ),
        impl=_web_login,
        phases=("exploit",),
    ))

    register(Tool(
        name="mac_vendor_lookup",
        description=(
            "Resolves a MAC's OUI to its vendor (local database, with an online retry "
            "if missing). It is the MOST RELIABLE identity signal in reconnaissance and "
            "**overrides nmap's `os_match`** when the two contradict each other. Note: "
            "it gives the VENDOR, not the model — do not infer a specific product line "
            "from the OUI in order to search for its CVEs."
        ),
        parameters=_obj(
            "mac",
            mac=_str("Target MAC in AA:BB:CC:DD:EE:FF format (returned by nmap_scan). "
                     "Required."),
        ),
        impl=_mac_vendor,
        phases=("recon",),
    ))

    register(Tool(
        name="fingerprint_consensus",
        description=(
            "Merges already-collected evidence (nmap_scan, http_interrogate, "
            "probe_hnap, probe_snmp, mDNS/CoAP, MAC OUI) into a single identity "
            "verdict with CONFIDENCE WEIGHTED by source. Deterministic — it runs "
            "neither probes nor an LLM. "
            "Use this tool AFTER http_interrogate + discovery probes and BEFORE "
            "cve_search: if `short_circuit=true` (HIGH confidence with vendor+model "
            "present) you may jump straight to cve_search; if label=LOW, run more "
            "probes (probe_hnap, probe_snmp, mDNS) to raise the consensus."
        ),
        parameters=_obj(
            mac=_str("Target MAC (defaults to the one in scan_cache)."),
            evidence=_obj_desc("Interrogation evidence supplied by hand (defaults to "
                               "the one cached in the session by http_interrogate)."),
            scan_results=_obj_desc("nmap results (defaults to the scan_cache)."),
        ),
        impl=_fingerprint_consensus,
        phases=("recon",),
    ))

    register(Tool(
        name="cve_search",
        description=(
            "Searches CVEs in the NVD and enriches them with the local family "
            "database, Exploit-DB PoCs, per-version applicability and `model_hint`. "
            "Returns up to 20 results. Requires `cpe` **or** `keyword`.\n"
            "PREFER `cpe`: it is the DETERMINISTIC search (it uses virtualMatchString "
            "and does not depend on which words you pick, so the same device always "
            "yields the same set). The `cpe` comes already resolved on each port of "
            "the `nmap_scan` (e.g. 'cpe:/a:pureftpd:pure-ftpd'). Use `keyword` only to "
            "refine a specific component, and then copy the terms from "
            "`cve_searches_suggested` VERBATIM: rewriting them ('Boa 0.94' vs 'Boa "
            "httpd') changes the result between runs without adding anything.\n"
            "Generic protocol keywords are REJECTED ('SNMP remote code execution', "
            "'TFTP vulnerability'): they return CVEs from vendors that are not the "
            "target. An open protocol is not a component with a CVE."
        ),
        parameters=_obj(
            cpe=_str("The port's CPE exactly as nmap_scan returned it (`cpe` field), "
                     "e.g. 'cpe:/a:dnsmasq:dnsmasq'. Preferred route: it is "
                     "deterministic and precise per version."),
            keyword=_str("NVD term (product, vendor, 'vendor model'). Alternative to "
                         "`cpe` when there is no CPE for that component."),
            version=_str("Detected version, to narrow the affected range (e.g. "
                         "'2.45'). Combines with `cpe` or with `keyword`."),
        ),
        impl=_cve_search,
        phases=("recon", "exploit"),
    ))

    register(Tool(
        name="cve_scan_recon",
        description="DETERMINISTIC CVE sweep from the scan_cache: walks the ports from "
                    "nmap_scan and searches CVEs by CPE (you pick no keywords → "
                    "reproducible). Complements cve_search. Use it after nmap_scan + "
                    "probes for the baseline sweep.",
        parameters=_obj(),
        impl=_cve_scan_recon,
        phases=("recon", "exploit"),
    ))

    register(Tool(
        name="execute_command",
        description=(
            "Runs an audit command (curl, nc, nmap, websocat, snmpwalk, printf|pipe, "
            "PROBE:*) validated by the PolicyEngine: allowlist of binaries and flags, "
            "no shell, no file redirection and no command substitution. Returns the "
            "truncated output. "
            "In **recon phase it is READ-ONLY**: POST/PUT/DELETE/PATCH and body flags "
            "(-d, --data, -F, -T) are rejected, because reconnaissance does not modify "
            "the device; to write, transition to exploit. "
            "Use `printf`, NEVER `echo -e`: the target's shell is usually dash and "
            "`echo -e` prints a literal '-e' (it is rewritten automatically, but do "
            "not rely on that).\n"
            "Do NOT pipe to `head`, `tail`, `grep`, `awk`, `sed` or `cut`: the "
            "output is ALREADY truncated for you (~2000 chars) and those pipes are "
            "rejected by the policy, costing you a turn. Read the output directly. "
            "For the same reason, do not append `2>&1`: stderr is already merged in."
        ),
        parameters=_obj(
            "cmd",
            cmd=_str("Command to run. Required. The literal <TARGET_IP> is replaced "
                     "with the target's IP."),
            target_ip=_str("Target IP (defaults to the session target)."),
            timeout=_int("Timeout in seconds (default 30, recommended maximum 120)."),
            cve_id=_str("CVE label or logical vector name, to trace the command in "
                        "the logs and in the report."),
            auto_retry_login=_bool(
                "If the target answers 401, automatically retry with a default-"
                "credential login and repeat the command (default true). Set it to "
                "false when what you want to PROVE is precisely that the endpoint "
                "requires authentication: the retry would contaminate the test."),
        ),
        impl=_execute_cmd,
        requires_confirmation=True,
        phases=("recon", "exploit"),  # recon: solo lectura (guard determinista)
    ))

    register(Tool(
        name="execute_chain",
        description=(
            "Multi-step reactive chain with regex variable capture: each step can save "
            "pieces of its output ({VAR}) and reuse them in later steps. It is the tool "
            "for CVEs that need to chain login → token/CSRF → payload, where isolated "
            "commands do not work because the second depends on what the first "
            "returned. "
            "Schema: {steps:[{cmd, save:{VAR:regex}, abort_unless, success_if, name}], "
            "success_if}. Every `cmd` goes through the same PolicyEngine."
        ),
        parameters=_obj(
            "chain",
            chain=_obj_desc(
                "Object with 'steps' (list of steps, required) and an optional "
                "'success_if'. Each step: {cmd, save:{VAR:regex}, abort_unless, "
                "success_if, name}."),
            target_ip=_str("Target IP (defaults to the session target)."),
            timeout=_int("Per-step timeout in seconds (default 30)."),
            cve_id=_str("CVE or logical chain name, for logs and the report."),
        ),
        impl=_execute_chain,
        requires_confirmation=True,
        phases=("exploit",),
    ))

    register(Tool(
        name="record_finding",
        description=(
            "Records a finding in the session. Separates DEVICE DATA (raw_output) from "
            "YOUR INTERPRETATION (interpretation) — that distinction is critical for "
            "professional reports:\n"
            "  - raw_output: what the device literally answered (banner, JSON, headers, "
            "status codes, curl output). FACTS.\n"
            "  - interpretation: your reasoning about that data (what it means, why it "
            "confirms/refutes, how many vectors you tried). OPINION.\n"
            "If you only pass `evidence`, it is treated as interpretation (legacy "
            "compatibility)."
        ),
        parameters=_obj(
            "title", "severity", "confirmed",
            cve_id=_str("Finding identifier: CVE-XXXX-YYYY, or a stable logical ID. "
                        "It is the deduplication key: repeating the same id UPDATES "
                        "the previous finding instead of duplicating it — and it is "
                        "also how the SAME fact is correlated across separate audits "
                        "of the same device. Two runs that find one thing and name it "
                        "two ways are indistinguishable from two runs that found two "
                        "different things.\n"
                        "REUSE an existing id whenever it applies: SOCKS5-NOAUTH, "
                        "SSH-DROPBEAR-OLD, TELNET-DEFAULT-CRED, FTP-ANON-LOGIN, "
                        "MQTT-ANON-ACCESS, MQTT-WILDCARD-SUB, HTTP-CONFIG-EXPOSED, "
                        "TFTP-ANON-DOWNLOAD, UPNP-DESCRIPTOR-EXPOSURE, "
                        "CHROMECAST-INFO-DISCLOSURE, RTSP-NO-AUTH, "
                        "WEB-UNAUTH-ACCESS, TLS-SELF-SIGNED. "
                        "Only invent one when nothing fits, and then use the shape "
                        "PROTOCOL-WHAT-OUTCOME in UPPERCASE. Never write a sentence.\n"
                        "Do NOT record that a service is merely present or reachable "
                        "(`SSH-EXPOSED`, `TELNET-EXPOSED`, `<PROTO>-EXPOSED`): the "
                        "open-ports table already reports the attack surface, the "
                        "probes emit those observations by themselves, and a finding "
                        "that restates the port list is not a finding. Record what "
                        "you DEMONSTRATED about the service — a version, a "
                        "configuration it accepted, data it returned, access it "
                        "granted."),
            title=_str("Short, descriptive finding title. Required."),
            severity=_enum(
                "Declared severity. The report's EFFECTIVE severity is this one capped "
                "by the `impact` class and by the finding type's ceiling.",
                "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"),
            confirmed=_bool(
                "true ONLY if you observed the vulnerable behaviour on the device "
                "(access obtained, data exfiltrated, command executed, crash "
                "reproduced). A version banner is NOT confirmation, and a result "
                "proving there is NO vulnerability is confirmed=false, not a "
                "low-severity confirmation. Required."),
            impact=_enum_desc(
                ("EXEC", "ACCESS", "EXFIL", "CRASH", "DISCLOSURE", "EXPOSURE",
                 "HYGIENE"),
                "Class of DEMONSTRATED impact. REQUIRED when confirmed=true with "
                "MEDIUM/HIGH/CRITICAL severity — if you omit it, severity is "
                "automatically capped to LOW (you did not demonstrate impact). Values: "
                "EXEC (you ran code/commands) · ACCESS (auth/session/shell bypass) · "
                "EXFIL (you extracted sensitive data: creds/config/keys) · CRASH "
                "(reproducible DoS/crash, NOT a timeout) · DISCLOSURE (non-sensitive "
                "info without auth: metadata/paths → capped MEDIUM) · EXPOSURE "
                "(reachable port/service with no endpoint exploited → capped LOW) · "
                "HYGIENE (missing control: headers, validation, with no impact shown → "
                "capped LOW). The proof must be in raw_output."
            ),
            raw_output=_str(
                "REAL data returned by the device (banner, JSON, HTTP response, "
                "curl/nc output). Verifiable facts, NOT your interpretation."
            ),
            interpretation=_str(
                "Your reasoning about the data: why the finding is "
                "confirmed/unconfirmed, which vectors you tried, what you conclude. "
                "Do NOT put raw data here — that belongs in raw_output."
            ),
            evidence=_str(
                "[LEGACY] Combination of output + interpretation. Use raw_output + "
                "interpretation separately instead."
            ),
            retract=_bool(
                "true to CORRECT DOWNWARDS a finding you already recorded under this "
                "same id. By default a re-registration can only escalate (confirmed "
                "and severity never go down), so if you recorded a candidate as HIGH "
                "and later verify it does NOT apply, your correction would be ignored. "
                "With retract=true, the severity, confirmed and impact of THIS call "
                "replace the previous ones. Use it only when the new evidence "
                "invalidates the old one, and explain why in interpretation."
            ),
            cmd=_str("Executable shell command that reproduces the finding. It is the "
                     "line the report hands the reader so they can re-verify it."),
        ),
        impl=_record_finding,
        phases=("recon", "exploit"),
    ))

    register(Tool(
        name="save_report",
        description=(
            "Generates the reports (HTML, JSON, Markdown and SARIF) with every finding "
            "accumulated in the session, already carrying effective severity, the "
            "aggregate risk score, historical context from the knowledge base and the "
            "code commit hash. Call it when closing the audit, before `done`."
        ),
        parameters=_obj(out_dir=_str("Output directory (default 'reports').")),
        impl=_save_report,
        phases=("exploit",),
    ))

    register(Tool(
        name="record_cve_findings",
        description=(
            "Records, in ONE call, every CVE that `cve_search` returned as a candidate "
            "(confirmed=false). It accepts the `cves[]` array as-is and takes the "
            "severity and description from each entry. Saves N turns compared with "
            "N × `record_finding`.\n"
            "Record ONLY plausible candidates for THIS device: a CVE from another "
            "vendor, or one whose requirement (port/service/SDK) you did not observe, "
            "is not a candidate — do not record it rather than recording it and "
            "dismissing it later. Every CVE recorded here is marked as pending "
            "individual testing: check them with `audit_status` and leave none untested "
            "or undismissed before `done`."
        ),
        parameters=_obj(
            "cves",
            cves=_array(_obj(), "List of CVEs in the cve_search['cves'] format. "
                                "Required."),
            confirmed=_bool("Mark them all as confirmed (default false). Leave it "
                            "false: a CVE is only confirmed with individual practical "
                            "proof."),
            note=_str("Note prepended to each one's interpretation."),
        ),
        impl=_record_cve_findings,
        phases=("recon", "exploit"),
    ))

    register(Tool(
        name="record_findings_batch_unconfirmed",
        description=(
            "Marks N CVEs as confirmed=false with the SAME reason in a single call. "
            "Use it when several fall for the same cause (e.g. an exploitation chain "
            "that fails at the first link invalidates all the dependent ones). Saves N "
            "`record_finding` turns. "
            "Do NOT use it for CVEs with a specific documented endpoint: those must be "
            "tested one by one with their exact path."
        ),
        parameters=_obj(
            "cve_ids", "reason",
            cve_ids=_array(_str(), "CVE IDs to mark as unconfirmed. Required."),
            reason=_str("Shared justification, injected as evidence into each one. "
                        "Required: it distinguishes NOT_VULNERABLE (tested, not "
                        "vulnerable) from INCONCLUSIVE (could not be tested)."),
            severity=_str("Shared severity (default MEDIUM)."),
        ),
        impl=_record_findings_batch_unconfirmed,
        phases=("recon", "exploit"),
    ))

    register(Tool(
        name="execute_websocket",
        description=(
            "Runs a REAL WebSocket exchange (full handshake, not curl with headers). "
            "Connect → send payload → receive N messages. Supports ws:// and wss:// "
            "(TLS with verify=False for self-signed certificates). Use it for WebSocket "
            "CVEs (LG WebOS CVE-2023-6317, Samsung Tizen, MQTT-over-WS). "
            "MUCH more reliable than `curl -H 'Upgrade: websocket'`."
        ),
        parameters=_obj(
            "url",
            url=_str("ws:// or wss:// URL (e.g. wss://192.168.1.33:3001/). Required."),
            payload=_str("JSON or text to send after the handshake (empty = handshake "
                         "only, useful to test whether the endpoint is WS)."),
            timeout=_int("Timeout in seconds (default 8)."),
            expect_n_messages=_int("Messages to wait for before closing (default 1). "
                                   "Raise it if the protocol answers in several "
                                   "frames, e.g. LG WebOS pairing."),
        ),
        impl=_execute_websocket,
        requires_confirmation=True,
        phases=("recon", "exploit"),
    ))

    register(Tool(
        name="recommend_probes",
        description=(
            "Turns the open ports into a prioritised PROBE PLAN: which probe to run on "
            "each port and why, plus `cve_searches_suggested` with the search terms "
            "already normalised (use them verbatim). ALWAYS call it right after "
            "`nmap_scan`: besides keeping you from leaving surface unexplored, it sets "
            "the coverage baseline that `transition_phase` requires (≥60 %) to move to "
            "exploit. "
            "If the target is 'quiet' (few ports), it includes the UDP discovery sweep: "
            "run it anyway, because nmap's UDP scan is unreliable and those services do "
            "not show up as open."
        ),
        parameters=_obj(
            ports=_array(
                _obj(),  # array de objetos o ints
                "Detected ports. Accepts [{'port':80,'proto':'tcp'}, …] or "
                "[80, 443, …]. If omitted, the scan_cache ports are used."
            ),
        ),
        impl=_recommend_probes,
        phases=("recon",),
    ))

    register(Tool(
        name="run_probes",
        description=(
            "Runs SEVERAL protocol probes in PARALLEL in a single turn (saves turns and "
            "time: UDP probes are slow and independent). Pass it the `ip` and the "
            "`probes` list with the names recommended by recommend_probes. Only "
            "'probe_*' probes are accepted (probe_snmp, probe_mdns, probe_coap, "
            "probe_tftp, probe_modbus, probe_telnet, etc.). Findings are auto-recorded "
            "exactly as with individual calls. For http_interrogate / cve_search / "
            "execute_* use the normal call."
        ),
        parameters=_obj(
            "probes",
            ip=_str("Target IP (injected into every probe that does not carry its own)."),
            probes=_array(
                _obj(
                    probe=_str("Probe name, e.g. 'probe_snmp'."),
                    args=_obj(),  # args opcionales específicos de la probe
                ),
                "Probes to run in parallel: [{'probe':'probe_snmp'}, …]. Required.",
            ),
        ),
        impl=_run_probes,
        phases=("recon",),
    ))

    register(Tool(
        name="audit_status",
        description=(
            "READ-ONLY status of the audit in progress (it does not touch the target "
            "nor consume the safety budget). Returns: findings recorded and confirmed "
            "by effective severity, **candidate CVEs you have not tested yet**, "
            "findings whose severity was capped for lack of an impact class or of "
            "proof, pending recommended probes and current coverage.\n"
            "Use it to keep track in long audits: before `transition_phase`, before "
            "`done`, or whenever you are unsure whether you already recorded something "
            "(it avoids duplicate findings). Its `next_actions` field tells you what is "
            "left to do."
        ),
        parameters=_obj(),
        impl=_audit_status,
        phases=("recon", "exploit"),
    ))

    register(Tool(
        name="transition_phase",
        description=(
            "Changes the agent's active phase (recon → exploit, or back). The next turn "
            "loads the system prompt and the tool subset of the new phase, and the "
            "deterministic restrictions change (in recon, `execute_command` is "
            "read-only). Call it ONLY once the current phase's objectives are met.\n"
            "**Coverage gate**: it blocks the move to 'exploit' if fewer than 60 % of "
            "the recommended probes have been run, and returns the missing ones. Use "
            "`force=true` only when a recommended probe does NOT apply to the target, "
            "and justify it in the next finding."
        ),
        parameters=_obj(
            "phase",
            phase=_enum("Destination phase. Required.", "recon", "exploit"),
            force=_bool("Force the transition, skipping the coverage gate "
                        "(default false)."),
        ),
        impl=_transition_phase,
        phases=("recon", "exploit"),
    ))

    register(Tool(
        name="done",
        description=(
            "Ends the run. Call it when the objective is met or no reasonable vectors "
            "remain. It attaches the aggregate risk score and, if `save_report` was not "
            "called earlier, saves the reports so no findings are lost. If it returns "
            "`warning_untested_cves`, do NOT ignore the warning: go back, test or "
            "dismiss each listed CVE and call `done` again."
        ),
        parameters=_obj(
            "summary",
            summary=_str("Executive summary: what was confirmed, with what proof, and "
                         "what was left inconclusive. Required."),
        ),
        impl=_done,
        phases=("recon", "exploit"),
    ))


build_registry()
