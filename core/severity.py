"""Gobernanza de severidad — la política determinista que decide qué puntúa.

Este módulo es la capa que hace **reproducible** el veredicto de una auditoría
(objetivos OM1 y OE1). Su cometido es que la misma evidencia produzca la misma
cifra en cualquier momento y desde cualquier consumidor: el bucle del agente, el
informe guardado, la base de conocimiento, el arnés de varianza o el dashboard.

Vivía dentro de `core/tools.py`, y esa ubicación tenía una consecuencia
práctica: al ser el registro de herramientas, importarlo arrastra las sondas y
la sesión, así que los módulos que solo necesitaban *preguntar* si un hallazgo
cuenta —la KB, la reflexión, los scripts de evaluación— no lo importaban y
acababan mirando el campo crudo `confirmed`. El resultado era una gobernanza que
solo se aplicaba en la mitad del sistema: el informe decía «1 confirmado» y la
KB aprendía «2». Aislarla aquí, sin dependencias del registro, elimina el motivo
para saltársela.

`core/tools.py` reexporta todo lo público, de modo que `tools.effective_severity`
y `tools.compute_risk_score` siguen siendo rutas válidas.

Las tres decisiones que implementa, en orden de aplicación:

  1. **Techo canónico por tipo** (`canonical_severity`) — lo declara la sonda al
     emitir el hallazgo; el LLM no puede superarlo re-registrándolo.
  2. **Cap de alcanzabilidad** — evidencia de «puerto abierto» nunca supera LOW,
     sea cual sea la clase de impacto declarada.
  3. **Tope por clase de impacto** (`impact`) — para reclamar HIGH/CRITICAL hay
     que nombrar qué se demostró y aportar la prueba.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple


# Clase de impacto que DEMUESTRA cada tipo de hallazgo emitido por las sondas.
#
# Por qué existe esta tabla: `effective_severity` topa a LOW cualquier confirmado
# MEDIUM+ que no declare clase de impacto (§4.8.5), y las sondas declaraban
# `severity` pero NUNCA `impact`. Consecuencia: un `TELNET-DEFAULT-CRED` en el que
# la sonda **entró de verdad y capturó el shell** puntuaba LOW, y solo subía a
# CRITICAL si el LLM se molestaba en re-registrarlo con `impact="ACCESS"`. Es decir:
# la evidencia determinista valía menos que la afirmación del modelo —lo contrario
# de la tesis del trabajo— y el score dependía de una intervención no determinista,
# justo la varianza que la política de impacto pretende eliminar.
#
# La tabla es deliberadamente CONSERVADORA: solo mapea lo que la sonda demuestra
# con una interacción real. Lo que solo prueba alcanzabilidad o coincidencia de
# banner (`*-EXPOSED`, firmas de versión) se mapea a EXPOSURE y por tanto sigue
# topando a LOW, que es lo correcto. Un id sin entrada queda sin clase → LOW.
_PROBE_IMPACT_CLASS: Dict[str, str] = {
    # ACCESS — la sonda se autenticó o entró sin credenciales válidas
    "TELNET-DEFAULT-CRED": "ACCESS",     # login + salida de shell capturada
    "SSH-DEFAULT-CREDS": "ACCESS",       # handshake SSH real + `id; uname -a`
    "RTSP-DEFAULT-CRED": "ACCESS",       # credenciales por defecto aceptadas
    "FTP-ANON-LOGIN": "ACCESS",          # 230 → sesión anónima concedida
    "MQTT-ANON-ACCESS": "ACCESS",        # CONNACK sin credenciales
    "MQTT-PUB-ALLOWED": "ACCESS",        # publicó en el broker sin autenticarse
    "WEAK-CREDENTIALS": "ACCESS",
    "LG-WEBOS-CVE-2023-6317": "ACCESS",  # pairing sin prompt → client-key emitida
    "CVE-2023-6317": "ACCESS",
    "SOCKS5-OPEN-RELAY": "ACCESS",       # CONNECT concedido + bytes del otro extremo
    # EXFIL — la sonda extrajo datos sensibles del dispositivo
    "HTTP-CONFIG-EXPOSED": "EXFIL",          # volcado de config con credenciales en claro
    "TFTP-ANON-DOWNLOAD": "EXFIL",           # devolvió bytes de firmware/config
    "MIIO-TOKEN-EXPOSED": "EXFIL",           # token en claro = control local total
    "MQTT-WILDCARD-SUB": "EXFIL",            # suscripción `#` → tráfico de todos los topics
    "MODBUS-NO-AUTH-READCOILS": "EXFIL",     # lectura de estado del proceso industrial
    # DISCLOSURE — divulgación sin auth de información NO sensible (tope MEDIUM)
    "MDNS-EXPOSED": "DISCLOSURE",
    "CHROMECAST-INFO-DISCLOSURE": "DISCLOSURE",
    "DIAL-EXPOSED": "DISCLOSURE",
    "MIIO-DEVICE-EXPOSED": "DISCLOSURE",
    "MODBUS-NO-AUTH-FC17": "DISCLOSURE",     # Report Slave ID = identificación
    "BACNET-NO-AUTH-WHOIS": "DISCLOSURE",    # I-Am revela identidad del equipo OT
    "RTSP-NO-AUTH": "DISCLOSURE",            # SDP con vídeo accesible, sin extraer frames
    # EXPOSURE — alcanzable, nada explotado (se mantiene en LOW a propósito)
    "TELNET-EXPOSED": "EXPOSURE",
    "SSH-EXPOSED": "EXPOSURE",
    "SMB-EXPOSED": "EXPOSURE",
    "SMB-V1-EXPOSED": "EXPOSURE",
    "CWMP-EXPOSED": "EXPOSURE",
    "OPCUA-EXPOSED": "EXPOSURE",
    "CHROMECAST-EXPOSED": "EXPOSURE",
    "LG-WEBOS-EXPOSED": "EXPOSURE",
    "UPNP-IGD-EXPOSED": "EXPOSURE",          # SCPD anuncia AddPortMapping, no ejercido
    "SOCKS5-NOAUTH": "EXPOSURE",             # handshake abierto, CONNECT denegado
    "SOCKS5-OPEN-RELAY-NODATA": "EXPOSURE",  # túnel concedido, nadie contestó
}

# Severidad FIJA por tipo de hallazgo — no un tope, un valor.
#
# El tope por clase de impacto acota por arriba, y funciona: en 26 informes de
# campo ningún DISCLOSURE superó MEDIUM. Pero por DEBAJO del tope no había nada,
# y ahí el modelo elegía libre: el mismo descriptor UPnP del mismo televisor
# salió LOW en una ejecución y MEDIUM en otra, con idéntica evidencia. Dos
# réplicas que confirman el mismo hecho tienen que puntuar igual, o la varianza
# medida en §5.10.2 incluye el humor del modelo.
#
# La severidad de un TIPO de hallazgo es una propiedad del tipo, igual que ya lo
# era su clase de impacto: si `SOCKS5-NOAUTH` significa «handshake abierto, sin
# CONNECT concedido», eso vale lo mismo hoy que mañana. Los valores se eligen
# CONSERVADORES —a la baja cuando hay duda— por la misma razón que el resto de
# la política: un descriptor UPnP legible es el comportamiento normal de un
# televisor de consumo, no un fallo, y ascenderlo a MEDIUM porque una réplica lo
# escribió así sería inflar por sorteo.
#
# Solo entran identificadores del vocabulario conocido. Un hallazgo que el
# modelo nombre por su cuenta sigue rigiéndose por el tope, que es lo correcto:
# no se puede fijar la severidad de algo cuyo significado no está declarado.
_CANONICAL_SEVERITY: Dict[str, str] = {
    # Exposición de descriptores/identidad: legible por diseño en equipos de
    # consumo. Se deja en LOW y deja de oscilar.
    "UPNP-DESCRIPTOR-EXPOSURE": "LOW",
    "CHROMECAST-EUREKA-INFO-EXPOSURE": "LOW",
    "CHROMECAST-INFO-DISCLOSURE": "LOW",
    "DIAL-EXPOSED": "LOW",
    "MIIO-DEVICE-EXPOSED": "LOW",
    # Alcanzabilidad de un servicio: LOW por definición de EXPOSURE.
    "SOCKS5-NOAUTH": "LOW",
    "SOCKS5-OPEN-RELAY-NODATA": "LOW",
    "TLS-SELF-SIGNED": "LOW",
    # Acceso o extracción demostrados: aquí la severidad alta está ganada.
    "SOCKS5-OPEN-RELAY": "HIGH",
    "TELNET-DEFAULT-CRED": "CRITICAL",
    "SSH-DEFAULT-CREDS": "CRITICAL",
    "RTSP-DEFAULT-CRED": "HIGH",
    "FTP-ANON-LOGIN": "MEDIUM",
    "MQTT-ANON-ACCESS": "HIGH",
    "WEB-UNAUTH-ACCESS": "MEDIUM",
    "HTTP-CONFIG-EXPOSED": "HIGH",
    "TFTP-ANON-DOWNLOAD": "HIGH",
    "MIIO-TOKEN-EXPOSED": "HIGH",
}

# Identificadores que solo REAFIRMAN LA SUPERFICIE: dicen que un servicio está
# ahí, que es exactamente lo que la tabla de puertos abiertos del informe ya
# dice. No son hallazgos; son la superficie contada dos veces.
#
# La distinción se volvió urgente al medir una tanda de campo: de 20 confirmados,
# 13 eran de clase EXPOSURE y NINGUNO demostraba acceso ni extracción. El caso
# que lo retrata es un `SSH-EXPOSED` cuya propia interpretación decía «se probaron
# múltiples credenciales por defecto SIN ÉXITO, sin acceso demostrado»: un
# negativo comprobado —buena noticia— contabilizado como vulnerabilidad
# confirmada. Es la misma forma que el SOCKS5 de la tanda anterior, que se cerró
# solo para SOCKS5.
#
# Importa porque «confirmado» es LA palabra que separa este trabajo de un
# escáner (§5.1). Si «el puerto 22 tiene SSH» cuenta como vulnerabilidad
# confirmada, la palabra deja de significar lo que el capítulo 5 dice que
# significa. Se les asigna severidad INFO, y con eso `is_confirmed_vuln` los
# excluye por la regla que ya existía —INFO es nota informativa o negativo— sin
# necesidad de una segunda regla que mantener sincronizada.
#
# NO entran aquí los hechos de configuración ni de versión, que sí dicen algo que
# la tabla de puertos no dice: `SSH-DROPBEAR-OLD` (versión antigua),
# `TLS-SELF-SIGNED` (certificado), `SOCKS5-NOAUTH` (el proxy ACEPTA no
# autenticar), `UPNP-DESCRIPTOR-EXPOSURE` (se leyó el contenido). El criterio es
# si el hallazgo añade algo a la superficie, no si su nombre acaba en EXPOSED.
_SURFACE_ONLY_IDS = frozenset({
    "SSH-EXPOSED", "TELNET-EXPOSED", "SMB-EXPOSED", "CWMP-EXPOSED",
    "OPCUA-EXPOSED", "CHROMECAST-EXPOSED", "LG-WEBOS-EXPOSED",
    "UPNP-IGD-EXPOSED", "MDNS-EXPOSED", "RTSP-EXPOSED",
})

# Los que las sondas y el modelo construyen con el puerto dentro
# (`HTTP-4070-EXPOSED`, `PORT-8888-EXPOSED`): «hay algo escuchando en el 4070»
# es la definición misma de superficie.
_SURFACE_ONLY_RE = re.compile(r"^(?:HTTP|HTTPS|PORT|TCP|UDP)-\d{1,5}-EXPOS(?:ED|URE)$")

# `<FAMILIA>-EXPOSURE` sin ningún cualificador: el identificador se compone del
# nombre de un protocolo y de «está expuesto», y nada más. Esa forma no puede
# decir otra cosa que lo que la tabla de puertos ya dice, se escriba como se
# escriba —y el modelo la escribe de muchas maneras: en campo llegó
# `HTTPS-ACCESSIBLE`, que la lista cerrada de arriba no contemplaba—.
#
# La regla es general a propósito: una lista de nombres exactos siempre va por
# detrás de la imaginación del modelo, mientras que la FORMA del identificador
# es estable.
_SOLO_FAMILIA_RE = re.compile(r"^[A-Z][A-Z0-9]{1,15}-EXPOS(?:ED|URE)$")


def is_surface_only(vuln_id: str) -> bool:
    """¿El identificador solo reafirma que el servicio está ahí?"""
    vid = (vuln_id or "").upper()
    if vid in _SURFACE_ONLY_IDS or _SURFACE_ONLY_RE.match(vid):
        return True
    if _SOLO_FAMILIA_RE.match(vid):
        # Excepción por declaración explícita: si el vocabulario dice que ese
        # tipo demuestra algo MÁS que alcanzabilidad —`DIAL-EXPOSED` lee el
        # descriptor del servicio y está declarado DISCLOSURE—, manda la tabla y
        # no la forma del nombre. Un identificador desconocido, en cambio, se
        # trata como lo que aparenta.
        return _PROBE_IMPACT_CLASS.get(vid, "EXPOSURE") == "EXPOSURE"
    return False


# Identificadores que denotan un resultado NEGATIVO comprobado: la sonda ejecutó
# la prueba y el dispositivo la superó. Son valiosos —dejan constancia de lo
# verificado— pero no son hallazgos, y contarlos como tales hacía que una
# configuración correcta puntuase igual que la vulnerable. Caso real: la réplica
# que recibió `05 ff` de un proxy SOCKS5 (o sea, que SÍ pedía credenciales)
# registró `confirmed=True` y sacó el mismo score que la que lo halló abierto.
_CONFIRMED_NEGATIVE_IDS = frozenset({
    "SOCKS5-AUTH-REQUIRED",
})

# Y la misma idea por FORMA, por el motivo que ya obligó a generalizar la regla
# de superficie: una lista de nombres exactos va siempre por detrás del modelo.
# `SOCKS5-AUTH-REQUIRED` estaba contemplado; cuando el mismo hecho ocurrió sobre
# HTTP el modelo escribió `HTTP-AUTH-REQUIRED` —«el panel requiere
# autenticación», con las credenciales por defecto rechazadas— y volvió a contar
# como hallazgo confirmado. Un identificador que dice que el dispositivo EXIGE
# autenticación, o que no es vulnerable, está reportando que el objetivo está
# bien configurado: es información valiosa y no es un hallazgo.
_NEGATIVO_CONFIRMADO_RE = re.compile(
    r"-(?:AUTH-REQUIRED|REQUIRES-AUTH|AUTH-ENFORCED|NOT-VULNERABLE|NOT-EXPLOITABLE|PATCHED)$")


def is_confirmed_negative(vuln_id: str) -> bool:
    """¿El identificador denota un resultado negativo comprobado?"""
    vid = (vuln_id or "").upper()
    return vid in _CONFIRMED_NEGATIVE_IDS or bool(_NEGATIVO_CONFIRMADO_RE.search(vid))

# Prefijos para los ids que las sondas construyen dinámicamente (firmas de banner
# y de versión). Todos son coincidencia de banner, nunca prueba práctica.
_PROBE_IMPACT_PREFIXES: Tuple[Tuple[str, str], ...] = (
    ("TELNET-MIRAI", "EXPOSURE"),
    ("CWMP-ROMPAGER", "EXPOSURE"),
    ("CWMP-MIRAI", "EXPOSURE"),
    # `probe_ssh` es banner-only por diseño (no intenta autenticarse), así que
    # SSH-OPENSSH-OLD-CVE / SSH-DROPBEAR-OLD / SSH-LIBSSH-OLD son coincidencias de
    # versión: exactamente lo que §4.8.5 dice que no debe inflar el veredicto.
    ("SSH-OPENSSH-OLD", "EXPOSURE"),
    ("SSH-DROPBEAR-OLD", "EXPOSURE"),
    ("SSH-LIBSSH-OLD", "EXPOSURE"),
)

def _probe_impact_class(vuln: Dict[str, Any], vuln_id: str) -> str:
    """Clase de impacto de un hallazgo emitido por una sonda.

    Prioridad: lo que declare la propia sonda (`impact` en la vulnerabilidad) →
    tabla explícita → prefijos de firmas de banner → cadena vacía (que
    `effective_severity` interpreta, conservadoramente, como sin demostrar).
    """
    declared = (vuln.get("impact") or "").strip().upper()
    if declared:
        return declared
    mapped = _PROBE_IMPACT_CLASS.get(vuln_id)
    if mapped:
        return mapped
    for prefix, impact in _PROBE_IMPACT_PREFIXES:
        if vuln_id.startswith(prefix):
            return impact
    return ""

_SEVERITY_WEIGHT = {"INFO": 0, "LOW": 1, "MEDIUM": 4, "HIGH": 7, "CRITICAL": 10}
_SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# ── Política de impacto (gobernanza de severidad) ───────────────────────────
# Un finding confirmado solo puntúa a severidad alta si el agente DEMUESTRA
# impacto. El agente declara la CLASE de impacto observado (campo `impact`);
# nosotros aplicamos un tope determinista por clase. Esto es agnóstico al tipo
# de vuln: NO comprobamos "si es clickjacking entonces X" — aplicamos una
# política uniforme sobre la naturaleza de la prueba, válida para cualquier
# hallazgo presente o futuro.
#
# Clave de consistencia: la severidad libre que asigna el LLM tiene varianza
# alta (mismo device → run1 LOW/10, run2 MEDIUM/50). Mover la decisión del LLM
# de "elige severidad" a "clasifica la prueba" (pregunta más objetiva) + tope
# fijo por clase hace que el score sea reproducible entre runs.
#
# Clases CON impacto demostrado (sin tope, respetan la severidad declarada):
#   EXEC       ejecución de código/comandos en el dispositivo
#   ACCESS     bypass de autenticación / sesión / shell obtenido
#   EXFIL      datos sensibles extraídos (credenciales, config, claves)
#   CRASH      DoS / crash reproducible (NO un timeout — ver exploit.md)
#   DISCLOSURE divulgación sin auth de info NO sensible (metadata, rutas) → tope MEDIUM
# Clases SIN impacto demostrado (tope LOW — son higiene/superficie, no exploits):
#   EXPOSURE   servicio/puerto alcanzable, sin endpoint explotado
#   HYGIENE    control de seguridad ausente (headers, validación) sin impacto mostrado
#   NONE       sin demostración
_IMPACT_MAX_SEVERITY = {
    "EXEC": "CRITICAL",
    "ACCESS": "CRITICAL",
    "EXFIL": "CRITICAL",
    "CRASH": "HIGH",
    "DISCLOSURE": "MEDIUM",
    "EXPOSURE": "LOW",
    "HYGIENE": "LOW",
    "NONE": "LOW",
}

# Alcanzabilidad ≠ explotación. Estos patrones provienen de la SALIDA de
# herramientas (nc/nmap/probes) —deterministas, NO del texto libre del modelo—
# e indican que la evidencia es solo "puerto abierto / sin respuesta", no una
# interacción no autenticada real. Un servicio que RECHAZA el método (SOCKS
# `05ff`) prueba además que SÍ exige auth.
_REACHABILITY_ONLY_RE = re.compile(
    r"succeeded!|port \[tcp|open\|filtered|protocol_confirmed['\"]?\s*[:=]\s*false|"
    r"no response|no banner|sin respuesta|timed out|command timed out|"
    r"connection refused|connection reset|0x05\s*0xff|\b05ff\b|no auth method|"
    r"no acceptable|"
    # Paráfrasis comunes del agente para "solo conecté / puerto abierto" — el
    # cap no debe esquivarse reescribiendo la salida de la tool con otras
    # palabras. (Caso real Echo: "Connection succeeded", "(open)", "HTTP/0.9".)
    r"connection succeeded|connection established|conexi[oó]n exitosa|"
    r"\bnc -z|\(open\)|\bport open\b|puerto abierto|\bhttp/0\.9\b|"
    r"tcpwrapped|accepts? connection|acepta conexi[oó]n",
    re.IGNORECASE)
# Señales de interacción/acción REAL (datos, shell, auth, fichero, HTTP con
# cuerpo…). Si aparece alguna, la evidencia NO es solo alcanzabilidad.
#
# Aquí había un patrón `"[a-z_]+"\s*:` cuya intención era «el dispositivo
# devolvió un cuerpo JSON», pero que en la práctica casaba con CUALQUIER clave
# de CUALQUIER objeto JSON. Como esta expresión corta-circuita el cap de
# alcanzabilidad, bastaba con que la evidencia arrastrase el dict del propio
# probe —`{"port": 23, "status": "open"}`, que es metadata de la herramienta, no
# datos del dispositivo— para que un «puerto abierto» puntuase CRITICAL. Peor
# aún, el veredicto dependía del ENTRECOMILLADO: el mismo contenido serializado
# como JSON (comillas dobles) esquivaba el cap y como `repr` de dict (comillas
# simples) no, es decir, no-determinismo dentro de la capa que existe para
# eliminarlo. Se sustituye por claves con carga semántica: un JSON solo cuenta
# como interacción real si trae DATOS del dispositivo, no su descripción.
_REAL_INTERACTION_RE = re.compile(
    r"uid=\d|gid=\d|root@|/bin/sh|/bin/bash|\$\s|HTTP/1\.[01]\s+(2|3)\d\d|"
    r"set-cookie|www-authenticate|password\s*[:=]|passwd|admin:[^\s]|"
    r"begin [a-z ]*private key|<\?xml|<html|firmware\.bin downloaded|"
    r"230 |login successful|client[_-]?key|leaked|credential|"
    # Claves JSON que denotan datos extraídos del dispositivo (no metadata de
    # la sonda). La lista es explícita a propósito: ampliarla es una decisión
    # consciente, no un efecto colateral de una regex genérica.
    r"[\"'](?:token|secret|api[_-]?key|private[_-]?key|serial(?:_number)?|"
    r"ssid|psk|passphrase|username|user|admin_pass|session|cookie|auth|"
    r"firmware(?:_version)?|model(?:_name)?|mac_?address|config|"
    r"sys_?descr|topic|payload|message|shell|stdout)[\"']\s*:|"
    # Los mismos datos, pero delimitados por MARCADO en vez de por JSON. El
    # HNAP/getcfg de D-Link responde `<password></password>`, que ninguna de
    # las alternativas anteriores reconoce: `password\s*[:=]` exige dos puntos
    # o igual, y `<?xml` solo aparece si el agente pegó la respuesta entera con
    # su prólogo. Una réplica que citó el fragmento sin prólogo se contaba como
    # «sin interacción real» mientras otra, con el mismo hallazgo y el volcado
    # completo, se contaba como demostrada. El formato en que el agente decide
    # recortar la respuesta no puede cambiar si el hallazgo cuenta.
    #
    # Se aceptan las ETIQUETAS, no la línea de petición: un `GET /...` citado
    # prueba lo que se pidió, nunca lo que el aparato contestó.
    r"</?(?:password|passwd|pwd|username|user|name|account|entry|serial|"
    r"ssid|psk|passphrase|token|secret)\b[^>]{0,80}>",
    re.IGNORECASE)


def _finding_evidence_blob(finding: Dict[str, Any]) -> str:
    """Texto de evidencia de un finding (raw_output + evidence), para los
    detectores deterministas. Tolera `evidence` no-string (dict/list).

    La serialización de lo no-string se hace con `json.dumps`, NO con `str()`:
    `str({'port': 23})` produce comillas SIMPLES y `json.dumps` DOBLES, y los
    detectores buscan claves entrecomilladas. Con `str()`, el mismo hallazgo
    puntuaba distinto según hubiera llegado como dict o como JSON ya
    serializado — una fuente de no-determinismo en la capa cuyo cometido es
    justamente eliminarlo. Ahora ambas rutas convergen al mismo texto.
    """
    raw = finding.get("raw_output") or ""
    ev = finding.get("evidence")
    if ev and not isinstance(ev, str):
        try:
            ev = json.dumps(ev, ensure_ascii=False, default=str, sort_keys=True)
        except (TypeError, ValueError):
            ev = str(ev)
    return (raw + " " + (ev or "")).strip()


def _has_real_interaction(finding: Dict[str, Any]) -> bool:
    """¿El raw_output contiene PRUEBA positiva de interacción real (shell, datos,
    sesión, fichero, credencial…)? Determinista, sobre la salida de tools."""
    blob = _finding_evidence_blob(finding)
    return bool(blob) and bool(_REAL_INTERACTION_RE.search(blob))


def _is_reachability_only(finding: Dict[str, Any]) -> bool:
    """¿La evidencia de un finding es solo *alcanzabilidad* (puerto abierto), sin
    interacción no autenticada real? Determinista, sobre la salida de tools."""
    raw = _finding_evidence_blob(finding)
    if not raw:
        return False
    if _REAL_INTERACTION_RE.search(raw):
        return False  # hay acción/datos reales → no es solo alcanzabilidad
    return bool(_REACHABILITY_ONLY_RE.search(raw))


def effective_severity(finding: Dict[str, Any], *,
                       apply_impact_cap: bool = True) -> str:
    """Severidad EFECTIVA tras aplicar la política de impacto.

    - Findings no confirmados: se respeta la severidad declarada (no puntúan
      igualmente en el score, así que el tope es irrelevante para ellos).
    - Confirmados INFO/LOW: se respetan (no inflan, no necesitan justificación).
    - Confirmados MEDIUM/HIGH/CRITICAL: se topan según la clase `impact`.
        · Evidencia solo de alcanzabilidad (puerto abierto, sin respuesta,
          método rechazado) → tope LOW, ignora el `impact` declarado. Un
          `nc -zv` que conecta NO es acceso/exfil: alcanzabilidad ≠ explotación.
          El detector cubre además las PARÁFRASIS comunes del agente ("connection
          succeeded", "(open)", "nc -zv", "http/0.9"…), no solo la salida literal
          de la tool — así el cap no se esquiva reescribiendo la evidencia.
        · Clase con impacto demostrado → tope alto, respeta lo declarado.
        · Clase sin impacto / ausente → tope LOW (conservador). Omitir `impact`
          en un confirmado de severidad alta = el agente no demostró impacto →
          se degrada a LOW. Fuerza honestidad: para reclamar HIGH/CRITICAL hay
          que nombrar la clase de impacto y aportar la prueba en raw_output.

    Determinista y agnóstico: misma (severity, impact) → misma salida, sea cual
    sea el tipo de vulnerabilidad.
    """
    sev = (finding.get("severity") or "INFO").upper()
    if sev not in _SEVERITY_RANK:
        sev = "INFO"
    # Techo canónico por tipo de hallazgo. Los probes de higiene/exposición
    # (MDNS-EXPOSED, LG-WEBOS-EXPOSED, CHROMECAST-INFO-DISCLOSURE, …) declaran
    # su severidad al emitir el finding. El LLM puede re-registrarlo con una
    # severidad mayor (varianza observada: mismo device → run1 mDNS INFO,
    # run2 mDNS MEDIUM), pero la severidad EFECTIVA nunca supera lo que declaró
    # la tool. Determinista y bidireccional: no depende del texto libre del
    # modelo. Se aplica también a no confirmados (un MDNS-EXPOSED sin confirmar
    # tampoco debe mostrarse como MEDIUM).
    canon = (finding.get("canonical_severity") or "").upper()
    if canon in _SEVERITY_RANK and _SEVERITY_RANK[sev] > _SEVERITY_RANK[canon]:
        sev = canon
    # Severidad FIJA por tipo de hallazgo, cuando el tipo es del vocabulario
    # conocido. A diferencia del techo de arriba, esta sustituye en las DOS
    # direcciones: es un valor, no un límite. Sin ella, el tope acotaba por
    # arriba y por debajo el modelo elegía, de modo que el mismo hecho puntuaba
    # LOW o MEDIUM según la réplica. Ver `_CANONICAL_SEVERITY`.
    from core.finding_ids import canonicalize_finding_id
    canon_id = canonicalize_finding_id(finding.get("cve_id")) or ""
    # Reafirmación de superficie → INFO, sea cual sea la severidad declarada.
    # Va antes que la severidad fija por tipo porque es una afirmación más
    # fuerte: no es que valga poco, es que no es un hallazgo.
    if is_surface_only(canon_id):
        return "INFO"
    fija = _CANONICAL_SEVERITY.get(canon_id)
    if fija:
        sev = fija
    # Resultado negativo comprobado: la prueba se ejecutó y el dispositivo la
    # superó. Es INFO por definición, venga como venga declarado. Va antes que
    # cualquier otro tope porque no es una cuestión de cuánta evidencia hay,
    # sino de qué demuestra: comprobar que algo NO es explotable no puede
    # puntuar como haberlo explotado.
    if is_confirmed_negative(finding.get("cve_id")):
        return "INFO"
    if not bool(finding.get("confirmed")):
        return sev
    if _SEVERITY_RANK[sev] <= _SEVERITY_RANK["LOW"]:
        return sev
    # Alcanzabilidad ≠ explotación. Un confirmado MEDIUM+ cuya evidencia es solo
    # "puerto abierto / sin respuesta / método rechazado" no puede superar
    # EXPOSURE (LOW), sea cual sea la clase de impacto declarada.
    if _is_reachability_only(finding):
        return "LOW"
    if not apply_impact_cap:
        # Recálculo retroactivo (§5.10.2): los informes anteriores al campo
        # `impact` no lo declaran, y toparlos por su ausencia mediría la edad
        # del informe en vez de la gravedad del hallazgo. El techo canónico y el
        # cap de alcanzabilidad —que se apoyan en datos presentes en TODOS los
        # runs— sí se han aplicado ya, de modo que la comparación sigue siendo
        # uniforme entre épocas.
        return sev
    impact = (finding.get("impact") or "").upper()
    if not impact:
        # Fallback determinista por TIPO de hallazgo. La clase de impacto es una
        # propiedad del tipo (un TELNET-DEFAULT-CRED demuestra acceso siempre), así
        # que aplicarla también aquí hace que **recalcular** la puntuación sobre un
        # informe guardado dé lo mismo que calcularla durante el run. Sin este
        # fallback, la misma evidencia puntuaba distinto según el momento del
        # cálculo, y las cifras del Capítulo 5 no eran reproducibles desde los
        # informes archivados —justo lo que OE5 promete—.
        impact = _probe_impact_class({}, (finding.get("cve_id") or "").upper())
    cap = _IMPACT_MAX_SEVERITY.get(impact)
    if cap is None:
        # Confirmado MEDIUM+ sin clase de impacto válida → tope conservador LOW.
        return "LOW"
    return sev if _SEVERITY_RANK[sev] <= _SEVERITY_RANK[cap] else cap


def is_confirmed_vuln(finding: Dict[str, Any], *,
                      apply_impact_cap: bool = True) -> bool:
    """¿Es una VULNERABILIDAD confirmada (no solo "verificada")?

    Un finding cuenta como vulnerabilidad confirmada SOLO si:
      (1) el agente lo marcó `confirmed=True`, Y
      (2) su severidad representa impacto real de seguridad (>= LOW).

    Severidad INFO se excluye siempre. INFO es, por definición, una nota
    informativa o un RESULTADO NEGATIVO (ej. "las credenciales por defecto
    NO funcionan", "endpoint devuelve 404"). Verificar un resultado negativo
    NO es confirmar una vulnerabilidad — el agente comprobó *ausencia* de
    vuln, no presencia. Sin este guard, el modelo podía inflar el contador de
    confirmados marcando `confirmed=True` en una negación (bug observado:
    WEB-AUTH-DEFAULT-CREDS confirmado INFO → "2 confirmados" cuando real = 1).

    Determinista: no depende de parsear texto de la interpretación (frágil),
    sino del par (confirmed, severity) que el reporter ya usa. El LLM no puede
    saltarse esto desde el prompt.

    Usa la severidad EFECTIVA, no la declarada: un hallazgo topado a INFO por el
    techo canónico (p.ej. MDNS-EXPOSED que el LLM infló a MEDIUM) es una nota
    informativa, no una vulnerabilidad confirmada — no debe inflar el contador.
    """
    if not bool(finding.get("confirmed")):
        return False
    return effective_severity(finding, apply_impact_cap=apply_impact_cap) != "INFO"


def asserts_unproven_action(finding: Dict[str, Any]) -> bool:
    """¿El identificador afirma una acción que su evidencia no muestra?

    `TFTP-ANON-DOWNLOAD` afirma que se descargó un fichero; `SSH-DEFAULT-CREDS`,
    que se entró. Son afirmaciones sobre algo que ocurrió, no sobre un estado. En
    campo se registró el primero con esta evidencia literal: «nmap: 69/udp
    open|filtered tftp. probe_tftp: protocol_confirmed=false» —la sonda decía
    explícitamente que no había confirmado nada—. La gobernanza de severidad lo
    dejó en LOW, así que la puntuación no se resintió; pero el informe publicaba
    una descarga que no ocurrió, y el nombre de un hallazgo forma parte de lo que
    el informe afirma.

    No se aplica a lo que emite una SONDA (`_from_probe`): la sonda ejecutó la
    interacción y su emisión ES la evidencia, de modo que exigirle además un
    texto que encaje en una expresión regular degradaría la capa determinista en
    favor de la que no lo es.

    **Por eso se evalúa solo al registrar, y NO al recalcular** sobre informes
    archivados. Tentaba hacerlo retroactivo —así desaparecería de la serie el
    `TFTP-ANON-DOWNLOAD` que se coló antes de existir esta regla—, pero los
    informes anteriores no llevan la marca de procedencia, de modo que la regla
    no puede distinguir lo que escribió el modelo de lo que emitió una sonda y
    degrada ambos. Aplicado a la evidencia acumulada, el laboratorio pasaba de
    12,9 a 5,8 confirmados y de CRITICAL a MEDIUM: no por ser más honesto, sino
    porque MQTT, Modbus y FTP —confirmados por sondas que sí ejecutaron la
    interacción— perdían su respaldo por un campo que en 2026-05 no existía. Es
    el mismo motivo por el que el tope por clase de impacto se desactiva al
    recalcular: una regla que se apoya en un campo ausente no mide la evidencia,
    mide la edad del informe. La decisión queda GRABADA en el informe
    (`confirmed=false`), que es donde tiene que estar para sobrevivir.
    """
    if finding.get("_from_probe"):
        return False
    from core.finding_ids import canonicalize_finding_id
    vuln_id = canonicalize_finding_id(finding.get("cve_id")) or ""
    # La clase que se DECLARA es la afirmación que hay que respaldar, venga de un
    # identificador conocido o de un CVE cualquiera. Mirar solo la tabla dejaba
    # fuera el caso más caro: en campo, el modelo marcó siete CVE de dnsmasq como
    # `EXEC`/`CRASH` confirmados cuya evidencia era la DESCRIPCIÓN del fallo
    # —«dnsmasq 2.45 is vulnerable to CVE-2017-14492»— y cuya propia
    # interpretación decía «candidatos … requieren verificación de
    # aplicabilidad». Coincidencia de versión ascendida a ejecución remota, que
    # es precisamente lo que la disciplina de confirmación existe para impedir.
    clase = (finding.get("impact") or "").upper() or _PROBE_IMPACT_CLASS.get(vuln_id, "")
    if clase not in ("ACCESS", "EXFIL", "EXEC", "CRASH"):
        return False
    return not _has_real_interaction(finding)


def compute_risk_score(findings: List[Dict[str, Any]],
                       *, apply_impact_cap: bool = True) -> Dict[str, Any]:
    """Calcula riesgo agregado del dispositivo.

    El score se calcula EXCLUSIVAMENTE sobre findings con `confirmed=True`.

    Razonamiento: un finding con `confirmed=False` representa típicamente
    uno de tres casos:
      (a) CVE descartado porque el modelo/versión no aplica al target.
      (b) Vector que el agente probó y rechazó (404, requires auth, …).
      (c) Hipótesis que requiere herramientas que el agente no tiene.
    Ninguno es evidencia de compromiso. Contarlos en el score producía la
    paradoja observada: 28 CVEs explícitamente descartados como "no aplica"
    llevaban un router con 4 hallazgos MEDIUM reales al label CRITICAL,
    contradiciendo el propio resumen del agente.

    Algoritmo:
        score = Σ weight(severity)  para confirmed=True  /  0.4
        Cap a 100.

    Etiquetas:
      0-9    NEGLIGIBLE
      10-29  LOW
      30-59  MEDIUM
      60-84  HIGH
      85-100 CRITICAL

    Calibración:
      • 1 CRITICAL confirmado  → 10 / 0.4 = 25     → LOW
      • 2 CRITICAL confirmados → 20 / 0.4 = 50     → MEDIUM
      • 4 CRITICAL confirmados → 40 / 0.4 = 100    → CRITICAL
      • 1 HIGH confirmado      → 7 / 0.4  ≈ 18     → LOW
      • 4 MEDIUM confirmados   → 16 / 0.4 = 40     → MEDIUM
      • 0 confirmados          → 0                 → NEGLIGIBLE
    Sin confirmados, el target NO se marca como vulnerable aunque la
    NVD haya devuelto CVEs aplicables — la propuesta es objetiva: sin
    evidencia operativa, no hay riesgo demostrado.

    Los `severity_counts` totales (incluyendo unconfirmed) se siguen
    devolviendo para diagnóstico, pero no entran en `risk_score`.

    `apply_impact_cap=False` desactiva ÚNICAMENTE el tope por clase de impacto,
    conservando el techo canónico y el cap de alcanzabilidad. Existe para
    recalcular con justicia informes ANTERIORES a la introducción del campo
    `impact` (§5.10.2): sus exploits reales no lo declaran, así que aplicarlo
    los penalizaría por una convención que aún no existía cuando se generaron.
    El arnés de varianza mantenía por eso una copia propia de los pesos, el
    divisor y las etiquetas; con este parámetro usa la misma función, y
    recalibrar la fórmula deja de poder desincronizar el Capítulo 5 de los
    informes que lo sustentan.
    """
    raw = 0.0
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    confirmed_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    confirmed_count = 0
    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        confirmed = is_confirmed_vuln(f)
        counts[sev] = counts.get(sev, 0) + 1
        if confirmed:
            # Severidad EFECTIVA (tras política de impacto) para puntuar y contar:
            # un confirmado sin impacto demostrado se topa a LOW, evitando que
            # gaps de higiene/exposición inflen el score de forma inconsistente.
            eff = effective_severity(f, apply_impact_cap=apply_impact_cap)
            raw += _SEVERITY_WEIGHT.get(eff, 0)
            confirmed_count += 1
            confirmed_counts[eff] = confirmed_counts.get(eff, 0) + 1

    score = min(100, round(raw / 0.4))

    if score >= 85:
        label = "CRITICAL"
    elif score >= 60:
        label = "HIGH"
    elif score >= 30:
        label = "MEDIUM"
    elif score >= 10:
        label = "LOW"
    else:
        label = "NEGLIGIBLE"

    return {
        "risk_score": score,
        "risk_label": label,
        # severity_counts cuenta todos los findings (para diagnóstico del agente)
        "severity_counts": counts,
        # confirmed_severity_counts es lo que el reporter debe mostrar como
        # "auténticos hallazgos" — desacopla la métrica visible del ruido.
        "confirmed_severity_counts": confirmed_counts,
        "confirmed_count": confirmed_count,
        "total_findings": len(findings),
    }
