"""
Policy Engine de Ejecución: allowlist de comandos y flags.
Bloquea shells libres y usa plantillas por protocolo (HTTP, WS, MQTT).
"""
import os
import re
from typing import List, Tuple, Optional, Any


# Allowlist: herramienta -> flags permitidos (regex o exact match)
ALLOWED_TOOLS = {
    "curl": [
        r"^-k$", r"^-s$", r"^-S$", r"^-i$", r"^-I$",
        r"^-m$", r"^-m\s*\d+$",
        r"^--connect-timeout$", r"^--connect-timeout\s*\d+$",
        r"^-d$", r"^--data$", r"^-d\s+", r"^--data\s+",
        r"^--data-binary$", r"^--data-raw$",
        r"^-X$", r"^-X\s+\w+$", r"^-H$", r"^-H\s+",
        r"^-A$", r"^-A\s+",    # User-Agent (bypass auth en D-Link)
        r"^-u$", r"^-u\s+",    # Basic auth credentials (user:pass)
        r"^-b$", r"^-b\s+",    # Cookie jar / literal cookie
        r"^-c$", r"^-c\s+",    # Cookie jar write
        r"^-L$",               # Follow redirects
        r"^--max-redirs$", r"^--max-redirs\s*\d+$",
        # `-o` eliminado: `-o` seguido de una ruta ESCRIBE EN DISCO, esquivando la
        # prohibición de redirección (`>`). La validación es token a token y no
        # puede exigir que el siguiente sea `-`, así que se rechaza `-o` entero:
        # curl ya escribe en stdout por defecto, que es lo que necesita auditar.
        r"^https?://", r"^-w\s+", r"^-v$", r"^-n$",
    ],
    "websocat": [
        r"^-k$", r"^-n1$", r"^-n\s*\d+$", r"^-t$", r"^--text$",
        r"^--one-shot$", r"^-1$",
        r"^--no-close$",
        r"^--insecure$",  # TLS sin verificación de cert (necesario para IoT self-signed)
        r"^--no-ssl-peer-verification$",
        r"^wss?://", r"^-E$", r"^-b\s+",
    ],
    "wscat": [
        r"^-c$", r"^-n$", r"^wss?://",
    ],
    # NOTA: -e (execute) eliminado intencionalmente — habilitaría bind shells arbitrarios
    "nc": [r"^-l$", r"^-v$", r"^-n$", r"^-p$", r"^-p\s*\d+$", r"^-z$",
           r"^-w$", r"^-w\s*\d+$", r"^-u$"],
    "netcat": [r"^-l$", r"^-v$", r"^-n$", r"^-p$", r"^-p\s*\d+$", r"^-z$",
               r"^-w$", r"^-w\s*\d+$", r"^-u$"],
    "nmap": [
        r"^-s[STUVA]$", r"^-sU$", r"^-sV$", r"^-sC$",
        r"^-p$", r"^-p\s*[\d\-,]+$", r"^[\d,\-]+$",   # -p solo o con puertos, y token de puertos separado
        r"^--script$", r"^--script\s+", r"^--script-args$", r"^--script-args\s+",
        r"^--data-payload$", r"^--data-payload\s+",    # payloads raw para buffer overflow
        r"^-A$", r"^-O$", r"^-T\d$", r"^-Pn$", r"^-n$", r"^-v$",
        r"^--open$", r"^-oX$", r"^-oN$",
    ],
    # NOTA: `wget` eliminado intencionalmente de la allowlist. Era el único
    # binario permitido capaz de ESCRIBIR EN DISCO: `wget -q http://host/x`
    # descarga a un fichero del directorio actual sin necesitar `-O`, con lo que
    # esquivaba la prohibición de redirección (`>`) que protege el resto del
    # catálogo. `curl` cubre el mismo caso de uso de auditoría y no puede escribir
    # ficheros (ver la nota de `-o` arriba). Además, la memoria del TFM (§5.11)
    # describe `wget` como binario fuera de la allowlist: ahora lo está.
    "ping": [
        r"^-c$", r"^-c\s*\d+$",
        r"^-n$", r"^-n\s*\d+$",
        r"^-W$", r"^-W\s*\d+$",
        r"^-i$", r"^-i\s*\d+(\.\d+)?$",
    ],
    "mosquitto_sub": [
        r"^-h\s+", r"^-p\s*\d+$", r"^-t\s+", r"^-v$", r"^-C\s*\d+$",
        r"^--cafile\s+", r"^-u\s+", r"^-P\s+",
    ],
    "echo": [r"^-n$", r"^-e$", r"^-ne$", r"^-en$"],  # flags estándar POSIX de echo
    # `printf` es OBLIGATORIO, no un extra: el shell de los dispositivos IoT suele
    # ser dash, donde `echo -e` imprime "-e" literal y rompe la enumeración por
    # telnet. El prompt de explotación instruye `printf '…' | nc <ip> 23` como el
    # patrón one-shot, y `core/tools.py` reescribe `echo -e` a `printf` por ese
    # mismo motivo — así que sin printf en la allowlist ese reescribido convertía
    # un comando permitido en una violación de política. No añade capacidad:
    # escribe en stdout y no puede ejecutar ni crear ficheros (sin redirección).
    "printf": [],
    # SNMP enumeration tools (read-only community string probes)
    "snmpwalk": [
        r"^-v$", r"^-v\s+\S+$", r"^1$", r"^2c$", r"^3$",  # version flags/values
        r"^-c$", r"^-c\s+\S+$",   # community string
        r"^-O[neqvf]*$",           # output formatting
        r"^-t$", r"^-t\s*\d+$",    # timeout
        r"^-r$", r"^-r\s*\d+$",    # retries
        r"^-m$", r"^-m\s+\S+$",    # MIB modules
    ],
    "snmpget": [
        r"^-v$", r"^-v\s+\S+$", r"^1$", r"^2c$", r"^3$",
        r"^-c$", r"^-c\s+\S+$",
        r"^-O[neqvf]*$",
        r"^-t$", r"^-t\s*\d+$",
        r"^-r$", r"^-r\s*\d+$",
        r"^[\d.]+$",  # OID dotted notation
    ],
    # Truncadores de salida. SOLO admiten flags numéricos: sin patrón que case
    # un operando de ruta, `head /etc/shadow` se rechaza como cualquier otro
    # comando con un argumento no declarado. Es lo que permite darlos por buenos
    # en la tubería sin convertirlos en un lector de ficheros arbitrarios.
    "head": [
        r"^-\d+$",                     # head -20
        r"^-n$", r"^-n\s*\d+$",        # head -n 20 · head -n20
        r"^-c$", r"^-c\s*\d+$",        # head -c 400
        r"^\d+$",                      # el operando suelto de `-n 20`
    ],
    "tail": [
        r"^-\d+$",
        r"^-n$", r"^-n\s*\+?\d+$",
        r"^-c$", r"^-c\s*\d+$",
        r"^\+?\d+$",
    ],
    "socat": [
        r"^-$", r"^-t\s*\d+$", r"^-T\s*\d+$", r"^-u$",
        r"^STDIO$", r"^STDIN$", r"^STDOUT$",
        r"^UDP-DATAGRAM:", r"^UDP4-DATAGRAM:", r"^UDP:", r"^UDP4:",
        r"^TCP:", r"^TCP4:", r"^TCP-CONNECT:",
    ],
}

# Herramientas permitidas en tuberías (solo estas en cada segmento)
#
# `head` y `tail` entran por evidencia de campo: en quince ejecuciones el modelo
# pidió `| head -20` catorce veces, en seis auditorías distintas, y las catorce
# se rechazaron. Truncar la salida no es una capacidad nueva —el contenido ya lo
# tenía— y el par no escribe en disco, no abre sockets y no ejecuta nada: negarlo
# solo compraba turnos perdidos.
#
# No es la misma decisión que `xxd`/`od`, que siguen fuera: aquellos pedían
# CODIFICAR bytes, y para eso `execute_command` adjunta ya el volcado hexadecimal
# cuando la respuesta trae no imprimibles. Aquí no hay sustituto: la alternativa
# real a `head` es leerlo todo.
PIPE_ALLOWED = {"echo", "printf", "curl", "websocat", "wscat", "nc", "netcat",
                "mosquitto_sub", "socat", "snmpwalk", "snmpget", "head", "tail"}

# Un rechazo que no dice qué hacer en su lugar se convierte en reintentos: en
# quince ejecuciones reales el modelo repitió `tftp` cuatro veces y
# `$(printf 'A%.0s' {1..2000})` cinco, porque el mensaje solo decía qué estaba
# prohibido. Cada entrada nombra la vía que SÍ existe. La clave se busca por
# subcadena en el comando rechazado.
POLICY_ALTERNATIVES = (
    ("tftp", "use the `probe_tftp` tool (anonymous RRQ of common files)"),
    ("socks5", "use `probe_socks5`, which negotiates the handshake and also tests the "
               "relay against the target's own 127.0.0.1"),
    ("-x ", "proxy pivoting is forbidden because it can reach third parties; "
            "`probe_socks5` runs the relay test inside the authorised scope"),
    ("coap-client", "use `probe_coap`"),
    ("mosquitto_pub", "use `probe_mqtt`"),
    ("snmpbulkwalk", "use `probe_snmp`"),
    # Aparecieron en la última tanda de campo, sin alternativa declarada: el
    # modelo los pidió y solo recibió una negativa, que es lo que produce
    # reintentos.
    ("ntpq", "use `probe_udp` with `proto_hint='ntp'`; NTP monlist mode is out of "
             "scope because it is amplifiable against third parties"),
    ("avahi-browse", "use `probe_mdns`, which queries the same service without "
                     "depending on a local daemon"),
    ("-w ", "`curl -w` writes formatting into the output and adds no evidence about "
            "the device; the response time already comes in `_elapsed_ms`"),
    ("ssh ", "use `probe_ssh` (banner) or `probe_ssh_credentials` (authentication)"),
    ("$(", "command substitution is forbidden; for repeated payloads use "
           "`probe_tcp` with `payload_hex`, which sends arbitrary bytes"),
    ("| xxd", "not needed: `execute_command` already returns `output_hex` when the "
              "response carries non-printable bytes"),
    ("| od", "not needed: `execute_command` already returns `output_hex` when the "
             "response carries non-printable bytes"),
    ("| hexdump", "not needed: `execute_command` already returns `output_hex`"),
    ("<", "if it came from an unsubstituted template (`<TARGET_IP>`), put the real IP; "
          "input redirection is forbidden"),
)


def _alternative_for(command_str: str) -> str:
    """Sufijo con la alternativa disponible, o cadena vacía si no hay ninguna."""
    bajo = (command_str or "").lower()
    for aguja, consejo in POLICY_ALTERNATIVES:
        if aguja in bajo:
            return f" — Instead: {consejo}."
    return ""

# Patrones prohibidos globalmente (no incluir ';' genérico: permitido en subshell echo;echo)
FORBIDDEN_PATTERNS = [
    r"`[^`]*`",        # backticks
    r"\$\([^)]*\)",    # $()
    r">\s*/",          # redirección a archivo absoluto
    r"<\s*[^<]",       # input redirection a archivo (excepto <<<)
    r"\|\s*bash",      # pipe a bash
    r"\|\s*sh\b",
    r"eval\s+",
    r"exec\s+",
    r"\|\s*grep\b",    # pipe a grep — innecesario, la IA analiza el output directamente
    r"\|\s*awk\b",     # pipe a awk
    r"\|\s*sed\b",     # pipe a sed
    r"\|\s*cut\b",     # pipe a cut
]


class PolicyViolation(Exception):
    """Violación de la política de ejecución."""
    pass


class PolicyEngine:
    """
    Motor de políticas que valida comandos antes de ejecución.
    Solo permite comandos y flags aprobados (allowlist).
    """

    def __init__(self, allowed_tools: Optional[dict] = None):
        self.allowed_tools = allowed_tools or ALLOWED_TOOLS
        self.forbidden = FORBIDDEN_PATTERNS
        self.pipe_allowed = PIPE_ALLOWED

    def _check_forbidden(self, raw: str) -> None:
        """Lanza PolicyViolation si hay patrones prohibidos.

        Antes de comparar se neutraliza el CONTENIDO de los payloads, porque son
        datos que viajan al dispositivo, no instrucciones que ejecute el shell
        local — que es lo único que esta capa debe contener:

        - `-d/--data …` de `curl`: evita leer el `<` de un cuerpo XML/SOAP como
          una redirección de entrada.
        - argumento entrecomillado de `echo`/`printf`: el patrón de enumeración
          por telnet que documenta el prompt de explotación
          (`printf 'id; cat /etc/*release 2>/dev/null\\nexit\\n' | nc <ip> 23`)
          lleva un `2>/dev/null` **dentro** de la carga, destinado al shell del
          dispositivo. Leerlo como redirección local rechazaba el comando y dejaba
          al agente sin la enumeración que su propio prompt le pide.

        Solo se neutraliza lo entrecomillado: una redirección real FUERA de las
        comillas (`printf 'x' > /tmp/f`) sigue detectándose y bloqueándose.
        """
        sanitized = re.sub(r"(-d|--data|--data-binary|--data-raw)\s+(['\"]).*?\2",
                           r"\1 PAYLOAD", raw, flags=re.DOTALL)
        sanitized = re.sub(r"\b(echo|printf)((?:\s+-\w+)*)\s+(['\"]).*?\3",
                           r"\1\2 PAYLOAD", sanitized, flags=re.DOTALL)
        for pat in self.forbidden:
            if re.search(pat, sanitized):
                raise PolicyViolation(f"Forbidden pattern detected: {pat}")

    @staticmethod
    def _normalize_segment_executable(segment: str) -> str:
        """
        Convierte /usr/bin/websocat ... en websocat ... para que coincida con la allowlist.
        """
        segment = segment.strip()
        if not segment:
            return segment
        parts = segment.split(None, 1)
        exe = os.path.basename(parts[0])
        if len(parts) == 1:
            return exe
        return f"{exe} {parts[1]}"

    def _extract_first_tool(self, segment: str) -> Optional[str]:
        """Extrae la primera herramienta de un segmento de comando."""
        segment = self._normalize_segment_executable(segment)
        for tool in self.allowed_tools:
            if segment.startswith(tool) and (
                len(segment) == len(tool)
                or segment[len(tool) : len(tool) + 1] in (" ", "\t", "\n")
            ):
                return tool
        return None

    @staticmethod
    def _expand_clustered_flags(arg: str, allowed_patterns: List[str]) -> List[str]:
        """Desagrupa flags cortos POSIX (`-sk` → `-s`, `-k`) para validarlos.

        Motivo: `curl -sk` es la forma idiomática y la que aparece en los prompts,
        pero la validación es token a token y `-sk` no coincide con `^-s$` ni con
        `^-k$`, así que TODO comando con flags agrupados era rechazado con
        `POLICY_VIOLATION` — el agente perdía turnos ejecutando lo que su propio
        prompt le indicaba.

        La expansión NO relaja la política: solo se aplica si **cada letra** del
        grupo está permitida individualmente. Si alguna no lo está (o el token
        lleva un valor pegado, como `-m30`), se devuelve el token intacto y sigue
        la validación normal, que decidirá.
        """
        if not re.match(r"^-[A-Za-z]{2,}$", arg):
            return [arg]
        letters = [f"-{c}" for c in arg[1:]]
        for letter in letters:
            if not any(re.fullmatch(pat.rstrip("$") + "$", letter)
                       for pat in allowed_patterns if pat.startswith("^-")):
                return [arg]
        return letters

    # Metacaracteres de shell que no tienen por qué aparecer en un OPERANDO
    # (URL, host, puerto, comunidad SNMP, ruta de MIB…). El ejecutor no usa
    # `shell=True`, así que no son ejecutables por sí mismos, pero un operando
    # que los lleva es señal de que el modelo intentó componer algo distinto de
    # lo que la herramienta espera, y eso merece rechazo explícito en lugar de
    # confiar en que la capa de abajo lo neutralice.
    _OPERAND_FORBIDDEN = re.compile(r"[;&|<>`$\n\r]")

    # Flags cuyo VALOR es una carga destinada al dispositivo, no un operando
    # local: cuerpos HTTP, cabeceras, topics MQTT, credenciales. Un cuerpo SOAP
    # legítimo lleva `<` y `>`, y una cabecera lleva `;`. Es la misma distinción
    # que hace `_check_forbidden` al neutralizar las cargas antes de buscar
    # patrones prohibidos: esta capa contiene el plano de ejecución LOCAL, y el
    # contenido que viaja al objetivo no forma parte de él.
    _PAYLOAD_FLAGS = frozenset({
        "-d", "--data", "--data-binary", "--data-raw",
        "-H", "--header", "-A", "-b", "-u", "-w", "-t", "-P", "-e",
        "--script-args", "--data-payload",
    })

    # Herramientas cuyo operando sería un fichero LOCAL, no un objetivo de red.
    # La regla general acepta operandos desconocidos como dato —correcto para
    # una URL o un host— y eso convertiría un truncador de salida en un lector
    # de ficheros arbitrarios. Consumen de la tubería o no consumen nada.
    _NO_OPERAND_TOOLS = frozenset({"head", "tail"})

    def _validate_args(self, tool: str, args: List[str]) -> None:
        """Valida que los argumentos cumplan la allowlist de flags.

        Nota sobre la comprobación final: durante mucho tiempo el rechazo solo
        se aplicaba si el argumento empezaba por `-`, con lo que **cualquier
        operando pasaba sin mirar**, dijera lo que dijera. Los flags estaban
        acotados y sus valores no. Ahora los operandos también se validan —de
        forma deliberadamente permisiva, porque son datos y no instrucciones—
        pero se rechazan si llevan metacaracteres de shell, salvo cuando son la
        carga de un flag que transporta datos al dispositivo (`_PAYLOAD_FLAGS`).
        """
        allowed_patterns = self.allowed_tools.get(tool, [])
        expanded: List[str] = []
        for arg in args:
            expanded.extend(self._expand_clustered_flags(arg, allowed_patterns))
        # Índices que son la carga de un flag de datos: se validan contra la
        # allowlist como siempre, pero no contra los metacaracteres de shell.
        payload_positions = {
            i + 1 for i, a in enumerate(expanded)
            if a.split("=", 1)[0] in self._PAYLOAD_FLAGS
        }
        # `echo` y `printf` no llevan la carga tras un flag: su primer operando
        # ES la carga. Es el patrón de enumeración que documentan los propios
        # prompts —`printf 'id; cat /etc/*release 2>/dev/null\nexit\n' | nc <ip> 23`—
        # cuyo `;` y `2>/dev/null` van dirigidos al shell DEL DISPOSITIVO. Sin
        # esta excepción, la política volvería a rechazar exactamente lo que el
        # sistema le pide al agente que haga.
        if tool in ("echo", "printf"):
            for i, a in enumerate(expanded):
                if not a.startswith("-"):
                    payload_positions.add(i)
                    break
        for position, arg in enumerate(expanded):
            # Herramientas SIN operandos. La regla general de más abajo acepta
            # como «dato» cualquier operando que no encaje en ningún patrón, y
            # para `curl` o `nc` es lo correcto: su operando es una URL o un
            # host. Para un truncador de salida el operando es un FICHERO LOCAL,
            # de modo que la misma regla convertía `head` en un lector de
            # `/etc/shadow`. Aquí solo se admiten flags declarados y números.
            if tool in self._NO_OPERAND_TOOLS and not arg.startswith("-"):
                if not re.match(r"^\+?\d+$", arg):
                    raise PolicyViolation(
                        f"{tool} only accepts numeric flags, not operands: {arg[:50]}"
                        f" — Instead: use it at the end of a pipe "
                        f"(`curl -sk <url> | {tool} -20`), never over a file.")
                continue
            # La carga de un flag de datos viaja al dispositivo: no se somete a
            # la comprobación de metacaracteres locales (un cuerpo SOAP lleva
            # `<`, una cabecera lleva `;`). Sí sigue pasando por la allowlist.
            check_metachars = position not in payload_positions
            # Permitir URLs (contienen ://)
            if "://" in arg:
                if check_metachars:
                    self._reject_shell_metachars(tool, arg)
                continue
            # Permitir números (ej. -m 4, --connect-timeout 5)
            if re.match(r"^\d+$", arg):
                continue
            # Permitir IPs y hosts (solo si NO empieza por '-', para no saltarse la allowlist de flags)
            if not arg.startswith("-"):
                if re.match(r"^[\d.]+$", arg) or re.match(r"^[\w.-]+$", arg):
                    if " " not in arg and ";" not in arg:
                        continue
            # Permitir JSON literales como un solo argumento
            if arg.strip().startswith("{") and arg.strip().endswith("}"):
                continue
            # Permitir rutas a archivos temp (@path)
            if arg.startswith("@") and "/" in arg:
                if check_metachars:
                    self._reject_shell_metachars(tool, arg)
                continue
            # Verificar contra allowlist
            matched = False
            for pat in allowed_patterns:
                if re.match(pat, arg) or re.search(pat, arg):
                    matched = True
                    break
            if matched:
                continue
            if arg.startswith("-"):
                raise PolicyViolation(f"Flag not allowed for {tool}: {arg[:50]}")
            # Operando que no encaja en ningún patrón: se acepta como dato, pero
            # nunca con metacaracteres de shell dentro.
            if check_metachars:
                self._reject_shell_metachars(tool, arg)

    @classmethod
    def _reject_shell_metachars(cls, tool: str, arg: str) -> None:
        if cls._OPERAND_FORBIDDEN.search(arg):
            raise PolicyViolation(
                f"Operand with shell metacharacters for {tool}: {arg[:50]}")

    @staticmethod
    def _split_semicolon_outside_single_quotes(inner: str) -> List[str]:
        """Divide por ';' solo fuera de comillas simples (estilo bash)."""
        parts: List[str] = []
        buf: List[str] = []
        in_sq = False
        for c in inner:
            if c == "'" and not in_sq:
                in_sq = True
                buf.append(c)
            elif c == "'" and in_sq:
                in_sq = False
                buf.append(c)
            elif c == ";" and not in_sq:
                parts.append("".join(buf).strip())
                buf = []
            else:
                buf.append(c)
        if buf:
            parts.append("".join(buf).strip())
        return [p for p in parts if p]

    def _parse_subshell_echo_payloads(self, left: str, require_json: bool = True) -> list:
        """
        Parsea (echo '...'; sleep N; echo '...') y devuelve una lista de acciones:
        - ('echo', 'payload_string')
        - ('sleep', N)  (solo si require_json=False, para nc/netcat/telnet)
        Solo se permiten comandos echo (y sleep si require_json=False).
        Si require_json=True, cada payload debe empezar por '{' (JSON / LG SSAP).
        """
        import shlex

        s = left.strip()
        if not (s.startswith("(") and s.endswith(")")):
            raise PolicyViolation("The left-hand subshell must be ( ... )")
        inner = s[1:-1].strip()
        chunks = self._split_semicolon_outside_single_quotes(inner)
        if not chunks:
            raise PolicyViolation("Empty subshell")

        actions: list = []
        has_echo = False
        for ch in chunks:
            try:
                parts = shlex.split(ch)
            except ValueError as e:
                raise PolicyViolation(f"Could not parse subshell fragment: {e}")

            if not parts:
                continue
            exe = os.path.basename(parts[0]).lower()
            # echo + sleep permitidos en todos los subshells. sleep es necesario
            # para timing de handshakes (Telnet login, SSAP pairing webOS, etc.).
            # require_json sigue afectando el formato del echo, no el comando permitido.
            allowed_subshell_cmds = {"echo", "sleep"}
            if exe not in allowed_subshell_cmds:
                raise PolicyViolation(f"Only {'/'.join(allowed_subshell_cmds)} allowed in a subshell, not: {exe}")

            if exe == "sleep":
                # Extraer el número de segundos
                if len(parts) < 2:
                    raise PolicyViolation("sleep with no arguments")
                try:
                    delay = float(parts[1])
                except (ValueError, IndexError):
                    raise PolicyViolation(f"sleep with an invalid argument: {parts[1:]}")
                actions.append(("sleep", delay))
                continue

            # echo command
            args = parts[1:]
            # echo -n '...' o echo -e '...' o echo '...'
            while args and args[0] in ("-n", "-e", "-ne"):
                args = args[1:]
            if not args:
                raise PolicyViolation("echo with no arguments in the subshell")

            payload = args[0] if len(args) == 1 else " ".join(args)
            pl = payload.strip()
            if require_json and not pl.startswith("{"):
                raise PolicyViolation(
                    "Every echo payload in a subshell must start with '{' (JSON / SSAP message)"
                )
            actions.append(("echo", payload))
            has_echo = True

        if not has_echo:
            raise PolicyViolation("No valid echo payloads in the subshell")
        return actions

    def validate_and_parse(self, command_str: str) -> Tuple[str, Any, Optional[str]]:
        """Valida el comando y devuelve (tool, args, json_file_path).

        Soporta tuberías convertiéndolas en una cadena de subprocesos segura.
        Lanza PolicyViolation si no cumple la política, con la alternativa
        disponible añadida al mensaje cuando la hay: el rechazo tiene que
        enseñar, no solo negar.
        """
        try:
            return self._validate_and_parse(command_str)
        except PolicyViolation as e:
            alternativa = _alternative_for(command_str)
            raise PolicyViolation(f"{e}{alternativa}") from None

    def _validate_and_parse(self, command_str: str) -> Tuple[str, Any, Optional[str]]:
        if not command_str or not command_str.strip():
            raise PolicyViolation("Empty command")

        self._check_forbidden(command_str)

        # Detectar tuberías: echo '...' | websocat ...  o  (echo '...'; echo '...') | websocat ...
        if "|" in command_str:
            parts = [p.strip() for p in command_str.split("|")]
            if len(parts) != 2:
                raise PolicyViolation("Only 2-segment pipes are allowed (e.g. echo | websocat)")

            left_raw, right_raw = parts[0], parts[1]
            right_tool = self._extract_first_tool(right_raw)
            if right_tool not in self.pipe_allowed:
                raise PolicyViolation(
                    f"Tool not allowed on the right-hand side of the pipe: {right_tool or right_raw[:40]}"
                )

            # Subshell: (echo '{...}'; echo '{...}') | websocat/nc ...
            if left_raw.strip().startswith("("):
                import shlex

                try:
                    right_parts = shlex.split(right_raw.strip())
                except ValueError as e:
                    raise PolicyViolation(f"Error parsing the right-hand side of the pipe: {e}")
                if not right_parts:
                    raise PolicyViolation("Empty destination segment")
                right_parts[0] = os.path.basename(right_parts[0])
                rt = right_parts[0].lower()
                if rt not in ("websocat", "wscat", "nc", "netcat", "socat"):
                    raise PolicyViolation("After a subshell, only a pipe to websocat/wscat/nc/socat is allowed")
                # nc/netcat/socat permiten texto plano (ej. credenciales telnet); websocat/wscat exigen JSON
                require_json = rt in ("websocat", "wscat")
                actions = self._parse_subshell_echo_payloads(left_raw, require_json=require_json)
                self._validate_args(rt, right_parts[1:])
                return ("multi_echo_pipe", [actions, right_parts], None)

            left_tool = self._extract_first_tool(left_raw)
            if left_tool not in self.pipe_allowed:
                raise PolicyViolation(
                    f"Tool not allowed on the left-hand side of the pipe: {left_tool or left_raw[:40]}"
                )

            return self._parse_pipe_command(left_raw, right_raw)

        # Comando simple sin pipe
        return self._parse_simple_command(command_str)

    def _parse_simple_command(self, raw: str) -> Tuple[str, List[str], Optional[str]]:
        """Parsea un comando simple sin tuberías."""
        import shlex

        cleaned = raw.strip().replace("```bash", "").replace("```", "").strip()
        try:
            parts = shlex.split(cleaned)
        except ValueError as e:
            raise PolicyViolation(f"Error parsing command: {e}")

        if not parts:
            raise PolicyViolation("Empty command after parsing")

        tool = os.path.basename(parts[0]).lower()
        parts[0] = tool  # ejecutar sin ruta absoluta (PATH del sistema)
        if tool not in self.allowed_tools:
            raise PolicyViolation(f"Tool not allowed: {tool}")

        args = parts[1:]
        self._validate_args(tool, args)

        json_path = None
        for i, a in enumerate(args):
            if a.startswith("@") and ("tmp" in a or "temp" in a):
                json_path = a[1:].strip('"')
                break

        return tool, args, json_path

    def _parse_pipe_command(self, left: str, right: str) -> Tuple[str, List[str], Optional[str]]:
        """
        Para "echo 'PAYLOAD' | websocat ..." devuelve el comando que se ejecutará
        como proceso principal (websocat) con stdin desde echo.
        Retorno: ("pipe_pair", [left_cmd, right_cmd], None) para que el ejecutor
        sepa que debe usar subprocess.Popen con pipe.
        """
        import shlex

        left_tool = self._extract_first_tool(left)
        right_tool = self._extract_first_tool(right)

        # Dos formas de tubería, y solo dos:
        #
        #   1. ENVIAR una carga a un servicio del objetivo — `echo|printf` hacia
        #      un cliente de red. Es la que existía.
        #   2. TRUNCAR la salida de un comando ya permitido — cualquier
        #      productor de `PIPE_ALLOWED` hacia `head`/`tail`. El destino no
        #      toca la red ni el disco: solo recorta lo que el productor ya
        #      obtuvo, así que no amplía lo que el agente puede hacer, solo lo
        #      que puede leer cómodamente.
        envio = (left_tool in ("echo", "printf")
                 and right_tool in ("websocat", "wscat", "nc", "netcat",
                                    "socat", "mosquitto_sub"))
        truncado = (right_tool in self._NO_OPERAND_TOOLS
                    and left_tool in self.pipe_allowed
                    and left_tool not in self._NO_OPERAND_TOOLS)
        if not (envio or truncado):
            raise PolicyViolation(
                "In a pipe you may only send a payload "
                "(`echo|printf` → websocat/wscat/nc/socat) or trim the output "
                "(`<command> | head -N`)")

        try:
            left_parts = shlex.split(left.strip())
            right_parts = shlex.split(right.strip())
        except ValueError as e:
            raise PolicyViolation(f"Error parsing pipe: {e}")

        if not left_parts or not right_parts:
            raise PolicyViolation("Empty pipe segments")

        left_parts[0] = os.path.basename(left_parts[0])
        right_parts[0] = os.path.basename(right_parts[0])

        self._validate_args(left_tool or "echo", left_parts[1:] if len(left_parts) > 1 else [])
        self._validate_args(right_tool or "websocat", right_parts[1:])

        # Devolvemos una estructura especial: el ejecutor manejará el par
        return ("pipe_pair", [left_parts, right_parts], None)
