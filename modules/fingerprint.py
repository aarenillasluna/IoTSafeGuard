"""
DeviceFingerprinter — pipeline multi-fuente con consensus scoring.

Etapas:
  1. PASIVA        : MAC OUI + nmap CPE + detección MAC virtualizada/LAA.
  2. DISCOVERY     : mDNS + CoAP + SSDP (ya recolectado por interrogator).
  3. HTTP ACTIVA   : HNAP1 + (evidencia HTTP/TLS/favicon provista).
  4. PROTOCOLOS    : SNMP sysDescr/sysObjectID + banners TCP (provistos).
  5. FUSIÓN        : scoring ponderado por fuente; corto-circuito si HIGH.

Sin cache por IP (usuario emula diferentes firmwares sobre misma IP).
Cache interna por hash de evidencia agregada (misma evidencia = misma identidad).
"""
from __future__ import annotations

import json
import re
from typing import Dict, List, Optional

from loguru import logger
from mac_vendor_lookup import MacLookup


# -------------------------------------------------------------------------
# Señales virtualizadas / LAA
# -------------------------------------------------------------------------
VIRT_MAC_PREFIXES = {
    "00:05:69": "VMware",
    "00:0C:29": "VMware",
    "00:1C:14": "VMware",
    "00:50:56": "VMware",
    "00:03:FF": "Microsoft Hyper-V",
    "00:15:5D": "Microsoft Hyper-V",
    "00:1C:42": "Parallels",
    "00:16:3E": "Xen",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "0A:00:27": "VirtualBox host-only",
}

# =========================================================================
# Vendor canonicalization
#
# Distintas fuentes devuelven el mismo vendor con strings diferentes:
#   SSDP    "LG Electronics."         (con punto final)
#   mDNS    "LG Electronics"
#   OUI     "LG Innotek"  (NIC chipset, no la marca del producto)
#   heur.   "LG"
#
# Sin canonicalización, la KB acumula N perfiles para el mismo fabricante.
# Estrategia: MAC OUI cuando exista (deterministico, IEEE-asignado) y mapeo
# por sinónimos para strings que vienen de probes o nombre del modelo.
# =========================================================================

# OUI prefix → canonical vendor name. Source: IEEE registry + observación
# directa en runs reales. Solo familias frecuentes en IoT — el resto cae al
# normalizer por nombre.
_OUI_TO_CANONICAL = {
    # LG family — chip y device brand son el mismo grupo
    "14:7F:67": "LG", "B4:E6:2D": "LG", "CC:2D:8C": "LG",
    "60:E3:AC": "LG", "00:1C:62": "LG", "00:5A:13": "LG",
    # Samsung
    "00:14:C2": "Samsung", "00:21:19": "Samsung", "78:1F:DB": "Samsung",
    "C8:14:79": "Samsung", "28:39:5E": "Samsung",
    # Google / Chromecast
    "00:1A:11": "Google", "F4:F5:D8": "Google", "FA:8F:CA": "Google",
    # D-Link
    "B0:C5:54": "D-Link", "00:1B:11": "D-Link",
    # TP-Link
    "60:E3:27": "TP-Link", "98:DA:C4": "TP-Link", "98:DE:D0": "TP-Link",
    # Cisco / Linksys
    "00:23:69": "Cisco", "C8:D7:19": "Cisco",
    # Ubiquiti
    "F0:9F:C2": "Ubiquiti", "B4:FB:E4": "Ubiquiti", "44:D9:E7": "Ubiquiti",
    # Hikvision / Dahua (cameras)
    "DC:9F:DB": "Hikvision", "00:0E:8E": "Hikvision",
    "44:19:B6": "Hikvision", "C0:51:7E": "Hikvision",
    "AC:CB:51": "Dahua", "3C:EF:8C": "Dahua",
    # Philips Hue
    "00:17:88": "Philips", "EC:B5:FA": "Philips",
    # Raspberry Pi
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
}

# Sinónimos de nombre — clave normalizada (lower, sin punctuation final) → canónico.
_VENDOR_SYNONYMS = {
    "lg": "LG", "lg electronics": "LG", "lg innotek": "LG",
    "lg display": "LG", "lge": "LG",
    "samsung": "Samsung", "samsung electronics": "Samsung",
    "d-link": "D-Link", "dlink": "D-Link", "d link": "D-Link",
    "tp-link": "TP-Link", "tplink": "TP-Link", "tp link": "TP-Link",
    "asus": "ASUS", "asustek": "ASUS", "asustek computer": "ASUS",
    "netgear": "Netgear",
    "linksys": "Cisco", "cisco-linksys": "Cisco", "cisco systems": "Cisco", "cisco": "Cisco",
    "ubiquiti": "Ubiquiti", "ubiquiti networks": "Ubiquiti",
    "huawei": "Huawei", "huawei technologies": "Huawei",
    "xiaomi": "Xiaomi",
    "google": "Google", "google llc": "Google", "google (chromecast)": "Google",
    "philips": "Philips", "philips hue": "Philips",
    "hikvision": "Hikvision", "hikvision digital technology": "Hikvision",
    "dahua": "Dahua", "dahua technology": "Dahua",
    "synology": "Synology", "qnap": "QNAP",
    "telefonica": "Telefonica", "telefónica": "Telefonica", "movistar": "Telefonica",
    "fiberhome": "FiberHome", "technicolor": "Technicolor",
    "sagem": "Sagemcom", "sagemcom": "Sagemcom",
    "mitrastar": "MitraStar", "comtrend": "Comtrend",
    "zte": "ZTE", "alcatel": "Alcatel",
    "belkin": "Belkin", "belkin (wemo)": "Belkin",
    "zyxel": "Zyxel", "mikrotik": "MikroTik", "tenda": "Tenda",
    "raspberry pi": "Raspberry Pi", "raspberry pi foundation": "Raspberry Pi",
}


def _normalize_vendor_key(name: str) -> str:
    """Normaliza un string de vendor para usar como clave en _VENDOR_SYNONYMS.
    Quita puntos/comas finales, colapsa espacios, lowercase."""
    if not name:
        return ""
    s = name.strip().lower()
    # Quitar puntuación al inicio y final
    s = s.strip(".,;:!?()[]{}\"' \t")
    # Colapsar espacios múltiples
    s = re.sub(r"\s+", " ", s)
    return s


def normalize_mac(mac: Optional[str]) -> Optional[str]:
    """Forma canónica de una MAC: 12 hex en mayúsculas separados por ':'.

    **Fuente única de verdad** para normalizar y comparar MACs en todo el
    proyecto (identidad por MAC). Acepta cualquier separador (`:`, `-`, none) y
    cualquier caja; devuelve `None` si no contiene exactamente 48 bits. Usar
    siempre esto antes de comparar dos MACs evita falsos «dispositivos distintos»
    por diferencias de formato.
    """
    if not mac:
        return None
    hexs = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(hexs) != 12:
        return None
    return ":".join(hexs[i:i + 2] for i in range(0, 12, 2))


def _mac_prefix(mac: str) -> str:
    """Primeros 8 chars del MAC canónico (`AA:BB:CC`). Robusto a separadores."""
    n = normalize_mac(mac)
    if n:
        return n[:8]
    return mac.upper()[:8] if mac and len(mac) >= 8 else ""


# OUIs de adaptadores virtuales / emuladores. Una MAC con este prefijo NO
# identifica hardware físico: la comparten todas las instancias del emulador
# (p. ej. la `52:54:00` de QEMU que usa FirmAE en el re-hosting de firmware).
_EMULATOR_OUIS = {
    "52:54:00",  # QEMU / KVM (FirmAE)
    "08:00:27",  # VirtualBox
    "00:0C:29", "00:50:56", "00:05:69", "00:1C:14",  # VMware
    "00:16:3E",  # Xen
    "00:15:5D",  # Hyper-V
}


def is_synthetic_mac(mac: Optional[str]) -> bool:
    """¿La MAC es sintética (emulador/VM o localmente administrada)?

    Una MAC sintética no es identidad de hardware fiable: la OUI de QEMU la
    comparten todas las imágenes re-hospedadas y el bit *locally-administered*
    indica una dirección no garantizada única. Sirve para no agrupar/atribuir
    por una MAC que no distingue dispositivos (relevante con FirmAE/QEMU).
    """
    pref = _mac_prefix(mac or "")
    if not pref:
        return False
    if pref in _EMULATOR_OUIS:
        return True
    try:
        return bool(int(pref[:2], 16) & 0x02)  # bit localmente administrado
    except ValueError:
        return False


def device_key(mac: Optional[str], firmware: Optional[str] = None,
               ip: Optional[str] = None) -> str:
    """Clave de identidad de un dispositivo, **anclada a la MAC, nunca a la IP**.

    Fuente única de verdad para identificar un dispositivo entre ejecuciones.
    La MAC es el ancla porque está disponible desde el primer ARP (mientras que
    vendor/modelo se descubren más tarde) y es estable para hardware real:

    - **MAC real** → la MAC normalizada (identidad de hardware).
    - **MAC sintética** (emulador/QEMU, compartida entre imágenes FirmAE) →
      `MAC|<firmware|ip>|emu`, para no fundir dispositivos emulados distintos.
    - **Sin MAC** (objetivo enrutado, sin ARP) → `ip:<ip>` como último recurso
      (no estable, pero es lo único disponible; se marca explícitamente).

    Nota: una MAC privada/aleatoria (p. ej. iPhone con «dirección Wi-Fi
    privada») es sintética y rota con el tiempo — un dispositivo así no es
    rastreable de forma estable por diseño del propio SO, y eso es un límite
    inherente, no del agente.
    """
    m = normalize_mac(mac)
    if m and not is_synthetic_mac(m):
        return m
    if m:  # MAC sintética: desambiguar para no colapsar emulados distintos
        disc = (firmware or "").strip() or (ip or "").strip() or "?"
        return f"{m}|{disc}|emu"
    return f"ip:{(ip or '?').strip()}"


def canonicalize_vendor(name: Optional[str], mac: Optional[str] = None) -> Optional[str]:
    """Devuelve el nombre canónico del vendor.

    Prioridad:
      1. MAC OUI lookup en _OUI_TO_CANONICAL (deterministico, IEEE-asignado).
      2. Sinónimo conocido en _VENDOR_SYNONYMS (normalizado).
      3. El nombre original con strip de puntuación final (mejor que nada).
      4. None si no hay nada utilizable.

    Idempotente: canonicalize_vendor("LG", None) == "LG".
    """
    # Step 1: MAC OUI (más fiable) — salvo MAC sintética (emulador/QEMU): su OUI
    # (p. ej. 52:54:00, registrada a Realtek) mis-mapearía el vendor real del
    # dispositivo emulado, así que se ignora y se cae al nombre detectado.
    if mac and not is_synthetic_mac(mac):
        oui = _mac_prefix(mac)
        if oui in _OUI_TO_CANONICAL:
            return _OUI_TO_CANONICAL[oui]

    # Step 2: nombre normalizado contra tabla de sinónimos
    if name:
        key = _normalize_vendor_key(name)
        if key in _VENDOR_SYNONYMS:
            return _VENDOR_SYNONYMS[key]
        # Step 3: fallback al nombre original limpio (sin punctuation final)
        cleaned = name.strip().strip(".,;:!?\"'")
        if cleaned:
            return cleaned

    return None


# =========================================================================
# Device type detection — basada en evidencia explícita por fuente, no
# substring random en un blob JSON. Cada (fuente, marker) suma puntos al
# tipo correspondiente; gana el que tenga score más alto.
# =========================================================================

# (source_key, regex/substring, device_type, weight)
_DEVICE_TYPE_SIGNALS: List[tuple] = [
    # mDNS service types — señal fuerte (servicios reales del device)
    ("mdns", "_airplay._tcp", "smarttv", 5),
    ("mdns", "_googlecast._tcp", "smarttv", 5),
    ("mdns", "_roku-rcp._tcp", "smarttv", 5),
    ("mdns", "_raop._tcp", "smarttv", 4),   # Remote Audio Output Protocol = AirPlay
    ("mdns", "_ipp._tcp", "printer", 5),
    ("mdns", "_printer._tcp", "printer", 5),
    ("mdns", "_homekit._tcp", "smarthub", 5),
    ("mdns", "_hap._tcp", "smarthub", 5),
    ("mdns", "_smb._tcp", "nas", 3),
    ("mdns", "_afpovertcp._tcp", "nas", 4),
    # HNAP / SSDP UPnP descriptions
    ("hnap", "router", "router", 5),
    ("hnap", "gateway", "router", 5),
    ("ssdp_xml", "InternetGatewayDevice", "router", 5),
    ("ssdp_xml", "WLANConfiguration", "router", 4),
    ("ssdp_xml", "MediaRenderer", "smarttv", 4),
    ("ssdp_xml", "AVTransport", "smarttv", 3),
    # SNMP sysDescr fields
    ("snmp", "router", "router", 4),
    ("snmp", "printer", "printer", 4),
    # Banners TCP en puertos típicos
    ("tcp_banner", "AirTunes", "smarttv", 4),
    ("tcp_banner", "Chromecast", "smarttv", 4),
    ("tcp_banner", "Hikvision", "camera", 5),
    ("tcp_banner", "Dahua", "camera", 5),
    ("tcp_banner", "RTSP", "camera", 2),  # peso bajo, RTSP también en TVs
    # HTTP title — peso medio (puede ser engañoso)
    ("http_title", "LG TV", "smarttv", 3),
    ("http_title", "webOS", "smarttv", 4),
    ("http_title", "smart tv", "smarttv", 3),
    ("http_title", "router", "router", 2),
    ("http_title", "printer", "printer", 3),
    ("http_title", "camera", "camera", 3),
]


def _detect_device_type(emap: Dict[str, Dict]) -> Optional[str]:
    """Suma evidencia por fuente y devuelve el tipo con score más alto.
    Devuelve None si ninguna señal aplica."""
    scores: Dict[str, int] = {}
    for source_key, marker, dtype, weight in _DEVICE_TYPE_SIGNALS:
        src = emap.get(source_key)
        if not src:
            continue
        blob = json.dumps(src, default=str, ensure_ascii=False).lower()
        if marker.lower() in blob:
            scores[dtype] = scores.get(dtype, 0) + weight
    if not scores:
        return None
    return max(scores.items(), key=lambda kv: kv[1])[0]


def _is_virt_mac(mac: str) -> Optional[str]:
    if not mac:
        return None
    prefix = mac.upper()[:8]
    return VIRT_MAC_PREFIXES.get(prefix)


def _is_laa_mac(mac: str) -> bool:
    """Bit 1 del primer octeto → locally administered (no IEEE)."""
    if not mac or len(mac) < 2:
        return False
    try:
        first = int(mac.split(":")[0], 16)
        return bool(first & 0b10)
    except Exception:
        return False


# -------------------------------------------------------------------------
# Evidencia: normalización y scoring
# -------------------------------------------------------------------------

# Pesos por fuente — suman la confianza total
SOURCE_WEIGHTS = {
    "hnap": 1.00,        # HNAP1 SOAP: fabricante/modelo/firmware explícitos
    "ssdp_xml": 0.95,    # SSDP descripción XML: idem
    "snmp": 0.90,        # sysDescr: texto técnico preciso
    "tcp_banner": 0.70,  # SSH/Telnet/FTP banners a menudo delatan modelo
    "http_title": 0.60,  # Título HTML frecuente y útil
    "http_server": 0.55, # Server header
    "mdns": 0.85,        # Bonjour revela modelo Apple/Cast/Printer
    "coap": 0.80,
    "tls_cert": 0.65,    # CN/SAN del cert (raro pero determinista)
    "nmap_cpe": 0.75,    # CPE del fingerprint -O
    "mac_oui": 0.25,     # Solo fabricante del chip NIC
    "favicon": 0.60,     # Hash coincide con DB pública
}

HIGH_CONFIDENCE_THRESHOLD = 1.20  # Si se supera, short-circuit (saltamos LLM)


def _score(sources: Dict[str, float]) -> float:
    return round(sum(sources.values()), 3)


def _label_confidence(total: float) -> str:
    if total >= HIGH_CONFIDENCE_THRESHOLD:
        return "HIGH"
    if total >= 0.75:
        return "MEDIUM"
    return "LOW"


# Palabras de banner que cumplen el patrón de modelo sin serlo (hora, fechas…).
_BANNER_NOISE = {"NOW", "PORT", "HTTP", "HTTPS", "UTC", "GMT", "RFC", "TCP", "UDP"}

# Nombres de algoritmos criptográficos que encajan en el patrón XXX-99. Salen
# de las listas de negociación de SSH/TLS, no del hardware.
_CRYPTO_TOKENS = {
    "CURVE25519", "X25519", "AES128", "AES192", "AES256", "SHA1", "SHA256",
    "SHA384", "SHA512", "NISTP256", "NISTP384", "NISTP521", "RSA1024",
    "RSA2048", "RSA4096", "SSH2", "GROUP1", "GROUP14", "GROUP16", "GROUP18",
    "CHACHA20", "POLY1305", "MD5", "RIPEMD160", "TLS1", "SECP256R1",
    "SECP384R1", "SECP521R1", "ED25519", "DES3", "CAST128", "BLOWFISH",
}

# Señales de que la cadena es una lista de negociación criptográfica y no la
# descripción de un producto.
_CRYPTO_CONTEXT_RE = re.compile(
    r"(?:SHA\d|HMAC|ECDH|DIFFIE|CURVE\d|-CBC|-CTR|-GCM|SSH-2\.0|@OPENSSH|@LIBSSH)"
)

# El mismo accidente, otro vocabulario: nombres de NORMA o de CODIFICACIÓN que
# encajan en el patrón XXX-99. Un firmware Netgear se publicó cinco veces de
# cinco como modelo «ISO-8859», leído de `Content-Type: text/html;
# charset=ISO-8859-1`. Igual que con la criptografía, la lista de tokens no
# basta —la siguiente cabecera traerá `WINDOWS-1252`— así que se reconoce
# también el CONTEXTO en el que aparecen.
_ENCODING_TOKENS = {
    "ISO8859", "ISO", "UTF8", "UTF16", "UTF32", "ASCII", "ANSI", "LATIN1",
    "CP1252", "WINDOWS1252", "IEEE", "IETF", "ANSI99",
}
_ENCODING_CONTEXT_RE = re.compile(
    r"(?:CHARSET|CONTENT-TYPE|TEXT/HTML|TEXT/PLAIN|APPLICATION/|ENCODING=|"
    r"ACCEPT-CHARSET|META HTTP-EQUIV)"
)


def _extract_model_from_text(text: str) -> Optional[str]:
    """Heurística ligera: patrones XXX-99 típicos IoT.

    Reglas para evitar falsos positivos observados:
      - `\\b` al inicio: no agarra substrings dentro de otra palabra
        (antes `vulnroUTER-X1000` → "UTER-X1000").
      - separador SOLO `-` (no espacio): antes "Local time is now 07:35"
        → "NOW 07". Los modelos IoT reales usan guion o nada, no espacio.
      - blacklist de tokens de banner comunes que cumplen el patrón.
      - los nombres de algoritmo criptográfico NO son modelos. En campo, un
        router Askey se publicó cinco veces de cinco como modelo «CURVE25519»,
        leído de `curve25519-sha256` en la lista de intercambio de claves de
        Dropbear. De ahí pasaba a la KB, al CPE y a las búsquedas de CVE.

    Al descartar un candidato se sigue buscando en el resto de la cadena en vez
    de rendirse: un banner puede traer basura criptográfica ANTES del modelo
    real, y devolver `None` por eso perdería la identidad de todas formas.
    """
    if not text:
        return None
    upper = text.upper()
    # Ej: DIR-815, TL-WR841N, DCS-932L, WR841N
    # `[A-Z]{0,3}` tras el separador, no `[A-Z]?`: con una sola letra, el
    # modelo `TL-WR841N` se publicaba truncado como `WR841N` —el prefijo `TL-`
    # es parte del nombre comercial, no un adorno— y con él se consultaba la
    # NVD y se indexaba la KB. Dos letras es lo normal en TP-Link (TL-WR, TL-WA,
    # TL-SG) y tres en algún Zyxel.
    for m in re.finditer(r"\b[A-Z]{2,4}-?[A-Z]{0,3}\d{2,5}[A-Z0-9]{0,4}\b", upper):
        candidate = m.group(0)
        alpha_prefix = re.match(r"[A-Z]+", candidate)
        if alpha_prefix and alpha_prefix.group(0) in _BANNER_NOISE:
            continue
        if candidate in _CRYPTO_TOKENS:
            continue
        # Un identificador criptográfico va pegado a su parámetro por `-`, `@`
        # o `_` (CURVE25519-SHA256, AES128-GCM, ECDH-SHA2-NISTP521). Un modelo
        # real termina en separador de palabra, coma o fin de cadena.
        tail = upper[m.end():m.end() + 1]
        if tail in ("-", "@", "_") and _CRYPTO_CONTEXT_RE.search(upper):
            continue
        # Una norma o codificación se reconoce por su token (ISO-8859) o por
        # aparecer donde se declaran codificaciones (charset=, Content-Type).
        if candidate.replace("-", "") in _ENCODING_TOKENS:
            continue
        if (alpha_prefix and alpha_prefix.group(0) in ("ISO", "UTF", "ANSI", "ASCII")
                and _ENCODING_CONTEXT_RE.search(upper)):
            continue
        return candidate
    return None


def _model_from_http_title(title: Optional[str]) -> Optional[str]:
    """Extrae el modelo de un <title> compuesto cuando `_extract_model_from_text`
    no aplica (modelos con letras antes del guion, ej. 'VulnRouter-X1000').

    Conservador: quita palabras de relleno de UI (Admin, Login, …) y acepta un
    token restante SOLO si parece identificador de modelo (mezcla letra+dígito,
    3-40 chars). Así un título genérico ('Login', 'Welcome', 'Index of /') → None.
    """
    if not title:
        return None
    _UI_NOISE = {
        "admin", "login", "panel", "home", "configuration", "config", "setup",
        "management", "status", "console", "portal", "dashboard", "web", "ui",
        "interface", "system", "welcome", "router", "gateway", "page", "control",
        "device", "index", "of",
    }
    tokens = [t for t in re.split(r"\s+", title.strip())
              if t and t.lower() not in _UI_NOISE]
    for t in tokens:
        cand = t.strip(".,;:!?\"'")
        if 3 <= len(cand) <= 40 and re.search(r"\d", cand) and re.search(r"[A-Za-z]", cand):
            return cand
    return None


def _cpe_component(value: Optional[str]) -> str:
    """Sanitiza un componente CPE 2.3. Empty/None → '*'.

    Reglas:
      - Strip leading/trailing whitespace y puntuación (`.,;:`).
      - Lowercase + replace de espacios y `/` por `_`.
      - Whitelist: solo [a-z0-9_-]. Resto → `_`.
      - Colapsar múltiples `_` consecutivos a uno solo.
      - Si tras todo queda vacío o un único `_`, devolver `*` (any).
    """
    if not value:
        return "*"
    s = value.strip().strip(".,;:!?\"' \t")
    if not s:
        return "*"
    s = s.lower().replace(" ", "_").replace("/", "_")
    s = re.sub(r"[^a-z0-9_\-]", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s or "*"


def _build_cpe(manufacturer: Optional[str], model: Optional[str], firmware: Optional[str]) -> Optional[str]:
    """CPE 2.3 string — útil para queries NVD. Sanitizado para que NVD lo acepte."""
    if not manufacturer and not model:
        return None
    vendor = _cpe_component(manufacturer)
    product = _cpe_component(model)
    version = _cpe_component(firmware)
    return f"cpe:2.3:h:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


# -------------------------------------------------------------------------
# Main class
# -------------------------------------------------------------------------

class DeviceFingerprinter:
    """
    Orquesta evidencias activas/pasivas + consensus scoring.

    Dos modos de uso:
      • `consensus_only(...)` — solo agrega evidencia ya recolectada por otras
        tools del agente (nmap_scan, http_interrogate, probes activas) y aplica
        scoring determinista. NO ejecuta probes adicionales NI llama al LLM.
        Es el modo utilizado por la tool `fingerprint_consensus` en el agent loop.
      • `analyze_with_ai(...)` — pipeline completo legacy: ejecuta probes propias
        (mDNS, CoAP, HNAP, SNMP) y delega fusión final a un LLMBrain externo.
        Conservado por compatibilidad con el agente monolítico anterior.
    """

    def __init__(self, timeout: int = 3, lazy_mac_lookup: bool = True):
        self.timeout = timeout
        self.mac_lookup = None
        if not lazy_mac_lookup:
            self._ensure_mac_lookup()

    def _ensure_mac_lookup(self) -> None:
        """Carga la BD OUI bajo demanda. Lenta la primera vez (descarga ~3 MB)."""
        if self.mac_lookup is not None:
            return
        logger.debug("[FINGERPRINT] Cargando BD de fabricantes MAC...")
        try:
            self.mac_lookup = MacLookup()
        except Exception as e:
            logger.warning(f"[FINGERPRINT] BD MAC no cargable: {e}")
            self.mac_lookup = None

    # ----- Etapa 1: MAC OUI + virt detection ------------------------------

    def get_real_manufacturer(self, mac_address: Optional[str],
                              oui_vendor: Optional[str] = None) -> Dict:
        """
        Resuelve OUI. Devuelve dict con vendor, reliability (por MAC LAA/virt).

        `oui_vendor` es una resolución YA hecha por quien llama, y existe porque
        había dos caminos que no se hablaban. La herramienta `mac_vendor_lookup`
        del agente resuelve en cuatro capas —librería local, actualización de la
        base, tabla curada y, como último recurso, una API pública— mientras que
        aquí solo se consultaba la librería local. Para cualquier OUI ausente de
        esa librería el resultado era «Fabricante Genérico (No listado en IEEE)»
        aunque el agente YA supiera el fabricante: la respuesta determinista se
        obtenía y se tiraba, y la ranura de evidencia «MAC OUI» —con su peso
        declarado en el consenso— se quedaba sin alimentar.

        Se usa solo como RESPALDO y después de las comprobaciones de MAC
        virtualizada y localmente administrada, que siguen mandando: una MAC
        sintética de QEMU no debe resolverse a fabricante por mucho que alguien
        traiga un nombre (§4.7).
        """
        out = {"vendor": None, "mac": mac_address, "reliable": True, "note": None}
        if not mac_address:
            out["vendor"] = "Desconocido (Sin MAC)"
            out["reliable"] = False
            out["note"] = "no_mac"
            return out

        virt = _is_virt_mac(mac_address)
        if virt:
            out["vendor"] = f"Virtualizado ({virt})"
            out["reliable"] = False
            out["note"] = "virtualized_mac"
            return out

        if _is_laa_mac(mac_address):
            out["reliable"] = False
            out["note"] = "laa_mac"

        self._ensure_mac_lookup()
        if not self.mac_lookup:
            out["vendor"] = "Error BD MAC"
            out["reliable"] = False
            return out

        try:
            out["vendor"] = self.mac_lookup.lookup(mac_address)
        except KeyError:
            if oui_vendor:
                out["vendor"] = oui_vendor
                out["note"] = "oui_resuelto_por_el_llamante"
            else:
                out["vendor"] = "Fabricante Genérico (No listado en IEEE)"
                out["reliable"] = False
        except Exception as e:
            logger.warning(f"[FINGERPRINT] Lookup MAC error: {e}")
            out["vendor"] = "Error Lookup"
            out["reliable"] = False
        return out

    # ----- Modo agente: solo consenso, sin LLM, sin probes adicionales -----

    def consensus_only(
        self,
        mac_address: Optional[str],
        scan_results: Optional[Dict] = None,
        evidence: Optional[Dict] = None,
        hnap_info: Optional[Dict] = None,
        snmp_info: Optional[Dict] = None,
        mdns_services: Optional[List[Dict]] = None,
        coap_info: Optional[Dict] = None,
        oui_vendor: Optional[str] = None,
    ) -> Dict:
        """Agrega evidencia ya recolectada y aplica scoring determinista.

        Pensado para invocarse desde la tool `fingerprint_consensus` del agente:
        toma los resultados que el LLM ya ha conseguido con tools previas
        (nmap_scan, http_interrogate, probe_hnap, probe_snmp, ...) y los fusiona
        en un veredicto único con confianza ponderada por fuente.

        No ejecuta probes adicionales — esa decisión la toma el agente. No
        llama a ningún LLM — esto ES el output que el agente va a leer.

        Returns:
            dict con: vendor_chip, deterministic, consensus{score,label,sources},
                      cpe, evidence_sources, confidence, summary, short_circuit.
        """
        scan_results = scan_results or {}
        evidence = evidence or {}

        mac_info = self.get_real_manufacturer(mac_address, oui_vendor=oui_vendor)
        vendor_chip = mac_info["vendor"]

        evidence_by_source = self._build_evidence_map(
            scan_results=scan_results,
            evidence=evidence,
            hnap_info=hnap_info,
            snmp_info=snmp_info,
            mdns_services=mdns_services or [],
            coap_info=coap_info,
            mac_info=mac_info,
        )
        sources_present = {
            k: SOURCE_WEIGHTS[k] for k in evidence_by_source if evidence_by_source[k]
        }
        total_score = _score(sources_present)
        score_label = _label_confidence(total_score)

        deterministic = self._deterministic_identity(evidence_by_source)
        cpe = _build_cpe(
            deterministic.get("manufacturer"),
            deterministic.get("model"),
            deterministic.get("firmware_version"),
        )
        summary = self._format_summary(deterministic, score_label)
        short_circuit = bool(
            score_label == "HIGH"
            and deterministic.get("manufacturer")
            and deterministic.get("model")
        )

        return {
            "vendor_chip": vendor_chip,
            "deterministic": deterministic,
            "consensus": {
                "score": total_score,
                "label": score_label,
                "sources": list(sources_present.keys()),
            },
            "cpe": cpe,
            "evidence_sources": sources_present,
            "confidence": score_label,
            "summary": summary,
            "short_circuit": short_circuit,
        }

    # ----- Construcción de mapa por fuente ---------------------------------

    def _build_evidence_map(
        self,
        scan_results: Dict,
        evidence: Dict,
        hnap_info: Optional[Dict],
        snmp_info: Optional[Dict],
        mdns_services: List[Dict],
        coap_info: Optional[Dict],
        mac_info: Dict,
    ) -> Dict[str, Dict]:
        emap: Dict[str, Dict] = {}

        if hnap_info:
            emap["hnap"] = {
                "manufacturer": hnap_info.get("manufacturer"),
                "model": hnap_info.get("model"),
                "model_description": hnap_info.get("model_description"),
                "firmware_version": hnap_info.get("firmware_version"),
                "hardware_version": hnap_info.get("hardware_version"),
                "device_type": hnap_info.get("device_type"),
                "actions_ok": hnap_info.get("actions_ok"),
            }

        if evidence.get("ssdp_model"):
            emap["ssdp_xml"] = {
                "manufacturer": evidence.get("ssdp_manufacturer"),
                "model": evidence.get("ssdp_model"),
                "exact_model": evidence.get("ssdp_exact_model"),
                "services": [s.get("type") for s in (evidence.get("ssdp_services") or [])],
            }

        if snmp_info:
            emap["snmp"] = {
                "community": snmp_info.get("community"),
                "sys_descr": snmp_info.get("sys_descr"),
                "sys_object_id": snmp_info.get("sys_object_id"),
                "sys_name": snmp_info.get("sys_name"),
                "vendor_guess": snmp_info.get("vendor_guess"),
            }

        if evidence.get("tcp_banners"):
            emap["tcp_banner"] = {"banners_by_port": evidence["tcp_banners"]}

        if evidence.get("http_title"):
            emap["http_title"] = {"title": evidence["http_title"]}
        # Modelo explícito extraído del HTTP por el interrogator/agente (si lo pasó):
        # señal limpia, sin regex. NO tocamos manufacturer aquí — el vendor sigue
        # canonicalizándose por MAC OUI (fuente primaria).
        if evidence.get("model_from_http"):
            emap["http_model"] = {"model": evidence["model_from_http"]}

        if evidence.get("http_server") or evidence.get("http_powered_by") or evidence.get("http_www_authenticate"):
            emap["http_server"] = {
                "server": evidence.get("http_server"),
                "powered_by": evidence.get("http_powered_by"),
                "www_authenticate": evidence.get("http_www_authenticate"),
                "paths_sample": (evidence.get("http_paths_evidence") or [])[:6],
            }

        if mdns_services:
            emap["mdns"] = {"services": mdns_services[:10]}

        if coap_info:
            emap["coap"] = {
                "well_known_core": (coap_info.get("well_known_core") or "")[:1000],
                "oic_res": (coap_info.get("oic_res") or "")[:1000],
            }

        if evidence.get("tls_cert_cn") or evidence.get("tls_cert_san"):
            emap["tls_cert"] = {
                "cn": evidence.get("tls_cert_cn"),
                "san": evidence.get("tls_cert_san"),
                "issuer": evidence.get("tls_cert_issuer"),
            }

        if scan_results.get("os_cpe") or scan_results.get("os_match"):
            emap["nmap_cpe"] = {
                "os_match": scan_results.get("os_match"),
                "os_cpe": scan_results.get("os_cpe"),
            }

        # MAC OUI solo si es fiable (no virt, no LAA). Incluimos `mac` para
        # que _deterministic_identity pueda canonicalizar el vendor por OUI.
        if mac_info.get("vendor") and mac_info.get("reliable"):
            emap["mac_oui"] = {
                "vendor": mac_info["vendor"],
                "mac": mac_info.get("mac"),
                "note": mac_info.get("note"),
            }

        if evidence.get("favicon_mmh3") or evidence.get("favicon_sha256"):
            emap["favicon"] = {
                "mmh3": evidence.get("favicon_mmh3"),
                "sha256": evidence.get("favicon_sha256"),
            }

        return emap

    # ----- Extracción determinista (sin IA) -------------------------------

    def _deterministic_identity(self, emap: Dict[str, Dict]) -> Dict:
        """
        Fusiona por prioridad (orden de SOURCE_WEIGHTS desc).
        No inventa nada; solo copia lo explícito.
        """
        out: Dict = {
            "manufacturer": None,
            "model": None,
            "model_family": None,
            "firmware_version": None,
            "hardware_version": None,
            "device_type": None,
        }

        # HNAP: mayor prioridad
        if (h := emap.get("hnap")):
            out["manufacturer"] = out["manufacturer"] or h.get("manufacturer")
            out["model"] = out["model"] or h.get("model")
            out["firmware_version"] = out["firmware_version"] or h.get("firmware_version")
            out["hardware_version"] = out["hardware_version"] or h.get("hardware_version")
            out["device_type"] = out["device_type"] or h.get("device_type")

        # SSDP XML
        if (s := emap.get("ssdp_xml")):
            out["manufacturer"] = out["manufacturer"] or s.get("manufacturer")
            out["model"] = out["model"] or s.get("model")

        # SNMP
        if (sn := emap.get("snmp")):
            if not out["manufacturer"] and sn.get("vendor_guess"):
                out["manufacturer"] = sn["vendor_guess"]
            if not out["model"] and sn.get("sys_descr"):
                m = _extract_model_from_text(sn["sys_descr"])
                if m:
                    out["model"] = m

        # mDNS
        if (mdns := emap.get("mdns")):
            for svc in mdns.get("services", []):
                props = svc.get("properties") or {}
                if not out["model"] and props.get("md"):
                    out["model"] = props["md"]
                if not out["manufacturer"] and props.get("manufacturer"):
                    out["manufacturer"] = props["manufacturer"]

        # Banners TCP
        if not out["model"] and (tb := emap.get("tcp_banner")):
            for port, banner in (tb.get("banners_by_port") or {}).items():
                m = _extract_model_from_text(banner)
                if m:
                    out["model"] = m
                    break

        # Modelo explícito del HTTP (interrogator/agente) — señal limpia, sin regex.
        if not out["model"] and (hm := emap.get("http_model")):
            out["model"] = hm.get("model")

        # HTTP title/server: patrón XXX-9999 (DIR-815, DCS-932L…)
        if not out["model"]:
            for key in ("http_title", "http_server"):
                if src := emap.get(key):
                    blob = " ".join(str(v) for v in src.values() if v)
                    m = _extract_model_from_text(blob)
                    if m:
                        out["model"] = m
                        break

        # Último recurso: título compuesto (VulnRouter-X1000 Admin → VulnRouter-X1000)
        if not out["model"] and (t := emap.get("http_title")):
            out["model"] = _model_from_http_title(t.get("title"))

        # device_type por evidencia explícita (no substring random)
        if not out["device_type"]:
            out["device_type"] = _detect_device_type(emap)

        # Fabricante fallback desde MAC OUI si sigue vacío
        if not out["manufacturer"] and (oui := emap.get("mac_oui")):
            out["manufacturer"] = oui.get("vendor")

        # Canonicalización final del vendor — preferir MAC OUI cuando exista
        mac_for_canon = None
        if (oui := emap.get("mac_oui")):
            # mac_info no contiene la MAC bruta; la sacamos del scan_results si
            # llegó en emap. Si no, canonicalize_vendor cae a sinónimos por nombre.
            mac_for_canon = oui.get("mac")
        canonical = canonicalize_vendor(out["manufacturer"], mac_for_canon)
        if canonical:
            out["manufacturer"] = canonical

        return out

    def _format_summary(self, profile: Dict, confidence: str) -> str:
        dtype = profile.get("device_type") or "Device"
        mfr = profile.get("manufacturer") or "Unknown"
        model = profile.get("model") or "?"
        fw = profile.get("firmware_version")
        tail = f" FW:{fw}" if fw else ""
        return f"{dtype} - {mfr} {model}{tail} (Certeza: {confidence})"


# Claves cuyo contenido describe a TERCEROS, no al dispositivo auditado. Es la
# distinción que decide si dos MAC son el mismo aparato o dos aparatos.
#
# El caso que lo motiva es real y estuvo a punto de colarse: el televisor LG
# publica en `/setup/scan_results` (Chromecast/Eureka) el resultado de su
# escaneo wifi, con el `hotspot_bssid` de los puntos de acceso VECINOS. Un
# barrido ingenuo del blob de evidencia recogía esa BSSID y la enlazaba como
# «otra interfaz» del televisor: la base de conocimiento habría fusionado la
# tele con el router del vecino. En la tanda de campo no llegó a pasar solo
# porque esa BSSID concreta era localmente administrada y el filtro de MAC
# sintéticas la descartó — suerte, no diseño. La mayoría de los puntos de acceso
# tienen OUI universal y habrían pasado.
_FOREIGN_MAC_KEYS = (
    "scan_results", "configured_networks", "neighbors", "neighbours",
    "bssid", "hotspot", "wifi_networks", "access_points", "arp",
    "clients", "peers", "stations", "leases", "dhcp",
)

_MAC_RE = re.compile(
    r"(?<![0-9A-Fa-f:])[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}(?![0-9A-Fa-f:])")


def _walk_own_evidence(node, key_path: str = ""):
    """Produce el texto de la evidencia que describe AL PROPIO dispositivo.

    Poda las ramas cuya clave delata datos de terceros (`_FOREIGN_MAC_KEYS`):
    una MAC encontrada ahí pertenece a otro aparato, y enlazarla fusionaría dos
    dispositivos distintos —un error mucho peor que no fusionar, porque corrompe
    el histórico de ambos sin dejar rastro—.
    """
    lowered = key_path.lower()
    if any(bad in lowered for bad in _FOREIGN_MAC_KEYS):
        return
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk_own_evidence(v, f"{key_path}.{k}")
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from _walk_own_evidence(item, key_path)
    elif node is not None:
        yield str(node)


def harvest_macs(*sources) -> List[str]:
    """MAC de las interfaces DEL PROPIO dispositivo que aparezcan en la evidencia.

    Un equipo real tiene varias interfaces y anuncia unas u otras según por
    dónde se le hable: el televisor de la tanda de campo publica por mDNS la MAC
    de su wifi y su número de serie con otra MAC embebida, mientras ARP ve la de
    ethernet. `device_key` clava sobre UNA, así que sin correlacionarlas el mismo
    aparato se aprende como dos dispositivos distintos.

    Dos salvaguardas, y ambas existen para el mismo fin —no fusionar aparatos que
    no lo son—:

      · Se podan las ramas de evidencia que describen a terceros (resultados de
        escaneo wifi, tablas ARP, listas de clientes): una MAC ahí es de OTRO
        equipo.
      · Se descartan las sintéticas y la nula: enlazar por una MAC que rota
        fusionaría equipos sin relación con el paso del tiempo.
    """
    found: List[str] = []
    for src in sources:
        if not src:
            continue
        chunks = [src] if isinstance(src, str) else list(_walk_own_evidence(src))
        for chunk in chunks:
            for raw in _MAC_RE.findall(chunk):
                mac = normalize_mac(raw)
                if not mac or mac in found:
                    continue
                if mac == "00:00:00:00:00:00" or is_synthetic_mac(mac):
                    continue
                found.append(mac)
    return found
