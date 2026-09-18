"""
MITRE ATT&CK for ICS/IoT — Mapeo de nodos del framework a tácticas y técnicas.
Referencia: https://attack.mitre.org/techniques/ics/
"""
from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class MitreTechnique:
    """Técnica MITRE ATT&CK individual."""
    technique_id: str
    name: str
    tactic: str
    tactic_id: str
    description: str = ""
    url: str = ""

    def __post_init__(self):
        if not self.url:
            # Generar URL automáticamente
            base = "https://attack.mitre.org/techniques/"
            tid = self.technique_id.replace(".", "/")
            object.__setattr__(self, "url", f"{base}{tid}/")


# ============================================================================
# Catálogo de técnicas relevantes para IoT pentesting
# ============================================================================
TECHNIQUE_CATALOG: Dict[str, MitreTechnique] = {
    # --- Reconnaissance (TA0043) ---
    "T1595": MitreTechnique(
        "T1595", "Active Scanning", "Reconnaissance", "TA0043",
        "Escaneo activo de puertos y servicios para identificar superficies de ataque.",
    ),
    "T1592": MitreTechnique(
        "T1592", "Gather Victim Host Information", "Reconnaissance", "TA0043",
        "Recolección de información del host: OS, firmware, servicios activos.",
    ),
    # --- Resource Development (TA0042) ---
    "T1588.005": MitreTechnique(
        "T1588.005", "Obtain Capabilities: Exploits", "Resource Development", "TA0042",
        "Obtención de exploits públicos (NVD, Exploit-DB) para vulnerabilidades identificadas.",
    ),
    # --- Initial Access (TA0001) ---
    "T1190": MitreTechnique(
        "T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001",
        "Explotación de servicios web/API expuestos (HTTP, WebSocket, UPnP).",
    ),
    "T1078": MitreTechnique(
        "T1078", "Valid Accounts", "Initial Access", "TA0001",
        "Uso de credenciales por defecto o filtradas para acceso inicial.",
    ),
    # --- Credential Access (TA0006) ---
    "T1110": MitreTechnique(
        "T1110", "Brute Force", "Credential Access", "TA0006",
        "Fuerza bruta contra mecanismos de autenticación del dispositivo.",
    ),
    "T1557": MitreTechnique(
        "T1557", "Adversary-in-the-Middle", "Credential Access", "TA0006",
        "Interceptación de protocolos IoT no cifrados (MQTT, CoAP, SSDP).",
    ),
    # --- Discovery (TA0007) ---
    "T1046": MitreTechnique(
        "T1046", "Network Service Scanning", "Discovery", "TA0007",
        "Descubrimiento de servicios de red mediante escaneo de puertos.",
    ),
    "T1018": MitreTechnique(
        "T1018", "Remote System Discovery", "Discovery", "TA0007",
        "Identificación de dispositivos en la red (ARP, SSDP, mDNS).",
    ),
    # --- Collection (TA0009) ---
    "T1119": MitreTechnique(
        "T1119", "Automated Collection", "Collection", "TA0009",
        "Recolección automatizada de datos del dispositivo (XML, banners, headers).",
    ),
    # --- Lateral Movement (TA0008) ---
    "T1021": MitreTechnique(
        "T1021", "Remote Services", "Lateral Movement", "TA0008",
        "Uso de servicios remotos (SSH, Telnet) para movimiento lateral.",
    ),
    # --- Impact (TA0040) ---
    "T1498": MitreTechnique(
        "T1498", "Network Denial of Service", "Impact", "TA0040",
        "Denegación de servicio contra dispositivos IoT frágiles.",
    ),
}


# ============================================================================
# Mapeo: fase del agente (o categoría de tool) → técnicas MITRE ATT&CK
# ============================================================================
# Claves usadas por el reporter al narrar la auditoría. Las dos primeras
# coinciden con las fases reales del agente (recon, exploit); el resto son
# categorías de tools que el reporter agrupa cuando la evidencia lo
# justifica (interrogación HTTP/SOAP, búsqueda CVE, auth bypass).
NODE_TO_TECHNIQUES: Dict[str, List[str]] = {
    "recon": ["T1595", "T1046", "T1592"],
    "interrogate": ["T1592", "T1119", "T1018"],
    "vulnerabilities": ["T1588.005"],
    "exploit": ["T1190", "T1078"],
    "auth_bypass": ["T1110", "T1557"],
    "report": [],  # Report no mapea a técnica ofensiva
}


def get_techniques_for_node(node_name: str) -> List[MitreTechnique]:
    """Devuelve las técnicas MITRE ATT&CK asociadas a una fase/categoría."""
    tech_ids = NODE_TO_TECHNIQUES.get(node_name, [])
    return [TECHNIQUE_CATALOG[tid] for tid in tech_ids if tid in TECHNIQUE_CATALOG]


def get_all_mapped_techniques() -> List[MitreTechnique]:
    """Devuelve todas las técnicas mapeadas (sin duplicados), ordenadas por tactic_id."""
    seen = set()
    techniques = []
    for tech_ids in NODE_TO_TECHNIQUES.values():
        for tid in tech_ids:
            if tid not in seen and tid in TECHNIQUE_CATALOG:
                seen.add(tid)
                techniques.append(TECHNIQUE_CATALOG[tid])
    return sorted(techniques, key=lambda t: (t.tactic_id, t.technique_id))


def get_tactic_summary() -> Dict[str, Dict]:
    """Resumen agrupado por táctica para visualización en reportes."""
    tactics: Dict[str, Dict] = {}
    for tech in get_all_mapped_techniques():
        if tech.tactic_id not in tactics:
            tactics[tech.tactic_id] = {
                "tactic_id": tech.tactic_id,
                "tactic_name": tech.tactic,
                "techniques": [],
            }
        tactics[tech.tactic_id]["techniques"].append({
            "id": tech.technique_id,
            "name": tech.name,
            "description": tech.description,
            "url": tech.url,
        })
    return tactics


def build_attack_narrative(executed_nodes: List[str]) -> List[Dict]:
    """
    Construye una narrativa de ataque MITRE basada en los nodos ejecutados.
    Útil para el reporte final: muestra qué tácticas se ejercitaron.
    """
    narrative = []
    for node in executed_nodes:
        techs = get_techniques_for_node(node)
        if techs:
            narrative.append({
                "phase": node,
                "techniques": [
                    {
                        "id": t.technique_id,
                        "name": t.name,
                        "tactic": t.tactic,
                        "tactic_id": t.tactic_id,
                        "url": t.url,
                    }
                    for t in techs
                ],
            })
    return narrative


# ============================================================================
# Mapping tool → técnicas MITRE (para filtrar el report a lo realmente usado)
# ============================================================================
TOOL_TO_TECHNIQUES: Dict[str, List[str]] = {
    # Reconnaissance
    "nmap_scan":           ["T1595", "T1046", "T1018"],   # Active Scanning, Net Service Scanning, Remote System Discovery
    "mac_vendor_lookup":   ["T1592"],                      # Gather Victim Host Info
    "http_interrogate":    ["T1592", "T1595"],
    # Discovery — IoT/UDP probes
    "probe_mdns":          ["T1018", "T1046"],
    "probe_coap":          ["T1046"],
    "probe_upnp_igd":      ["T1046", "T1018"],
    "probe_wsdiscovery":   ["T1018", "T1046"],
    "probe_bacnet":        ["T1046"],
    "probe_tftp":          ["T1046"],
    # Discovery — IoT/TCP probes
    "probe_hnap":          ["T1592"],
    "probe_snmp":          ["T1046", "T1592"],
    "probe_dial":          ["T1046", "T1592"],
    "probe_chromecast":    ["T1592"],
    "probe_lg_webos":      ["T1190", "T1592"],             # WebSocket pairing → Exploit Public-Facing
    "probe_telnet":        ["T1078", "T1110"],             # default creds attempt
    "probe_ssh":           ["T1592"],
    "probe_ftp":           ["T1078", "T1110"],             # anonymous login attempt
    "probe_smb":           ["T1046"],
    "probe_modbus":        ["T1046"],
    "probe_opcua":         ["T1046"],
    "probe_rtsp":          ["T1078", "T1110"],             # RTSP default creds
    "probe_mqtt":          ["T1046", "T1557"],             # MQTT broker access ~ MitM
    "probe_cwmp":          ["T1190"],
    # Information gathering meta
    "cve_search":          ["T1588.005"],                  # Obtain Capabilities: Exploits
    # Exploitation
    "execute_command":     ["T1190", "T1078"],
    "execute_chain":       ["T1190", "T1078"],
    "execute_websocket":   ["T1190"],
    "web_login":           ["T1078", "T1110"],
}


def get_techniques_used_by_tools(tool_names: List[str]) -> List[MitreTechnique]:
    """Devuelve solo las técnicas MITRE asociadas a las tools efectivamente
    invocadas. Reemplaza al `get_all_mapped_techniques()` que devuelve todo
    el catálogo (incluyendo técnicas que NUNCA se usaron en el run).

    Esto evita el "MITRE boilerplate problem": reportes que listaban Brute
    Force / Adversary-in-the-Middle aunque NUNCA se ejecutaran ataques de
    ese tipo.
    """
    seen: set = set()
    techniques: List[MitreTechnique] = []
    for tool in tool_names:
        for tid in TOOL_TO_TECHNIQUES.get(tool, []):
            if tid not in seen and tid in TECHNIQUE_CATALOG:
                seen.add(tid)
                techniques.append(TECHNIQUE_CATALOG[tid])
    return sorted(techniques, key=lambda t: (t.tactic_id, t.technique_id))


def get_tactic_summary_for_tools(tool_names: List[str]) -> Dict[str, Dict]:
    """Variante de get_tactic_summary() que filtra al subset de técnicas
    realmente usadas según las tools del run."""
    techs = get_techniques_used_by_tools(tool_names)
    tactics: Dict[str, Dict] = {}
    for t in techs:
        if t.tactic_id not in tactics:
            tactics[t.tactic_id] = {
                "tactic_id": t.tactic_id,
                "tactic_name": t.tactic,
                "techniques": [],
            }
        tactics[t.tactic_id]["techniques"].append({
            "id": t.technique_id,
            "name": t.name,
            "description": t.description,
            "url": t.url,
        })
    return tactics
