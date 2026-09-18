"""
Sistema de telemetría: scoring de técnicas, falsos positivos y cobertura de superficie.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from datetime import datetime
import json
from pathlib import Path

from loguru import logger


@dataclass
class TechniqueMetrics:
    """Métricas por técnica/CVE."""
    cve_id: str
    attempts: int = 0
    successes: int = 0
    false_positives: int = 0
    error_types: Dict[str, int] = field(default_factory=dict)


class TelemetryCollector:
    """
    Recopila y calcula:
    - Tasa de éxito por técnica
    - Ratio de falsos positivos
    - Cobertura real de la superficie detectada
    """

    def __init__(self, session_id: Optional[str] = None):
        self.session_id = session_id or datetime.now().strftime("%Y%m%d_%H%M%S")
        self.techniques: Dict[str, TechniqueMetrics] = {}
        self.surface_ports: set = set()
        self.surface_services: set = set()
        # Superficie NO confirmada: puertos UDP que nmap reporta `open|filtered`
        # (conjetura, no confirmación). Se registra aparte para no inflar la
        # superficie real ni penalizar la cobertura con puertos que casi nunca
        # son testables. Ej. LG TV: snmp/coap/tftp/L2TP open|filtered flipan
        # entre runs sin ser servicios reales.
        self.surface_ports_unconfirmed: set = set()
        self.surface_services_unconfirmed: set = set()
        self.total_cves_tested: int = 0
        self.total_successes: int = 0
        self.total_manual_review: int = 0

    def record_exploit_attempt(
        self,
        cve_id: str,
        success: bool,
        error_type: str = "FAIL",
        manual_review: bool = False,
    ) -> None:
        """Registra un intento de explotación."""
        if cve_id not in self.techniques:
            self.techniques[cve_id] = TechniqueMetrics(cve_id=cve_id)
        t = self.techniques[cve_id]
        t.attempts += 1
        self.total_cves_tested += 1
        if success:
            t.successes += 1
            self.total_successes += 1
        if manual_review:
            t.false_positives += 1
            self.total_manual_review += 1
        t.error_types[error_type] = t.error_types.get(error_type, 0) + 1

    def record_surface(self, ports: List[Dict], services: Optional[List[str]] = None) -> None:
        """Registra superficie detectada.

        Los puertos con `state_confidence == 'open|filtered'` (conjetura de UDP,
        no confirmación) van a los conjuntos *_unconfirmed y NO cuentan como
        superficie real. Un puerto TCP normal (sin state_confidence) o UDP `open`
        sí cuenta como confirmado.
        """
        for p in ports:
            if not isinstance(p, dict):
                continue
            unconfirmed = str(p.get("state_confidence") or "").lower() == "open|filtered"
            port_set = self.surface_ports_unconfirmed if unconfirmed else self.surface_ports
            svc_set = self.surface_services_unconfirmed if unconfirmed else self.surface_services
            if "port" in p:
                port_set.add(p["port"])
            if p.get("service_name"):
                svc_set.add(str(p["service_name"]))
        if services:
            self.surface_services.update(services)

    def success_rate_by_technique(self) -> Dict[str, float]:
        """Tasa de éxito por CVE/técnica."""
        return {
            cve_id: (t.successes / t.attempts) if t.attempts else 0.0
            for cve_id, t in self.techniques.items()
        }

    def false_positive_ratio(self) -> float:
        """Ratio de falsos positivos (manual review) sobre total intentos."""
        if self.total_cves_tested == 0:
            return 0.0
        return self.total_manual_review / self.total_cves_tested

    def surface_coverage(self, tested_ports: List[int], tested_services: List[str]) -> float:
        """
        Cobertura real: % de superficie (puertos+servicios) que fue efectivamente probada.
        """
        total = len(self.surface_ports) + len(self.surface_services)
        if total == 0:
            return 1.0
        tested = len([p for p in self.surface_ports if p in tested_ports])
        tested += len([s for s in self.surface_services if s in tested_services])
        return tested / total

    def to_dict(self) -> Dict[str, Any]:
        """Serialización para persistencia."""
        return {
            "session_id": self.session_id,
            "total_cves_tested": self.total_cves_tested,
            "total_successes": self.total_successes,
            "total_manual_review": self.total_manual_review,
            "false_positive_ratio": self.false_positive_ratio(),
            "success_rate_by_technique": self.success_rate_by_technique(),
            "surface_ports": list(self.surface_ports),
            "surface_services": list(self.surface_services),
            # Superficie UDP `open|filtered` (conjetura no confirmada), separada
            # para no inflar la superficie real ni la cobertura.
            "surface_ports_unconfirmed": list(self.surface_ports_unconfirmed),
            "surface_services_unconfirmed": list(self.surface_services_unconfirmed),
            "techniques": {
                k: {
                    "attempts": v.attempts,
                    "successes": v.successes,
                    "false_positives": v.false_positives,
                    "error_types": v.error_types,
                }
                for k, v in self.techniques.items()
            },
        }

    def save_report(self, path: Optional[Path] = None) -> Path:
        """Guarda reporte JSON de telemetría."""
        p = path or Path("reports") / f"telemetry_{self.session_id}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
        logger.info(f"[TELEMETRY] Reporte guardado: {p}")
        return p
