#!/usr/bin/env python3
"""Baseline scanner harness — comparación cabeza a cabeza con IoTSafeGuard-Agent.

Ejecuta un escáner de vulnerabilidades clásico (por defecto, Nmap con los
scripts NSE `vuln` + `vulners`) sobre el mismo objetivo que el agente y emite
un informe en el **mismo esquema** que `IoTSafeGuard-Agent` (vía
`modules.reporter.Reporter`), puntuando con la **misma** función
`core.tools.compute_risk_score`. Así la comparación del Capítulo 5 es directa y
no depende de cifras de la literatura, sino de una ejecución propia.

Decisión metodológica (honesta, no un hombre de paja):
  • Los CVE que `vulners` empareja por VERSIÓN/CPE se marcan `confirmed=False`
    (candidatos): el escáner detecta, no explota.
  • Los scripts NSE `vuln` que reportan `State: VULNERABLE` (es decir, que
    realmente probaron la condición) se marcan `confirmed=True`. Se le da al
    escáner el crédito de lo que sí confirma.

El resultado esperado es la traducción numérica de la tesis del trabajo: un
escáner produce muchos candidatos y **confirma poco o nada con explotación**,
por lo que su *risk score* —calculado solo sobre confirmados, igual que para el
agente— queda muy por debajo del que obtiene el agente sobre el mismo objetivo.

Uso:
    sudo ./venv/bin/python scripts/baseline_scan.py --target 172.30.0.10
    ./venv/bin/python scripts/baseline_scan.py --target 172.30.0.10 \
        --scripts vuln,vulners --report-dir reports/baseline

Requisitos: `nmap` en el PATH. Los scripts `vulners` requieren conectividad a
Internet (consulta la base de datos de Vulners). Sin red, usa solo `vuln`.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

# --- Importes del proyecto (mismo reporter y mismo scoring que el agente) ---
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from core.tools import compute_risk_score  # noqa: E402
from modules.reporter import Reporter  # noqa: E402

_CVE_CVSS_RE = re.compile(r"(CVE-\d{4}-\d{3,7})\D+(\d{1,2}\.\d)")
_VULNERABLE_RE = re.compile(r"\bState:\s*VULNERABLE\b", re.IGNORECASE)


def cvss_to_severity(score: float) -> str:
    """Mapea CVSS base (0–10) a la escala de severidad del proyecto."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


def run_nmap(target: str, scripts: str, extra_args: Optional[List[str]] = None) -> str:
    """Ejecuta Nmap con salida XML y devuelve la ruta del fichero XML."""
    nmap = _which("nmap")
    if not nmap:
        sys.exit("ERROR: 'nmap' no está en el PATH. Instálalo o usa otro escáner.")
    xml_path = tempfile.NamedTemporaryFile(
        prefix="baseline_nmap_", suffix=".xml", delete=False
    ).name
    cmd = [nmap, "-sV", "-Pn", "--script", scripts, "-oX", xml_path]
    if extra_args:
        cmd.extend(extra_args)
    cmd.append(target)
    print(f"[baseline] Ejecutando: {' '.join(cmd)}")
    # El escaneo de vulnerabilidades puede tardar; sin timeout agresivo.
    subprocess.run(cmd, check=False)
    return xml_path


def _which(binary: str) -> Optional[str]:
    from shutil import which

    return which(binary)


def parse_nmap_xml(xml_path: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], str]:
    """Parsea el XML de Nmap.

    Devuelve (findings, open_ports, os_detected).
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    findings: List[Dict[str, Any]] = []
    open_ports: List[Dict[str, Any]] = []
    os_detected = "—"
    seen_cves: set = set()

    for host in root.findall("host"):
        # OS (si -O estuvo activo)
        osel = host.find("os")
        if osel is not None:
            match = osel.find("osmatch")
            if match is not None:
                os_detected = match.get("name", os_detected)

        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid", "?")
            proto = port.get("protocol", "tcp")
            svc = port.find("service")
            product = (svc.get("product", "") if svc is not None else "").strip()
            version = (svc.get("version", "") if svc is not None else "").strip()
            svc_name = (svc.get("name", "") if svc is not None else "").strip()
            banner = " ".join(x for x in (product, version) if x) or svc_name or "?"
            open_ports.append(
                {"port": f"{portid}/{proto}", "service": svc_name, "banner": banner}
            )
            svc_label = f"{svc_name}:{portid}"

            for script in port.findall("script"):
                sid = script.get("id", "")
                output = script.get("output", "") or ""

                if sid == "vulners":
                    # Match por versión/CPE → candidatos (confirmed=False)
                    for m in _CVE_CVSS_RE.finditer(output):
                        cve, score_s = m.group(1), m.group(2)
                        if cve in seen_cves:
                            continue
                        seen_cves.add(cve)
                        score = float(score_s)
                        findings.append(_finding(
                            cve_id=cve, service=svc_label, severity=cvss_to_severity(score),
                            cvss=score, confirmed=False,
                            title=f"{cve} candidato por versión ({banner})",
                            raw_output=f"[{sid}] {banner} → {cve} (CVSS {score})",
                        ))
                else:
                    # Otros scripts de la categoría `vuln`: ¿probaron la condición?
                    confirmed = bool(_VULNERABLE_RE.search(output))
                    # ¿Trae CVE asociado?
                    cve_m = re.search(r"CVE-\d{4}-\d{3,7}", output)
                    cve = cve_m.group(0) if cve_m else None
                    # Severidad: si trae CVSS lo usamos; si no, HIGH para VULNERABLE,
                    # INFO en caso contrario (solo informativo).
                    cvss_m = _CVE_CVSS_RE.search(output)
                    if cvss_m:
                        sev = cvss_to_severity(float(cvss_m.group(2)))
                        score = float(cvss_m.group(2))
                    else:
                        sev = "HIGH" if confirmed else "INFO"
                        score = None
                    if not confirmed and sev == "INFO":
                        continue  # script informativo sin vuln → no es un finding
                    rid = cve or sid
                    if rid in seen_cves:
                        continue
                    seen_cves.add(rid)
                    findings.append(_finding(
                        cve_id=cve, service=svc_label, severity=sev, cvss=score,
                        confirmed=confirmed,
                        title=f"{sid} {'VULNERABLE' if confirmed else 'candidato'} ({banner})",
                        raw_output=f"[{sid}] {output.strip()[:400]}",
                    ))

    return findings, open_ports, os_detected


def _finding(cve_id: Optional[str], service: str, severity: str, cvss: Optional[float],
             confirmed: bool, title: str, raw_output: str) -> Dict[str, Any]:
    """Construye un finding en el esquema que consumen el Reporter y el scoring.

    Nota: `impact` se deja vacío a propósito. Para un confirmado de severidad
    MEDIUM+, `effective_severity` lo topa a LOW si no hay clase de impacto
    demostrada — exactamente igual que para el agente. El escáner no demuestra
    impacto, así que la regla se le aplica sin excepción (comparación justa).
    """
    f: Dict[str, Any] = {
        "service": service,
        "title": title,
        "severity": severity,
        "confirmed": confirmed,   # usado por compute_risk_score / is_confirmed_vuln
        "vuln_found": confirmed,  # usado por el reporter para contar confirmados
        "impact": "",
        "raw_output": raw_output,
        "details": severity,
        "source": "baseline-scanner",
    }
    if cve_id:
        f["cve_id"] = cve_id
    if cvss is not None:
        f["cvss"] = {"score": cvss, "version": "3.x"}
    return f


def build_comparison(label: str, findings: List[Dict[str, Any]],
                     risk: Dict[str, Any]) -> Dict[str, Any]:
    """Resumen compacto para construir la tabla comparativa del Capítulo 5.

    Se usa `is_confirmed_vuln` —el mismo criterio que aplica el agente— y no el
    campo crudo. La tabla compara dos escáneres: si cada columna contase los
    confirmados con una regla distinta, la comparación no mediría capacidad de
    detección sino la diferencia entre dos definiciones de «confirmado».
    """
    from core.severity import effective_severity, is_confirmed_vuln

    candidates = sum(1 for f in findings if not is_confirmed_vuln(f))
    confirmed = sum(1 for f in findings if is_confirmed_vuln(f))
    by_sev: Dict[str, int] = {}
    for f in findings:
        s = effective_severity(f)
        by_sev[s] = by_sev.get(s, 0) + 1
    return {
        "scanner": label,
        "total_findings": len(findings),
        "candidates_unconfirmed": candidates,
        "confirmed_exploited": confirmed,
        "risk_score": risk.get("risk_score"),
        "risk_label": risk.get("risk_label"),
        "severity_distribution": by_sev,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Baseline scanner harness (comparable con IoTSafeGuard-Agent).")
    ap.add_argument("--target", required=True, help="IP/host objetivo (el mismo que audita el agente).")
    ap.add_argument("--scanner", default="nmap", choices=["nmap"], help="Escáner baseline (de momento: nmap).")
    ap.add_argument("--scripts", default="vuln,vulners", help="Scripts NSE (coma-separados).")
    ap.add_argument("--report-dir", default="reports_baseline",
                    help="Carpeta de salida (user-owned; no requiere sudo, a diferencia de reports/).")
    ap.add_argument("--label", default=None, help="Etiqueta del escáner en el resumen.")
    ap.add_argument("--xml", default=None, help="Usar un XML de Nmap ya generado (omite el escaneo).")
    ap.add_argument("--nmap-extra", default="", help="Argumentos extra para nmap (entre comillas).")
    args = ap.parse_args()

    label = args.label or f"{args.scanner}:{args.scripts}"

    if args.xml:
        xml_path = args.xml
        print(f"[baseline] Usando XML existente: {xml_path}")
    else:
        extra = args.nmap_extra.split() if args.nmap_extra else None
        xml_path = run_nmap(args.target, args.scripts, extra)

    findings, open_ports, os_detected = parse_nmap_xml(xml_path)
    risk = compute_risk_score(findings)
    comparison = build_comparison(label, findings, risk)

    # --- Informe en el mismo esquema que el agente ---
    reporter = Reporter(report_dir=args.report_dir)
    reporter.add_entry(
        ip=args.target,
        os_match=os_detected,
        ports=open_ports,
        attack_plan=(
            f"BASELINE ({label}): escaneo de vulnerabilidades por versión/firma. "
            "Un escáner detecta candidatos por banner/CPE; no orquesta verificación "
            "por explotación. Los marcados confirmados son scripts NSE que probaron "
            "la condición (State: VULNERABLE)."
        ),
        attack_results=findings,
        device_identity={"vendor": "", "model": "", "firmware": "",
                         "note": "Un escáner clásico no realiza fingerprinting por consenso."},
        risk_summary=risk,
        executed_tools=[f"{args.scanner} --script {args.scripts}"],
        run_metadata={"summary": f"Baseline {label}", "finish_reason": "scanner_done",
                      "scanner_comparison": comparison},
    )
    base = reporter.generate_reports(executed_nodes=["recon", "vulnerabilities", "report"])

    # --- Resumen en terminal, listo para la tabla del Capítulo 5 ---
    print("\n" + "=" * 64)
    print(f"  COMPARACIÓN BASELINE — {label}")
    print("=" * 64)
    print(f"  Objetivo:                 {args.target}")
    print(f"  Hallazgos totales:        {comparison['total_findings']}")
    print(f"  Candidatos (no confirm.): {comparison['candidates_unconfirmed']}")
    print(f"  Confirmados (explotados): {comparison['confirmed_exploited']}")
    print(f"  Risk score (mismo cálculo): {comparison['risk_score']}/100 ({comparison['risk_label']})")
    print(f"  Distribución severidad:   {comparison['severity_distribution']}")
    print(f"  Informe:                  {base}.md")
    print("=" * 64)
    print("  → Compárese con el run del agente sobre el MISMO objetivo:")
    print("    un escáner detecta por versión y confirma poco/nada con explotación;")
    print("    el agente separa candidatos de confirmados y solo estos puntúan.")


if __name__ == "__main__":
    main()
