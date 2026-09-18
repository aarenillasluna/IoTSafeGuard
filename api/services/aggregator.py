"""Agregador read-only sobre `data/kb.json` + `reports/audit_report_*.json`.

Construye vistas de alto nivel que el frontend consume:

  * `list_reports()`               — todos los reportes con metadata + risk.
  * `get_report(report_id)`        — un reporte completo.
  * `list_devices()`               — devices agrupados por identidad canónica
                                     (vendor + model + MAC), NUNCA por IP
                                     (la misma IP puede aparecer en distintas
                                     redes con distintos dispositivos).
  * `get_device(device_key)`       — runs + IPs vistas + CVEs por device.
  * `list_cves()`                  — todos los CVEs vistos, con contadores
                                     confirmed/dismissed agregados.
  * `get_cve(cve_id)`              — apariciones detalladas con link a reporte.

Diseño: el agregador re-lee los ficheros bajo demanda (con cache simple por
mtime). No mantiene estado en memoria entre requests más allá del caché —
así nunca queda desincronizado con la realidad del disco.
"""
from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPORTS_DIR = os.path.join(REPO_ROOT, "reports")
KB_PATH = os.path.join(REPO_ROOT, "data", "kb.json")

_REPORT_FILENAME_RE = re.compile(r"^audit_report_(\d{8}_\d{6})\.json$")


# ---------------------------------------------------------------------------
# Modelos públicos (dict simples para serialización JSON automática)
# ---------------------------------------------------------------------------
@dataclass
class _CachedFile:
    path: str
    mtime: float
    data: Any


class _Cache:
    """Cache thread-safe por mtime — invalida automáticamente si el fichero cambia."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: Dict[str, _CachedFile] = {}

    def get(self, path: str) -> Optional[Any]:
        if not os.path.exists(path):
            return None
        mtime = os.path.getmtime(path)
        with self._lock:
            entry = self._entries.get(path)
            if entry and entry.mtime == mtime:
                return entry.data
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"[aggregator] failed to read {path}: {e}")
            return None
        with self._lock:
            self._entries[path] = _CachedFile(path=path, mtime=mtime, data=data)
        return data

    def invalidate(self) -> None:
        with self._lock:
            self._entries.clear()


_CACHE = _Cache()


# ---------------------------------------------------------------------------
# Identidad canónica del device — composite key (vendor + model + MAC)
# ---------------------------------------------------------------------------
def _normalize_mac(mac: Optional[str]) -> Optional[str]:
    # Delega en la fuente única de verdad (modules.fingerprint) para no divergir.
    from modules.fingerprint import normalize_mac
    return normalize_mac(mac)


def _is_synthetic_mac(mac: Optional[str]) -> bool:
    """¿La MAC es sintética (emulador/VM o localmente administrada)?

    Delega en `modules.fingerprint.is_synthetic_mac` (única fuente de verdad de
    la lógica MAC/OUI). Una MAC sintética no identifica hardware físico, así que
    no debe usarse para agrupar dispositivos (relevante con FirmAE/QEMU).
    """
    from modules.fingerprint import is_synthetic_mac
    return is_synthetic_mac(_normalize_mac(mac))


def _device_key(vendor: Optional[str], model: Optional[str],
                mac: Optional[str], firmware: Optional[str] = None,
                ip: Optional[str] = None) -> str:
    """Composite key estable de identidad de dispositivo.

    Para hardware físico, la clave es `vendor|model|MAC` (regla del proyecto).
    Para dispositivos **emulados** (MAC sintética, p. ej. FirmAE/QEMU), la MAC
    no distingue instancias, así que se sustituye por el firmware (o, en su
    defecto, la IP) y se marca con sufijo `|emu`, evitando que imágenes
    distintas se fundan en un único perfil.
    """
    v = (vendor or "").strip() or "Unknown"
    m = (model or "").strip() or "Unknown"
    mac_n = _normalize_mac(mac)
    if mac_n and not _is_synthetic_mac(mac_n):
        return f"{v}|{m}|{mac_n}"
    # MAC ausente o sintética → no es identidad fiable.
    if _is_synthetic_mac(mac_n):
        disc = (firmware or "").strip() or (ip or "").strip() or "Unknown"
        return f"{v}|{m}|{disc}|emu"
    return f"{v}|{m}|"


def _canonical_name(vendor: Optional[str], model: Optional[str],
                    mac: Optional[str]) -> str:
    """Nombre legible para mostrar en la UI.

    Examples:
      ("D-Link", "DIR-815", "00:DE:FA:1A:01:00")  → "D-Link DIR-815 (00:DE:FA:…)"
      ("Telefonica", None, "74:93:DA:5B:8B:80")   → "Telefonica device (74:93:DA:…)"
      (None, None, "AA:BB:…")                     → "Unknown device (AA:BB:…)"
      (None, None, None)                          → "Unknown device"
    """
    mac_n = _normalize_mac(mac)
    mac_short = mac_n[:8] + "…" if mac_n else None
    if vendor and model:
        base = f"{vendor} {model}"
    elif vendor:
        base = f"{vendor} device"
    elif model:
        base = model
    else:
        base = "Unknown device"
    suffix = " [emu]" if _is_synthetic_mac(mac_n) else ""
    return (f"{base} ({mac_short}){suffix}" if mac_short else f"{base}{suffix}")


# ---------------------------------------------------------------------------
# Lectura de KB + reportes
# ---------------------------------------------------------------------------
def _load_kb() -> Dict[str, Any]:
    return _CACHE.get(KB_PATH) or {}


def _list_report_files() -> List[Tuple[str, str]]:
    """Devuelve [(report_id, full_path), ...] ordenado desc por timestamp."""
    if not os.path.isdir(REPORTS_DIR):
        return []
    out: List[Tuple[str, str]] = []
    for f in os.listdir(REPORTS_DIR):
        m = _REPORT_FILENAME_RE.match(f)
        if not m:
            continue
        out.append((m.group(1), os.path.join(REPORTS_DIR, f)))
    out.sort(key=lambda x: x[0], reverse=True)
    return out


def _load_report(path: str) -> Optional[Dict[str, Any]]:
    return _CACHE.get(path)


def _first_finding(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Devuelve `raw["findings"][0]` o un dict vacío.

    El JSON del reporter tiene shape: `{"findings": [<entry per target>, ...]}`.
    En la práctica `run.py` audita un solo target por ejecución, así que cada
    fichero contiene exactamente un entry. Esta helper centraliza el acceso
    para que si en el futuro se soportan multi-target, sólo haya un sitio donde
    tocar.
    """
    findings = raw.get("findings") or []
    return findings[0] if findings else {}


def _report_summary(report_id: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    """Subconjunto del JSON pensado para la lista (no incluye attack_results
    completos, sólo los contadores y la identidad)."""
    entry = _first_finding(raw)
    risk = entry.get("risk_summary") or {}
    identity = entry.get("device_identity") or {}
    vendor = identity.get("vendor")
    model = identity.get("model")
    firmware = identity.get("firmware")
    mac = identity.get("mac")
    target_ip = entry.get("target_ip")
    return {
        "id": report_id,
        "timestamp": entry.get("timestamp"),
        "target_ip": target_ip,
        "vendor": vendor,
        "model": model,
        "firmware": firmware,
        "mac": _normalize_mac(mac),
        "device_key": _device_key(vendor, model, mac, firmware, target_ip),
        "device_name": _canonical_name(vendor, model, mac),
        "emulated": _is_synthetic_mac(mac),
        "risk_score": risk.get("risk_score"),
        "risk_label": risk.get("risk_label"),
        "confirmed_count": risk.get("confirmed_count", 0),
        "total_findings": risk.get("total_findings", 0),
        "severity_counts": risk.get("severity_counts") or {},
        "confirmed_severity_counts": risk.get("confirmed_severity_counts") or {},
    }


# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------
def invalidate_cache() -> None:
    """Fuerza re-lectura. Útil tras lanzar una auditoría desde la UI."""
    _CACHE.invalidate()


def list_reports() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for report_id, path in _list_report_files():
        raw = _load_report(path)
        if not raw:
            continue
        out.append(_report_summary(report_id, raw))
    return out


def get_report(report_id: str) -> Optional[Dict[str, Any]]:
    for rid, path in _list_report_files():
        if rid == report_id:
            return _load_report(path)
    return None


def list_devices() -> List[Dict[str, Any]]:
    """Agrupa reports por device identity (NUNCA por IP)."""
    grouped: Dict[str, Dict[str, Any]] = {}
    for summary in list_reports():
        key = summary["device_key"]
        entry = grouped.setdefault(key, {
            "device_key": key,
            "device_name": summary["device_name"],
            "vendor": summary["vendor"],
            "model": summary["model"],
            "firmware": summary["firmware"],
            "mac": summary["mac"],
            "ips_seen": set(),
            "runs_count": 0,
            "first_seen": summary["timestamp"],
            "last_seen": summary["timestamp"],
            "total_confirmed": 0,
            "total_findings": 0,
            "last_risk_label": summary["risk_label"],
            "last_risk_score": summary["risk_score"],
        })
        if summary.get("target_ip"):
            entry["ips_seen"].add(summary["target_ip"])
        entry["runs_count"] += 1
        entry["total_confirmed"] += summary.get("confirmed_count", 0)
        entry["total_findings"] += summary.get("total_findings", 0)
        # timestamps son strings ISO/yyyymmdd_hhmmss — ordenan lexicográficamente
        if summary["timestamp"] and summary["timestamp"] < (entry["first_seen"] or ""):
            entry["first_seen"] = summary["timestamp"]
        if summary["timestamp"] and summary["timestamp"] > (entry["last_seen"] or ""):
            entry["last_seen"] = summary["timestamp"]
            entry["last_risk_label"] = summary["risk_label"]
            entry["last_risk_score"] = summary["risk_score"]
    # Convertir sets a lists para JSON, ordenar por last_seen desc
    out = []
    for entry in grouped.values():
        entry["ips_seen"] = sorted(entry["ips_seen"])
        out.append(entry)
    out.sort(key=lambda e: e["last_seen"] or "", reverse=True)
    return out


def get_device(device_key: str) -> Optional[Dict[str, Any]]:
    """Detalle de un device: identity + runs + CVEs únicos vistos."""
    summaries = [s for s in list_reports() if s["device_key"] == device_key]
    if not summaries:
        return None

    # Agregamos info del primer summary (todos comparten identity)
    first = summaries[0]
    runs: List[Dict[str, Any]] = []
    cves_seen: Dict[str, Dict[str, Any]] = {}
    ips_seen: set = set()

    for s in summaries:
        if s.get("target_ip"):
            ips_seen.add(s["target_ip"])
        # Cargar reporte completo para extraer attack_results del entry
        full = get_report(s["id"]) or {}
        entry = _first_finding(full)
        attack_results = entry.get("attack_results", [])

        runs.append({
            "report_id": s["id"],
            "timestamp": s["timestamp"],
            "target_ip": s["target_ip"],
            "risk_score": s["risk_score"],
            "risk_label": s["risk_label"],
            "confirmed_count": s["confirmed_count"],
            "total_findings": s["total_findings"],
        })

        for r in attack_results:
            cve_id = (r.get("cve_id") or "").strip()
            if not cve_id or not cve_id.startswith("CVE-"):
                continue
            entry = cves_seen.setdefault(cve_id, {
                "cve_id": cve_id,
                "severity": r.get("severity"),
                "occurrences": 0,
                "confirmed_occurrences": 0,
                "last_run": s["id"],
            })
            entry["occurrences"] += 1
            if r.get("vuln_found"):
                entry["confirmed_occurrences"] += 1
            if s["id"] > entry["last_run"]:
                entry["last_run"] = s["id"]

    return {
        "device_key": device_key,
        "device_name": first["device_name"],
        "vendor": first["vendor"],
        "model": first["model"],
        "firmware": first["firmware"],
        "mac": first["mac"],
        "ips_seen": sorted(ips_seen),
        "runs_count": len(runs),
        "runs": runs,
        "cves_seen": sorted(cves_seen.values(), key=lambda c: c["cve_id"]),
    }


def list_cves() -> List[Dict[str, Any]]:
    """CVEs vistos en algún reporte, con contadores cruzados.

    Combina dos fuentes:
      1. `attack_results` de cada reporte (autoritativo para confirmed/dismissed
         por device).
      2. `cve_validation_history` de la KB (resumen acumulado global).
    """
    kb = _load_kb()
    history = kb.get("cve_validation_history", {})

    # Aggregamos desde reports para conocer dónde y cuándo se confirmó cada CVE
    by_cve: Dict[str, Dict[str, Any]] = {}
    for summary in list_reports():
        full = get_report(summary["id"]) or {}
        finding_entry = _first_finding(full)
        for r in finding_entry.get("attack_results", []):
            cve_id = (r.get("cve_id") or "").strip()
            if not cve_id or not cve_id.startswith("CVE-"):
                continue
            entry = by_cve.setdefault(cve_id, {
                "cve_id": cve_id,
                "severity": r.get("severity"),
                "score": None,
                "description": None,
                "total_occurrences": 0,
                "confirmed_occurrences": 0,
                "devices_seen": set(),
                "last_seen": None,
            })
            entry["total_occurrences"] += 1
            if r.get("vuln_found"):
                entry["confirmed_occurrences"] += 1
            entry["devices_seen"].add(summary["device_name"])
            if not entry["last_seen"] or summary["timestamp"] > entry["last_seen"]:
                entry["last_seen"] = summary["timestamp"]

        # Inyectar score/description desde system_cves (NVD lookups) si están
        for sc in finding_entry.get("system_cves", []):
            sid = sc.get("id")
            if sid and sid in by_cve:
                by_cve[sid]["score"] = sc.get("score")
                by_cve[sid]["description"] = sc.get("description")

    # Cruzar con KB history para enriquecer
    for cve_id, hist in history.items():
        entry = by_cve.setdefault(cve_id, {
            "cve_id": cve_id,
            "severity": None,
            "score": None,
            "description": None,
            "total_occurrences": 0,
            "confirmed_occurrences": 0,
            "devices_seen": set(),
            "last_seen": None,
        })
        # `tested_n_times` y `confirmed_count` son globales (no necesariamente
        # alineados con reports, ya que el KB acumula a través de runs viejos
        # cuyos reports pueden haber sido borrados).
        entry["kb_tested_n_times"] = hist.get("tested_n_times", 0)
        entry["kb_confirmed_count"] = hist.get("confirmed_count", 0)
        entry["kb_vendors_tested"] = hist.get("vendors_tested", [])

    out = []
    for entry in by_cve.values():
        entry["devices_seen"] = sorted(entry["devices_seen"])
        out.append(entry)
    # Orden: confirmados primero, después por total_occurrences desc
    out.sort(key=lambda e: (
        -e["confirmed_occurrences"], -e["total_occurrences"], e["cve_id"],
    ))
    return out


def get_cve(cve_id: str) -> Optional[Dict[str, Any]]:
    """Detalle de un CVE: todas sus apariciones con link a reporte/device."""
    occurrences: List[Dict[str, Any]] = []
    severity = None
    score = None
    description = None

    for summary in list_reports():
        full = get_report(summary["id"]) or {}
        finding_entry = _first_finding(full)
        # Match en attack_results
        for r in finding_entry.get("attack_results", []):
            if (r.get("cve_id") or "").strip() != cve_id:
                continue
            occurrences.append({
                "report_id": summary["id"],
                "timestamp": summary["timestamp"],
                "device_key": summary["device_key"],
                "device_name": summary["device_name"],
                "target_ip": summary["target_ip"],
                "confirmed": bool(r.get("vuln_found")),
                "severity": r.get("severity"),
                "title": r.get("title"),
                # `repro_cmd` es el nombre actual; los informes ya generados
                # llevan `executed_cmd`, que afirmaba una ejecución no garantizada.
                "repro_cmd": r.get("repro_cmd") or r.get("executed_cmd"),
                "raw_output": (r.get("raw_output") or "")[:2000],
                "interpretation": (r.get("interpretation") or "")[:2000],
            })
            severity = severity or r.get("severity")
        # NVD metadata desde system_cves
        for sc in finding_entry.get("system_cves", []):
            if sc.get("id") == cve_id:
                score = score or sc.get("score")
                description = description or sc.get("description")

    if not occurrences:
        return None

    occurrences.sort(key=lambda o: o["timestamp"] or "", reverse=True)
    kb_hist = _load_kb().get("cve_validation_history", {}).get(cve_id, {})

    return {
        "cve_id": cve_id,
        "severity": severity,
        "score": score,
        "description": description,
        "total_occurrences": len(occurrences),
        "confirmed_occurrences": sum(1 for o in occurrences if o["confirmed"]),
        "occurrences": occurrences,
        "kb_history": {
            "tested_n_times": kb_hist.get("tested_n_times", 0),
            "confirmed_count": kb_hist.get("confirmed_count", 0),
            "first_test": kb_hist.get("first_test"),
            "last_test": kb_hist.get("last_test"),
            "vendors_tested": kb_hist.get("vendors_tested", []),
        },
    }


def global_stats() -> Dict[str, Any]:
    """Resumen para la home: totales y últimos N runs."""
    kb = _load_kb()
    reports = list_reports()
    devices = list_devices()
    cves = list_cves()
    confirmed_cves = sum(1 for c in cves if c["confirmed_occurrences"] > 0)
    return {
        "runs_total": len(reports),
        "devices_total": len(devices),
        "cves_total": len(cves),
        "cves_confirmed_at_least_once": confirmed_cves,
        "vendors_known": list(kb.get("vendor_profiles", {}).keys()),
        "last_5_runs": reports[:5],
    }
