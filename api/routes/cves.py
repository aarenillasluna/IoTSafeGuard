"""Routes: buscador de CVEs a lo largo de todos los runs.

Cada CVE incluye:
  - `total_occurrences`        — veces que apareció en algún reporte
  - `confirmed_occurrences`    — veces que fue confirmado (vuln_found=true)
  - `devices_seen`             — nombres canónicos de devices donde apareció
  - `kb_*`                     — contadores acumulados del KB global

Filtrado client-side (la lista no es enorme). Si crece, añadir ?q= en backend.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from api.services import aggregator

router = APIRouter()


@router.get("")
def list_cves() -> dict:
    return {"cves": aggregator.list_cves()}


@router.get("/{cve_id}")
def get_cve(cve_id: str) -> dict:
    detail = aggregator.get_cve(cve_id)
    if not detail:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} no visto en histórico")
    return detail
