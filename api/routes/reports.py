"""Routes: listado y detalle de reportes generados por el agente."""
from __future__ import annotations

import os
import re

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from api.services import aggregator

router = APIRouter()

# `report_id` compone una ruta de fichero. Se valida contra la forma que genera
# el reporter (timestamp) en vez de confiar en que el prefijo `audit_report_` y
# la extensión acoten lo que se puede pedir: el resto de la API valida IP, CIDR
# y modelo con este mismo criterio, y esta ruta era la excepción.
_REPORT_ID_RE = re.compile(r"^\d{8}_\d{6}(_\d+)?$")


def _check_report_id(report_id: str) -> str:
    if not _REPORT_ID_RE.match(report_id or ""):
        raise HTTPException(status_code=400,
                            detail=f"report_id con formato inválido: {report_id!r}")
    return report_id


@router.get("")
def list_reports() -> dict:
    """Lista todos los reportes con metadata + risk summary."""
    return {"reports": aggregator.list_reports()}


@router.get("/stats")
def stats() -> dict:
    """Resumen global para la home (totales + últimos runs)."""
    return aggregator.global_stats()


@router.get("/{report_id}")
def get_report(report_id: str) -> dict:
    report = aggregator.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"report {report_id} not found")
    return report


@router.get("/{report_id}/html", response_class=FileResponse)
def get_report_html(report_id: str) -> FileResponse:
    """Sirve el HTML auto-contenido que ya genera el reporter — para embeber en iframe."""
    report_id = _check_report_id(report_id)
    html_path = os.path.join(aggregator.REPORTS_DIR, f"audit_report_{report_id}.html")
    if not os.path.exists(html_path):
        raise HTTPException(status_code=404, detail="report HTML missing")
    return FileResponse(html_path, media_type="text/html")


@router.get("/{report_id}/sarif", response_class=FileResponse)
def get_report_sarif(report_id: str) -> FileResponse:
    report_id = _check_report_id(report_id)
    sarif_path = os.path.join(aggregator.REPORTS_DIR, f"audit_report_{report_id}.sarif")
    if not os.path.exists(sarif_path):
        raise HTTPException(status_code=404, detail="SARIF missing")
    return FileResponse(sarif_path, media_type="application/json",
                        filename=f"audit_report_{report_id}.sarif")
