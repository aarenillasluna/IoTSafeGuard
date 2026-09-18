"""Routes: devices agrupados por identidad canónica (vendor + model + MAC).

NUNCA por IP — el mismo 192.168.1.1 puede aparecer en redes distintas. La
agrupación se hace en `aggregator.list_devices()` con el composite key.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from api.services import aggregator

router = APIRouter()


@router.get("")
def list_devices() -> dict:
    return {"devices": aggregator.list_devices()}


@router.get("/{device_key:path}")
def get_device(device_key: str) -> dict:
    detail = aggregator.get_device(device_key)
    if not detail:
        raise HTTPException(status_code=404, detail=f"device {device_key!r} not found")
    return detail
