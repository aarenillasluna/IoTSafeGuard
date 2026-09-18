"""Route: descubrimiento de subred via `nmap -sn` (host discovery).

Devuelve la lista de hosts vivos con (ip, mac, hostname, vendor) — el frontend
muestra el resultado y permite al usuario hacer click en cualquiera para
lanzar un audit completo contra esa IP.

Asume que el backend corre con privilegios suficientes para que nmap pueda
hacer ARP requests (mismo trust boundary que el agente: sudo).
"""
from __future__ import annotations

import asyncio
import re
import xml.etree.ElementTree as ET
from typing import List

from fastapi import APIRouter, HTTPException
from loguru import logger
from pydantic import BaseModel, Field, field_validator

router = APIRouter()


def _is_private_network(ip_str: str) -> bool:
    """¿La red pertenece a un rango privado o de enlace local?

    Se comprueba sobre la dirección de red del CIDR. Es una restricción de
    ALCANCE, no de seguridad —quien controla el backend puede editar el código—,
    pero traduce a comportamiento el compromiso que la memoria declara: el
    sistema se limita a la LAN del operador.
    """
    import ipaddress
    try:
        addr = ipaddress.IPv4Address(ip_str)
    except ipaddress.AddressValueError:
        return False
    return addr.is_private or addr.is_link_local or addr.is_loopback


# Prefijo mínimo admitido. Un `/0` o un `/8` lanzarían un barrido de millones
# de hosts, y el alcance del proyecto —declarado en §4.12 y en el compromiso
# ético de la memoria— es la LAN del operador: ni exploración de Internet ni
# escaneo de rangos de terceros. La validación anterior aceptaba `0.0.0.0/0`,
# de modo que la delimitación existía en el texto pero no en el código.
_MIN_PREFIX = 22  # /22 = 1.024 direcciones, holgado para cualquier red doméstica


class SubnetScanPayload(BaseModel):
    cidr: str = Field(..., description="Subred a escanear (ej. 192.168.1.0/24)")
    timeout_seconds: int = Field(default=60, ge=5, le=600)

    @field_validator("cidr")
    @classmethod
    def _validate_cidr(cls, v: str) -> str:
        # CIDR IPv4 — validación estricta para evitar inyección de args.
        m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$", v.strip())
        if not m:
            raise ValueError("cidr debe ser IPv4/prefix (ej. 192.168.1.0/24)")
        ip_str, prefix_str = m.group(1), m.group(2)
        for octet in ip_str.split("."):
            if not (0 <= int(octet) <= 255):
                raise ValueError(f"octeto fuera de rango: {octet}")
        prefix = int(prefix_str)
        if not (0 <= prefix <= 32):
            raise ValueError(f"prefix fuera de rango: {prefix_str}")
        if prefix < _MIN_PREFIX:
            raise ValueError(
                f"prefijo /{prefix} demasiado amplio (mínimo /{_MIN_PREFIX}): "
                "el alcance del sistema es la red local, no rangos masivos"
            )
        if not _is_private_network(ip_str):
            raise ValueError(
                f"{ip_str} no pertenece a un rango privado (RFC 1918 / enlace "
                "local). El sistema solo audita infraestructura propia en LAN"
            )
        return f"{ip_str}/{prefix}"


def _parse_nmap_xml(xml_text: str) -> List[dict]:
    """Extrae hosts vivos del XML de `nmap -sn`."""
    hosts: List[dict] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        logger.warning(f"[scan] nmap XML parse error: {e}")
        return hosts
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = mac = vendor = hostname = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")
        names = host.find("hostnames")
        if names is not None:
            name_el = names.find("hostname")
            if name_el is not None:
                hostname = name_el.get("name")
        if ip:
            hosts.append({
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "hostname": hostname,
            })
    return hosts


@router.post("")
async def scan_subnet(payload: SubnetScanPayload) -> dict:
    """Ejecuta `nmap -sn -oX - <cidr>` con timeout y devuelve los hosts vivos."""
    args = ["nmap", "-sn", "-T4", "-oX", "-", payload.cidr]
    logger.info(f"[scan] {' '.join(args)} (timeout={payload.timeout_seconds}s)")
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=payload.timeout_seconds,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise HTTPException(status_code=504,
                                detail=f"nmap timeout tras {payload.timeout_seconds}s")
        if proc.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"nmap exit={proc.returncode}: {stderr.decode(errors='replace')[:500]}",
            )
        hosts = _parse_nmap_xml(stdout.decode("utf-8", errors="replace"))
        return {"cidr": payload.cidr, "hosts": hosts, "host_count": len(hosts)}
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="nmap no instalado en PATH")
