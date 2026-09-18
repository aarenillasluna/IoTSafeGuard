"""
SNMP v1/v2c probe — sysDescr.0 / sysObjectID.0 / sysName.0.

Fuente determinista de fabricante y modelo cuando el dispositivo expone SNMP
con community por defecto. Usa snmpget del sistema (net-snmp) como primer
intento; fallback a pysnmp v1arch asyncio si no está disponible.
"""
import shutil
import subprocess
from loguru import logger

COMMUNITIES = ("public", "private", "cisco", "admin", "router", "default")

# OIDs estándar y de fabricante comunes
OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
}

# OID → prefijo de fabricante (enterprises subtree 1.3.6.1.4.1.<X>)
ENTERPRISE_VENDORS = {
    "1.3.6.1.4.1.9.": "Cisco",
    "1.3.6.1.4.1.171.": "D-Link",
    "1.3.6.1.4.1.11.": "HP",
    "1.3.6.1.4.1.8072.": "Net-SNMP",
    "1.3.6.1.4.1.2636.": "Juniper",
    "1.3.6.1.4.1.14988.": "MikroTik",
    "1.3.6.1.4.1.4526.": "Netgear",
    "1.3.6.1.4.1.11863.": "TP-Link",
    "1.3.6.1.4.1.41112.": "Ubiquiti",
    "1.3.6.1.4.1.674.": "Dell",
    "1.3.6.1.4.1.311.": "Microsoft",
    "1.3.6.1.4.1.2021.": "UC Davis (linux)",
}


def _vendor_from_oid(oid_value: str) -> str | None:
    for prefix, vendor in ENTERPRISE_VENDORS.items():
        if oid_value.startswith(prefix):
            return vendor
    return None


def _snmpget_cli(ip: str, community: str, oid: str, timeout: float = 2.0) -> str | None:
    bin_path = shutil.which("snmpget")
    if not bin_path:
        return None
    try:
        proc = subprocess.run(
            [
                bin_path, "-v", "2c", "-c", community,
                "-t", str(int(timeout)), "-r", "0",
                "-Oqv",  # quick, value only
                ip, oid,
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 1,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0:
        return None
    out = (proc.stdout or "").strip().strip('"')
    if not out or "No Such" in out or "Timeout" in out:
        return None
    return out


def _snmpget_pysnmp(ip: str, community: str, oid: str, timeout: float = 2.0) -> str | None:
    """Fallback puro-Python si snmpget no está disponible."""
    try:
        import asyncio
        from pysnmp.hlapi.v1arch.asyncio import (
            SnmpDispatcher, CommunityData, UdpTransportTarget,
            ObjectType, ObjectIdentity, get_cmd,
        )
    except Exception:
        return None

    async def _run():
        snmp = SnmpDispatcher()
        try:
            target = await UdpTransportTarget.create((ip, 161), timeout=timeout, retries=0)
            err_indication, err_status, err_index, var_binds = await get_cmd(
                snmp,
                CommunityData(community, mpModel=1),
                target,
                ObjectType(ObjectIdentity(oid)),
            )
        finally:
            snmp.close_dispatcher()
        if err_indication or err_status:
            return None
        for _oid, val in var_binds:
            s = val.prettyPrint()
            if s and "No Such" not in s:
                return s
        return None

    try:
        return asyncio.run(_run())
    except Exception as e:
        logger.debug(f"[SNMP] pysnmp error {ip} {community} {oid}: {e}")
        return None


def _query(ip: str, community: str, oid: str, timeout: float = 2.0) -> str | None:
    res = _snmpget_cli(ip, community, oid, timeout=timeout)
    if res is not None:
        return res
    return _snmpget_pysnmp(ip, community, oid, timeout=timeout)


def snmp_probe(ip: str, timeout: float = 2.0,
               communities: list | tuple | None = None) -> dict | None:
    """
    Intenta SNMP v2c con lista de communities; primer match gana.
    Devuelve dict con sysDescr/sysObjectID/sysName/vendor_guess o None.

    Args:
      ip: target.
      timeout: per-query timeout en segundos.
      communities: lista personalizada de community strings. Si None, usa
        la lista por defecto (`COMMUNITIES`). Útil para targets que tienen
        community no estándar conocida (ej: "cusadmin" en routers Comcast).
    """
    candidates = list(communities) if communities else list(COMMUNITIES)
    for community in candidates:
        desc = _query(ip, community, OIDS["sysDescr"], timeout=timeout)
        if not desc:
            continue
        logger.success(f"[SNMP] {ip} community='{community}' sysDescr={desc[:120]}")
        obj_id = _query(ip, community, OIDS["sysObjectID"], timeout=timeout)
        sys_name = _query(ip, community, OIDS["sysName"], timeout=timeout)
        return {
            "community": community,
            "sys_descr": desc,
            "sys_object_id": obj_id,
            "sys_name": sys_name,
            "vendor_guess": _vendor_from_oid(obj_id or ""),
        }
    logger.debug(f"[SNMP] {ip} sin community por defecto")
    return None
