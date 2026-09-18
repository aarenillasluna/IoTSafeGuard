"""
Discovery probes:
- mDNS / DNS-SD (zeroconf): servicios Bonjour/Avahi filtrados por IP objetivo.
- CoAP (.well-known/core): descubrimiento nativo IoT (RFC 6690).
"""
import asyncio
import socket
import time
from loguru import logger

try:
    from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
    _HAS_ZEROCONF = True
except Exception:
    _HAS_ZEROCONF = False

try:
    import aiocoap
    _HAS_AIOCOAP = True
except Exception:
    _HAS_AIOCOAP = False


# Tipos de servicio comunes en IoT / consumer. Lista agresiva pero acotada.
IOT_SERVICE_TYPES = (
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_workstation._tcp.local.",
    "_googlecast._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_hap._tcp.local.",          # HomeKit
    "_companion-link._tcp.local.",
    "_ipp._tcp.local.",           # Printer IPP
    "_ipps._tcp.local.",
    "_printer._tcp.local.",
    "_pdl-datastream._tcp.local.",
    "_scanner._tcp.local.",
    "_ssh._tcp.local.",
    "_smb._tcp.local.",
    "_afpovertcp._tcp.local.",
    "_hue._tcp.local.",
    "_miio._udp.local.",          # Xiaomi
    "_axis-video._tcp.local.",
    "_dahua._tcp.local.",
    "_dhnap._tcp.local.",
    "_nest-ws._tcp.local.",
    "_sonos._tcp.local.",
)


class _IPFilteredListener(ServiceListener):  # type: ignore[misc]
    def __init__(self, target_ip: str, out: list):
        self.target_ip_bytes = socket.inet_aton(target_ip)
        self.out = out

    def add_service(self, zc, type_, name):
        try:
            info = zc.get_service_info(type_, name, timeout=1500)
        except Exception:
            return
        if not info:
            return
        addrs = info.addresses or []
        if self.target_ip_bytes not in addrs:
            return
        props_raw = info.properties or {}
        props: dict = {}
        for k, v in props_raw.items():
            try:
                key = k.decode(errors="ignore") if isinstance(k, bytes) else str(k)
                val = v.decode(errors="ignore") if isinstance(v, bytes) else (v if v is None else str(v))
                props[key] = val
            except Exception:
                continue
        self.out.append({
            "type": type_,
            "name": name,
            "server": getattr(info, "server", None),
            "port": getattr(info, "port", None),
            "properties": props,
        })

    def update_service(self, *a, **k): pass
    def remove_service(self, *a, **k): pass


def mdns_probe(ip: str, listen_seconds: float = 2.5) -> list[dict]:
    """
    Lanza ServiceBrowser para tipos comunes y filtra por IP.
    Return: lista de dicts con tipo/nombre/puerto/properties.
    """
    if not _HAS_ZEROCONF:
        logger.debug("[mDNS] zeroconf no disponible")
        return []
    results: list[dict] = []
    try:
        zc = Zeroconf()
    except Exception as e:
        logger.warning(f"[mDNS] No se pudo abrir socket multicast: {e}")
        return []
    listener = _IPFilteredListener(ip, results)
    browsers = []
    try:
        for t in IOT_SERVICE_TYPES:
            try:
                browsers.append(ServiceBrowser(zc, t, listener))
            except Exception:
                continue
        time.sleep(listen_seconds)
    finally:
        try:
            zc.close()
        except Exception:
            pass
    if results:
        logger.success(f"[mDNS] {ip} → {len(results)} servicios detectados")
    return results


async def _coap_get(ip: str, path: str, timeout: float) -> tuple[int | None, str | None]:
    try:
        ctx = await aiocoap.Context.create_client_context()
    except Exception as e:
        logger.debug(f"[CoAP] no se pudo crear contexto: {e}")
        return None, None
    try:
        msg = aiocoap.Message(code=aiocoap.GET, uri=f"coap://{ip}{path}")
        try:
            resp = await asyncio.wait_for(ctx.request(msg).response, timeout=timeout)
        except asyncio.TimeoutError:
            return None, None
        code = getattr(resp.code, "name", None) or str(resp.code)
        payload = resp.payload.decode(errors="ignore") if resp.payload else ""
        return code, payload
    except Exception as e:
        logger.debug(f"[CoAP] {ip}{path} error: {e}")
        return None, None
    finally:
        try:
            await ctx.shutdown()
        except Exception:
            pass


def coap_probe(ip: str, timeout: float = 3.0) -> dict | None:
    """
    GET coap://<ip>/.well-known/core + /oic/res (OCF/IoTivity) si aplica.
    """
    if not _HAS_AIOCOAP:
        logger.debug("[CoAP] aiocoap no disponible")
        return None

    async def _run() -> dict | None:
        out: dict = {"well_known_core": None, "oic_res": None}
        code1, body1 = await _coap_get(ip, "/.well-known/core", timeout)
        if body1:
            out["well_known_core"] = body1[:4000]
        code2, body2 = await _coap_get(ip, "/oic/res", timeout)
        if body2:
            out["oic_res"] = body2[:4000]
        if not any(v for v in out.values()):
            return None
        return out

    try:
        return asyncio.run(_run())
    except Exception as e:
        logger.debug(f"[CoAP] run falló: {e}")
        return None
