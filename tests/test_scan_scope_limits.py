"""El alcance declarado en la memoria debe existir también en el código.

`_validate_cidr` comprobaba la FORMA del CIDR y el rango de los octetos, pero
aceptaba `0.0.0.0/0` y cualquier rango público. La memoria (§4.12 y el
compromiso ético) delimita el sistema a la LAN del operador —«no incorpora
escaneo de rangos de terceros»—, así que la restricción vivía solo en el texto.

Es una restricción de ALCANCE, no de seguridad: quien controla el backend puede
editar el código. Pero un trabajo que declara un límite ético debería hacerlo
cumplir por defecto en su propia interfaz.
"""
import pytest
from pydantic import ValidationError

from api.routes.scan import SubnetScanPayload


@pytest.mark.parametrize("cidr", [
    "192.168.1.0/24",
    "10.0.0.0/24",
    "172.30.0.0/24",     # la red del lab Docker
    "192.168.0.0/22",    # el prefijo más amplio admitido
])
def test_local_networks_are_accepted(cidr):
    assert SubnetScanPayload(cidr=cidr).cidr == cidr


@pytest.mark.parametrize("cidr", [
    "0.0.0.0/0",         # Internet entero
    "10.0.0.0/8",        # 16 millones de hosts
    "192.168.0.0/16",
])
def test_sweeping_prefixes_are_rejected(cidr):
    with pytest.raises(ValidationError, match="demasiado amplio"):
        SubnetScanPayload(cidr=cidr)


@pytest.mark.parametrize("cidr", [
    "8.8.8.0/24",        # Google DNS
    "1.1.1.0/24",        # Cloudflare
    "52.94.236.0/24",    # infraestructura de terceros cualquiera
])
def test_public_ranges_are_rejected(cidr):
    with pytest.raises(ValidationError, match="rango privado"):
        SubnetScanPayload(cidr=cidr)


def test_documentation_ranges_are_allowed_because_they_are_not_routable():
    """`203.0.113.0/24` (TEST-NET-3) lo clasifica `ipaddress` como no
    globalmente enrutable, igual que RFC 1918. Se deja pasar a propósito: el
    criterio es «no alcanzar infraestructura de terceros», y estos rangos, por
    definición, no la alcanzan."""
    assert SubnetScanPayload(cidr="203.0.113.0/24").cidr == "203.0.113.0/24"


def test_malformed_input_is_still_rejected():
    with pytest.raises(ValidationError):
        SubnetScanPayload(cidr="192.168.1.0/24; rm -rf /")
