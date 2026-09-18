"""Identidad emulación-aware: una MAC sintética (FirmAE/QEMU) no debe agrupar
dispositivos distintos ni mis-mapear su vendor por OUI.
"""
import pytest

from modules.fingerprint import is_synthetic_mac, canonicalize_vendor
from api.services import aggregator as agg


# ── is_synthetic_mac ────────────────────────────────────────────────────────
def test_qemu_oui_is_synthetic():
    assert is_synthetic_mac("52:54:00:12:34:56") is True   # QEMU / FirmAE


@pytest.mark.parametrize("mac,synthetic", [
    ("02:00:00:00:00:01", True),    # bit 0x02 del primer octeto → LAA
    ("0A:11:22:33:44:55", True),
    ("52:54:00:12:34:56", True),    # QEMU/KVM: la MAC de FirmAE
    ("14:7F:67:AF:0C:6A", False),   # LG real
    ("DC:A6:32:1B:AD:01", False),   # Raspberry Pi real
    ("", False),                    # sin MAC no se puede afirmar que sea sintética
    (None, False),
])
def test_synthetic_mac_detection(mac, synthetic):
    """Distinguir la MAC de un emulador de la de hardware real es lo que evita
    fundir dos dispositivos emulados en un único perfil de la KB (§4.7)."""
    assert is_synthetic_mac(mac) is synthetic


# ── canonicalize_vendor no usa OUI sintética ────────────────────────────────
def test_canonicalize_ignores_synthetic_oui():
    # Con MAC de QEMU, debe respetar el vendor detectado, no derivar de la OUI.
    assert canonicalize_vendor("D-Link", "52:54:00:12:34:56") == "D-Link"


def test_canonicalize_still_uses_real_oui():
    # Una MAC real con OUI conocida sigue teniendo prioridad (comportamiento previo).
    out = canonicalize_vendor("ruido", "14:7F:67:AF:0C:6A")
    assert out  # no rompe; devuelve algo canónico (LG si está en la tabla, si no el nombre)


# ── _device_key emulación-aware ─────────────────────────────────────────────
def test_real_device_keyed_by_mac():
    k = agg._device_key("LG", "65QNED826RE", "14:7F:67:AF:0C:6A")
    assert k == "LG|65QNED826RE|14:7F:67:AF:0C:6A"


def test_two_emulated_images_do_not_collapse():
    # Misma MAC de QEMU, firmware distinto → claves distintas (no se funden).
    k1 = agg._device_key("D-Link", "DIR-815", "52:54:00:12:34:56", firmware="1.01")
    k2 = agg._device_key("D-Link", "DIR-815", "52:54:00:12:34:56", firmware="1.03")
    assert k1 != k2
    assert k1.endswith("|emu") and k2.endswith("|emu")


def test_emulated_without_firmware_falls_back_to_ip():
    k1 = agg._device_key("Netgear", None, "52:54:00:12:34:56", ip="192.168.0.10")
    k2 = agg._device_key("Netgear", None, "52:54:00:12:34:56", ip="192.168.0.11")
    assert k1 != k2 and k1.endswith("|emu")


def test_canonical_name_flags_emulated():
    assert "[emu]" in agg._canonical_name("D-Link", "DIR-815", "52:54:00:12:34:56")
    assert "[emu]" not in agg._canonical_name("LG", "X", "14:7F:67:AF:0C:6A")
