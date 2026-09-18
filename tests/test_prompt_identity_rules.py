"""Regresión: las reglas de identidad del prompt de recon deben sobrevivir a
ediciones (incluida la traducción a inglés con estructura XML de iter_18).

En particular, la regla de **granularidad del CVE** (no buscar CVE de un modelo
concreto cuando solo se conoce el fabricante por OUI) — introducida tras una
auditoría real contra un Amazon Echo donde el agente buscó CVE de "Fire TV" por la
OUI Amazon y registró 3 candidatos inaplicables.
"""
from core.prompts import get_phase_prompt, reset_cache


def setup_function():
    reset_cache()


def test_recon_prompt_has_cve_granularity_rule():
    p = get_phase_prompt("recon").lower()
    # No inventar línea de producto a partir de la OUI…
    assert "granularity" in p
    assert "model = none" in p or "confirmed model" in p
    # …y debe quedar el escarmiento concreto del Echo/Fire TV documentado.
    assert "fire tv" in p and "echo" in p


def test_recon_prompt_still_prioritises_oui_over_osmatch():
    p = get_phase_prompt("recon").lower()
    assert "os_match" in p
    assert "oui" in p


def test_phase_prompts_are_xml_structured():
    """La estructura XML es el contrato de forma del prompt: secciones etiquetadas
    y cerradas. Un prompt que se degrade a prosa suelta rompe este test."""
    for phase, required_tags in (
        ("recon", ("role", "phase_objectives", "device_identity",
                   "mandatory_workflow", "cve_search_rules", "response_format")),
        ("exploit", ("role", "phase_objectives", "cve_validation",
                     "cve_endpoint_table", "reporting", "closing")),
    ):
        p = get_phase_prompt(phase)
        for tag in required_tags:
            assert f"<{tag}>" in p, f"falta <{tag}> en el prompt de {phase}"
            assert f"</{tag}>" in p, f"falta el cierre </{tag}> en {phase}"


def test_phase_prompts_pin_report_language_to_spanish():
    """El prompt es inglés pero el informe se entrega en español: si se pierde la
    directiva, los artefactos del Capítulo 5 cambiarían de idioma sin avisar."""
    for phase in ("recon", "exploit"):
        p = get_phase_prompt(phase)
        assert "<output_language>" in p
        assert "Spanish" in p
        # raw_output nunca se traduce: es la prueba forense.
        assert "raw_output" in p


def test_recon_prompt_documents_the_deterministic_readonly_guard():
    """La restricción de solo lectura en recon ya no es una promesa de texto: la
    aplica el tooling. El prompt debe decirlo para que el agente no la descubra
    a base de errores."""
    p = get_phase_prompt("recon")
    assert "READ-ONLY" in p
    assert "transition_phase" in p


def test_recon_prompt_covers_tcp_vendor_protocols():
    """Tuya (6668) y ESPHome (6053) son TCP: el prompt los nombra y ahora existe
    la herramienta para hablarlos."""
    p = get_phase_prompt("recon")
    assert "probe_tcp" in p
    assert "6668" in p and "6053" in p
