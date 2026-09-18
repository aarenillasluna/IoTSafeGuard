"""Todo lo que lee el MODELO va en inglés; todo lo que lee una PERSONA, en español.

§4.4 de la memoria justifica el inglés del lado del modelo: es el idioma en el
que estos modelos han sido predominantemente entrenados y en el que están
redactadas las guías de *tool use* del proveedor. La frontera no es «el proyecto
es español» sino **quién lee cada cadena**:

  · Superficie del modelo (inglés) — los *prompts* de fase, las descripciones de
    las herramientas y de sus parámetros, los mensajes de guarda, y todo lo que
    las tools CONTESTAN (`instruction`, `note`, `error`, `_hint`, `reason`), que
    es lo que el agente lee para decidir su siguiente paso.
  · Superficie humana (español) — los informes, la memoria, los comentarios del
    código y los mensajes de log del operador.

La parte fácil de acertar es el catálogo, porque se ve de un vistazo. La que se
escapa es la de tiempo de ejecución: un rechazo de la política o el error de una
sonda solo aparecen cuando algo sale mal, y son justo el momento en el que el
idioma importa, porque son la única realimentación con la que el agente puede
corregirse. Por eso aquí se vigilan los dos conjuntos, y no solo el visible.
"""
import re

import pytest

from core import tools as toolbox
from core.agent_guards import build_repetition_warning, build_validation_hint

# Palabras funcionales del español que no existen en inglés. Se buscan como
# palabra completa para que un identificador («para_hint») o un nombre propio no
# produzcan falsos positivos.
_SPANISH_MARKERS = (
    "que", "para", "los", "las", "del", "con", "una", "por", "sin", "como",
    "está", "según", "más", "puerto", "objetivo", "sesión", "hallazgo",
    "severidad", "búsqueda", "comando", "usuario", "contraseña", "fase",
    "devuelve", "ejecuta", "solo", "cada", "este", "esta", "debe", "si",
)
_MARKER_RE = re.compile(
    r"\b(" + "|".join(_SPANISH_MARKERS) + r")\b", re.IGNORECASE)


def _spanish_hits(text: str) -> list:
    if not text:
        return []
    return sorted(set(m.group(0).lower() for m in _MARKER_RE.finditer(text)))


@pytest.fixture(scope="module", autouse=True)
def _registry():
    toolbox.build_registry()


def _iter_schema_descriptions(schema, path=""):
    """Recorre un JSON Schema y produce (ruta, descripción) de cada nivel."""
    if not isinstance(schema, dict):
        return
    if schema.get("description"):
        yield path or "<root>", schema["description"]
    for name, prop in (schema.get("properties") or {}).items():
        yield from _iter_schema_descriptions(prop, f"{path}.{name}" if path else name)
    if isinstance(schema.get("items"), dict):
        yield from _iter_schema_descriptions(schema["items"], f"{path}[]")


def test_tool_descriptions_are_english():
    offenders = []
    for name, tool in sorted(toolbox._REGISTRY.items()):
        hits = _spanish_hits(tool.description)
        if hits:
            offenders.append(f"{name}: {hits}")
    assert not offenders, (
        "Descripciones de herramientas en español. El catálogo es superficie del "
        "modelo y va en inglés (§4.4):\n  " + "\n  ".join(offenders))


def test_parameter_descriptions_are_english():
    offenders = []
    for name, tool in sorted(toolbox._REGISTRY.items()):
        for path, desc in _iter_schema_descriptions(tool.parameters):
            hits = _spanish_hits(desc)
            if hits:
                offenders.append(f"{name}.{path}: {hits}")
    assert not offenders, (
        "Descripciones de parámetros en español:\n  " + "\n  ".join(offenders))


def test_guard_messages_are_english():
    """Se inyectan en el contexto del modelo junto al system prompt."""
    messages = [
        build_validation_hint("probe_ssh", {"ip": "1.2.3.4"}, {"error": "missing arg"}),
        build_repetition_warning("nmap_scan", {}, 3),
        build_repetition_warning("cve_search", {}, 1, reason="cycle", cycle_length=2),
    ]
    for message in messages:
        assert not _spanish_hits(message), f"guard en español: {message[:120]}"


def test_the_reflection_prompt_is_english_but_pins_the_output_language():
    """Traducir el prompt sin fijar el idioma de salida habría cambiado en
    silencio el idioma de los informes de reflexión — el efecto exacto que
    iter_18 documenta y que la directiva existe para evitar."""
    from core.reflection import REFLECTION_PROMPT
    assert "You are a senior reviewer" in REFLECTION_PROMPT
    assert "OUTPUT LANGUAGE" in REFLECTION_PROMPT
    assert "**Spanish**" in REFLECTION_PROMPT


def test_phase_prompts_pin_the_output_language_too():
    """La asimetría de §4.4: razonar en inglés, escribir el informe en español."""
    from core.prompts import get_phase_prompt
    for phase in ("recon", "exploit"):
        prompt = get_phase_prompt(phase)
        assert "<output_language>" in prompt
        assert "Spanish" in prompt


def test_policy_rejections_and_their_alternatives_are_english():
    """El rechazo de la política es lo que MÁS lee el modelo cuando se equivoca:
    es la única realimentación que tiene para corregir el comando. Si llega en
    español, la mitad de la superficie de contención queda fuera de la decisión
    de §4.4 justo en el momento en que más importa."""
    from core.policy_engine import PolicyEngine, PolicyViolation, POLICY_ALTERNATIVES

    engine = PolicyEngine()
    rechazados = [
        "rm -rf /",                      # binario fuera de la allowlist
        "curl `whoami`",                 # patrón prohibido
        "curl http://x | grep token",    # filtrado local
        "echo 'a' | echo 'b' | websocat wss://x",   # tubería de tres tramos
        "curl -x socks5://1.2.3.4:1080 http://y",   # flag no permitido
        "curl -sk 'http://1.2.3.4/a;id'",           # operando con metacaracteres
        "head /etc/shadow",              # truncador con operando de ruta
        "( echo 'x' ) | websocat ws://1.2.3.4",     # subshell sin JSON
    ]
    for comando in rechazados:
        try:
            engine.validate_and_parse(comando)
        except PolicyViolation as pv:
            hits = _spanish_hits(str(pv))
            assert not hits, f"rechazo en español para {comando!r}: {hits} — {pv}"
        else:
            pytest.fail(f"la política debía rechazar {comando!r}")

    for aguja, consejo in POLICY_ALTERNATIVES:
        hits = _spanish_hits(consejo)
        assert not hits, f"alternativa en español para {aguja!r}: {hits}"


def test_tool_results_that_steer_the_agent_are_english():
    """Las tools no solo se describen: CONTESTAN. Sus `instruction`, `note`,
    `error`, `_hint` y `reason` son lo que el agente lee para decidir el turno
    siguiente, y viajan en el mismo contexto que las descripciones."""
    from core.tools import _cve_search, _recommend_probes

    rechazo = _cve_search({"keyword": "router default credentials"})
    assert rechazo["error"] == "generic_keyword_rejected"
    assert not _spanish_hits(rechazo["note"]), rechazo["note"]

    plan = _recommend_probes({"ports": [
        {"port": 23, "proto": "tcp"}, {"port": 1080, "proto": "tcp"},
        {"port": 6668, "proto": "tcp"}, {"port": 6379, "proto": "tcp"},
        {"port": 54321, "proto": "udp"},
    ]})
    assert not _spanish_hits(plan["instruction"]), plan["instruction"]
    for rec in plan["recommendations"] + plan["mandatory_after_nmap"]:
        hits = _spanish_hits(rec.get("reason", ""))
        assert not hits, f"{rec['probe']}: {hits} — {rec.get('reason')}"


def test_probe_errors_are_english():
    """Una sonda que falla devuelve el motivo al modelo, no a una persona."""
    from modules.iot_probes import probe_tcp_raw, probe_udp_raw

    fallos = [
        probe_tcp_raw("127.0.0.1", port=9, payload_hex="zzzz"),
        probe_tcp_raw("127.0.0.1", port=9, proto_hint="protocolo-inventado"),
        probe_udp_raw("127.0.0.1", port=9, payload_hex="zzzz"),
        probe_udp_raw("127.0.0.1", port=9, proto_hint="protocolo-inventado"),
    ]
    for out in fallos:
        error = out.get("error") or ""
        assert error, f"se esperaba un error en {out}"
        assert not _spanish_hits(error), error


def test_the_safety_layer_speaks_to_the_model_in_english():
    """El kill-switch no es solo una parada: le dice al agente qué hacer a
    continuación (guardar informe y cerrar), y eso es superficie del modelo."""
    from core.safety_monitor import SafetyMonitorV2

    monitor = SafetyMonitorV2("10.0.0.5")
    monitor.trigger_kill_switch()
    assert not _spanish_hits(monitor.kill_switch_reason), monitor.kill_switch_reason
