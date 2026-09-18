"""El cap de alcanzabilidad no puede depender de la FORMA de la evidencia.

Dos defectos gemelos, ambos en la capa determinista que sostiene OM1:

  1. `_REAL_INTERACTION_RE` incluía `"[a-z_]+"\\s*:`, es decir CUALQUIER clave de
     CUALQUIER JSON. Como esa expresión corta-circuita el cap, bastaba con que
     la evidencia arrastrase el dict del propio probe (`{"port": 23, "status":
     "open"}` — metadata de la herramienta, no datos del dispositivo) para que
     un simple «puerto abierto» puntuase CRITICAL.

  2. `_finding_evidence_blob` serializaba lo no-string con `str()`, que produce
     comillas SIMPLES, mientras un JSON ya serializado trae DOBLES. El mismo
     contenido, por tanto, capeaba o no según cómo hubiera llegado.

Juntos convertían la capa anti-inflación en algo que el agente esquivaba sin
proponérselo, con solo pegar la salida cruda de la sonda.
"""
from core.tools import _is_reachability_only, effective_severity


def _f(**kw):
    base = {"severity": "CRITICAL", "confirmed": True, "impact": "ACCESS"}
    base.update(kw)
    return base


# ── 1. Metadata de sonda en JSON no es «interacción real» ───────────────────

def test_probe_metadata_json_does_not_defeat_the_cap():
    finding = _f(raw_output='{"port": 23, "status": "open", "banner": null}\n'
                            'Connection succeeded')
    assert _is_reachability_only(finding) is True
    assert effective_severity(finding) == "LOW"


def test_plain_text_reachability_still_capped():
    finding = _f(raw_output="Connection succeeded to port 23 (open)")
    assert effective_severity(finding) == "LOW"


# ── 2. La forma de `evidence` no cambia el veredicto ────────────────────────

def test_dict_and_json_evidence_agree():
    """Mismo contenido, dos representaciones → misma severidad efectiva."""
    as_dict = _f(severity="HIGH", impact="EXEC",
                 raw_output="nc -zv 1.2.3.4 23 succeeded!",
                 evidence={"note": "solo conecta"})
    as_json = _f(severity="HIGH", impact="EXEC",
                 raw_output="nc -zv 1.2.3.4 23 succeeded!",
                 evidence='{"note": "solo conecta"}')
    assert effective_severity(as_dict) == effective_severity(as_json) == "LOW"


def test_list_evidence_is_serialized_without_crashing():
    finding = _f(raw_output="port open", evidence=["a", {"b": 1}])
    assert effective_severity(finding) == "LOW"


# ── 3. Los datos REALES siguen contando como interacción ────────────────────

def test_extracted_device_data_is_real_interaction():
    """Un JSON con datos del dispositivo (token, ssid) sí es exfiltración."""
    finding = _f(impact="EXFIL",
                 raw_output='{"token": "abc123", "ssid": "casa", "psk": "x"}')
    assert _is_reachability_only(finding) is False
    assert effective_severity(finding) == "CRITICAL"


def test_shell_output_is_real_interaction():
    finding = _f(impact="EXEC", raw_output="uid=0(root) gid=0(root) groups=0(root)")
    assert _is_reachability_only(finding) is False
    assert effective_severity(finding) == "CRITICAL"


def test_http_body_is_real_interaction():
    finding = _f(impact="DISCLOSURE",
                 raw_output="HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>...")
    assert _is_reachability_only(finding) is False
    # DISCLOSURE topa a MEDIUM por política de impacto, no por alcanzabilidad.
    assert effective_severity(finding) == "MEDIUM"


def test_sysdescr_json_from_snmp_counts_as_data():
    finding = _f(impact="DISCLOSURE",
                 raw_output='{"sys_descr": "Linux router 2.6.31", "community": "public"}')
    assert _is_reachability_only(finding) is False
