"""Descubrir el mecanismo de login deja de pedirse y pasa a hacerse.

En la tanda del 2026-08-08, `web_login` agotó sus cinco estrategias contra un
router de operador y devolvió `method="all_failed"` con una nota que decía
literalmente «baja el JS principal y busca doLogin/submitForm». La misma
instrucción estaba en el prompt de explotación. El modelo la ignoró en **4 de
las 4** ejecuciones en que se dio la condición, teniendo en la mano un `GET /`
que devolvía 200 con HTML.

El disparador no era el problema: `all_failed` es binario, lo emite código
determinista y llega en el instante exacto. Insistir más no arregla que no se
actúe. Un paso mecánico omitido de forma sistemática no es una decisión del
agente: es código que falta. Mismo razonamiento que la solo-lectura en recon
(§4.5.1) —una regla que solo vive en el prompt no existe—.
"""
import contextlib
import http.server
import socketserver
import threading

import pytest

from modules.interrogator import (
    _parse_login_forms,
    discover_login_mechanism,
    extract_js_endpoints,
)


@contextlib.contextmanager
def serve(pages):
    """Servidor local que devuelve `pages[path]`, o 404."""
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = pages.get(self.path)
            if body is None:
                self.send_response(404); self.end_headers(); return
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a): pass

    with socketserver.TCPServer(("127.0.0.1", 0), H) as srv:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            yield f"http://127.0.0.1:{srv.server_address[1]}"
        finally:
            srv.shutdown()


# ── Extracción de endpoints en JS ──────────────────────────────────────────

@pytest.mark.parametrize("snippet, expected", [
    ('fetch("/cgi-bin/login.cgi")', "/cgi-bin/login.cgi"),
    ('x.open("POST", "/api/v1/auth")', "/api/v1/auth"),
    ('$.post("/goform/setLogin")', "/goform/setLogin"),
    ('axios.get("/status.asp")', "/status.asp"),
    ('new Request("/legacy.php")', "/legacy.php"),
    ('var o = {url: "/data.json"}', "/data.json"),
])
def test_every_common_ajax_idiom_is_recognised(snippet, expected):
    """El patrón anterior solo veía `Ajax.Request`/`new Request` con `.php`."""
    assert expected in extract_js_endpoints(snippet)


@pytest.mark.parametrize("noise", [
    'fetch("data:text/plain,x")', 'href="javascript:void(0)"',
    'a("#anchor")', 'x("mailto:a@b.c")',
])
def test_non_http_references_are_ignored(noise):
    assert extract_js_endpoints(noise) == []


# ── Formularios de login ───────────────────────────────────────────────────

def test_password_field_comes_from_the_type_not_the_name():
    """Firmware de operador visto en campo: `<input name="psd" type="password">`.
    Tomarlo del nombre dejaba el campo sin identificar, que es la mitad inútil
    del hallazgo: sabes dónde enviar pero no qué enviar."""
    html = ('<form action="/cgi-bin/luci" method="post">'
            '<input name="usr"><input name="psd" type="password"></form>')
    form = _parse_login_forms(html)[0]
    assert form["action"] == "/cgi-bin/luci"
    assert form["method"] == "POST"
    assert form["password_field"] == "psd"
    assert form["username_field"] == "usr"


def test_a_search_box_is_not_mistaken_for_a_login():
    html = '<form action="/search"><input name="q"><input name="lang"></form>'
    assert _parse_login_forms(html) == []


# ── Descubrimiento completo ────────────────────────────────────────────────

ROUTER_HTML = (b'<html><head><script src="/js/app.js"></script></head><body>'
               b'<form action="/cgi-bin/luci" method="post">'
               b'<input name="usr"><input name="psd" type="password">'
               b'</form></body></html>')
ROUTER_JS = (b'function doLogin(){ fetch("/cgi-bin/auth.cgi",{method:"POST"}); }'
             b'var api={url:"/api/v1/status"};')


def test_it_maps_a_panel_whose_login_lives_only_in_the_js():
    with serve({"/": ROUTER_HTML, "/js/app.js": ROUTER_JS}) as base:
        d = discover_login_mechanism(base, timeout=5)
    assert d["reachable"] is True
    assert d["login_forms"][0]["action"] == "/cgi-bin/luci"
    assert d["login_forms"][0]["password_field"] == "psd"
    # El endpoint de auth se separa del resto por su nombre.
    assert any("auth.cgi" in e for e in d["login_endpoints"])
    assert any("status" in e for e in d["other_endpoints"])
    assert d["js_files_scanned"]


def test_inline_scripts_count_too():
    html = b'<html><script>fetch("/session/login")</script></html>'
    with serve({"/": html}) as base:
        d = discover_login_mechanism(base, timeout=5)
    assert any("/session/login" in e for e in d["login_endpoints"])


def test_a_panel_with_nothing_to_find_says_so_instead_of_guessing():
    """Un CGI sin JS ni formulario es un resultado legítimo, no un fallo. El
    agente debe poder registrarlo y pasar a otro vector."""
    with serve({"/": b"<html><body>Access denied</body></html>"}) as base:
        d = discover_login_mechanism(base, timeout=5)
    assert d["reachable"] is True
    assert d["login_forms"] == [] and d["login_endpoints"] == []
    assert d["notes"] and "no login form" in d["notes"][0].lower()


def test_an_unreachable_panel_does_not_raise():
    d = discover_login_mechanism("http://127.0.0.1:1", timeout=1)
    assert d["reachable"] is False
    assert d["login_forms"] == []


def test_web_login_attaches_the_discovery_on_all_failed(monkeypatch):
    """El contrato que ve el agente: si no se pudo autenticar, el resultado ya
    trae el mapa en vez de una instrucción que cumplir."""
    import core.tools as toolbox

    monkeypatch.setattr(
        "modules.interrogator.discover_login_mechanism",
        lambda base, timeout=8: {
            "base_url": base, "reachable": True,
            "login_forms": [{"action": "/cgi-bin/luci", "method": "POST",
                             "username_field": "usr", "password_field": "psd",
                             "all_fields": ["psd", "usr"]}],
            "login_endpoints": ["http://x/cgi-bin/auth.cgi"],
            "other_endpoints": [], "js_files_scanned": [], "notes": [],
        })

    s = toolbox.AgentSession(target_ip="127.0.0.1")
    toolbox.bind_session(s)
    try:
        # Puerto cerrado → todas las estrategias fallan → rama all_failed.
        out = toolbox._web_login({"ip": "127.0.0.1", "port": 1, "timeout": 1})
    finally:
        toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))

    assert out["method"] == "all_failed"
    assert out["login_discovery"]["login_forms"][0]["password_field"] == "psd"
    assert "login_discovery" in out["note"]


# ── La extracción determinista no es la única voz ──────────────────────────
#
# El paso que el modelo omitía era BAJAR la página. Que fallara
# INTERPRETÁNDOLA no está demostrado —nunca llegó a ese punto— y leer un
# formulario es de lo que un LLM hace bien. El riesgo real de automatizar
# también la interpretación es que la regex falle EN SILENCIO y el modelo se
# fíe del negativo, descartando un login que él habría visto.

def test_evidence_is_attached_even_when_extraction_succeeds():
    with serve({"/": ROUTER_HTML, "/js/app.js": ROUTER_JS}) as base:
        d = discover_login_mechanism(base, timeout=5)
    assert d["login_forms"], "el caso fácil debe seguir resolviéndose solo"
    assert "<form" in d["html_evidence"], "…pero con la evidencia para revisarlo"


def test_a_form_the_regex_cannot_parse_still_reaches_the_model():
    """Atributos sin comillas: la regex de `action` no casa, pero el modelo
    tiene delante el formulario y puede leerlo."""
    weird = (b"<html><body><form action=/cgi-bin/login method=post>"
             b"<input name=user><input name=pw type=password>"
             b"</form></body></html>")
    with serve({"/": weird}) as base:
        d = discover_login_mechanism(base, timeout=5)
    assert "/cgi-bin/login" in d["html_evidence"]
    assert d["notes"] and "not a verdict" in d["notes"][0].lower()


def test_the_negative_is_offered_as_a_hint_not_a_conclusion():
    with serve({"/": b"<html><body>Access denied</body></html>"}) as base:
        d = discover_login_mechanism(base, timeout=5)
    note = d["notes"][0].lower()
    assert "hint" in note and "not a verdict" in note
    assert "read `html_evidence`" in note or "html_evidence" in note


def test_evidence_prefers_forms_and_scripts_over_page_head():
    """En un panel real la cabecera son kilobytes de CSS que no dicen nada."""
    noisy = (b"<html><head>" + b"<style>" + b"x" * 5000 + b"</style></head>"
             b"<body><form action='/auth'><input name='p' type='password'>"
             b"</form></body></html>")
    with serve({"/": noisy}) as base:
        d = discover_login_mechanism(base, timeout=5)
    assert "/auth" in d["html_evidence"]
    assert "xxxxx" not in d["html_evidence"]


def test_evidence_is_bounded():
    huge = (b"<html><body><form action='/a'><input type='password' name='p'>"
            + b"<!-- " + b"y" * 20000 + b" -->" + b"</form></body></html>")
    with serve({"/": huge}) as base:
        d = discover_login_mechanism(base, timeout=5)
    assert len(d["html_evidence"]) < 3200
    assert "recortado" in d["html_evidence"]
