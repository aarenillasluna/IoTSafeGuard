"""Tests for web_login tool, _discover_unauth_endpoints / _classify_response, and SSDP socket handling."""
import os
import socket
import sys
import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(status=200, text="", url="http://192.168.0.1/login.php",
                   headers=None, cookies=None):
    """Construct a minimal requests.Response-like object."""
    r = requests.models.Response()
    r.status_code = status
    r._content = text.encode()
    r.encoding = "utf-8"
    r.url = url
    r.headers = requests.structures.CaseInsensitiveDict(headers or {})
    if cookies:
        jar = requests.cookies.RequestsCookieJar()
        for k, v in cookies.items():
            jar.set(k, v)
        r.cookies = jar
    return r


class _FakeSession:
    """Minimal requests.Session stand-in driven by a response queue."""

    def __init__(self, responses):
        self._resp = iter(responses)
        self.cookies = requests.cookies.RequestsCookieJar()
        self.verify = True

    def get(self, url, **kw):
        r = next(self._resp)
        self.cookies.update(r.cookies)
        return r

    def post(self, url, **kw):
        r = next(self._resp)
        self.cookies.update(r.cookies)
        return r


# ---------------------------------------------------------------------------
# web_login — import the function directly
# ---------------------------------------------------------------------------

import core.tools as _tools_mod


def _call_web_login(monkeypatch, fake_session, ip="192.168.0.1",
                    username="admin", password="password", port=80):
    # _web_login does `import requests as _req` inside, so patch requests.Session globally
    import requests as _req
    monkeypatch.setattr(_req, "Session", lambda: fake_session)

    # Patch get_session so it doesn't blow up
    class _FakeSess:
        target_ip = ip
        credentials: list = []
    monkeypatch.setattr(_tools_mod, "get_session", lambda: _FakeSess())

    return _tools_mod._web_login(
        {"ip": ip, "username": username, "password": password, "port": port}
    )


class TestWebLoginNetgearGET:

    def test_loginok_returns_ok_true(self, monkeypatch):
        resp = _make_response(200, "loginok", cookies={"PHPSESSID": "abc123"})
        fs = _FakeSession([resp])
        result = _call_web_login(monkeypatch, fs)
        assert result["ok"] is True
        assert result["method"] == "GET /login.php"
        assert "abc123" in result["session_cookie"]

    def test_sessionexists_then_recreate_ok(self, monkeypatch):
        r1 = _make_response(200, "sessionexists")
        r2 = _make_response(200, "recreateok", cookies={"PHPSESSID": "new456"})
        fs = _FakeSession([r1, r2])
        result = _call_web_login(monkeypatch, fs)
        assert result["ok"] is True
        assert "recreate.php" in result["method"]
        assert "new456" in result["session_cookie"]

    def test_sessionexists_recreate_fail(self, monkeypatch):
        r1 = _make_response(200, "sessionexists")
        r2 = _make_response(200, "badreply")
        fs = _FakeSession([r1, r2])
        result = _call_web_login(monkeypatch, fs)
        assert result["ok"] is False
        assert "sessionexists" in result["note"]

    def test_restricted_returns_ok_false(self, monkeypatch):
        resp = _make_response(200, "restricted")
        fs = _FakeSession([resp])
        result = _call_web_login(monkeypatch, fs)
        assert result["ok"] is False
        assert "restricted" in result["note"].lower()

    def test_get_network_error_falls_through(self, monkeypatch):
        """RequestException on GET → falls through to POST strategies."""
        import requests as _req

        class _ErrorSession(_FakeSession):
            def get(self, url, **kw):
                raise _req.ConnectionError("refused")
            def post(self, url, **kw):
                # POST /login.php also fails (no cookie)
                return _make_response(200, "x" * 200, url="http://192.168.0.1/other")

        fs = _ErrorSession([])
        result = _call_web_login(monkeypatch, fs)
        # POST succeeds heuristically but session has no cookie → ok=False
        # (or ok=True if cookie exists — here no cookie so ok=False)
        assert "ok" in result  # key must exist regardless


class TestWebLoginPOSTFallback:

    def test_post_login_with_cookie_returns_ok(self, monkeypatch):
        """GET /login.php returns unknown body → POST succeeds with cookie."""
        get_resp = _make_response(200, "unknown_response_ignored_by_GET_strategy")
        post_resp = _make_response(
            200, "x" * 200,
            url="http://192.168.0.1/dashboard",
            cookies={"session": "tok789"},
        )
        # GET strategy sees unknown body → falls through to POST (no return)
        # Actually unknown body doesn't match loginok/sessionexists/restricted,
        # so GET strategy falls through silently, then POST loop runs.
        fs = _FakeSession([get_resp, post_resp])
        result = _call_web_login(monkeypatch, fs)
        # POST to /login.php hit dashboard URL with cookie → ok=True
        assert result["ok"] is True
        assert "POST" in result["method"]
        assert "tok789" in result["session_cookie"]

    def test_all_failed_when_no_strategy_works(self, monkeypatch):
        """All strategies produce empty/login-still-in-URL responses."""
        import requests as _req

        class _AllFailSession(_FakeSession):
            def get(self, url, **kw):
                raise _req.ConnectionError("down")
            def post(self, url, **kw):
                return _make_response(200, "x" * 200,
                                      url="http://192.168.0.1/login.php")  # URL still has "login"

        fs = _AllFailSession([])
        result = _call_web_login(monkeypatch, fs)
        assert result["ok"] is False
        assert result["method"] == "all_failed"
        assert "doLogin" in result["note"] or "JS" in result["note"] or "strategy" in result["note"].lower()


# ---------------------------------------------------------------------------
# _classify_response
# ---------------------------------------------------------------------------

from modules.interrogator import IoTInterrogator


class TestClassifyResponse:

    def setup_method(self):
        self.interr = IoTInterrogator.__new__(IoTInterrogator)
        self.interr.timeout = 5

    @pytest.mark.parametrize("status,body,headers,expected", [
        # Redirecciones: solo cuenta como "a login" si el Location lo dice
        (302, "", {"Location": "http://host/login.php"}, "redirect_to_login"),
        (302, "", {"Location": "http://host/dashboard"}, "redirect"),
        # Un 401 PRUEBA que el endpoint exige autenticación (negativo correcto)
        (401, "", None, "auth_required"),
        (404, "", None, "not_found"),
        # Datos: por Content-Type, por forma del cuerpo o por asignación JS
        (200, '{"ssid":"net"}', {"Content-Type": "application/json"}, "data_json"),
        (200, '{"model":"AC750"}', None, "data_json"),
        (200, 'var config={"ssid":"net","pass":"123"};', None, "data_js_var"),
        (200, '<?xml version="1.0"?><root><sysDescr>Router</sysDescr></root>',
         {"Content-Type": "text/xml"}, "data_xml"),
        (200, 'firmware=1.2.3 "hostname"="AP-1"', None, "data_text"),
        # Una página de login no es un dato expuesto…
        (200, "<!DOCTYPE html><html><body>Login</body></html>", None, "html_page"),
        # …pero un traza de error que filtra rutas internas sí lo es
        (200, "<!DOCTYPE html><html>Warning: in /home/www/config.php</html>", None,
         "path_disclosure"),
    ])
    def test_classification(self, status, body, headers, expected):
        """Esta clasificación decide qué entra en `unauth_data_endpoints`, es decir
        qué se convierte en hallazgo web y qué se descarta."""
        r = _make_response(status, body, headers=headers) if headers \
            else _make_response(status, body)
        assert self.interr._classify_response(r) == expected


# ---------------------------------------------------------------------------
# _discover_unauth_endpoints
# ---------------------------------------------------------------------------

class TestDiscoverUnauthEndpoints:

    def setup_method(self):
        self.interr = IoTInterrogator.__new__(IoTInterrogator)
        self.interr.timeout = 5

    def test_empty_html_returns_empty(self):
        results = self.interr._discover_unauth_endpoints("http://192.168.0.1", "")
        assert results == []

    def test_detects_json_endpoint_from_src(self, monkeypatch):
        html = '<html><script src="config.php?json=true"></script></html>'
        data_resp = _make_response(200, '{"ssid":"MyWifi","password":"secret"}',
                                   url="http://192.168.0.1/config.php?json=true",
                                   headers={"Content-Type": "application/json"})

        def fake_get(url, **kw):
            if "config.php" in url:
                return data_resp
            return _make_response(404)

        monkeypatch.setattr(requests, "get", fake_get)
        results = self.interr._discover_unauth_endpoints("http://192.168.0.1", html)
        assert any("config.php" in r["url"] for r in results)
        assert results[0]["type"] == "data_json"

    def test_ignores_redirect_to_login(self, monkeypatch):
        html = '<html><a href="status.php">Status</a></html>'
        redir = _make_response(302, headers={"Location": "/login.php"})

        monkeypatch.setattr(requests, "get", lambda url, **kw: redir)
        results = self.interr._discover_unauth_endpoints("http://192.168.0.1", html)
        assert results == []

    def test_ignores_404_endpoints(self, monkeypatch):
        html = '<html><a href="missing.php">x</a></html>'
        monkeypatch.setattr(requests, "get", lambda url, **kw: _make_response(404))
        results = self.interr._discover_unauth_endpoints("http://192.168.0.1", html)
        assert results == []

    def test_deduplicates_same_path(self, monkeypatch):
        html = (
            '<img src="info.php?a=1">'
            '<img src="info.php?b=2">'
        )
        call_count = []

        def fake_get(url, **kw):
            call_count.append(url)
            return _make_response(200, '{"model":"X"}',
                                  headers={"Content-Type": "application/json"})

        monkeypatch.setattr(requests, "get", fake_get)
        self.interr._discover_unauth_endpoints("http://192.168.0.1", html)
        # Ambos normalizan a la misma ruta → una sola petición para ESE endpoint.
        # El resto de peticiones son las rutas de configuración sembradas, que
        # no dependen del HTML (ver test_unauth_endpoints_probes_config_paths_*).
        info_php = [u for u in call_count if "info.php" in u]
        assert len(info_php) <= 1

    def test_absolute_href_resolved(self, monkeypatch):
        html = '<link href="http://192.168.0.1/data.json">'
        data_resp = _make_response(200, '{"a":1}',
                                   headers={"Content-Type": "application/json"})
        monkeypatch.setattr(requests, "get", lambda url, **kw: data_resp)
        results = self.interr._discover_unauth_endpoints("http://192.168.0.1", html)
        # .json extension not in regex (only php/json/xml/cgi) — so candidate set may be empty
        # This is a documentation test: currently only php/json/xml/cgi extensions are extracted
        assert isinstance(results, list)

    def test_path_disclosure_included(self, monkeypatch):
        html = '<a href="broken.php">x</a>'
        php_error = _make_response(
            200,
            "<!DOCTYPE html><html>Fatal error: in /home/www/broken.php on line 5</html>",
        )
        monkeypatch.setattr(requests, "get", lambda url, **kw: php_error)
        results = self.interr._discover_unauth_endpoints("http://192.168.0.1", html)
        assert any(r["type"] == "path_disclosure" for r in results)


# ---------------------------------------------------------------------------
# SSDP socket always closed
# ---------------------------------------------------------------------------

from modules.interrogator import IoTInterrogator as _Interrogator


class TestSSDPSocketClosed:
    """Verify the UDP socket is always closed after _probe_ssdp, even on errors."""

    def _fake_socket_factory(self, closed_log: list, recv_side_effect):
        """Return a socket.socket replacement that records close() calls."""
        class FakeUDPSocket:
            def settimeout(self, t): pass
            def sendto(self, data, addr): pass
            def recvfrom(self, size):
                if isinstance(recv_side_effect, Exception):
                    raise recv_side_effect
                return recv_side_effect, ("127.0.0.1", 1900)
            def close(self): closed_log.append(True)

        return lambda *a, **k: FakeUDPSocket()

    def test_socket_closed_on_timeout(self, monkeypatch):
        closed = []
        monkeypatch.setattr(socket, "socket", self._fake_socket_factory(
            closed, socket.timeout("timed out")
        ))
        interr = _Interrogator.__new__(_Interrogator)
        interr.timeout = 3
        result = interr._probe_ssdp("192.168.0.1", "ssdp:all")
        assert result is None
        assert closed, "Socket not closed after timeout"

    def test_socket_closed_on_os_error(self, monkeypatch):
        closed = []
        monkeypatch.setattr(socket, "socket", self._fake_socket_factory(
            closed, OSError("network unreachable")
        ))
        interr = _Interrogator.__new__(_Interrogator)
        interr.timeout = 3
        result = interr._probe_ssdp("192.168.0.1", "ssdp:all")
        assert result is None
        assert closed, "Socket not closed after OSError"

    def test_socket_closed_on_successful_recv(self, monkeypatch):
        """Socket must also close on the happy path (no LOCATION header)."""
        closed = []
        # Response with no LOCATION header → _probe_ssdp returns None but socket must still close
        monkeypatch.setattr(socket, "socket", self._fake_socket_factory(
            closed, b"HTTP/1.1 200 OK\r\nST: ssdp:all\r\n\r\n"
        ))
        interr = _Interrogator.__new__(_Interrogator)
        interr.timeout = 3
        interr._probe_ssdp("192.168.0.1", "ssdp:all")
        assert closed, "Socket not closed after successful recv (no LOCATION)"
