"""Cliente NVD (`modules/cve_api.py`) — la ruta CPE que sostiene OM1.

Este módulo estaba al 32 % de cobertura pese a contener la pieza en la que se apoya
la reproducibilidad del pipeline de CVE: la consulta por **`virtualMatchString`**,
que hace que el mismo escaneo produzca siempre el mismo conjunto de candidatos
(§4.6.2). Aquí se cubren las cuatro capas del cliente sin tocar la red:

  1. Normalización de CPE 2.2/2.3 → cadena de *match* (lógica pura, determinista).
  2. Consulta por CPE: parámetro exacto enviado y tratamiento del resultado vacío.
  3. Transporte: reintentos con *backoff*, `Retry-After`, y qué códigos NO se
     reintentan (un 404 es respuesta esperada, no un fallo que merezca 5 intentos).
  4. Cachés de dos niveles (memoria y disco) y el orden de estrategias, que es lo
     que garantiza que la vía determinista se use ANTES que la de palabras clave.
"""
import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import modules.cve_api as cve_api
from modules.cve_api import NVDCVEClient


def _client():
    """Cliente sin __init__: las pruebas de lógica pura no necesitan estado."""
    return NVDCVEClient.__new__(NVDCVEClient)


@pytest.fixture
def client(monkeypatch, tmp_path):
    """Cliente real con la red, las esperas y las cachés neutralizadas."""
    monkeypatch.setattr(cve_api, "_DISK_CACHE_PATH", str(tmp_path / "nvd_cache.json"))
    NVDCVEClient._RESULT_CACHE.clear()
    c = NVDCVEClient(api_key=None)
    monkeypatch.setattr(c, "_sleep_rate_limit", lambda: None)
    monkeypatch.setattr(cve_api.time, "sleep", lambda *_: None)
    return c


class _Resp:
    """Respuesta HTTP mínima con la interfaz que usa `_make_request`."""

    def __init__(self, status=200, payload=None, headers=None, bad_json=False):
        self.status_code = status
        self._payload = payload if payload is not None else {"totalResults": 0}
        self.headers = headers or {}
        self._bad_json = bad_json

    def json(self):
        if self._bad_json:
            raise ValueError("no es JSON")
        return self._payload


def _nvd_payload(*cve_ids, score=9.8):
    """Respuesta NVD con la forma real que espera `_parse_nvd_response`."""
    return {
        "totalResults": len(cve_ids),
        "vulnerabilities": [
            {"cve": {
                "id": cid,
                "descriptions": [{"lang": "en", "value": f"desc de {cid}"}],
                "metrics": {"cvssMetricV31": [
                    {"cvssData": {"baseScore": score, "baseSeverity": "CRITICAL"}}]},
            }} for cid in cve_ids
        ],
    }


# --------------------------------------------------- 1) normalización de marca

class TestExtractBrandClean:
    """Normalización mínima: lowercase + trim. La selección del término
    distintivo ocurre aguas arriba vía LLM (plan_nvd_queries)."""

    @pytest.mark.parametrize("raw,expected", [
        ("D-Link DIR-815", "d-link dir-815"),      # lowercase
        ("Google Chromecast", "google chromecast"),  # preserva multipalabra
        ("linux/webOS", "linux/webos"),              # preserva la barra
        ("  openwrt  ", "openwrt"),                  # recorta
        ("", ""),
        (None, ""),
    ])
    def test_normalizes(self, raw, expected):
        assert _client()._extract_brand_clean(raw) == expected


# ------------------------------------------------------- 2) normalización CPE

@pytest.mark.parametrize("raw_cpe,version,expected", [
    # 2.2 URI de nmap, sin versión → prefijo vendor:product (match por rango)
    ("cpe:/a:pureftpd:pure-ftpd", None, "cpe:2.3:a:pureftpd:pure-ftpd"),
    # 2.2 con versión embebida → se conserva
    ("cpe:/a:dnsmasq:dnsmasq:2.45", None, "cpe:2.3:a:dnsmasq:dnsmasq:2.45"),
    # la versión explícita del scan gana sobre la embebida
    ("cpe:/a:dnsmasq:dnsmasq:2.45", "2.80", "cpe:2.3:a:dnsmasq:dnsmasq:2.80"),
    # 2.3 nativo
    ("cpe:2.3:a:lighttpd:lighttpd:1.4.35", None, "cpe:2.3:a:lighttpd:lighttpd:1.4.35"),
    # comodines: NO se añaden a la cadena (provocarían el 404 del cpeName exacto)
    ("cpe:/a:nginx:nginx:*", None, "cpe:2.3:a:nginx:nginx"),
    ("cpe:/a:nginx:nginx:-", None, "cpe:2.3:a:nginx:nginx"),
    ("cpe:2.3:o:linux:linux_kernel:*:*:*", None, "cpe:2.3:o:linux:linux_kernel"),
    # entradas que no son CPE o están incompletas → None (no se inventa nada)
    ("no-soy-un-cpe", None, None),
    ("cpe:/a:solovendor", None, None),
    ("cpe:/a::producto", None, None),
    ("", None, None),
    (None, None, None),
])
def test_to_cpe23_match(raw_cpe, version, expected):
    """Determinismo de OM1: el mismo CPE del escaneo produce siempre la misma
    cadena de consulta, y una entrada inválida no genera una consulta basura."""
    assert NVDCVEClient._to_cpe23_match(raw_cpe, version) == expected


# ------------------------------------------------------ 3) consulta por CPE

def test_virtual_match_sends_the_exact_parameter(client, monkeypatch):
    """Debe consultarse `virtualMatchString` (match por prefijo), NUNCA `cpeName`:
    NVD devuelve 404 a un cpeName con versión comodín."""
    sent = {}

    def fake_get(url, params=None, headers=None, timeout=None):
        sent.update(params or {})
        return _Resp(payload=_nvd_payload("CVE-2021-33558"))

    monkeypatch.setattr(cve_api.requests, "get", fake_get)
    cves = client._cves_by_virtual_match("cpe:2.3:a:boa:boa:0.94.13")
    assert sent["virtualMatchString"] == "cpe:2.3:a:boa:boa:0.94.13"
    assert "cpeName" not in sent
    assert [c["id"] for c in cves] == ["CVE-2021-33558"]


def test_virtual_match_with_zero_results_returns_empty(client, monkeypatch):
    monkeypatch.setattr(cve_api.requests, "get",
                        lambda *a, **k: _Resp(payload={"totalResults": 0}))
    assert client._cves_by_virtual_match("cpe:2.3:a:x:y") == []


def test_virtual_match_without_cpe_does_not_call_the_api(client, monkeypatch):
    """Sin CPE no hay consulta: evita un round-trip inútil de 6 s a la NVD."""
    called = []
    monkeypatch.setattr(cve_api.requests, "get",
                        lambda *a, **k: called.append(1) or _Resp())
    assert client._cves_by_virtual_match(None) == []
    assert not called


# ------------------------------------------------------------- 4) transporte

def test_make_request_returns_parsed_json(client, monkeypatch):
    monkeypatch.setattr(cve_api.requests, "get",
                        lambda *a, **k: _Resp(payload={"totalResults": 1}))
    assert client._make_request("http://x", {}) == {"totalResults": 1}


def test_make_request_rejects_200_with_invalid_json(client, monkeypatch):
    """Un 200 con cuerpo corrupto no puede propagarse como si fuera datos."""
    monkeypatch.setattr(cve_api.requests, "get",
                        lambda *a, **k: _Resp(bad_json=True))
    assert client._make_request("http://x", {}) is None


@pytest.mark.parametrize("status", [429, 503, 500, 502])
def test_make_request_retries_transient_failures_then_succeeds(client, monkeypatch, status):
    calls = []

    def flaky(*a, **k):
        calls.append(1)
        if len(calls) == 1:
            return _Resp(status=status)
        return _Resp(payload={"totalResults": 7})

    monkeypatch.setattr(cve_api.requests, "get", flaky)
    assert client._make_request("http://x", {}) == {"totalResults": 7}
    assert len(calls) == 2, "debía reintentar tras un fallo transitorio"


@pytest.mark.parametrize("status", [404, 403, 400])
def test_make_request_does_not_retry_non_retryable_codes(client, monkeypatch, status):
    """Un 404 es una respuesta ESPERADA (cpeName ausente del diccionario), no un
    fallo: reintentarlo cuatro veces son 24 s de auditoría tirados."""
    calls = []
    monkeypatch.setattr(cve_api.requests, "get",
                        lambda *a, **k: calls.append(1) or _Resp(status=status))
    assert client._make_request("http://x", {}) is None
    assert len(calls) == 1


def test_make_request_gives_up_after_max_retries(client, monkeypatch):
    calls = []
    monkeypatch.setattr(cve_api.requests, "get",
                        lambda *a, **k: calls.append(1) or _Resp(status=503))
    assert client._make_request("http://x", {}) is None
    assert len(calls) == NVDCVEClient._MAX_RETRIES + 1


def test_make_request_survives_transport_errors(client, monkeypatch):
    calls = []

    def boom(*a, **k):
        calls.append(1)
        raise cve_api.requests.exceptions.ConnectionError("sin red")

    monkeypatch.setattr(cve_api.requests, "get", boom)
    assert client._make_request("http://x", {}) is None
    assert len(calls) == NVDCVEClient._MAX_RETRIES + 1


def test_make_request_sends_the_api_key_when_configured(monkeypatch, tmp_path):
    monkeypatch.setattr(cve_api, "_DISK_CACHE_PATH", str(tmp_path / "c.json"))
    seen = {}

    def capture(url, params=None, headers=None, timeout=None):
        seen.update(headers or {})
        return _Resp(payload={"totalResults": 0})

    monkeypatch.setattr(cve_api.requests, "get", capture)
    c = NVDCVEClient(api_key="LA-CLAVE")
    monkeypatch.setattr(c, "_sleep_rate_limit", lambda: None)
    c._make_request("http://x", {})
    assert seen.get("apiKey") == "LA-CLAVE"


class TestBackoff:
    def test_retry_after_header_wins(self):
        assert _client()._compute_backoff(0, retry_after=7.0) == 7.0

    def test_retry_after_is_capped(self):
        c = _client()
        assert c._compute_backoff(0, retry_after=9999) == NVDCVEClient._MAX_BACKOFF

    @pytest.mark.parametrize("attempt", [0, 1, 2, 3, 4])
    def test_exponential_within_bounds(self, attempt):
        """Crece exponencialmente pero acotado, con jitter de ±25 %."""
        wait = _client()._compute_backoff(attempt, retry_after=None)
        expected = NVDCVEClient._BASE_BACKOFF * (2 ** attempt)
        assert 0.1 <= wait <= NVDCVEClient._MAX_BACKOFF
        assert wait <= max(0.1, expected * 1.25) + 1e-9


def test_rate_limiter_serializes_requests(monkeypatch):
    """La espera entre peticiones protege la cuota de la NVD; sin ella el
    ThreadPoolExecutor de `run_probes` la agotaría en un batch."""
    c = NVDCVEClient.__new__(NVDCVEClient)
    import threading
    c._rate_lock = threading.Lock()
    c.delay = 0.05
    c.last_request_time = time.time()
    t0 = time.time()
    c._sleep_rate_limit()
    assert time.time() - t0 >= 0.04


# ------------------------------------------------- 5) cachés de dos niveles

def test_process_cache_avoids_a_second_call(client, monkeypatch):
    calls = []
    monkeypatch.setattr(cve_api.requests, "get",
                        lambda *a, **k: calls.append(1) or _Resp(
                            payload=_nvd_payload("CVE-2017-17215")))
    first = client.get_cves_for_product("boa", "0.94", nmap_cpe="cpe:/a:boa:boa")
    second = client.get_cves_for_product("boa", "0.94", nmap_cpe="cpe:/a:boa:boa")
    assert [c["id"] for c in first] == [c["id"] for c in second] == ["CVE-2017-17215"]
    assert len(calls) == 1, "la segunda consulta debía servirse de la caché"


def test_disk_cache_survives_a_new_client(client, monkeypatch, tmp_path):
    """La caché en disco es lo que evita volver a golpear la NVD entre runs — y
    por eso sus permisos importaban (§4.8.1)."""
    monkeypatch.setattr(cve_api.requests, "get",
                        lambda *a, **k: _Resp(payload=_nvd_payload("CVE-2019-14513")))
    client.get_cves_for_product("dnsmasq", "2.45", nmap_cpe="cpe:/a:dnsmasq:dnsmasq")
    assert os.path.isfile(cve_api._DISK_CACHE_PATH)

    NVDCVEClient._RESULT_CACHE.clear()          # simula un proceso nuevo
    calls = []
    monkeypatch.setattr(cve_api.requests, "get",
                        lambda *a, **k: calls.append(1) or _Resp())
    fresh = NVDCVEClient(api_key=None)
    monkeypatch.setattr(fresh, "_sleep_rate_limit", lambda: None)
    cves = fresh.get_cves_for_product("dnsmasq", "2.45", nmap_cpe="cpe:/a:dnsmasq:dnsmasq")
    assert [c["id"] for c in cves] == ["CVE-2019-14513"]
    assert not calls, "debía servirse de la caché en disco, sin red"


def test_disk_cache_entry_expires(client, monkeypatch, tmp_path):
    stale = {"clave": {"ts": time.time() - cve_api._DISK_CACHE_TTL - 10,
                       "result": [{"id": "CVE-VIEJO"}]}}
    (tmp_path / "nvd_cache.json").write_text(json.dumps(stale), encoding="utf-8")
    assert cve_api._disk_cache_get("clave") is None


def test_disk_cache_tolerates_a_corrupt_file(client, tmp_path):
    (tmp_path / "nvd_cache.json").write_text("{no es json", encoding="utf-8")
    assert cve_api._disk_cache_get("cualquiera") is None      # degrada, no revienta
    cve_api._disk_cache_put("k", [{"id": "CVE-1"}])           # y puede reescribirlo
    assert cve_api._disk_cache_get("k") == [{"id": "CVE-1"}]


# ------------------------------------------- 6) orden de estrategias (OM1)

def test_cpe_strategy_short_circuits_before_keyword_search(client, monkeypatch):
    """La vía determinista va PRIMERO: si el CPE del escaneo devuelve resultados,
    no se consulta por palabras clave (que es la fuente de varianza entre runs)."""
    resolve_called = []
    monkeypatch.setattr(client, "resolve_cpe",
                        lambda *a, **k: resolve_called.append(1) or None)
    monkeypatch.setattr(cve_api.requests, "get",
                        lambda *a, **k: _Resp(payload=_nvd_payload("CVE-2021-33558")))
    cves = client._get_cves_uncached("boa", "0.94.13", nmap_cpe="cpe:/a:boa:boa")
    assert [c["id"] for c in cves] == ["CVE-2021-33558"]
    assert not resolve_called, "no debía caer a inferencia ni a keywords"


def test_broad_keyword_can_be_disabled(client, monkeypatch):
    """`cve_scan_recon` desactiva el keyword versionless para no arrastrar ruido de
    ecosistema; la firma tiene que respetarlo."""
    monkeypatch.setattr(client, "resolve_cpe", lambda *a, **k: None)
    queried = []

    def spy(url, params=None, headers=None, timeout=None):
        queried.append((params or {}).get("keywordSearch"))
        return _Resp(payload={"totalResults": 0})

    monkeypatch.setattr(cve_api.requests, "get", spy)
    client._get_cves_uncached("nginx", "", nmap_cpe=None, allow_broad_keyword=False)
    assert "nginx" not in [q for q in queried if q]


def test_parse_nvd_response_extracts_id_score_and_severity(client):
    parsed = client._parse_nvd_response(_nvd_payload("CVE-2021-1", score=7.5))
    assert parsed and parsed[0]["id"] == "CVE-2021-1"
    assert parsed[0]["score"] == 7.5
    assert parsed[0]["severity"]
    assert "desc de" in parsed[0]["description"]


def test_parse_nvd_response_tolerates_missing_metrics(client):
    payload = {"totalResults": 1, "vulnerabilities": [
        {"cve": {"id": "CVE-SIN-METRICAS",
                 "descriptions": [{"lang": "en", "value": "x"}]}}]}
    parsed = client._parse_nvd_response(payload)
    assert parsed[0]["id"] == "CVE-SIN-METRICAS"


def test_rank_locally_puts_the_matching_version_first(client):
    cves = [
        {"id": "CVE-OTRA", "score": 9.9, "description": "afecta a 1.0"},
        {"id": "CVE-EXACTA", "score": 5.0, "description": "dnsmasq 2.45 desbordamiento"},
    ]
    ranked = client._rank_locally(list(cves), "2.45")
    assert ranked[0]["id"] == "CVE-EXACTA", "la coincidencia de versión manda sobre el CVSS"


# --------------------------- 7) estrategia 2: CPE inferido por la API de la NVD

def _cpe_payload(cpe_name):
    return {"products": [{"cpe": {"cpeName": cpe_name}}]}


def test_resolve_cpe_uses_the_official_dictionary_entry(client, monkeypatch):
    """Cuando nmap no da CPE, se busca el oficial en el diccionario de la NVD."""
    monkeypatch.setattr(cve_api.requests, "get", lambda *a, **k: _Resp(
        payload=_cpe_payload("cpe:2.3:a:dnsmasq:dnsmasq:2.45:*:*:*:*:*:*:*")))
    assert client.resolve_cpe("dnsmasq", "2.45").startswith("cpe:2.3:a:dnsmasq:dnsmasq:2.45")


def test_resolve_cpe_retries_with_brand_only_and_injects_the_version(client, monkeypatch):
    """Si la búsqueda precisa (producto+versión) no encuentra nada, se reintenta
    solo con la marca y se INYECTA la versión detectada en el CPE reconstruido."""
    responses = [
        _Resp(payload={"products": []}),                                   # precisa: vacía
        _Resp(payload=_cpe_payload("cpe:2.3:a:lighttpd:lighttpd:1.0:*:*:*:*:*:*:*")),
    ]
    monkeypatch.setattr(cve_api.requests, "get", lambda *a, **k: responses.pop(0))
    resolved = client.resolve_cpe("lighttpd", "1.4.35")
    assert resolved.split(":")[5] == "1.4.35", "debía inyectar la versión detectada"


def test_resolve_cpe_ignores_products_too_short_to_be_distinctive(client, monkeypatch):
    """Un término de menos de 3 caracteres devolvería medio diccionario: no se
    consulta siquiera."""
    called = []
    monkeypatch.setattr(cve_api.requests, "get",
                        lambda *a, **k: called.append(1) or _Resp())
    assert client.resolve_cpe("ab", "1.0") is None
    assert not called


def test_resolve_cpe_caches_its_answer(client, monkeypatch):
    calls = []
    monkeypatch.setattr(cve_api.requests, "get", lambda *a, **k: calls.append(1) or _Resp(
        payload=_cpe_payload("cpe:2.3:a:boa:boa:0.94:*:*:*:*:*:*:*")))
    client.resolve_cpe("boa", "0.94")
    client.resolve_cpe("boa", "0.94")
    assert len(calls) == 1


def test_resolve_cpe_returns_none_when_the_dictionary_has_nothing(client, monkeypatch):
    monkeypatch.setattr(cve_api.requests, "get",
                        lambda *a, **k: _Resp(payload={"products": []}))
    assert client.resolve_cpe("producto-inexistente", "9.9") is None


def test_keyword_fallback_runs_only_after_both_cpe_strategies(client, monkeypatch):
    """Orden de estrategias completo: CPE del scan → CPE inferido → keywords."""
    order = []

    def spy(url, params=None, headers=None, timeout=None):
        params = params or {}
        if "virtualMatchString" in params:
            order.append("cpe")
            return _Resp(payload={"totalResults": 0})
        if url == client.base_url_cpe:
            order.append("resolve")
            return _Resp(payload={"products": []})
        order.append(f"keyword:{params.get('keywordSearch')}")
        return _Resp(payload={"totalResults": 0})

    monkeypatch.setattr(cve_api.requests, "get", spy)
    client._get_cves_uncached("dnsmasq", "2.45", nmap_cpe="cpe:/a:dnsmasq:dnsmasq")
    assert order[0] == "cpe"
    assert "resolve" in order
    assert any(o.startswith("keyword") for o in order)
