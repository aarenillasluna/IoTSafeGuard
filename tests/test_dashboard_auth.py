"""El backend lanza escaneos con privilegios de root: conviene poder exigir identidad.

`api/services/audit_runner.py` arranca `run.py` bajo `sudo` contra la IP que le
digan. Quien alcance el puerto, por tanto, ejecuta escaneos privilegiados sobre
la red del operador. La única contención era el bind a `127.0.0.1`, que protege
frente a la red pero no frente a otro proceso local ni frente a una página que
apunte al puerto desde el navegador del propio usuario.

El token es OPCIONAL a propósito —es una herramienta local de un solo usuario y
exigirlo siempre sería fricción sin destinatario—, pero cuando se define se
aplica en todas las rutas, y cuando no, el arranque lo advierte para que la
ausencia sea una decisión.
"""
import pytest
from fastapi.testclient import TestClient

from api.main import _TOKEN_ENV, create_app


@pytest.fixture
def no_token(monkeypatch):
    monkeypatch.delenv(_TOKEN_ENV, raising=False)
    return TestClient(create_app())


@pytest.fixture
def with_token(monkeypatch):
    monkeypatch.setenv(_TOKEN_ENV, "s3cr3t-token")
    return TestClient(create_app())


def test_without_a_token_configured_nothing_changes(no_token):
    """El flujo local de siempre sigue funcionando sin fricción."""
    assert no_token.get("/api/health").status_code == 200
    assert no_token.get("/api/reports").status_code == 200


def test_with_a_token_configured_requests_without_it_are_rejected(with_token):
    r = with_token.get("/api/reports")
    assert r.status_code == 401
    assert _TOKEN_ENV in r.json()["detail"]


def test_the_right_token_in_the_header_is_accepted(with_token):
    r = with_token.get("/api/reports", headers={"X-API-Token": "s3cr3t-token"})
    assert r.status_code == 200


def test_the_right_token_as_a_query_param_is_accepted(with_token):
    """El WebSocket del panel en vivo no puede fijar cabeceras desde el
    navegador, así que se admite también por query string."""
    r = with_token.get("/api/reports?token=s3cr3t-token")
    assert r.status_code == 200


def test_a_wrong_token_is_rejected(with_token):
    r = with_token.get("/api/reports", headers={"X-API-Token": "otro"})
    assert r.status_code == 401


def test_a_token_prefix_is_not_enough(with_token):
    """La comparación es en tiempo constante; un prefijo correcto no debe pasar
    ni filtrar información por temporización."""
    r = with_token.get("/api/reports", headers={"X-API-Token": "s3cr3t"})
    assert r.status_code == 401


def test_health_stays_open_so_monitoring_does_not_need_the_secret(with_token):
    assert with_token.get("/api/health").status_code == 200


def test_launching_an_audit_is_protected(with_token):
    """La ruta que de verdad importa: la que ejecuta nmap como root."""
    r = with_token.post("/api/audits", json={"target_ip": "192.168.1.50"})
    assert r.status_code == 401


def test_subnet_scan_is_protected(with_token):
    r = with_token.post("/api/scan", json={"cidr": "192.168.1.0/24"})
    assert r.status_code == 401
