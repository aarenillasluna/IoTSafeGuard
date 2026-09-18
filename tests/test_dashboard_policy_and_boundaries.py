"""El dashboard no puede desactivar en silencio la capa que OE2 declara cumplida.

`audit_runner` fijaba `--no-policy` en el propio código, sin alternativa: la
interfaz que la memoria presenta como entregable (OM4) lanzaba TODAS las
auditorías con el `PolicyEngine` apagado —es decir, con `shell=True`— mientras
§4.5.1 y §6.3 afirmaban lo contrario. No era un fallo de la política sino de su
cableado, y por eso no lo detectaba ninguna prueba de `policy_engine.py`.

Se fija aquí: la política está ACTIVA por defecto, desactivarla es explícito, y
queda registrado en el resumen del audit para que un run sin contención sea
distinguible de uno con ella.

Se cubren además las dos fronteras que quedaban sin validar (`extra_args` y los
identificadores que componen rutas de fichero), por coherencia con el resto de
la API, donde la validación de entrada es una capa de contención declarada.
"""
import asyncio

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from api.main import create_app
from api.routes.audits import StartAuditPayload, StartBatchPayload
from api.services import audit_runner


@pytest.fixture
def client():
    return TestClient(create_app())


def _spawn_args(monkeypatch, **start_kwargs) -> list:
    """Args con los que el manager habría lanzado `run.py`, sin lanzarlo.

    Se usa `asyncio.run` en vez de `pytest.mark.asyncio`: el proyecto no
    instala `pytest-asyncio`, y con ese marcador la prueba no falla — se SALTA
    en silencio. Una prueba saltada que nadie mira es peor que no tenerla,
    justamente aquí, donde lo que se comprueba es que una capa de seguridad no
    se desactiva sola.
    """
    spawned = {}

    async def fake_exec(*args, **kwargs):
        spawned["args"] = list(args)
        raise RuntimeError("no lanzamos procesos de verdad en la prueba")

    monkeypatch.setattr(audit_runner.asyncio, "create_subprocess_exec", fake_exec)

    async def _go():
        mgr = audit_runner.AuditManager()
        with pytest.raises(RuntimeError):
            await mgr.start("10.0.0.5", **start_kwargs)

    asyncio.run(_go())
    return spawned["args"]


# ── La política está activa salvo petición explícita ────────────────────────

def test_policy_is_on_by_default(monkeypatch):
    args = _spawn_args(monkeypatch)
    assert "--no-policy" not in args, (
        "el dashboard no debe desactivar el PolicyEngine por su cuenta")
    assert "--auto" in args


def test_policy_can_be_disabled_explicitly(monkeypatch):
    args = _spawn_args(monkeypatch, policy_disabled=True)
    assert "--no-policy" in args


def test_summary_declares_the_posture():
    audit = audit_runner.Audit(audit_id="20260101_000000", target_ip="10.0.0.5",
                               model=None, extra_args=[], policy_disabled=True)
    assert audit.as_summary()["policy_disabled"] is True
    default = audit_runner.Audit(audit_id="20260101_000001", target_ip="10.0.0.5",
                                 model=None, extra_args=[])
    assert default.as_summary()["policy_disabled"] is False


# ── `extra_args` deja de ser una lista libre ────────────────────────────────

def test_known_flags_are_accepted():
    payload = StartAuditPayload(target_ip="10.0.0.5",
                                extra_args=["--max-turns", "50", "--no-safety"])
    assert payload.extra_args == ["--max-turns", "50", "--no-safety"]


def test_unknown_flag_is_rejected():
    with pytest.raises(ValidationError):
        StartAuditPayload(target_ip="10.0.0.5", extra_args=["--rm-rf", "/"])


def test_no_policy_cannot_sneak_in_through_extra_args():
    """El campo `disable_policy` sería decorativo si `extra_args` lo colase."""
    with pytest.raises(ValidationError):
        StartAuditPayload(target_ip="10.0.0.5", extra_args=["--no-policy"])


def test_flag_value_is_constrained():
    with pytest.raises(ValidationError):
        StartAuditPayload(target_ip="10.0.0.5",
                          extra_args=["--hint", "a; rm -rf /"])


def test_flag_without_value_is_rejected():
    with pytest.raises(ValidationError):
        StartAuditPayload(target_ip="10.0.0.5", extra_args=["--max-turns"])


def test_batch_validates_extra_args_too():
    with pytest.raises(ValidationError):
        StartBatchPayload(target_ips=["10.0.0.5"], extra_args=["--no-policy"])


# ── Identificadores que componen rutas ──────────────────────────────────────

@pytest.mark.parametrize("bad_id", [
    "../../../etc/passwd",
    "..%2f..%2fetc",
    "no-es-un-timestamp",
    "",
])
def test_report_id_must_look_like_a_timestamp(client, bad_id):
    for suffix in ("html", "sarif"):
        r = client.get(f"/api/reports/{bad_id}/{suffix}")
        assert r.status_code in (400, 404), (bad_id, suffix, r.status_code)


def test_audit_log_id_must_look_like_a_timestamp(client):
    r = client.get("/api/audits/..%2f..%2fetc%2fpasswd/log")
    assert r.status_code in (400, 404)


def test_wellformed_ids_are_not_blocked_by_the_validator(client):
    """La validación no debe romper el caso legítimo: un id bien formado que
    simplemente no existe da 404, no 400."""
    r = client.get("/api/reports/20260101_000000/html")
    assert r.status_code == 404
