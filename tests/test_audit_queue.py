"""Las auditorías se ejecutan de una en una, sea cual sea el objetivo.

La concurrencia anterior era ENTRE objetivos: secuencial dentro de cada uno,
solapada entre ellos. El razonamiento —dos runs contra el MISMO dispositivo se
interfieren, contra dispositivos distintos no— es cierto respecto al objetivo,
pero pasa por alto todo lo que los runs comparten aunque apunten a equipos
distintos:

  · la cuota del proveedor LLM (N runs = N veces el ritmo de peticiones, y el
    bucle degrada al modelo de reserva al agotarla, con lo que unas réplicas
    acaban conducidas por otro modelo que otras);
  · la red y la CPU del anfitrión, con varios `nmap` a la vez;
  · la base de conocimiento, que todos leen al arrancar y escriben al terminar.

Ninguna es interferencia entre objetivos, pero todas rompen la comparabilidad
entre réplicas, que es lo que el análisis de varianza necesita. Para un banco de
pruebas de una sola máquina, terminar antes no compensa comparar peor.
"""
import asyncio

import pytest

from api.services import audit_runner


class _FakeProc:
    """Subproceso simulado: se le controla cuándo termina."""

    def __init__(self, pid=1234):
        self.pid = pid
        self.returncode = None
        self.stdout = self
        self._finish = asyncio.Event()

    async def readline(self):
        await self._finish.wait()
        return b""

    async def wait(self):
        await self._finish.wait()
        self.returncode = 0
        return 0

    def finish(self, code=0):
        """`code` distinto de cero simula un run que termina mal, que es lo que
        hace `run.py` ante cualquier final que no sea `done()`."""
        self.returncode = code
        self._finish.set()

    async def wait(self):  # noqa: F811 - respeta el returncode ya fijado
        await self._finish.wait()
        return self.returncode


@pytest.fixture
def spawner(monkeypatch, tmp_path):
    """Sustituye el lanzamiento real y registra el orden de arranque."""
    monkeypatch.setattr(audit_runner, "RUNS_LOG_DIR", str(tmp_path))
    monkeypatch.setattr(audit_runner, "_log_path",
                        lambda aid: str(tmp_path / f"{aid}.log"))
    state = {"spawned": [], "procs": []}

    async def fake_exec(*args, **kwargs):
        target = args[args.index("--target") + 1]
        state["spawned"].append(target)
        proc = _FakeProc(pid=1000 + len(state["procs"]))
        state["procs"].append(proc)
        return proc

    monkeypatch.setattr(audit_runner.asyncio, "create_subprocess_exec", fake_exec)
    return state


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ── Una a la vez ───────────────────────────────────────────────────────────

def test_only_one_audit_runs_at_a_time(spawner):
    async def scenario():
        mgr = audit_runner.AuditManager()
        for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
            await mgr.enqueue(ip)
        await asyncio.sleep(0.05)
        # Solo la primera ha arrancado; las otras esperan turno.
        assert spawner["spawned"] == ["10.0.0.1"]

        spawner["procs"][0].finish()
        await asyncio.sleep(0.05)
        assert spawner["spawned"] == ["10.0.0.1", "10.0.0.2"]

        spawner["procs"][1].finish()
        await asyncio.sleep(0.05)
        assert spawner["spawned"] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        spawner["procs"][2].finish()
        await asyncio.sleep(0.05)

    asyncio.run(scenario())


def test_the_queue_preserves_the_order_it_was_given(spawner):
    async def scenario():
        mgr = audit_runner.AuditManager()
        order = ["10.0.0.9", "10.0.0.7", "10.0.0.8"]
        for ip in order:
            await mgr.enqueue(ip)
        for i in range(len(order)):
            await asyncio.sleep(0.05)
            spawner["procs"][i].finish()
        await asyncio.sleep(0.05)
        assert spawner["spawned"] == order

    asyncio.run(scenario())


def test_replicas_of_one_target_are_all_queued(spawner):
    async def scenario():
        mgr = audit_runner.AuditManager()
        await mgr.start_replicas("10.0.0.5", 3)
        await asyncio.sleep(0.05)
        assert spawner["spawned"] == ["10.0.0.5"], "solo una corriendo"
        summaries = await mgr.list()
        assert len(summaries) == 3, "las tres réplicas figuran desde el principio"
        assert sum(1 for s in summaries if s["is_queued"]) == 2
        for p in spawner["procs"]:
            p.finish()
        await asyncio.sleep(0.05)

    asyncio.run(scenario())


# ── Estado visible ─────────────────────────────────────────────────────────

def test_a_queued_audit_is_not_reported_as_running(spawner):
    """Mostrarla «en curso» durante minutos hacía pensar que se había colgado."""
    async def scenario():
        mgr = audit_runner.AuditManager()
        await mgr.enqueue("10.0.0.1")
        second = await mgr.enqueue("10.0.0.2")
        await asyncio.sleep(0.05)
        s = second.as_summary()
        assert s["is_queued"] is True
        assert s["is_running"] is False
        assert s["queue_position"] >= 1
        spawner["procs"][0].finish()
        await asyncio.sleep(0.05)
        for p in spawner["procs"]:
            p.finish()
        await asyncio.sleep(0.05)

    asyncio.run(scenario())


def test_a_queued_audit_can_be_cancelled_before_it_starts(spawner):
    """Sin esto, «detener» algo encolado no hacía nada y arrancaba igualmente
    minutos después."""
    async def scenario():
        mgr = audit_runner.AuditManager()
        await mgr.enqueue("10.0.0.1")
        victim = await mgr.enqueue("10.0.0.2")
        await mgr.enqueue("10.0.0.3")
        await asyncio.sleep(0.05)

        await mgr.stop(victim.audit_id)
        for p in spawner["procs"]:
            p.finish()
        await asyncio.sleep(0.1)
        for p in spawner["procs"]:
            p.finish()
        await asyncio.sleep(0.1)

        assert "10.0.0.2" not in spawner["spawned"], "la cancelada no debe arrancar"
        assert "10.0.0.3" in spawner["spawned"], "la siguiente sí"

    asyncio.run(scenario())


# ── La concurrencia sigue disponible, pero explícita ──────────────────────

def test_concurrent_mode_still_overlaps_targets(spawner):
    async def scenario():
        mgr = audit_runner.AuditManager()
        await mgr.start_replicas("10.0.0.1", 1, concurrent=True)
        await mgr.start_replicas("10.0.0.2", 1, concurrent=True)
        await asyncio.sleep(0.05)
        assert spawner["spawned"] == ["10.0.0.1", "10.0.0.2"], "ambas a la vez"
        for p in spawner["procs"]:
            p.finish()
        await asyncio.sleep(0.05)

    asyncio.run(scenario())


def test_a_crashing_spawn_does_not_stall_the_queue(spawner, monkeypatch):
    """Si una auditoría no arranca, las siguientes deben seguir su curso."""
    calls = {"n": 0}
    real = audit_runner.asyncio.create_subprocess_exec

    async def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("no se pudo lanzar")
        return await real(*args, **kwargs)

    monkeypatch.setattr(audit_runner.asyncio, "create_subprocess_exec", flaky)

    async def scenario():
        mgr = audit_runner.AuditManager()
        await mgr.enqueue("10.0.0.1")
        await mgr.enqueue("10.0.0.2")
        await asyncio.sleep(0.1)
        assert "10.0.0.2" in spawner["spawned"], "la cola no se atasca"
        for p in spawner["procs"]:
            p.finish()
        await asyncio.sleep(0.05)

    asyncio.run(scenario())


# ── Modo por dispositivo: paralelo entre aparatos, serie dentro de cada uno ──

def test_por_dispositivo_arranca_una_replica_de_cada_aparato(spawner):
    """Lo que pide una tanda de 3 aparatos × 5 réplicas: tres corriendo, una
    por aparato, y nunca dos contra el mismo."""
    async def scenario():
        mgr = audit_runner.AuditManager()
        for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
            await mgr.start_replicas(ip, 5, modo="por_dispositivo")
        await asyncio.sleep(0.05)
        assert sorted(spawner["spawned"]) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

        # Al terminar la réplica 1 de .1, arranca la réplica 2 de .1 —no la de
        # otro aparato—: dentro del carril el orden es estricto.
        spawner["procs"][0].finish()
        await asyncio.sleep(0.05)
        assert spawner["spawned"].count("10.0.0.1") == 2
        assert spawner["spawned"].count("10.0.0.2") == 1
        for p in spawner["procs"]:
            p.finish()
        await asyncio.sleep(0.05)

    asyncio.run(scenario())


def test_por_dispositivo_nunca_solapa_replicas_del_mismo_aparato(spawner):
    """La única interferencia que sí es física: dos runs contra el mismo
    aparato. El modo rápido no puede permitirla."""
    async def scenario():
        mgr = audit_runner.AuditManager()
        await mgr.start_replicas("10.0.0.7", 4, modo="por_dispositivo")
        await asyncio.sleep(0.05)
        assert spawner["spawned"] == ["10.0.0.7"], "una sola, aunque sea el modo rápido"
        for p in spawner["procs"]:
            p.finish()
        await asyncio.sleep(0.05)

    asyncio.run(scenario())


def test_el_alias_concurrent_ya_no_manda_las_replicas_a_la_cola_global(spawner):
    """El defecto que corrige el modo: `concurrent=True` sacaba de la cola SOLO
    la primera réplica de cada objetivo y mandaba el resto a la cola global. Con
    3×5 eso daba tres en paralelo y luego doce en serie —ni una cosa ni la otra—.
    """
    async def scenario():
        mgr = audit_runner.AuditManager()
        await mgr.start_replicas("10.0.0.1", 3, concurrent=True)
        await mgr.start_replicas("10.0.0.2", 3, concurrent=True)
        await asyncio.sleep(0.05)
        assert sorted(spawner["spawned"]) == ["10.0.0.1", "10.0.0.2"]

        # Terminar la de .1 debe arrancar OTRA de .1, no dejarla detrás de .2
        # en una cola compartida.
        spawner["procs"][0].finish()
        await asyncio.sleep(0.05)
        assert spawner["spawned"].count("10.0.0.1") == 2
        for p in spawner["procs"]:
            p.finish()
        await asyncio.sleep(0.05)

    asyncio.run(scenario())


def test_el_modo_secuencial_sigue_siendo_el_de_por_defecto(spawner):
    """La comparabilidad entre réplicas no puede depender de que nadie toque un
    desplegable: el modo rápido se elige, no se hereda."""
    async def scenario():
        mgr = audit_runner.AuditManager()
        await mgr.start_replicas("10.0.0.1", 2)
        await mgr.start_replicas("10.0.0.2", 2)
        await asyncio.sleep(0.05)
        assert spawner["spawned"] == ["10.0.0.1"], "una a la vez, sin excepción"
        for p in spawner["procs"]:
            p.finish()
        await asyncio.sleep(0.05)

    asyncio.run(scenario())


def test_detener_una_encolada_no_afecta_a_los_otros_carriles(spawner):
    """Cancelar una réplica de un aparato no puede parar a los demás."""
    async def scenario():
        mgr = audit_runner.AuditManager()
        await mgr.start_replicas("10.0.0.1", 2, modo="por_dispositivo")
        await mgr.start_replicas("10.0.0.2", 2, modo="por_dispositivo")
        await asyncio.sleep(0.05)

        encoladas = [a for a in (await mgr.list()) if a["is_queued"]]
        victima = next(a for a in encoladas if a["target_ip"] == "10.0.0.1")
        await mgr.stop(victima["audit_id"])

        for p in spawner["procs"]:
            p.finish()
        await asyncio.sleep(0.1)
        for p in spawner["procs"]:
            p.finish()
        await asyncio.sleep(0.1)

        assert spawner["spawned"].count("10.0.0.1") == 1, "la cancelada no arranca"
        assert spawner["spawned"].count("10.0.0.2") == 2, "el otro carril sigue"

    asyncio.run(scenario())


# ── Una credencial rechazada no se arregla sola entre ejecuciones ──────────

def test_una_credencial_rechazada_cancela_lo_que_queda_en_el_carril(spawner, tmp_path):
    """En campo, una clave de proveedor caducada se llevó por delante las CINCO
    réplicas de una tanda: cada una arrancó, pidió su primer turno, recibió 403 y
    murió en medio segundo, dejando cinco registros idénticos y ningún dato. Un
    fallo de credencial es CONFIGURACIÓN, no un fallo transitorio: reintentarlo
    con la misma clave está garantizado que falla igual."""
    async def scenario():
        mgr = audit_runner.AuditManager()
        await mgr.start_replicas("10.0.0.8", 5)
        await asyncio.sleep(0.05)

        # La primera termina con el registro de un 403 del proveedor.
        primera = [a for a in mgr._audits.values() if a.process is not None][0]
        with open(primera.log_path, "w", encoding="utf-8") as fh:
            fh.write("ERROR [AGENT] API error turn 1: Error code: 403\n"
                     "SUCCESS [AGENT] finalizado: reason=auth_error: 403\n")
        spawner["procs"][0].finish(code=1)
        await asyncio.sleep(0.15)

        assert spawner["spawned"] == ["10.0.0.8"], "no debe arrancar ninguna más"
        canceladas = [a for a in mgr._audits.values() if a.was_stopped]
        assert len(canceladas) == 4, "las cuatro pendientes quedan canceladas"

    asyncio.run(scenario())


def test_un_fallo_normal_no_cancela_el_resto(spawner):
    """La guarda mira el MOTIVO, no el código de salida: un run que agota su
    presupuesto también sale distinto de cero, y ahí las réplicas siguientes sí
    tienen sentido."""
    async def scenario():
        mgr = audit_runner.AuditManager()
        await mgr.start_replicas("10.0.0.9", 3)
        await asyncio.sleep(0.05)
        primera = [a for a in mgr._audits.values() if a.process is not None][0]
        with open(primera.log_path, "w", encoding="utf-8") as fh:
            fh.write("SUCCESS [AGENT] finalizado: reason=budget_exhausted turns=150\n")
        spawner["procs"][0].finish(code=1)
        await asyncio.sleep(0.15)
        assert spawner["spawned"].count("10.0.0.9") == 2, "la siguiente arranca"
        for p in spawner["procs"]:
            p.finish()
        await asyncio.sleep(0.1)

    asyncio.run(scenario())
