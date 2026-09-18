"""Tool `run_probes` (iter_10): ejecuta varias probes de protocolo en paralelo en
un solo turno, aplicando los side-effects (auto-registro, cobertura) de forma
serializada. Reduce turnos LLM → menos coste/latencia.
"""
import time

import core.tools as toolbox


def setup_function():
    toolbox.build_registry()
    toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))


def test_run_probes_registered_in_recon():
    recon_tools = {t.name for t in toolbox._REGISTRY.values() if "recon" in t.phases}
    assert "run_probes" in recon_tools


def test_runs_probes_in_parallel(monkeypatch):
    """Tres probes que 'tardan' 0.3 s cada una deben acabar en ~0.3 s (paralelo),
    no en ~0.9 s (secuencial)."""
    def make_slow(tag):
        def _impl(args):
            time.sleep(0.3)
            return {"ok": True, "ip": args.get("ip"), "service": tag,
                    "protocol_confirmed": False, "vulnerabilities": []}
        return _impl

    for name in ("probe_snmp", "probe_mdns", "probe_coap"):
        monkeypatch.setitem(toolbox._REGISTRY, name,
                            toolbox.Tool(name=name, description="x", parameters={},
                                         impl=make_slow(name), phases=("recon",)))

    t0 = time.time()
    r = toolbox.dispatch("run_probes", {
        "ip": "10.0.0.9",
        "probes": [{"probe": "probe_snmp"}, {"probe": "probe_mdns"}, {"probe": "probe_coap"}],
    })
    elapsed = time.time() - t0

    assert r["ok"] is True
    assert set(r["executed"]) == {"probe_snmp", "probe_mdns", "probe_coap"}
    assert elapsed < 0.7            # paralelo (≈0.3s), no 0.9s secuencial
    # El ip común se inyectó en cada probe.
    assert all(e["ip"] == "10.0.0.9" for e in r["results"])


def test_auto_registers_findings_from_batch(monkeypatch):
    """Un hallazgo devuelto por una probe en el batch se auto-registra en la sesión
    (side-effect aplicado en el hilo principal)."""
    def vuln_impl(args):
        return {
            "ok": True, "ip": args.get("ip"), "service": "telnet",
            "protocol_confirmed": True,
            "vulnerabilities": [{
                "id": "TELNET-EXPOSED", "severity": "MEDIUM",
                "description": "Telnet expuesto", "confirmed": True,
            }],
        }
    monkeypatch.setitem(toolbox._REGISTRY, "probe_telnet",
                        toolbox.Tool(name="probe_telnet", description="x",
                                     parameters={}, impl=vuln_impl, phases=("recon",)))

    n_before = len(toolbox.get_session().findings)
    r = toolbox.dispatch("run_probes", {"ip": "10.0.0.9",
                                        "probes": [{"probe": "probe_telnet"}]})
    assert r["ok"] is True
    assert len(toolbox.get_session().findings) > n_before
    # Y quedó marcada como probe ejecutada (cobertura).
    assert "probe_telnet" in toolbox.get_session().executed_probes


def test_rejects_non_probe_tools():
    r = toolbox.dispatch("run_probes", {
        "ip": "10.0.0.9",
        "probes": [{"probe": "execute_command"}, {"probe": "cve_search"}],
    })
    assert r["ok"] is False
    assert "execute_command" in (r.get("rejected") or {})


def test_one_probe_crash_does_not_kill_batch(monkeypatch):
    def boom(args):
        raise RuntimeError("socket explotó")
    def ok(args):
        return {"ok": True, "ip": args.get("ip"), "protocol_confirmed": False,
                "vulnerabilities": []}
    monkeypatch.setitem(toolbox._REGISTRY, "probe_snmp",
                        toolbox.Tool(name="probe_snmp", description="x",
                                     parameters={}, impl=boom, phases=("recon",)))
    monkeypatch.setitem(toolbox._REGISTRY, "probe_mdns",
                        toolbox.Tool(name="probe_mdns", description="x",
                                     parameters={}, impl=ok, phases=("recon",)))
    r = toolbox.dispatch("run_probes", {"ip": "10.0.0.9",
                                        "probes": [{"probe": "probe_snmp"},
                                                   {"probe": "probe_mdns"}]})
    assert r["ok"] is True
    by_name = {e["probe"]: e for e in r["results"]}
    assert "error" in by_name["probe_snmp"]      # la que petó reporta error
    assert by_name["probe_mdns"]["ok"] is True   # la otra sigue bien
