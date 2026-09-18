"""
Tests del split de fases (recon ↔ exploit) en el agente.

Cubre:
- Filtrado de tools por fase en core/tools.py.
- Carga de prompts por fase desde core/prompts.py.
- Tool `transition_phase` y propagación de `_transition_to`.
- Swap de fase real en el loop del agente.
"""
from __future__ import annotations

import os
import sys
from types import SimpleNamespace

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core import tools as toolbox
from core import prompts as prompts_mod
import core.claude_agent as ca
from core.claude_agent import ClaudeAgent, ClaudeConfig
from core.observability import Observer


# --------------------------------------------------------------------- Helpers

def _bloque_tool(name, args, uid="t1"):
    """Bloque `tool_use` del SDK Anthropic."""
    return SimpleNamespace(type="tool_use", name=name, input=args, id=uid)


class _RespuestaFalsa:
    """Lo que devuelve `messages.create()`: bloques + motivo de parada."""
    def __init__(self, bloques):
        self.content = bloques
        self.stop_reason = "tool_use"
        self.usage = SimpleNamespace(input_tokens=0, output_tokens=0,
                                     cache_read_input_tokens=0,
                                     cache_creation_input_tokens=0)


class _MensajesFalsos:
    def __init__(self, guion):
        self._guion = list(guion)
        self.calls = []  # (model, system, nº de tools) por turno

    def create(self, **kw):
        system = kw.get("system")
        # El system va como bloque con cache_control, no como cadena suelta.
        if isinstance(system, list):
            system = " ".join(b.get("text", "") for b in system if isinstance(b, dict))
        self.calls.append({
            "model": kw.get("model"),
            "system": system or "",
            "tool_count": len(kw.get("tools") or []),
        })
        assert self._guion, "No quedan respuestas guionizadas"
        return _RespuestaFalsa(self._guion.pop(0))


class _ClienteFalso:
    def __init__(self, guion):
        self.messages = _MensajesFalsos(guion)


@pytest.fixture(autouse=True)
def _session():
    s = toolbox.AgentSession(target_ip="10.0.0.1")
    toolbox.bind_session(s)
    toolbox.build_registry()
    yield s


@pytest.fixture
def agent(monkeypatch):
    for k in ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("LANGFUSE_ENABLED", "false")
    monkeypatch.setattr(ca, "get_kb", lambda: None)
    ag = ClaudeAgent.__new__(ClaudeAgent)
    ag.cfg = ClaudeConfig(
        model="claude-haiku-4-5",
        max_turns=10, wall_clock_seconds=60,
        enable_planner=False,
        enable_reflection=False,
        enable_kb=False,
    )
    ag.client = None
    ag.observer = Observer()
    ag.current_phase = ag.cfg.initial_phase
    ag._tools_invoked = []
    ag._cve_search_results = []
    ag.kb = None
    return ag


# --------------------------------------------------------------------- Tools per phase

class TestToolPhases:

    def test_recon_excludes_exploit_only_tools(self):
        names = {t.name for t in toolbox.list_tools(phase="recon")}
        assert "web_login" not in names
        assert "execute_chain" not in names
        assert "save_report" not in names

    def test_recon_includes_recon_tools(self):
        names = {t.name for t in toolbox.list_tools(phase="recon")}
        for needed in ("nmap_scan", "probe_hnap", "probe_snmp", "probe_mdns",
                       "probe_coap", "http_interrogate", "mac_vendor_lookup",
                       "cve_search", "record_finding", "transition_phase", "done"):
            assert needed in names, f"recon falta {needed}"

    def test_exploit_includes_exploit_tools(self):
        names = {t.name for t in toolbox.list_tools(phase="exploit")}
        for needed in ("web_login", "execute_command", "execute_chain",
                       "cve_search", "record_finding", "save_report",
                       "transition_phase", "done", "nmap_scan", "http_interrogate"):
            assert needed in names, f"exploit falta {needed}"

    def test_exploit_excludes_pure_recon_probes(self):
        names = {t.name for t in toolbox.list_tools(phase="exploit")}
        assert "probe_mdns" not in names
        assert "probe_coap" not in names
        assert "mac_vendor_lookup" not in names

    def test_el_catalogo_se_filtra_por_fase(self):
        all_decls = toolbox.list_claude_tools()
        recon_decls = toolbox.list_claude_tools(phase="recon")
        exploit_decls = toolbox.list_claude_tools(phase="exploit")
        # cada subconjunto debe ser estrictamente más pequeño que el total
        assert len(recon_decls) < len(all_decls)
        assert len(exploit_decls) < len(all_decls)


# --------------------------------------------------------------------- Prompts

class TestPrompts:

    def test_planner_prompt_substitutes_goal(self):
        out = prompts_mod.get_planner_prompt("Audit 192.168.1.1")
        assert "Audit 192.168.1.1" in out

    def test_recon_prompt_mentions_recon(self):
        p = prompts_mod.get_phase_prompt("recon")
        assert "RECON" in p.upper()
        assert "transition_phase" in p

    def test_exploit_prompt_mentions_exploit(self):
        p = prompts_mod.get_phase_prompt("exploit")
        assert "EXPLOIT" in p.upper()
        assert "web_login" in p
        assert "save_report" in p

    def test_invalid_phase_raises(self):
        with pytest.raises(ValueError):
            prompts_mod.get_phase_prompt("nonexistent")  # type: ignore


# --------------------------------------------------------------------- transition_phase tool

class TestTransitionTool:

    def test_transition_to_exploit_returns_marker(self):
        r = toolbox.dispatch("transition_phase", {"phase": "exploit"})
        assert r["ok"] is True
        assert r["_transition_to"] == "exploit"

    def test_transition_to_recon_returns_marker(self):
        r = toolbox.dispatch("transition_phase", {"phase": "recon"})
        assert r["ok"] is True
        assert r["_transition_to"] == "recon"

    def test_transition_invalid_phase_validation_error(self):
        r = toolbox.dispatch("transition_phase", {"phase": "lol"})
        assert r["ok"] is False
        assert r.get("error_type") == "VALIDATION"

    def test_transition_missing_phase_defaults_to_validation_error(self):
        r = toolbox.dispatch("transition_phase", {})
        assert r["ok"] is False


# --------------------------------------------------------------------- Loop swap

class TestAgentPhaseSwap:

    def test_initial_phase_is_recon(self, agent):
        assert agent.current_phase == "recon"

    def test_los_kwargs_de_peticion_siguen_a_la_fase(self, agent):
        recon = agent._create_kwargs([{"role": "user", "content": "x"}],
                                     prompts_mod.get_phase_prompt("recon"))
        agent.current_phase = "exploit"
        exploit = agent._create_kwargs([{"role": "user", "content": "x"}],
                                       prompts_mod.get_phase_prompt("exploit"))

        def _texto(system):
            return " ".join(b.get("text", "") for b in system).upper()

        assert _texto(recon["system"]) != _texto(exploit["system"])
        assert "RECON" in _texto(recon["system"])
        assert "EXPLOIT" in _texto(exploit["system"])
        # Cada fase expone su subconjunto de tools
        assert len(recon["tools"]) > 0
        assert len(exploit["tools"]) > 0
        assert recon["tools"] != exploit["tools"]

    def test_loop_swaps_phase_on_transition(self, agent):
        """El loop ejecuta transition_phase y la siguiente llamada usa el prompt nuevo."""
        agent.client = _ClienteFalso([
            [_bloque_tool("transition_phase", {"phase": "exploit"}, "a")],
            [_bloque_tool("done", {"summary": "swapped ok"}, "b")],
        ])
        result = agent.run("test")
        assert result["finish_reason"] == "done_called"
        assert agent.current_phase == "exploit"
        calls = agent.client.messages.calls
        assert len(calls) == 2
        assert "RECON" in calls[0]["system"].upper()
        assert "EXPLOIT" in calls[1]["system"].upper()
