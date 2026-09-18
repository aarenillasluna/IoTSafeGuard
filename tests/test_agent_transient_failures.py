"""Un fallo transitorio no debe costar la auditoría entera.

Dos defectos en el manejo de errores del bucle de Claude:

1. `APIConnectionError` —el error MÁS probable de todos: wifi, DNS, proxy— era
   el único sin reintento. Caía en el `except Exception` genérico y abortaba:
   una auditoría de dos horas se perdía por un parpadeo de la conexión.

2. Los contadores de reintento no se ponían a cero tras un turno bueno, así que
   eran acumulativos durante todo el run. Seis rate-limits repartidos a lo largo
   de dos horas degradaban el modelo al fallback de forma PERMANENTE, aunque
   entre medias hubiera habido cientos de turnos correctos. El resultado es un
   informe atribuido a un modelo que solo condujo parte del run.
"""
import anthropic
import pytest

import core.tools as toolbox
from core.claude_agent import ClaudeAgent, ClaudeConfig


@pytest.fixture(autouse=True)
def _bound_session():
    toolbox.bind_session(toolbox.AgentSession(target_ip="10.0.0.1"))
    yield
    toolbox.bind_session(toolbox.AgentSession(target_ip="127.0.0.1"))


class _Resp:
    """Respuesta mínima con una tool_call a `done`."""
    stop_reason = "tool_use"
    usage = None

    class _Block:
        type = "tool_use"
        id = "t1"
        name = "done"
        input = {"summary": "fin"}

    content = [_Block()]


def _agent(monkeypatch, side_effects):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    agent = ClaudeAgent(config=ClaudeConfig(enable_planner=False, enable_kb=False,
                                            enable_reflection=False, max_turns=10))
    calls = {"n": 0, "models": []}

    def fake_create(**kwargs):
        calls["models"].append(kwargs.get("model"))
        i = calls["n"]
        calls["n"] += 1
        effect = side_effects[i] if i < len(side_effects) else _Resp()
        if isinstance(effect, Exception):
            raise effect
        return effect

    monkeypatch.setattr(agent.client.messages, "create", fake_create)
    monkeypatch.setattr("core.claude_agent.time.sleep", lambda s: None)
    return agent, calls


def _connection_error():
    return anthropic.APIConnectionError(request=None)


def test_connection_error_is_retried_not_fatal(monkeypatch):
    agent, calls = _agent(monkeypatch, [_connection_error(), _Resp()])
    result = agent.run("audita 10.0.0.1")
    assert result["finish_reason"] == "done_called"
    assert calls["n"] == 2, "debe haber reintentado tras el corte de red"


def test_connection_retries_are_bounded(monkeypatch):
    agent, calls = _agent(monkeypatch, [_connection_error()] * 12)
    result = agent.run("audita 10.0.0.1")
    assert result["finish_reason"].startswith("connection_error")
    # 5 reintentos + el intento inicial: no reintenta indefinidamente.
    assert calls["n"] == 6


def test_a_connection_blip_does_not_switch_the_model(monkeypatch):
    """Cambiar de modelo no arregla un problema de conectividad."""
    agent, calls = _agent(monkeypatch, [_connection_error(), _Resp()])
    agent.run("audita 10.0.0.1")
    assert len(set(calls["models"])) == 1


def test_retry_counter_resets_after_a_good_turn(monkeypatch):
    """Cortes aislados repartidos por el run no deben acumularse hasta agotar
    el presupuesto de reintentos."""
    effects = []
    for _ in range(4):
        effects += [_connection_error(), _Resp()]
    agent, calls = _agent(monkeypatch, effects)
    # `done` corta en la primera respuesta buena, así que se comprueba el
    # contador directamente sobre el estado del agente tras un ciclo.
    agent.run("audita 10.0.0.1")
    assert agent._connection_retries == 0, (
        "un turno correcto debe devolver el contador a cero")
