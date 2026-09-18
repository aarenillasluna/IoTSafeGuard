"""Prompt caching + usage: _create_kwargs marca cache_control en system, tools y
último mensaje (clave para que el input no crezca brutal en runs largos)."""
import core.claude_agent as ca


def test_mark_last_message_cache_string():
    msgs = [{"role": "user", "content": "hola"}]
    out = ca._mark_last_message_cache(msgs)
    blk = out[-1]["content"]
    assert isinstance(blk, list) and blk[-1]["cache_control"] == {"type": "ephemeral"}
    assert msgs[-1]["content"] == "hola"          # no muta el original


def test_mark_last_message_cache_dict_list():
    msgs = [{"role": "user", "content": [{"type": "tool_result", "content": "x"}]}]
    out = ca._mark_last_message_cache(msgs)
    assert out[-1]["content"][-1]["cache_control"] == {"type": "ephemeral"}


def test_mark_last_message_cache_skips_sdk_objects():
    class _Block:  # simula objeto del SDK (no dict)
        pass
    msgs = [{"role": "assistant", "content": [_Block()]}]
    out = ca._mark_last_message_cache(msgs)
    assert out is msgs                            # no se toca → seguro


def test_create_kwargs_has_cache_control(monkeypatch):
    # agente mínimo sin cliente real
    monkeypatch.setattr(ca, "_make_client", lambda model, api_key=None: object())
    monkeypatch.setattr(ca, "get_observer", lambda: None)
    monkeypatch.setattr(ca, "get_kb", lambda: None)
    a = ca.ClaudeAgent(config=ca.ClaudeConfig(model="claude-haiku", enable_kb=False))
    a.current_phase = "recon"
    kw = a._create_kwargs([{"role": "user", "content": "scan"}], "SYS PROMPT")
    # system es bloque con cache_control
    assert isinstance(kw["system"], list)
    assert kw["system"][0]["cache_control"] == {"type": "ephemeral"}
    # última tool con cache_control
    assert kw["tools"] and kw["tools"][-1]["cache_control"] == {"type": "ephemeral"}
    # último mensaje con cache breakpoint
    assert kw["messages"][-1]["content"][-1]["cache_control"] == {"type": "ephemeral"}
