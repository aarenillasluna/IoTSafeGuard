"""Routing de modelo: planner+reflexión usan reasoning_model (más capaz) si se
configura; si no, caen al modelo principal. Cliente separado para cross-provider.
"""
import core.claude_agent as ca


class _FakeMsgs:
    def __init__(self, tag): self.tag = tag
    def create(self, **kw):
        class _R:
            content = [type("C", (), {"text": "PLAN"})()]
        _FakeMsgs.last = kw           # captura el último create()
        return _R()


class _FakeClient:
    def __init__(self, model): self.model = model; self.messages = _FakeMsgs(model)


def _agent(monkeypatch, reasoning_model=None):
    monkeypatch.setattr(ca, "_make_client", lambda model, api_key=None: _FakeClient(model))
    monkeypatch.setattr(ca, "get_observer", lambda: _NullObs())
    monkeypatch.setattr(ca, "get_kb", lambda: None)
    cfg = ca.ClaudeConfig(model="claude-haiku", reasoning_model=reasoning_model,
                          enable_kb=False, enable_reflection=False)
    return ca.ClaudeAgent(config=cfg)


class _NullGen:
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def update(self, **k): pass


class _NullObs:
    def generation(self, **k): return _NullGen()
    def trace(self, **k): return _NullGen()


def test_reasoning_defaults_to_main_model(monkeypatch):
    a = _agent(monkeypatch)
    assert a.reasoning_model == "claude-haiku"
    assert a.reasoning_client is a.client          # mismo cliente


def test_reasoning_model_uses_separate_client(monkeypatch):
    a = _agent(monkeypatch, reasoning_model="claude-opus")
    assert a.reasoning_model == "claude-opus"
    assert a.reasoning_client is not a.client       # cliente propio
    assert a.reasoning_client.model == "claude-opus"


def test_plan_uses_reasoning_model(monkeypatch):
    a = _agent(monkeypatch, reasoning_model="claude-opus")
    a._plan("audita 1.2.3.4")
    assert _FakeMsgs.last["model"] == "claude-opus"  # el planner razonó con Opus
