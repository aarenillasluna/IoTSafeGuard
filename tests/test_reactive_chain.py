"""
Tests del ejecutor reactivo de cadenas de exploits (modules/exploiter.py).
Se parchea `ActiveExploiter.execute_poc` via mock para evitar llamadas reales.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.exploiter import ActiveExploiter


@pytest.fixture
def exploiter():
    return ActiveExploiter()


def _patch_execute_poc(monkeypatch, ex, outputs):
    """Intercept execute_poc (string path) to return canned outputs in order."""
    queue = list(outputs)
    calls = []

    real = ActiveExploiter.execute_poc

    def fake(self, command_str, target_ip, timeout=60, **kwargs):
        # Re-enter real method only when command is a reactive dict or list
        if isinstance(command_str, (dict, list)):
            return real(self, command_str, target_ip, timeout=timeout, **kwargs)
        calls.append(command_str)
        if not queue:
            return {"success": False, "output": "", "error_type": "FAIL",
                    "requires_manual_verification": False}
        return queue.pop(0)

    monkeypatch.setattr(ActiveExploiter, "execute_poc", fake)
    return calls


def test_var_substitution_and_success(monkeypatch, exploiter):
    chain = {
        "steps": [
            {
                "name": "login",
                "cmd": "curl -s http://<TARGET_IP>/login -m 8",
                "save": {"SID": r"sessionid=([A-Za-z0-9]+)"},
                "abort_unless": r"(?i)(200 OK|sessionid)",
            },
            {
                "name": "rce",
                "cmd": "curl -b sess={SID} http://<TARGET_IP>/exec -m 8",
                "success_if": r"uid=\d+",
            },
        ]
    }
    outputs = [
        {"success": False, "output": "HTTP/1.1 200 OK\nSet-Cookie: sessionid=ABC123xyz",
         "error_type": "FAIL", "requires_manual_verification": False},
        {"success": True, "output": "uid=0(root) gid=0(root)",
         "error_type": "NONE", "requires_manual_verification": False,
         "discovered_credentials": []},
    ]
    calls = _patch_execute_poc(monkeypatch, exploiter, outputs)

    result = exploiter.execute_reactive_chain(chain, "10.0.0.1")

    assert result["success"] is True
    assert result["chain_vars"]["SID"] == "ABC123xyz"
    assert calls[0] == "curl -s http://10.0.0.1/login -m 8"
    assert calls[1] == "curl -b sess=ABC123xyz http://10.0.0.1/exec -m 8"


def test_abort_unless_triggers_llm_advance(monkeypatch, exploiter):
    chain = {
        "steps": [
            {
                "name": "login",
                "cmd": "curl http://<TARGET_IP>/login",
                "abort_unless": r"sessionid",
            }
        ]
    }
    outputs = [
        {"success": False, "output": "HTTP/1.1 401 Unauthorized",
         "error_type": "FAIL", "requires_manual_verification": False},
        {"success": True, "output": "uid=0",
         "error_type": "NONE", "requires_manual_verification": False},
    ]
    _patch_execute_poc(monkeypatch, exploiter, outputs)

    advance_called = {"count": 0}

    def fake_advance(cve_id, history, vars_map, last_output, cve_context):
        advance_called["count"] += 1
        assert "401" in last_output
        return {
            "name": "retry_with_basic",
            "cmd": "curl -u admin:admin http://<TARGET_IP>/login",
            "success_if": r"uid=\d+",
        }

    result = exploiter.execute_reactive_chain(
        chain, "10.0.0.1", llm_advance=fake_advance, max_advances=3,
        cve_context={"target_ip": "10.0.0.1"},
    )

    assert advance_called["count"] == 1
    assert result["success"] is True
    assert result["advances_used"] == 1


def test_abort_give_up_without_advance(monkeypatch, exploiter):
    chain = {
        "steps": [
            {
                "name": "login",
                "cmd": "curl http://<TARGET_IP>/login",
                "abort_unless": r"sessionid",
            },
            {
                "name": "exploit",
                "cmd": "curl http://<TARGET_IP>/exec",
            },
        ]
    }
    outputs = [
        {"success": False, "output": "HTTP/1.1 401 Unauthorized",
         "error_type": "FAIL", "requires_manual_verification": False},
    ]
    _patch_execute_poc(monkeypatch, exploiter, outputs)

    result = exploiter.execute_reactive_chain(chain, "10.0.0.1")

    # Without llm_advance, chain breaks after abort
    assert result["success"] is False
    assert "401" in result["output"]


def test_empty_chain_returns_fail(exploiter):
    result = exploiter.execute_reactive_chain({"steps": []}, "10.0.0.1")
    assert result["success"] is False
    assert result["error_type"] == "FAIL"


def test_global_success_if(monkeypatch, exploiter):
    chain = {
        "steps": [
            {"name": "s1", "cmd": "curl http://<TARGET_IP>/a"},
            {"name": "s2", "cmd": "curl http://<TARGET_IP>/b"},
        ],
        "success_if": r"(?i)ROOT_PWND",
    }
    outputs = [
        {"success": False, "output": "part1 normal", "error_type": "FAIL",
         "requires_manual_verification": False},
        {"success": False, "output": "part2 ROOT_PWND here", "error_type": "FAIL",
         "requires_manual_verification": False},
    ]
    _patch_execute_poc(monkeypatch, exploiter, outputs)

    result = exploiter.execute_reactive_chain(chain, "10.0.0.1")
    assert result["success"] is True


def test_max_total_steps_caps_loop(monkeypatch, exploiter):
    chain = {
        "steps": [
            {"name": "s", "cmd": "curl http://<TARGET_IP>/x",
             "abort_unless": r"NEVER_MATCHES"},
        ]
    }
    out = {"success": False, "output": "nope", "error_type": "FAIL",
           "requires_manual_verification": False}
    _patch_execute_poc(monkeypatch, exploiter, [out] * 20)

    # llm_advance always supplies a new failing step
    def fake_advance(**kwargs):
        return {
            "name": "again",
            "cmd": "curl http://<TARGET_IP>/y",
            "abort_unless": r"NEVER_MATCHES",
        }

    result = exploiter.execute_reactive_chain(
        chain, "10.0.0.1", llm_advance=fake_advance, max_advances=20,
    )
    assert result["success"] is False
    assert result["advances_used"] <= ActiveExploiter._MAX_TOTAL_STEPS


def test_legacy_list_dispatch(monkeypatch, exploiter):
    """List of alternatives still dispatches to execute_chain."""
    outputs = [
        {"success": False, "output": "fail1", "error_type": "FAIL",
         "requires_manual_verification": False},
        {"success": True, "output": "uid=0", "error_type": "NONE",
         "requires_manual_verification": False, "discovered_credentials": []},
    ]
    _patch_execute_poc(monkeypatch, exploiter, outputs)

    result = exploiter.execute_poc(
        ["curl a", "curl b"], "10.0.0.1",
    )
    assert result["success"] is True


def test_dict_dispatch_from_execute_poc(monkeypatch, exploiter):
    """execute_poc recognises dict-with-steps and forwards to reactive."""
    chain = {
        "steps": [
            {"name": "s1", "cmd": "curl http://<TARGET_IP>/",
             "success_if": r"200 OK"},
        ]
    }
    outputs = [
        {"success": False, "output": "HTTP/1.1 200 OK", "error_type": "FAIL",
         "requires_manual_verification": False},
    ]
    _patch_execute_poc(monkeypatch, exploiter, outputs)
    result = exploiter.execute_poc(chain, "10.0.0.1")
    assert result["success"] is True


def test_substitute_vars_literal():
    vars_map = {"FOO": "bar", "TOKEN": "xyz123"}
    out = ActiveExploiter._substitute_vars(
        "echo {FOO} and {TOKEN} to <TARGET_IP>", vars_map, "1.2.3.4"
    )
    assert out == "echo bar and xyz123 to 1.2.3.4"


def test_substitute_vars_missing_placeholder_preserved():
    out = ActiveExploiter._substitute_vars("echo {MISSING}", {}, "1.2.3.4")
    assert out == "echo {MISSING}"
