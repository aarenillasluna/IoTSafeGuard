"""
Tests para core/agent_guards.py — RepetitionDetector + validation hints.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.agent_guards import (
    RepetitionDetector,
    _hash_call,
    build_repetition_warning,
    build_validation_hint,
    looks_like_validation_error,
)


class TestHashCall:

    @pytest.mark.parametrize("call_a,call_b,same", [
        # misma llamada → mismo hash (es lo que detecta la repetición)
        (("nmap_scan", {"ip": "1.2.3.4", "ports": "80"}),
         ("nmap_scan", {"ip": "1.2.3.4", "ports": "80"}), True),
        # el orden de los args no cambia la identidad de la llamada
        (("nmap_scan", {"ip": "1.2.3.4", "ports": "80"}),
         ("nmap_scan", {"ports": "80", "ip": "1.2.3.4"}), True),
        # herramienta distinta → llamada distinta
        (("nmap_scan", {"ip": "1.2.3.4"}), ("cve_search", {"ip": "1.2.3.4"}), False),
        # argumento distinto → llamada distinta (si no, se bloquearía un reintento
        # legítimo contra otro objetivo)
        (("nmap_scan", {"ip": "1.2.3.4"}), ("nmap_scan", {"ip": "1.2.3.5"}), False),
    ])
    def test_call_identity(self, call_a, call_b, same):
        assert (_hash_call(*call_a) == _hash_call(*call_b)) is same

    def test_handles_none_args(self):
        a = _hash_call("done", None)
        b = _hash_call("done", {})
        assert a == b


class TestRepetitionDetector:

    def test_first_call_does_not_trigger(self):
        det = RepetitionDetector(threshold=3)
        assert det.observe("nmap_scan", {"ip": "1.1.1.1"}) is False
        assert det.consecutive == 1

    def test_below_threshold_no_trigger(self):
        det = RepetitionDetector(threshold=3)
        det.observe("x", {"a": 1})
        triggered = det.observe("x", {"a": 1})
        assert triggered is False
        assert det.consecutive == 2

    def test_at_threshold_triggers(self):
        det = RepetitionDetector(threshold=3)
        det.observe("x", {"a": 1})
        det.observe("x", {"a": 1})
        triggered = det.observe("x", {"a": 1})
        assert triggered is True
        assert det.consecutive == 3

    def test_different_call_resets_counter(self):
        det = RepetitionDetector(threshold=3)
        det.observe("x", {"a": 1})
        det.observe("x", {"a": 1})
        det.observe("y", {"a": 1})  # diferente tool
        assert det.consecutive == 1

    def test_different_args_resets_counter(self):
        det = RepetitionDetector(threshold=3)
        det.observe("x", {"a": 1})
        det.observe("x", {"a": 1})
        det.observe("x", {"a": 2})
        assert det.consecutive == 1

    def test_history_capped_at_50(self):
        det = RepetitionDetector(threshold=99)
        for i in range(100):
            det.observe("tool", {"i": i})
        assert len(det.history) == 50

    def test_reset_clears_state(self):
        det = RepetitionDetector(threshold=3)
        det.observe("x", {"a": 1})
        det.observe("x", {"a": 1})
        det.reset()
        assert det.consecutive == 0
        assert det.last_hash is None

    def test_continues_to_trigger_after_threshold(self):
        det = RepetitionDetector(threshold=3)
        det.observe("x", {"a": 1})
        det.observe("x", {"a": 1})
        assert det.observe("x", {"a": 1}) is True
        assert det.observe("x", {"a": 1}) is True  # 4ª también dispara


class TestLooksLikeValidationError:

    def test_ok_true_is_not_validation(self):
        assert looks_like_validation_error({"ok": True, "error": "x"}) is False

    def test_unknown_tool_is_validation(self):
        assert looks_like_validation_error(
            {"error": "unknown tool 'foo'", "available": []}
        ) is True

    @pytest.mark.parametrize("result", [
        {"error": "missing required arg ip"},
        {"error": "invalid type for ports"},
        {"error_type": "VALIDATION"},
        {"error_type": "bad_args"},
    ])
    def test_argument_errors_are_recognised(self, result):
        """Distinguir "args mal formados" de "fallo real" es lo que permite al
        agente reintentar UNA vez con los args corregidos en lugar de abandonar."""
        assert looks_like_validation_error(result) is True

    def test_generic_runtime_error_is_not_validation(self):
        # un fallo de red no es validation
        assert looks_like_validation_error(
            {"ok": False, "error_type": "NETWORK", "error": "connection refused"}
        ) is False

    def test_non_dict_returns_false(self):
        assert looks_like_validation_error("nope") is False  # type: ignore
        assert looks_like_validation_error(None) is False  # type: ignore


class TestBuildValidationHint:

    def test_includes_tool_name(self):
        hint = build_validation_hint("nmap_scan", {"ip": "1.1.1.1"}, {"error": "missing port"})
        assert "nmap_scan" in hint

    def test_includes_arg_keys(self):
        hint = build_validation_hint(
            "cve_search",
            {"vendor": "x", "model": "y"},
            {"error_type": "VALIDATION"},
        )
        assert "vendor" in hint
        assert "model" in hint

    def test_warns_against_repeating(self):
        # El texto va al contexto del modelo y está en inglés (§4.4); lo que se
        # comprueba es la instrucción, no el idioma en que se dé.
        hint = build_validation_hint("foo", {}, {"error": "missing"})
        assert "do not repeat" in hint.lower()


class TestBuildRepetitionWarning:

    def test_contains_tool_name_and_count(self):
        msg = build_repetition_warning("nmap_scan", {"ip": "1.1.1.1"}, 3)
        assert "nmap_scan" in msg
        assert "3" in msg

    def test_suggests_alternative(self):
        msg = build_repetition_warning("foo", {}, 5)
        assert "change strategy" in msg.lower()
