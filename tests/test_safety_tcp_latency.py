"""Regresión (iter_10): el SafetyMonitor debe medir la degradación del objetivo
también cuando ICMP está bloqueado (caso real: Amazon Echo y muchos IoT con
firewall que descartan ping). El fallback TCP `_check_tcp` confirma vitalidad y
**registra la latencia del connect**, de modo que `is_degraded()` no queda ciego
sin ICMP.
"""
import core.safety_monitor as sm
from core.safety_monitor import SafetyMonitorV2


def test_tcp_check_feeds_latency(monkeypatch):
    mon = SafetyMonitorV2(target_ip="10.0.0.5", open_ports=[1080],
                          latency_threshold_ms=2000.0)

    # Simula un connect TCP lento (1.2s) sin tocar la red real.
    class _FakeConn:
        def __enter__(self): return self
        def __exit__(self, *a): return False

    t = {"now": 0.0}
    monkeypatch.setattr(sm.time, "time", lambda: t["now"])

    def fake_connect(addr, timeout=2):
        t["now"] += 1.2          # el connect "tarda" 1.2 s
        return _FakeConn()

    monkeypatch.setattr(sm.socket, "create_connection", fake_connect)

    assert mon._check_tcp() is True
    # La latencia del connect quedó registrada (≈1200 ms), no vacía.
    assert len(mon._latencies) == 1
    assert 1100 <= mon._latencies[0] <= 1300


def test_tcp_latency_can_trigger_degradation_without_icmp(monkeypatch):
    mon = SafetyMonitorV2(target_ip="10.0.0.5", open_ports=[1080],
                          latency_threshold_ms=2000.0, degradation_window=3)
    # ICMP siempre falla (host bloquea ping).
    monkeypatch.setattr(mon, "_check_icmp", lambda: False)

    class _FakeConn:
        def __enter__(self): return self
        def __exit__(self, *a): return False

    t = {"now": 0.0}
    monkeypatch.setattr(sm.time, "time", lambda: t["now"])

    def slow_connect(addr, timeout=2):
        t["now"] += 3.0          # 3 s por connect → por encima del umbral
        return _FakeConn()

    monkeypatch.setattr(sm.socket, "create_connection", slow_connect)

    # Varias comprobaciones de salud alimentan latencias TCP altas…
    for _ in range(3):
        mon._check_tcp()
    # …y la degradación se detecta pese a no tener ICMP.
    assert mon.is_degraded() is True


def test_tcp_no_open_ports_returns_false():
    mon = SafetyMonitorV2(target_ip="10.0.0.5", open_ports=[])
    assert mon._check_tcp() is False
    assert len(mon._latencies) == 0
