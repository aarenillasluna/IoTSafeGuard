"""Fallback online de OUI: cuando la lib local no conoce la OUI (p. ej. Tuya
B8:06:0D), se resuelve por API pública en vez de quedar 'exhausted' — evitando
que el agente se fíe del fingerprint de SO de nmap (que misidentifica IoT).
"""
import io
import core.tools as t


class _Resp(io.BytesIO):
    status = 200
    def __enter__(self): return self
    def __exit__(self, *a): self.close()


def test_online_lookup_parses_vendor(monkeypatch):
    t._OUI_ONLINE_CACHE.clear()
    monkeypatch.setattr("urllib.request.urlopen",
                        lambda req, timeout=4: _Resp(b"Tuya Smart Inc."))
    assert t._oui_online_lookup("B8:06:0D:28:1F:64") == "Tuya Smart Inc."


def test_online_lookup_rejects_html_and_caches(monkeypatch):
    t._OUI_ONLINE_CACHE.clear()
    calls = {"n": 0}
    def fake(req, timeout=4):
        calls["n"] += 1
        return _Resp(b"<html>error</html>")
    monkeypatch.setattr("urllib.request.urlopen", fake)
    assert t._oui_online_lookup("AA:BB:CC:00:00:00") is None
    assert t._oui_online_lookup("AA:BB:CC:11:22:33") is None   # mismo OUI → cache
    assert calls["n"] == 1                                     # solo 1 petición


def test_online_lookup_tolerates_network_error(monkeypatch):
    t._OUI_ONLINE_CACHE.clear()
    def boom(req, timeout=4):
        raise OSError("network down")
    monkeypatch.setattr("urllib.request.urlopen", boom)
    assert t._oui_online_lookup("DE:AD:BE:00:00:00") is None   # no crashea


class _FakeMacLookup:
    def lookup(self, mac):
        raise KeyError("OUI desconocida en la lib local")
    def update_vendors(self):
        raise OSError("sin red para update")


def test_mac_vendor_falls_through_to_online(monkeypatch):
    t._OUI_ONLINE_CACHE.clear()
    import mac_vendor_lookup
    monkeypatch.setattr(mac_vendor_lookup, "MacLookup", _FakeMacLookup)
    monkeypatch.setattr(t, "_oui_fallback_lookup", lambda mac: None)   # no en tabla estática
    monkeypatch.setattr(t, "_oui_online_lookup", lambda mac: "Tuya Smart Inc.")
    monkeypatch.setattr(t, "_MAC_VENDORS_UPDATED", True)               # salta el update
    r = t._mac_vendor({"mac": "B8:06:0D:28:1F:64"})
    assert r["ok"] is True and r["vendor"] == "Tuya Smart Inc."
    assert r["source"] == "oui_online_api"


def test_mac_vendor_exhausted_when_online_also_fails(monkeypatch):
    t._OUI_ONLINE_CACHE.clear()
    import mac_vendor_lookup
    monkeypatch.setattr(mac_vendor_lookup, "MacLookup", _FakeMacLookup)
    monkeypatch.setattr(t, "_oui_fallback_lookup", lambda mac: None)
    monkeypatch.setattr(t, "_oui_online_lookup", lambda mac: None)
    monkeypatch.setattr(t, "_MAC_VENDORS_UPDATED", True)
    r = t._mac_vendor({"mac": "00:11:22:33:44:55"})
    assert r["ok"] is False and r["source"] == "exhausted"


# ---------------------------------------------------------------------------
# Fallback OUI estático (tabla local _OUI_FALLBACK)
# (consolidado aquí desde test_coverage_improvements.py — iter_08)
# ---------------------------------------------------------------------------
class TestMacVendorFallback:

    def test_lg_innotek_resolved_via_static_fallback(self):
        t.build_registry()
        # 14:7F:67 está en _OUI_FALLBACK
        r = t.dispatch("mac_vendor_lookup", {"mac": "14:7F:67:AF:0C:6A"})
        assert r["ok"] is True
        assert "LG" in r["vendor"]
        # Source debe ser fallback estático o lookup actualizado (cualquier éxito vale)
        assert r.get("source") in (
            "oui_static_fallback", "mac_vendor_lookup", "mac_vendor_lookup_updated"
        )

    def test_unknown_oui_returns_error(self):
        t.build_registry()
        # OUI inventada
        r = t.dispatch("mac_vendor_lookup", {"mac": "ZZ:ZZ:ZZ:00:00:00"})
        assert r["ok"] is False
