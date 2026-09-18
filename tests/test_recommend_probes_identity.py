"""recommend_probes no debe heredar identidad por IP: si la MAC del escaneo
difiere de la del registro KB de esa IP, es otro dispositivo (IP reutilizada) y
su histórico (vendor/probes) NO debe inyectarse al agente. Regresión: un iPhone
en la IP que tuvo la LG TV era tratado como LG WebOS.
"""
import core.tools as t


class _FakeKB:
    def __init__(self, record, vp=None):
        self._rec, self._vp = record, vp or {}

    def get_device_record(self, ip=None, *, mac=None, firmware=None):
        # Fake "legado": devuelve el registro LG ignorando la MAC, para ejercitar
        # la defensa en profundidad del guard (descartar si la MAC no coincide).
        return self._rec

    def get_vendor_profile(self, vendor):
        return self._vp


_LG_REC = {"vendor": "LG", "model": "65QNED826RE", "firmware": "p20.33.31.23",
           "mac": "14:7F:67:AF:0C:6A", "audit_count": 19, "findings_count_last": 8}
_LG_VP = {"useful_probes": ["probe_lg_webos", "probe_mdns"], "patched_cves": [],
          "device_count": 1}


def _bind(monkeypatch, scan_mac):
    import core.knowledge_base as kbmod
    monkeypatch.setattr(kbmod, "get_kb", lambda: _FakeKB(_LG_REC, _LG_VP))
    sess = t.AgentSession(target_ip="192.168.1.33")
    sess.scan_cache = {"ip": "192.168.1.33", "mac": scan_mac}
    t.bind_session(sess)


def test_no_inherit_when_mac_differs(monkeypatch):
    _bind(monkeypatch, "2E:F5:E7:FA:84:20")   # iPhone, distinta de LG
    res = t._recommend_probes({"ports": [{"port": 3000, "proto": "tcp"},
                                         {"port": 62078, "proto": "tcp"}]})
    assert "kb_context" not in res             # no se filtra la LG
    assert all("[KB:" not in r.get("reason", "") for r in res["recommendations"])
    assert "patched para" not in res["instruction"]


def test_inherit_when_mac_matches(monkeypatch):
    _bind(monkeypatch, "14:7F:67:AF:0C:6A")    # misma MAC = misma LG
    res = t._recommend_probes({"ports": [{"port": 3000, "proto": "tcp"}]})
    assert "kb_context" in res
    assert res["kb_context"]["previous_audit"]["vendor"] == "LG"
