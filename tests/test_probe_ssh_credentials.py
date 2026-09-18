"""probe_ssh_credentials: auth SSH real vía cliente del sistema (mecánica
`_ssh_password_login` mockeada). Cubre la política (anti-lockout, confirmación,
abort) y que el comando ssh incluye crypto legada para IoT.
"""
import modules.iot_probes as ip_mod
from modules.iot_probes import probe_ssh_credentials, _ssh_command


def _patch_login(monkeypatch, responder):
    monkeypatch.setattr(ip_mod, "_ssh_password_login",
                        lambda ip, port, user, pw, timeout, verify_cmd:
                        responder(user, pw))


def test_default_creds_confirmed(monkeypatch):
    def responder(user, pw):
        if (user, pw) == ("root", "root"):
            return {"status": "success", "evidence": "uid=0(root)\nLinux router 2.6.31"}
        return {"status": "auth_failed", "evidence": ""}
    _patch_login(monkeypatch, responder)
    r = probe_ssh_credentials("10.0.0.1", delay=0)
    assert r["ok"] and r["protocol_confirmed"]
    v = r["vulnerabilities"]
    assert len(v) == 1 and v[0]["id"] == "SSH-DEFAULT-CREDS"
    assert v[0]["severity"] == "CRITICAL" and v[0]["impact"] == "REMOTE_SHELL"
    assert "uid=0(root)" in v[0]["evidence"]
    assert r["credentials"] == [
        {"service": "ssh", "username": "root", "password": "root", "port": 22}]
    assert r["details"]["attempts"] == 1            # para en el 1er éxito


def test_no_creds_match_respects_cap(monkeypatch):
    _patch_login(monkeypatch, lambda u, p: {"status": "auth_failed", "evidence": ""})
    r = probe_ssh_credentials("10.0.0.1", delay=0, max_attempts=5)
    assert r["ok"] and r["protocol_confirmed"]
    assert r["vulnerabilities"] == [] and r["credentials"] == []
    assert r["details"]["attempts"] == 5            # anti-lockout: tope
    assert "none of the" in r["details"]["result"]


def test_pairs_take_priority(monkeypatch):
    _patch_login(monkeypatch, lambda u, p:
                 {"status": "success", "evidence": "ok"} if (u, p) == ("svc", "s3cr3t")
                 else {"status": "auth_failed", "evidence": ""})
    r = probe_ssh_credentials("10.0.0.1", delay=0, pairs=[["svc", "s3cr3t"]])
    assert r["vulnerabilities"][0]["id"] == "SSH-DEFAULT-CREDS"
    assert r["credentials"][0]["username"] == "svc"


def test_unreachable_aborts(monkeypatch):
    _patch_login(monkeypatch, lambda u, p:
                 {"status": "unreachable", "evidence": "no matching host key"})
    r = probe_ssh_credentials("10.0.0.1", delay=0)
    assert r["error"] and r["details"].get("attempts", 0) <= 1   # no machaca


def test_no_client_reports_error(monkeypatch):
    _patch_login(monkeypatch, lambda u, p: {"status": "no_client", "evidence": ""})
    r = probe_ssh_credentials("10.0.0.1", delay=0)
    assert r["ok"] is False and "ssh" in r["error"].lower()


def test_ssh_command_includes_legacy_crypto():
    cmd = _ssh_command("1.2.3.4", 22, "root", 6, "id")
    assert cmd is not None
    joined = " ".join(cmd)
    assert "HostKeyAlgorithms=+ssh-rsa" in joined          # host key legado
    assert "PubkeyAuthentication=no" in joined             # solo password
    assert "NumberOfPasswordPrompts=1" in joined           # anti-lockout
    assert joined.endswith("root@1.2.3.4 id")


def test_registered_in_exploit_phase():
    import core.tools as t
    tool = t._REGISTRY.get("probe_ssh_credentials")
    assert tool is not None and "exploit" in tool.phases
