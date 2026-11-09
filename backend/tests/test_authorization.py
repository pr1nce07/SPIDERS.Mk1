"""GAP-13 / V-021: server-side authorization, independent of the UI's role selector."""
import copy
import hashlib
import re
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import app.main as M
from app.api import security as S
from app.config import Config
from app.security.keys import KeyStore

ROLES = ["operator", "investigator", "engineer", "admin"]
TOKENS = {r: f"token-{r}-0123456789" for r in ROLES}

# Minimum role for sensitive operations (blueprint GAP-13 item 2). Anything not listed must still need ≥ operator.
SENSITIVE = {
    ("POST", "/api/rules"): "engineer", ("POST", "/api/rules/publish"): "engineer",
    ("PUT", "/api/settings"): "engineer",
    ("POST", "/api/security/mavlink-keys"): "engineer", ("POST", "/api/security/mavlink-keys/{key_id}/activate"): "engineer",
    ("POST", "/api/security/mavlink-keys/{key_id}/revoke"): "engineer", ("POST", "/api/security/mavlink-keys/{key_id}/export"): "engineer",
    ("POST", "/api/baseline/approve"): "engineer", ("POST", "/api/audit/checkpoint"): "engineer",
    ("POST", "/api/forensics/verify"): "investigator", ("GET", "/api/forensics/cases/{case_id}/export"): "investigator",
    ("POST", "/api/forensics/cases/{case_id}/custody"): "investigator", ("POST", "/api/forensics/snapshot"): "investigator",
    ("POST", "/api/incidents/{incident_id}/status"): "investigator", ("GET", "/api/audit"): "investigator",
    ("GET", "/api/security/keys"): "investigator", ("POST", "/api/silktrace/evidence"): "investigator",
}


def _routes():
    for r in M.app.routes:
        if isinstance(r, APIRoute) and r.path.startswith("/api"):
            req = [d.call.__closure__[0].cell_contents for d in r.dependant.dependencies
                   if getattr(d.call, "__qualname__", "").startswith("require.")]
            for m in r.methods:
                yield m, r.path, (req[0] if req else None)


ALL = list(_routes())


class _Audit:
    def __init__(self):
        self.rows = []

    def record(self, action, target="", detail=None, actor="?", role="?"):
        self.rows.append({"action": action, "target": target, "detail": detail or {}, "actor": actor, "role": role})
        return self.rows[-1]


@pytest.fixture
def client(tmp_path):
    cfg = Config.load()
    cfg.data = copy.deepcopy(cfg.data)
    cfg.data["security"]["remote_mode"] = True
    cfg.data["security"]["tokens"] = [{"token_hash": hashlib.sha256(t.encode()).hexdigest(), "role": r, "user": f"{r}-user"}
                                      for r, t in TOKENS.items()]
    S._DENIED.clear()
    rt = SimpleNamespace(config=cfg, audit=_Audit(), keys=KeyStore(tmp_path / "keys"), signing_key_id=None,
                         errors=SimpleNamespace(record=lambda *a, **k: {"type": a[1] if len(a) > 1 else "ERR", "message": ""}),
                         active=None, capabilities={}, dirs={"audit": tmp_path})
    old = getattr(M.app.state, "runtime", None)
    M.app.state.runtime = rt
    try:
        yield TestClient(M.app), rt
    finally:
        M.app.state.runtime = old


def _hdr(role):
    return {"Authorization": f"Bearer {TOKENS[role]}"} if role else {}


def _url(path):
    return re.sub(r"\{[^}]+\}", "X-1", path)


def test_every_api_route_requires_a_role():
    assert ALL and all(req is not None for _, _, req in ALL), [x for x in ALL if x[2] is None]


@pytest.mark.parametrize("method,path,minimum", [(m, p, r) for (m, p), r in SENSITIVE.items()])
def test_sensitive_routes_declare_their_minimum_role(method, path, minimum):
    declared = {(m, p): r for m, p, r in ALL}
    assert (method, path) in declared, f"route missing: {method} {path}"
    assert ROLES.index(declared[(method, path)]) >= ROLES.index(minimum)


@pytest.mark.parametrize("method,path,req", [x for x in ALL if x[0] != "GET"])
def test_mutating_routes_reject_missing_token_and_lower_roles(client, method, path, req):
    c, rt = client
    url = _url(path)
    assert c.request(method, url, json={}).status_code == 401
    for role in ROLES[:ROLES.index(req)]:
        res = c.request(method, url, json={}, headers=_hdr(role))
        assert res.status_code == 403, (method, path, role, res.status_code, res.text[:200])


def test_denials_are_audited_and_rate_limited(client):
    c, rt = client
    for _ in range(5):
        c.post("/api/audit/checkpoint", headers=_hdr("investigator"))
    denied = [r for r in rt.audit.rows if r["action"] == "AUTHZ_DENIED"]
    assert len(denied) == 1 and denied[0]["actor"] == "investigator-user" and denied[0]["detail"]["required_role"] == "engineer"
    c.post("/api/audit/checkpoint")
    assert any(r["actor"].startswith("anonymous@") for r in rt.audit.rows if r["action"] == "AUTHZ_DENIED")


def test_operator_cannot_resolve_alerts(client):
    c, rt = client
    res = c.post("/api/ids/events/A-1/status", json={"status": "FALSE_POSITIVE"}, headers=_hdr("operator"))
    assert res.status_code == 403
    assert any(r["action"] == "AUTHZ_DENIED" and "FALSE_POSITIVE" in r["target"] for r in rt.audit.rows)


def test_engineer_key_view_never_contains_secrets(client):
    c, rt = client
    kid = rt.keys.generate_mavlink_key("engineer-user")["key_id"]
    res = c.get("/api/security/keys", headers=_hdr("engineer"))
    assert res.status_code == 200
    assert rt.keys.secret(kid).hex() not in res.text and res.json()["mavlink"]["keys"][0]["key_id"] == kid
    assert c.get("/api/security/keys", headers=_hdr("operator")).status_code == 403


def test_websocket_requires_token_in_remote_mode(client):
    c, rt = client
    with pytest.raises(WebSocketDisconnect) as e:
        with c.websocket_connect("/ws/telemetry") as ws:
            ws.receive_text()
    assert e.value.code == 4401
    assert any(r["target"] == "WS /ws/telemetry" for r in rt.audit.rows)


def test_local_mode_refuses_non_loopback_clients():
    cfg = Config.load()
    with pytest.raises(HTTPException) as e:
        S.principal_from(cfg, "192.168.1.50", None)
    assert e.value.status_code == 403
    assert S.principal_from(cfg, "127.0.0.1", None).role == "admin"
