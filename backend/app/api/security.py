"""Local-by-default access control with optional authenticated remote mode.

Local mode: only loopback clients are served (bind 127.0.0.1) and act as the
local admin. Remote mode: every request needs `Authorization: Bearer <token>`
(WebSockets: `?token=`); tokens are matched by SHA-256 against config and map to
roles operator < investigator < engineer < admin. Serve TLS in remote mode.
"""
from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from ipaddress import ip_address

from fastapi import HTTPException, Request, WebSocket

ROLES = ["operator", "investigator", "engineer", "admin"]


@dataclass
class Principal:
    user: str
    role: str

    def allows(self, role: str) -> bool:
        return ROLES.index(self.role) >= ROLES.index(role)


def _is_loopback(host: str | None) -> bool:
    if not host:
        return False
    if host in ("localhost", "testclient"):
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def _match_token(config, token: str | None) -> Principal | None:
    if not token:
        return None
    digest = hashlib.sha256(token.encode()).hexdigest()
    for t in config.get("security.tokens", []) or []:
        if hmac.compare_digest(str(t.get("token_hash", "")), digest):
            role = t.get("role", "operator")
            return Principal(user=t.get("user", "remote"), role=role if role in ROLES else "operator")
    return None


def principal_from(config, host: str | None, auth_header: str | None, query_token: str | None = None) -> Principal:
    if not config.get("security.remote_mode", False):
        if not _is_loopback(host):
            raise HTTPException(403, detail={"type": "FORBIDDEN", "message": "local mode: only loopback clients are allowed"})
        return Principal(user="local-operator", role="admin")
    token = None
    if auth_header and auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
    token = token or query_token
    p = _match_token(config, token)
    if p is None:
        raise HTTPException(401, detail={"type": "UNAUTHORIZED", "message": "valid bearer token required in remote mode"})
    return p


_DENIED: dict[tuple, float] = {}


def record_denied(runtime, actor: str, role: str, target: str, reason: str, required: str | None = None) -> None:
    """Audit failed authorization (GAP-13), rate-limited per (actor, target, reason) so it cannot flood the log."""
    key, now = (actor, target, reason), time.monotonic()
    if now - _DENIED.get(key, -1e9) < 10:
        return
    _DENIED[key] = now
    if len(_DENIED) > 5000:
        for k in sorted(_DENIED, key=_DENIED.get)[:2500]:
            _DENIED.pop(k, None)
    audit = getattr(runtime, "audit", None)
    if audit is not None:
        try:
            audit.record("AUTHZ_DENIED", target, {"reason": reason, "required_role": required}, actor, role)
        except Exception:
            pass


def require(role: str):
    def dep(request: Request) -> Principal:
        runtime = request.app.state.runtime
        host = request.client.host if request.client else None
        try:
            p = principal_from(runtime.config, host, request.headers.get("authorization"))
        except HTTPException as exc:
            record_denied(runtime, f"anonymous@{host}", "none", f"{request.method} {request.url.path}",
                          (exc.detail or {}).get("type", "DENIED") if isinstance(exc.detail, dict) else "DENIED", role)
            raise
        if not p.allows(role):
            record_denied(runtime, p.user, p.role, f"{request.method} {request.url.path}", "INSUFFICIENT_ROLE", role)
            raise HTTPException(403, detail={"type": "FORBIDDEN", "message": f"requires role '{role}' (you are '{p.role}')"})
        request.state.principal = p
        return p
    return dep


def ws_principal(ws: WebSocket, config) -> Principal:
    return principal_from(config, ws.client.host if ws.client else None, ws.headers.get("authorization"), ws.query_params.get("token"))
