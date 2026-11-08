"""Local-by-default access control with optional authenticated remote mode.

Local mode: only loopback clients are served (bind 127.0.0.1) and act as the
local admin. Remote mode: every request needs `Authorization: Bearer <token>`
(WebSockets: `?token=`); tokens are matched by SHA-256 against config and map to
roles operator < investigator < engineer < admin. Serve TLS in remote mode.
"""
from __future__ import annotations

import hashlib
import hmac
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


def require(role: str):
    def dep(request: Request) -> Principal:
        cfg = request.app.state.runtime.config
        p = principal_from(cfg, request.client.host if request.client else None, request.headers.get("authorization"))
        if not p.allows(role):
            raise HTTPException(403, detail={"type": "FORBIDDEN", "message": f"requires role '{role}' (you are '{p.role}')"})
        request.state.principal = p
        return p
    return dep


def ws_principal(ws: WebSocket, config) -> Principal:
    return principal_from(config, ws.client.host if ws.client else None, ws.headers.get("authorization"), ws.query_params.get("token"))
