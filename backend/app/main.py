"""SPIDERS.Mk1 — FastAPI application (REST + WebSocket).

Read-only by default: there is no endpoint that sends MAVLink to a vehicle.
"""
from __future__ import annotations

import asyncio
import json
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import and_, desc, select

from .api import queries as Q
from .api.security import Principal, require, ws_principal
from .config import PROJECT_ROOT, Config
from .core.runtime import VERSION, Runtime
from .forensic.hashing import sha256_file, verify_case
from .forensic.snapshot import SnapshotManager
from .ids.rules import catalog as rule_catalog
from .ids.rules import validate_rule
from .ids.rule_store import _definition
from .models.events import utc_now_iso
from .sources.simulation import scenario_list
from .storage import db as D

config = Config.load()


@asynccontextmanager
async def lifespan(app: FastAPI):
    rt = Runtime(config)
    app.state.runtime = rt
    await rt.start()
    try:
        yield
    finally:
        await rt.shutdown()


app = FastAPI(title="SPIDERS.Mk1", version=VERSION, lifespan=lifespan,
              description="Security Packet Intrusion Detection Evaluation and Response System. Ground Control + Distributed IDS + Incident Correlation + Forensic Evidence + Custom Ruleset builder. Read-only by default.")

MAX_JSON = 2 * 1024 * 1024


@app.middleware("http")
async def bounded_payloads(request: Request, call_next):
    cl = request.headers.get("content-length")
    limit = int(config.get("limits.max_upload_mb", 1024)) * (1 << 20) if request.url.path == "/api/logs/import" or "screenshot" in request.url.path else MAX_JSON
    if cl and cl.isdigit() and int(cl) > limit:
        return JSONResponse({"error_id": None, "type": "PAYLOAD_TOO_LARGE", "message": f"request body exceeds {limit} bytes"}, status_code=413)
    return await call_next(request)


def rt(request: Request) -> Runtime:
    return request.app.state.runtime


@app.exception_handler(HTTPException)
async def http_exc(request: Request, exc: HTTPException):
    d = exc.detail if isinstance(exc.detail, dict) else {"type": "HTTP_ERROR", "message": str(exc.detail)}
    return JSONResponse({"error_id": None, "component": "API", "recoverable": True, "timestamp": utc_now_iso(), **d}, status_code=exc.status_code)


@app.exception_handler(RequestValidationError)
async def val_exc(request: Request, exc: RequestValidationError):
    return JSONResponse({"error_id": None, "component": "API", "type": "INVALID_INPUT", "message": "request validation failed",
                         "details": [{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors()][:20], "recoverable": True,
                         "timestamp": utc_now_iso()}, status_code=422)


@app.exception_handler(Exception)
async def any_exc(request: Request, exc: Exception):
    r: Runtime = request.app.state.runtime
    if isinstance(exc, (ValueError, KeyError, FileNotFoundError, RuntimeError, FileExistsError)):
        code = 404 if isinstance(exc, (KeyError, FileNotFoundError)) else 409 if isinstance(exc, (RuntimeError, FileExistsError)) else 400
        err = r.errors.record("API", type(exc).__name__.upper(), str(exc), recoverable=True)
        return JSONResponse({k: v for k, v in err.items() if k != "_detail"}, status_code=code)
    err = r.errors.record("API", "INTERNAL_ERROR", f"{type(exc).__name__}: {exc}", recoverable=True, exc=exc)
    return JSONResponse({**{k: v for k, v in err.items() if k != "_detail"}, "message": "internal error (details available in engineer mode)"}, status_code=500)


VIEW = Depends(require("operator"))
OPERATE = Depends(require("operator"))
INVESTIGATE = Depends(require("investigator"))
ENGINEER = Depends(require("engineer"))


def actor(request: Request) -> tuple[str, str]:
    p: Principal = getattr(request.state, "principal", Principal("local-operator", "admin"))
    return p.user, p.role


# ====================================================================== health / meta
@app.get("/api/health")
def health(request: Request, _=VIEW):
    return rt(request).health()


@app.get("/api/capabilities")
def capabilities(request: Request, _=VIEW):
    return rt(request).capabilities


@app.get("/api/meta")
def meta(request: Request, _=VIEW):
    r = rt(request)
    p: Principal = request.state.principal
    return {"version": VERSION, "read_only": bool(r.config.get("security.read_only", True)), "user": p.user, "role": p.role,
            "remote_mode": bool(r.config.get("security.remote_mode", False)), "update_hz": r.config.get("gui.update_hz", 10),
            "dialect": r.registry.dialect_name, "custom_dialect": bool(r.config.get("mavlink.dialect_xml")),
            "scenarios": scenario_list(), "severities": ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
            "forensics": {"pre_event_seconds": r.config.get("forensics.pre_event_seconds"), "post_event_seconds": r.config.get("forensics.post_event_seconds")}}


# ====================================================================== vehicle / telemetry
@app.get("/api/vehicle")
@app.get("/api/telemetry/current")
def vehicle(request: Request, _=VIEW):
    return rt(request).telemetry_snapshot()


@app.get("/api/telemetry/history")
def telemetry_history(request: Request, session_id: Optional[str] = None, fields: str = "gps_speed,ekf_speed,groundspeed,altitude_rel",
                      max_points: int = Query(1500, le=10000), _=VIEW):
    r = rt(request)
    sid = session_id or (r.active.session_id if r.active else None)
    if not sid:
        return {"session_id": None, "series": {}}
    return {"session_id": sid, "series": Q.series(r, sid, [f for f in fields.split(",") if f], max_points)}


@app.get("/api/telemetry/track")
def telemetry_track(request: Request, session_id: Optional[str] = None, kind: str = "EKF", t_from: Optional[float] = None,
                    t_to: Optional[float] = None, _=VIEW):
    r = rt(request)
    sid = session_id or (r.active.session_id if r.active else None)
    return {"session_id": sid, "points": Q.track_points(r, sid, t_from, t_to, kind) if sid else []}


# ====================================================================== MAVLink
@app.get("/api/mavlink/registry")
def mavlink_registry(request: Request, _=VIEW):
    return rt(request).registry.catalog()


@app.get("/api/mavlink/messages")
def mavlink_messages(request: Request, session_id: Optional[str] = None, msg: Optional[str] = None, sysid: Optional[int] = None,
                     compid: Optional[int] = None, q: Optional[str] = None, after_idx: Optional[int] = None,
                     before_idx: Optional[int] = None, t_from: Optional[float] = None, t_to: Optional[float] = None,
                     errors_only: bool = False, limit: int = Query(500, le=5000), _=VIEW):
    r = rt(request)
    sid = session_id or (r.active.session_id if r.active else None)
    if not sid:
        return {"session_id": None, "messages": []}
    return {"session_id": sid, "messages": Q.packets(r, sid, msg, sysid, compid, q, after_idx, before_idx, t_from, t_to, errors_only, limit)}


@app.get("/api/mavlink/messages/{session_id}/{idx}")
def mavlink_message(request: Request, session_id: str, idx: int, _=VIEW):
    r = rt(request)
    p = Q.packet(r, session_id, idx)
    if not p:
        raise HTTPException(404, detail={"type": "NOT_FOUND", "message": f"packet {idx} not found in {session_id}"})
    raw = bytes.fromhex(p["raw_hex"]) if p.get("raw_hex") else b""
    hdr = {}
    if raw[:1] == b"\xfd" and len(raw) >= 10:
        hdr = {"magic": "0xFD (MAVLink 2)", "payload_len": raw[1], "incompat_flags": raw[2], "compat_flags": raw[3], "seq": raw[4],
               "sysid": raw[5], "compid": raw[6], "msgid": raw[7] | raw[8] << 8 | raw[9] << 16, "signed": bool(raw[2] & 1),
               "signature_hex": raw[-13:].hex() if raw[2] & 1 else None}
    elif raw[:1] == b"\xfe" and len(raw) >= 6:
        hdr = {"magic": "0xFE (MAVLink 1)", "payload_len": raw[1], "seq": raw[2], "sysid": raw[3], "compid": raw[4], "msgid": raw[5]}
    if hdr.get("signature_hex"):
        hdr["signature_note"] = "13-byte signature block (link id, 48-bit timestamp, 48-bit signature). The secret key is never displayed."
    info = r.registry.message_info(r.registry.by_name[p["msg"]]) if p.get("msg") in r.registry.by_name else None
    return {**p, "header": hdr, "definition": info}


@app.get("/api/mavlink/sources")
def mavlink_sources(request: Request, session_id: Optional[str] = None, _=VIEW):
    r = rt(request)
    sess = r.active
    sid = session_id or (sess.session_id if sess else None)
    out = {"session_id": sid, "sources": Q.sources_table(r, sid) if sid else []}
    if sess and sess.session_id == sid:
        seq = sess.pipeline.engine.get("MAVLINK_SEQUENCE")
        sig = sess.pipeline.engine.get("MAVLINK_SIGNING")
        out["sequence"] = seq.summary() if seq else []
        out["signing"] = sig.table() if sig else []
        out["signing_note"] = "MAVLink 2 signing authenticates frames; it does not encrypt telemetry."
        out["decoders"] = {k: {"decoded": d.decoded, "bad": d.bad, **d.signing_counters()} for k, d in sess.pipeline.decoders.items()}
    return out


# ====================================================================== IDS
@app.get("/api/ids")
def ids(request: Request, _=VIEW):
    return rt(request).ids_snapshot()


@app.get("/api/ids/detectors")
def ids_detectors(request: Request, _=VIEW):
    r = rt(request)
    if r.active:
        return r.active.pipeline.engine.health(r.active.pipeline.ctx)
    from .ids.engine import IDSEngine
    return IDSEngine(r.config, r.errors, r.registry).health()


class DetectorToggle(BaseModel):
    enabled: bool


@app.post("/api/ids/detectors/{det_id}")
def ids_detector_toggle(request: Request, det_id: str, body: DetectorToggle, _=ENGINEER):
    r = rt(request)
    if not r.active or not r.active.pipeline.engine.set_enabled(det_id, body.enabled):
        raise HTTPException(404, detail={"type": "NOT_FOUND", "message": "no active session or unknown detector"})
    r.audit.record("DETECTOR_ENABLED" if body.enabled else "DETECTOR_DISABLED", det_id, {}, *actor(request))
    return {"detector": det_id, "enabled": body.enabled}


class FaultBody(BaseModel):
    detector: str
    enabled: bool = True


@app.post("/api/ids/fault-injection")
def fault_injection(request: Request, body: FaultBody, _=ENGINEER):
    """Failure testing (§102): make one detector raise; the rest of the system must keep running."""
    r = rt(request)
    if not r.active:
        raise HTTPException(409, detail={"type": "NO_SESSION", "message": "no active session"})
    fi = r.active.pipeline.engine.fault_injection
    (fi.add if body.enabled else fi.discard)(body.detector)
    r.audit.record("FAULT_INJECTION", body.detector, {"enabled": body.enabled}, *actor(request))
    return {"fault_injection": sorted(fi)}


@app.get("/api/ids/comparison")
def ids_comparison(request: Request, _=VIEW):
    r = rt(request)
    return r.fc_ground_comparison(r.active.pipeline if r.active else None)


@app.get("/api/ids/events")
def ids_events(request: Request, session_id: Optional[str] = None, detector: Optional[str] = None, severity: Optional[str] = None,
               source: Optional[str] = None, status: Optional[str] = None, state: Optional[str] = None,
               min_conf: Optional[float] = None, t_from: Optional[float] = None, t_to: Optional[float] = None,
               incident_id: Optional[str] = None, q: Optional[str] = None, limit: int = Query(500, le=5000), _=VIEW):
    return Q.alerts(rt(request), session_id, detector, severity, source, status, state, min_conf, t_from, t_to, incident_id, q, limit)


@app.get("/api/ids/results/{result_id}")
def ids_result(request: Request, result_id: str, _=VIEW):
    res = Q.result(rt(request), result_id)
    if not res:
        raise HTTPException(404, detail={"type": "NOT_FOUND", "message": result_id})
    return res


class StatusBody(BaseModel):
    status: str
    note: str = Field("", max_length=2000)


ALERT_STATUSES = {"NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}
INCIDENT_STATUSES = {"OPEN", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}


@app.post("/api/ids/events/{alert_id}/status")
def alert_status(request: Request, alert_id: str, body: StatusBody, p: Principal = OPERATE):
    r = rt(request)
    if body.status not in ALERT_STATUSES:
        raise HTTPException(400, detail={"type": "INVALID_STATUS", "message": f"status must be one of {sorted(ALERT_STATUSES)}"})
    if body.status in ("FALSE_POSITIVE", "RESOLVED") and not p.allows("investigator"):
        raise HTTPException(403, detail={"type": "FORBIDDEN", "message": "investigator role required"})
    found = None
    if r.active and alert_id in r.active.pipeline.alerts:
        found = r.active.pipeline.alerts[alert_id]
    else:
        rows = Q._rows(r, select(D.ids_events).where(D.ids_events.c.alert_id == alert_id))
        if rows:
            found = (rows[0]["data"] or {}).get("alert") or {}
            found.update({"status": rows[0]["status"]})
            found["_row"] = rows[0]
    if not found:
        raise HTTPException(404, detail={"type": "NOT_FOUND", "message": alert_id})
    old = found.get("status")
    found["status"] = body.status
    found.setdefault("history", []).append({"at": utc_now_iso(), "from": old, "to": body.status, "by": p.user, "note": body.note})
    row = found.pop("_row", None)
    data = (row or {}).get("data") or {"alert": found}
    data["alert"] = found
    D_row = {"alert_id": alert_id, "session_id": found.get("session_id"), "t": found.get("t"), "result_id": found.get("result_id"),
             "detector": found.get("detector"), "severity": found.get("severity"), "confidence": found.get("confidence"),
             "source": found.get("source"), "state": found.get("state"), "status": body.status, "incident_id": found.get("incident_id"),
             "title": found.get("title"), "data": D.dumps(data)}
    r.db.upsert("ids_events", D_row)
    action = {"FALSE_POSITIVE": "FALSE_POSITIVE_MARKED", "RESOLVED": "ALERT_RESOLVED", "ACKNOWLEDGED": "ALERT_ACKNOWLEDGED"}.get(body.status, "ALERT_STATUS_CHANGED")
    r.audit.record(action, alert_id, {"from": old, "to": body.status, "note": body.note, "evidence_preserved": True}, p.user, p.role)
    r.bus.publish("IDS_ALERT", found, "workflow")
    return found


# ====================================================================== incidents
@app.get("/api/incidents")
def incidents_list(request: Request, session_id: Optional[str] = None, status: Optional[str] = None, severity: Optional[str] = None,
                   state: Optional[str] = None, q: Optional[str] = None, limit: int = Query(300, le=2000), _=VIEW):
    return Q.incidents(rt(request), session_id, status, severity, state, q, limit)


@app.get("/api/incidents/{incident_id}")
def incident_get(request: Request, incident_id: str, _=VIEW):
    d = Q.incident_detail(rt(request), incident_id)
    if not d:
        raise HTTPException(404, detail={"type": "NOT_FOUND", "message": incident_id})
    rt(request).audit.record("CASE_OPENED", incident_id, {}, *actor(request))
    return d


@app.post("/api/incidents/{incident_id}/status")
def incident_status(request: Request, incident_id: str, body: StatusBody, p: Principal = INVESTIGATE):
    r = rt(request)
    if body.status not in INCIDENT_STATUSES:
        raise HTTPException(400, detail={"type": "INVALID_STATUS", "message": f"status must be one of {sorted(INCIDENT_STATUSES)}"})
    live = r.active.pipeline.correlator.incidents.get(incident_id) if r.active and r.active.pipeline.correlator else None
    inc = live if live is not None else Q.incident(r, incident_id)
    if not inc:
        raise HTTPException(404, detail={"type": "NOT_FOUND", "message": incident_id})
    old = inc["status"]
    inc["status"] = body.status
    inc.setdefault("workflow", []).append({"at": utc_now_iso(), "from": old, "to": body.status, "by": p.user, "note": body.note})
    pub = {k: v for k, v in inc.items() if not k.startswith("_")}
    r.db.upsert("incidents", {"incident_id": incident_id, "session_id": pub["session_id"], "first_seen": pub["first_seen"],
                              "last_seen": pub["last_seen"], "state": pub["state"], "status": body.status, "severity": pub["severity"],
                              "confidence": pub["confidence"], "domain": pub["domain"], "title": pub["title"], "data": D.dumps(pub)})
    action = {"FALSE_POSITIVE": "FALSE_POSITIVE_MARKED", "RESOLVED": "INCIDENT_RESOLVED"}.get(body.status, "INCIDENT_STATUS_CHANGED")
    r.audit.record(action, incident_id, {"from": old, "to": body.status, "note": body.note, "evidence_preserved": True}, p.user, p.role)
    r.bus.publish("INCIDENT_UPDATED", pub, "workflow")
    return pub


@app.get("/api/timeline")
def timeline(request: Request, session_id: Optional[str] = None, types: Optional[str] = None, t_from: Optional[float] = None,
             t_to: Optional[float] = None, limit: int = Query(1000, le=10000), _=VIEW):
    r = rt(request)
    sid = session_id or (r.active.session_id if r.active else None)
    return {"session_id": sid, "events": Q.timeline(r, sid, t_from, t_to, types, limit) if sid else []}


# ====================================================================== rules / builder
@app.get("/api/rules/catalog")
def rules_catalog(request: Request, _=VIEW):
    r = rt(request)
    c = rule_catalog()
    c["ground_detectors"] = r.detector_ids()
    return c


@app.get("/api/rules")
def rules_list(request: Request, _=VIEW):
    return rt(request).rule_store.list()


@app.get("/api/rules/{rule_id}")
def rules_get(request: Request, rule_id: str, version: Optional[int] = None, _=VIEW):
    r = rt(request).rule_store.get(rule_id, version)
    if not r:
        raise HTTPException(404, detail={"type": "NOT_FOUND", "message": rule_id})
    return r


@app.get("/api/rules/{rule_id}/history")
def rules_history(request: Request, rule_id: str, _=VIEW):
    return rt(request).rule_store.history(rule_id)


@app.post("/api/rules/validate")
def rules_validate(request: Request, rule: dict, _=VIEW):
    return rt(request).rule_store.validate(rule)


@app.post("/api/rules")
def rules_save(request: Request, rule: dict, p: Principal = ENGINEER):
    r = rt(request)
    existed = r.rule_store.get(str(rule.get("rule_id"))) is not None
    res = r.rule_store.save_draft(rule, author=p.user)
    r.audit.record("RULE_MODIFIED" if existed else "RULE_CREATED", res["rule_id"], {"version": res["version"], "sha256": res["sha256"],
                                                                                     "valid": res["validation"]["valid"]}, p.user, p.role)
    return res


class TestBody(BaseModel):
    rule: dict
    dataset: str = "scenario:NORMAL_FLIGHT"


@app.post("/api/rules/test")
async def rules_test(request: Request, body: TestBody, p: Principal = ENGINEER):
    r = rt(request)
    return await asyncio.to_thread(r.test_rule, body.rule, body.dataset)


class TestAllBody(BaseModel):
    rule: dict


@app.post("/api/rules/test-expectations")
async def rules_test_expectations(request: Request, body: TestAllBody, _=ENGINEER):
    r = rt(request)
    out = []
    for t in body.rule.get("tests") or []:
        res = await asyncio.to_thread(r.test_rule, body.rule, t["dataset"])
        out.append({"dataset": t["dataset"], "expect": t.get("expect"), "triggered": res.get("triggered"),
                    "passed": res.get("expectation", {}).get("passed"), "triggers": len(res.get("triggers", []))})
    return {"results": out, "all_passed": all(x["passed"] for x in out) if out else None}


class PublishBody(BaseModel):
    rule_id: str
    version: Optional[int] = None


@app.post("/api/rules/publish")
def rules_publish(request: Request, body: PublishBody, p: Principal = ENGINEER):
    r = rt(request)
    res = r.rule_store.publish(body.rule_id, body.version, author=p.user)
    if res.get("published"):
        r.reload_rules()
        r.audit.record("RULE_PUBLISHED", body.rule_id, {"version": res["version"]}, p.user, p.role)
    return res


@app.post("/api/rules/{rule_id}/disable")
def rules_disable(request: Request, rule_id: str, p: Principal = ENGINEER):
    r = rt(request)
    if not r.rule_store.set_enabled(rule_id, False):
        raise HTTPException(404, detail={"type": "NOT_FOUND", "message": rule_id})
    r.reload_rules()
    r.audit.record("RULE_DISABLED", rule_id, {}, p.user, p.role)
    return {"rule_id": rule_id, "enabled": False}


@app.post("/api/rules/{rule_id}/enable")
def rules_enable(request: Request, rule_id: str, p: Principal = ENGINEER):
    r = rt(request)
    if not r.rule_store.set_enabled(rule_id, True):
        raise HTTPException(404, detail={"type": "NOT_FOUND", "message": rule_id})
    r.reload_rules()
    r.audit.record("RULE_ENABLED", rule_id, {}, p.user, p.role)
    return {"rule_id": rule_id, "enabled": True}


class CloneBody(BaseModel):
    new_id: str = Field(..., pattern=r"^[A-Za-z0-9_-]{1,64}$")


@app.post("/api/rules/{rule_id}/clone")
def rules_clone(request: Request, rule_id: str, body: CloneBody, p: Principal = ENGINEER):
    r = rt(request)
    res = r.rule_store.clone(rule_id, body.new_id, author=p.user)
    r.audit.record("RULE_CREATED", body.new_id, {"cloned_from": rule_id, "version": res["version"]}, p.user, p.role)
    return res


class LiveTestBody(BaseModel):
    rule: dict
    seconds: float = 120


@app.post("/api/rules/live-test")
def rules_live_test(request: Request, body: LiveTestBody, _=ENGINEER):
    r = rt(request)
    v = validate_rule(_definition(body.rule), r.registry, r.detector_ids())
    if not v["valid"]:
        return {"started": False, "validation": v}
    return {"started": True, **r.start_shadow(body.rule, body.seconds)}


@app.delete("/api/rules/live-test")
def rules_live_test_stop(request: Request, _=ENGINEER):
    rt(request).stop_shadow()
    return {"stopped": True}


@app.get("/api/rules/runs/recent")
def rule_runs(request: Request, rule_id: Optional[str] = None, _=VIEW):
    t = D.rule_runs
    stmt = select(t).order_by(desc(t.c.started)).limit(50)
    if rule_id:
        stmt = stmt.where(t.c.rule_id == rule_id)
    return Q._rows(rt(request), stmt)


# ====================================================================== forensics
@app.get("/api/forensics/cases")
def cases_list(request: Request, q: Optional[str] = None, severity: Optional[str] = None, detector: Optional[str] = None,
               incident_id: Optional[str] = None, sysid: Optional[str] = None, date: Optional[str] = None, source: Optional[str] = None, _=VIEW):
    return Q.cases(rt(request), q, severity, detector, incident_id, sysid, date, source)


@app.get("/api/forensics/cases/{case_id}")
def case_get(request: Request, case_id: str, _=VIEW):
    d = Q.case_detail(rt(request), case_id)
    if not d:
        raise HTTPException(404, detail={"type": "NOT_FOUND", "message": case_id})
    rt(request).audit.record("CASE_OPENED", case_id, {}, *actor(request))
    return d


@app.get("/api/forensics/cases/{case_id}/file")
def case_file(request: Request, case_id: str, path: str, download: bool = False, _=VIEW):
    data, p = Q.read_case_file(rt(request), case_id, path)
    if download or p.suffix in (".bin", ".png"):
        return FileResponse(p, filename=p.name)
    return Response(data, media_type="text/plain; charset=utf-8")


class SnapshotBody(BaseModel):
    incident_id: Optional[str] = None
    reason: str = Field("manual investigator request", max_length=500)
    pre_seconds: Optional[float] = Field(None, ge=0, le=3600)
    post_seconds: Optional[float] = Field(None, ge=0, le=3600)


@app.post("/api/forensics/snapshot")
def forensics_snapshot(request: Request, body: SnapshotBody, p: Principal = INVESTIGATE):
    r = rt(request)
    sess = r.active
    if not sess or not sess.pipeline.snapshots:
        raise HTTPException(409, detail={"type": "NO_RECORDING_SESSION", "message": "manual snapshots need an active live or simulation session (replays re-analyse existing evidence)"})
    inc = None
    if body.incident_id:
        inc = sess.pipeline.correlator.incidents.get(body.incident_id) if sess.pipeline.correlator else None
        if inc is None:
            raise HTTPException(404, detail={"type": "NOT_FOUND", "message": "incident is not part of the active session"})
    case_id = sess.pipeline.snapshot(reason=f"manual: {body.reason}", incident=inc, pre_s=body.pre_seconds, post_s=body.post_seconds)
    r.audit.record("SNAPSHOT_CREATED", case_id, {"incident_id": body.incident_id, "reason": body.reason}, p.user, p.role)
    return {"case_id": case_id, "status": "COLLECTING"}


class VerifyBody(BaseModel):
    case_id: str


@app.post("/api/forensics/verify")
def forensics_verify(request: Request, body: VerifyBody, p: Principal = INVESTIGATE):
    r = rt(request)
    d = Q.case_dir(r, body.case_id)
    res = verify_case(d)
    r.db.insert("artifact_hashes", {"case_id": body.case_id, "verified_at": utc_now_iso(), "result": res["status"], "data": D.dumps(res)}, critical=True)
    r.audit.record("HASH_VERIFIED", body.case_id, {"result": res["status"], "files": res.get("files_checked")}, p.user, p.role)
    return {"case_id": body.case_id, **res}


@app.post("/api/forensics/cases/{case_id}/screenshot")
async def case_screenshot(request: Request, case_id: str, file: UploadFile = File(...), p: Principal = OPERATE):
    r = rt(request)
    data = await file.read(20 * 1024 * 1024 + 1)
    if len(data) > 20 * 1024 * 1024 or data[:8] != b"\x89PNG\r\n\x1a\n":
        raise HTTPException(400, detail={"type": "INVALID_SCREENSHOT", "message": "PNG ≤ 20 MB required"})
    name = f"screenshots/incident-{case_id}.png"
    if (Q.case_dir(r, case_id) / name).exists():
        name = f"screenshots/incident-{case_id}-{utc_now_iso().replace(':', '')}.png"
    mgr = SnapshotManager(r.dirs["cases"], r.config, r.errors)
    res = await asyncio.to_thread(mgr.add_artifact, case_id, name, data, "GUI screenshot (html2canvas) captured by operator client")
    r.audit.record("CASE_ARTIFACT_ADDED", case_id, {"file": name, "sha256": res["artifact"]["sha256"],
                                                    "previous_manifest_sha256": res["previous_manifest_sha256"]}, p.user, p.role)
    return res


@app.get("/api/forensics/cases/{case_id}/export")
def case_export(request: Request, case_id: str, p: Principal = INVESTIGATE):
    r = rt(request)
    z = SnapshotManager(r.dirs["cases"], r.config, r.errors).export_zip(case_id)
    r.audit.record("CASE_EXPORTED", case_id, {"file": z.name, "sha256": sha256_file(z)}, p.user, p.role)
    return FileResponse(z, filename=z.name, media_type="application/zip")


# ====================================================================== connection / sessions / replay
class ConnectBody(BaseModel):
    type: str = Field(..., pattern="^(live|simulation|replay)$")
    spec: Optional[str] = Field(None, max_length=200)
    scenario: Optional[str] = None
    dataset: Optional[str] = Field(None, max_length=200)
    speed: float = Field(1.0, gt=0, le=20)


@app.post("/api/connection")
async def connection_open(request: Request, body: ConnectBody, p: Principal = OPERATE):
    r = rt(request)
    if body.type == "live":
        return await r.start_live(body.spec or r.config.get("mavlink.connection"), p.user, p.role)
    if body.type == "simulation":
        return await r.start_simulation(body.scenario or "NORMAL_FLIGHT", body.speed, actor=p.user, role=p.role)
    return await r.start_replay(body.dataset or "", body.speed, p.user, p.role)


@app.delete("/api/connection")
async def connection_close(request: Request, p: Principal = OPERATE):
    return await rt(request).stop_session("operator disconnect", p.user, p.role)


@app.get("/api/connection")
def connection_get(request: Request, _=VIEW):
    r = rt(request)
    hist = Q._rows(r, select(D.connections).order_by(desc(D.connections.c.id)).limit(30))
    return {"current": r.last_connection, "stats": r.active.pipeline.connection_stats() if r.active else None,
            "default_spec": r.config.get("mavlink.connection"), "history": hist,
            "examples": ["udp:127.0.0.1:14550", "tcp:127.0.0.1:5760", "/dev/ttyUSB0", "/dev/ttyACM0:115200", "COM3"]}


class ReplayBody(BaseModel):
    action: str = Field(..., pattern="^(play|pause|speed|seek|jump)$")
    value: Optional[Any] = None


@app.post("/api/replay/control")
async def replay_control(request: Request, body: ReplayBody, _=OPERATE):
    return await rt(request).replay_control(body.action, body.value)


@app.get("/api/replay/status")
def replay_status(request: Request, _=VIEW):
    r = rt(request)
    return r.active.replay.status() if r.active and r.active.replay else {"active": False}


@app.get("/api/replay/datasets")
def replay_datasets(request: Request, _=VIEW):
    r = rt(request)
    caps = sorted(r.dirs["captures"].glob("*.tlog"), key=lambda p: p.stat().st_mtime, reverse=True)[:100]
    out = [{"ref": f"capture:{p.stem}", "label": p.stem, "kind": "capture", "size": p.stat().st_size} for p in caps if p.stat().st_size > 0]
    for c in Q.cases(r, limit=100):
        out.append({"ref": f"case:{c['case_id']}", "label": f"{c['case_id']} ({(c.get('trigger') or {}).get('detector', '')})", "kind": "case"})
    for i in Q._rows(r, select(D.imports).order_by(desc(D.imports.c.imported_at)).limit(100)):
        if i["status"] in ("COMPLETE", "QUEUED", "ANALYZING"):
            out.append({"ref": f"import:{i['import_id']}", "label": f"{i['filename']} ({i['format']})", "kind": "import"})
    return out


@app.get("/api/sessions")
def sessions(request: Request, _=VIEW):
    return Q.session_list(rt(request))


@app.get("/api/simulation/scenarios")
def scenarios(_=VIEW):
    return scenario_list()


# ====================================================================== logs / import
@app.post("/api/logs/import")
async def logs_import(request: Request, file: UploadFile = File(...), p: Principal = INVESTIGATE):
    r = rt(request)
    limit = int(r.config.get("limits.max_upload_mb", 1024)) * (1 << 20)
    tmp = Path(tempfile.mkstemp(dir=r.dirs["work"], suffix=".upload")[1])
    size = 0
    with open(tmp, "wb") as fh:
        while chunk := await file.read(1 << 20):
            size += len(chunk)
            if size > limit:
                fh.close()
                tmp.unlink(missing_ok=True)
                raise HTTPException(413, detail={"type": "PAYLOAD_TOO_LARGE", "message": "upload exceeds limit"})
            fh.write(chunk)
    return await asyncio.to_thread(r.import_file, file.filename or "upload.bin", tmp, p.user, p.role)


@app.get("/api/logs/imports")
def logs_imports(request: Request, _=VIEW):
    r = rt(request)
    rows = Q._rows(r, select(D.imports).order_by(desc(D.imports.c.imported_at)).limit(200))
    live = r.imports
    out = []
    for row in rows:
        m = row.get("meta") or {}
        cur = live.get(row["import_id"])
        out.append({**row, "progress": (cur or {}).get("progress", m.get("progress")), "status": (cur or {}).get("status", row["status"]),
                    "meta": {k: v for k, v in m.items() if k != "path"}})
    return out


@app.get("/api/errors")
def errors(request: Request, detail: bool = False, component: Optional[str] = None, p: Principal = VIEW):
    return rt(request).errors.list(300, component, detail=detail and p.allows("engineer"))


@app.get("/api/system/events")
def system_events(request: Request, session_id: Optional[str] = None, limit: int = Query(300, le=3000), _=VIEW):
    t = D.system_events
    stmt = select(t).order_by(desc(t.c.id)).limit(limit)
    if session_id:
        stmt = stmt.where(t.c.session_id == session_id)
    return Q._rows(rt(request), stmt)


@app.get("/api/audit")
def audit(request: Request, limit: int = Query(500, le=5000), _=INVESTIGATE):
    return rt(request).audit.list(limit)


@app.get("/api/audit/verify")
def audit_verify(request: Request, _=INVESTIGATE):
    return rt(request).audit.verify()


# ====================================================================== analytics
@app.get("/api/analytics/series")
def analytics_series(request: Request, session_id: str, fields: str, max_points: int = Query(2000, le=20000), _=VIEW):
    return {"session_id": session_id, "series": Q.series(rt(request), session_id, fields.split(","), max_points)}


@app.get("/api/analytics/frequency")
def analytics_frequency(request: Request, session_id: str, _=VIEW):
    return Q.frequency(rt(request), session_id)


@app.get("/api/analytics/sources")
def analytics_sources(request: Request, session_id: str, _=VIEW):
    return Q.sources_table(rt(request), session_id)


@app.get("/api/analytics/correlation")
def analytics_correlation(request: Request, session_id: str, fields: str = "gps_speed,ekf_speed,groundspeed,altitude_rel,battery_v,ekf_vel_var,satellites", _=VIEW):
    return Q.correlation_matrix(rt(request), session_id, fields.split(","))


@app.get("/api/analytics/detector-history")
def analytics_detector_history(request: Request, session_id: str, _=VIEW):
    return Q.detector_history(rt(request), session_id)


@app.get("/api/analytics/compare")
def analytics_compare(request: Request, a: str, b: str, fields: str = "gps_speed,groundspeed,altitude_rel,battery_v", _=VIEW):
    r = rt(request)
    out = {}
    for sid in (a, b):
        s = Q.series(r, sid, fields.split(","), 1500)
        t0 = min((pts["points"][0][0] for pts in s.values() if pts.get("points")), default=0)
        out[sid] = {f: {"points": [[round(t - t0, 2), v] for t, v in d.get("points", [])], "provenance": d.get("provenance")} for f, d in s.items()}
        freq = Q.frequency(r, sid, top=10)
        out[sid]["_stats"] = {"messages": sum(freq["totals"].values()), "alerts": len(Q.alerts(r, session_id=sid, limit=5000)),
                              "incidents": len(Q.incidents(r, session_id=sid)),
                              "commands": len(Q._rows(r, select(D.commands).where(D.commands.c.session_id == sid).limit(5000))),
                              "parameter_changes": len(Q._rows(r, select(D.parameters).where(D.parameters.c.session_id == sid, D.parameters.c.kind == "CHANGE").limit(5000)))}
    return {"a": a, "b": b, "aligned_on": "relative time from first sample (s)", "sessions": out}


# ====================================================================== config diff / settings
def _params_at(r: Runtime, session_id: str, t_max: Optional[float] = None) -> dict:
    t = D.parameters
    conds = [t.c.session_id == session_id, t.c.kind.in_(["BASELINE", "CHANGE"])]
    if t_max is not None:
        conds.append(t.c.t <= t_max)
    rows = D.query(r.engine, select(t.c.name, t.c.value, t.c.t).where(and_(*conds)).order_by(t.c.t))
    out = {row["name"]: row["value"] for row in rows}
    if r.active and r.active.session_id == session_id and t_max is None:
        pd = r.active.pipeline.engine.get("PARAMETER")
        if pd:
            out.update(pd.values)
    return out


@app.get("/api/config/diff")
def config_diff(request: Request, a: str = "current", b: str = "previous", _=VIEW):
    r = rt(request)

    def resolve(ref: str) -> dict:
        sessions = [s for s in Q.session_list(r, 50) if s.get("kind") in ("live", "simulation", "import")]
        if ref == "current":
            sid = r.active.session_id if r.active else (sessions[0]["session_id"] if sessions else None)
            return {"label": f"current ({sid})", "session_id": sid, "params": _params_at(r, sid) if sid else {},
                    "thresholds": r.config.get("ids", {}), "rules": {x["rule_id"]: x.get("published_version") for x in r.rule_store.list()},
                    "firmware": r.capabilities.get("vehicle", {}), "connection": r.last_connection}
        if ref == "previous":
            cur = r.active.session_id if r.active else None
            prev = next((s for s in sessions if s["session_id"] != cur and not s.get("active")), None)
            sid = prev["session_id"] if prev else None
            return {"label": f"previous session ({sid})", "session_id": sid, "params": _params_at(r, sid) if sid else {},
                    "thresholds": None, "rules": None, "firmware": None, "connection": {"spec": prev.get("source")} if prev else None}
        if ref.startswith("incident:"):
            inc = Q.incident(r, ref.split(":", 1)[1])
            if not inc:
                raise KeyError(ref)
            manifest = None
            if inc.get("case_id") and (Q.case_dir(r, inc["case_id"]) / "manifest.json").exists():
                manifest = json.loads((Q.case_dir(r, inc["case_id"]) / "manifest.json").read_text())
            return {"label": f"at incident {inc['incident_id']}", "session_id": inc["session_id"],
                    "params": _params_at(r, inc["session_id"], inc["first_seen"]),
                    "thresholds": (manifest or {}).get("config_snapshot"),
                    "rules": {x["rule_id"]: x["version"] for x in (manifest or {}).get("rule_versions", [])} or {x["rule_id"]: x["version"] for x in inc.get("rule_versions", [])},
                    "firmware": (manifest or {}).get("vehicle"), "connection": (manifest or {}).get("session")}
        raise ValueError("ref must be current, previous or incident:<id>")

    A, B = resolve(a), resolve(b)

    def flat(d, prefix=""):
        out = {}
        if isinstance(d, dict):
            for k, v in d.items():
                out.update(flat(v, f"{prefix}{k}."))
        else:
            out[prefix[:-1]] = d
        return out

    def diff(x, y):
        if x is None or y is None:
            return {"available": False, "rows": [], "note": "N/A — not recorded for one side"}
        fx, fy = flat(x), flat(y)
        rows = [{"key": k, "a": fx.get(k), "b": fy.get(k), "changed": fx.get(k) != fy.get(k)} for k in sorted(set(fx) | set(fy))]
        return {"available": True, "rows": rows, "changed": sum(1 for rr in rows if rr["changed"])}

    return {"a": A["label"], "b": B["label"], "sections": {k: diff(A[k], B[k]) for k in ("params", "thresholds", "rules", "firmware", "connection")}}


@app.get("/api/settings")
def settings_get(request: Request, _=VIEW):
    return rt(request).config.redacted()


SETTABLE = {"forensics.pre_event_seconds", "forensics.post_event_seconds", "recording.rolling_minutes", "ids.suspected_threshold",
            "ids.confirmed_threshold", "ids.correlation_window_seconds", "gui.update_hz", "mavlink.connection", "mavlink.trusted_gcs_sysids",
            "mavlink.signing_expected", "database.retention_days", "forensics.auto_snapshot_severities"}


@app.put("/api/settings")
def settings_put(request: Request, patch: dict, p: Principal = ENGINEER):
    r = rt(request)
    flat_patch = {}

    def walk(d, prefix=""):
        for k, v in d.items():
            if isinstance(v, dict):
                walk(v, f"{prefix}{k}.")
            else:
                flat_patch[f"{prefix}{k}"] = v
    walk(patch)
    bad = [k for k in flat_patch if k not in SETTABLE and not k.startswith("ids.detectors.")]
    if bad:
        raise HTTPException(400, detail={"type": "NOT_SETTABLE", "message": f"not settable at runtime: {bad}"})
    for k, v in flat_patch.items():
        if isinstance(v, (int, float)) and not isinstance(v, bool) and v < 0:
            raise HTTPException(400, detail={"type": "INVALID_VALUE", "message": f"{k} must be non-negative"})
    old = {k: r.config.get(k) for k in flat_patch}
    r.config.update_overrides(patch)
    r.audit.record("SETTINGS_CHANGED", ",".join(flat_patch), {"old": old, "new": flat_patch}, p.user, p.role)
    return {"updated": flat_patch, "note": "detector threshold changes apply to the next session"}


# ====================================================================== websockets
@app.websocket("/ws/{channel}")
async def ws(websocket: WebSocket, channel: str):
    r: Runtime = websocket.app.state.runtime
    if channel not in ("telemetry", "ids", "incidents", "events", "health", "builder"):
        await websocket.close(code=4404)
        return
    try:
        ws_principal(websocket, r.config)
    except HTTPException:
        await websocket.close(code=4401)
        return
    await websocket.accept()
    client = r.hub.register(websocket, channel)
    # resync snapshot on (re)connect
    try:
        if channel == "telemetry":
            client.offer(json.dumps({"type": "state", "data": r.telemetry_snapshot()}, default=str).encode())
        elif channel == "ids":
            client.offer(json.dumps({"type": "detectors", "data": r.ids_snapshot()}, default=str).encode())
        elif channel == "health":
            client.offer(json.dumps({"type": "health", "data": r.health()}, default=str).encode())
        elif channel == "events":
            client.offer(json.dumps({"type": "connection", "data": r.last_connection}, default=str).encode())
        client.offer(json.dumps({"type": "hello", "data": {"channel": channel, "server_time": utc_now_iso()}}).encode())
    except Exception:
        pass
    pump = asyncio.create_task(r.hub.pump(client))
    try:
        while True:
            await websocket.receive_text()  # keepalive / ignore client messages (read-only)
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        pump.cancel()
        r.hub.unregister(client)


# ====================================================================== static frontend (production build)
_dist = PROJECT_ROOT / "frontend" / "dist"
if _dist.exists():
    app.mount("/assets", StaticFiles(directory=_dist / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        f = (_dist / path).resolve()
        if path and str(f).startswith(str(_dist.resolve())) and f.is_file():
            return FileResponse(f)
        return FileResponse(_dist / "index.html")
