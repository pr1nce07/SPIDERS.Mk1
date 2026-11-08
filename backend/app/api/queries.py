"""Read-side queries shared by the REST endpoints. They merge durable DB rows with
the in-memory state of the active session (whose latest rows may still be in the
batch writer, or never persisted at all for replays)."""
from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Optional

from sqlalchemy import and_, desc, func, or_, select

from ..forensic.hashing import verify_case
from ..ids.correlation import Correlator
from ..storage import db as D


def _rows(rt, stmt) -> list[dict]:
    return D.parse_json_cols(D.query(rt.engine, stmt))


# ------------------------------------------------------------------ alerts
def alerts(rt, session_id=None, detector=None, severity=None, source=None, status=None, state=None, min_conf=None,
           t_from=None, t_to=None, incident_id=None, q=None, limit=500) -> list[dict]:
    t = D.ids_events
    conds = []
    if session_id:
        conds.append(t.c.session_id == session_id)
    if detector:
        conds.append(t.c.detector.in_(detector.split(",")))
    if severity:
        conds.append(t.c.severity.in_(severity.split(",")))
    if source:
        conds.append(t.c.source.in_(source.split(",")))
    if status:
        conds.append(t.c.status.in_(status.split(",")))
    if state:
        conds.append(t.c.state.in_(state.split(",")))
    if min_conf is not None:
        conds.append(t.c.confidence >= float(min_conf))
    if t_from:
        conds.append(t.c.t >= float(t_from))
    if t_to:
        conds.append(t.c.t <= float(t_to))
    if incident_id:
        conds.append(t.c.incident_id == incident_id)
    if q:
        conds.append(or_(t.c.title.ilike(f"%{q}%"), t.c.detector.ilike(f"%{q}%"), t.c.alert_id.ilike(f"%{q}%")))
    rows = _rows(rt, select(t).where(and_(*conds)).order_by(desc(t.c.t)).limit(limit))
    out = {r["alert_id"]: {**((r.get("data") or {}).get("alert") or {}), **{k: r[k] for k in ("status", "incident_id")}} for r in rows}
    sess = rt.active
    if sess and (session_id in (None, sess.session_id)):
        for a in list(sess.pipeline.alerts.values()):
            if _match_alert(a, detector, severity, source, status, state, min_conf, t_from, t_to, incident_id, q):
                out[a["alert_id"]] = dict(a)
    res = sorted(out.values(), key=lambda a: -a.get("t", 0))
    return res[:limit]


def _match_alert(a, detector, severity, source, status, state, min_conf, t_from, t_to, incident_id, q) -> bool:
    if detector and a["detector"] not in detector.split(","):
        return False
    if severity and a["severity"] not in severity.split(","):
        return False
    if source and a["source"] not in source.split(","):
        return False
    if status and a["status"] not in status.split(","):
        return False
    if state and a["state"] not in state.split(","):
        return False
    if min_conf is not None and (a.get("confidence") or 0) < float(min_conf):
        return False
    if t_from and a["t"] < float(t_from):
        return False
    if t_to and a["t"] > float(t_to):
        return False
    if incident_id and a.get("incident_id") != incident_id:
        return False
    if q and q.lower() not in (a["title"] + a["detector"] + a["alert_id"]).lower():
        return False
    return True


def result(rt, result_id: str) -> Optional[dict]:
    sess = rt.active
    if sess:
        for r in sess.pipeline.results_buf.items:
            if r["result_id"] == result_id:
                return r
    rows = _rows(rt, select(D.detector_results).where(D.detector_results.c.result_id == result_id))
    return rows[0]["data"] if rows else None


# ------------------------------------------------------------------ incidents
def incidents(rt, session_id=None, status=None, severity=None, state=None, q=None, limit=300) -> list[dict]:
    t = D.incidents
    conds = []
    if session_id:
        conds.append(t.c.session_id == session_id)
    if status:
        conds.append(t.c.status.in_(status.split(",")))
    if severity:
        conds.append(t.c.severity.in_(severity.split(",")))
    if state:
        conds.append(t.c.state.in_(state.split(",")))
    if q:
        conds.append(or_(t.c.title.ilike(f"%{q}%"), t.c.incident_id.ilike(f"%{q}%")))
    rows = _rows(rt, select(t).where(and_(*conds)).order_by(desc(t.c.last_seen)).limit(limit))
    out = {r["incident_id"]: {**(r.get("data") or {}), "status": r["status"]} for r in rows}
    sess = rt.active
    if sess and sess.pipeline.correlator and session_id in (None, sess.session_id):
        for inc in sess.pipeline.correlator.incidents.values():
            pub = Correlator.public(inc)
            if (not status or pub["status"] in status.split(",")) and (not severity or pub["severity"] in severity.split(",")) \
                    and (not state or pub["state"] in state.split(",")) and (not q or q.lower() in (pub["title"] + pub["incident_id"]).lower()):
                out[pub["incident_id"]] = pub
    return sorted(out.values(), key=lambda i: -i.get("last_seen", 0))[:limit]


def incident(rt, incident_id: str) -> Optional[dict]:
    sess = rt.active
    if sess and sess.pipeline.correlator and incident_id in sess.pipeline.correlator.incidents:
        return Correlator.public(sess.pipeline.correlator.incidents[incident_id])
    rows = _rows(rt, select(D.incidents).where(D.incidents.c.incident_id == incident_id))
    if not rows:
        return None
    d = rows[0]["data"]
    d["status"] = rows[0]["status"]
    return d


def incident_detail(rt, incident_id: str) -> Optional[dict]:
    inc = incident(rt, incident_id)
    if not inc:
        return None
    sid = inc["session_id"]
    t0, t1 = inc["first_seen"] - 30, inc["last_seen"] + 30
    res_ids = [o["result_id"] for o in inc["observations"]]
    results = [r for r in (result(rt, rid) for rid in res_ids) if r]
    tl = timeline(rt, sid, t_from=t0, t_to=t1, limit=400)
    track = track_points(rt, sid, t_from=t0 - 60, t_to=t1 + 60, max_points=1200)
    case = None
    if inc.get("case_id"):
        case = case_summary(rt, inc["case_id"])
    return {"incident": inc, "results": results, "alerts": alerts(rt, incident_id=incident_id, limit=200), "timeline": tl,
            "track": track, "case": case, "graph": evidence_graph(rt, inc, results)}


def evidence_graph(rt, inc: dict, results: list[dict]) -> dict:
    nodes, edges = [], []
    iid = inc["incident_id"]
    nodes.append({"id": iid, "kind": "incident", "label": f"{iid}\n{inc['title']}", "state": inc["state"], "ref": {"incident_id": iid}})
    msgs: dict[str, dict] = {}
    for r in results:
        rid = r["result_id"]
        if r.get("kind") in ("observation",) and not r.get("state") in ("ANOMALOUS", "SUSPECTED", "CONFIRMED"):
            continue
        nodes.append({"id": rid, "kind": "detector", "label": f"{r['detector']}\n{r['title'][:40]}", "state": r["state"],
                      "source": r["source"], "ref": {"result_id": rid}})
        edges.append({"source": rid, "target": iid})
        if r.get("rule_id"):
            rn = f"rule:{r['rule_id']}:v{r['rule_version']}"
            if rn not in {n["id"] for n in nodes}:
                nodes.append({"id": rn, "kind": "rule", "label": f"{r['rule_id']} v{r['rule_version']}", "ref": {"rule_id": r["rule_id"], "version": r["rule_version"]}})
            edges.append({"source": rn, "target": rid})
        if r["source"] in ("FC", "LUA"):
            sn = f"src:{r['source']}"
            if sn not in {n["id"] for n in nodes}:
                nodes.append({"id": sn, "kind": "pushpak", "label": "FC AP_IDS (PIDS)" if r["source"] == "FC" else "Lua confirmation", "ref": {}})
            edges.append({"source": sn, "target": rid})
        for idx in (r.get("packet_refs") or [])[:12]:
            pk = packet(rt, inc["session_id"], idx)
            name = pk["msg"] if pk else f"packet #{idx}"
            key = f"msg:{name}"
            if key not in msgs:
                msgs[key] = {"id": key, "kind": "message", "label": name, "count": 0, "ref": {"session_id": inc["session_id"], "idx": idx, "msg": name}}
            msgs[key]["count"] += 1
            e = {"source": key, "target": rid}
            if e not in edges:
                edges.append(e)
    for m in msgs.values():
        m["label"] = f"{m['label']} ×{m['count']}"
        nodes.append(m)
    for a in inc.get("actors", []):
        an = f"actor:{a}"
        nodes.append({"id": an, "kind": "actor", "label": f"SYSID {a}", "ref": {"sysid": a}})
        edges.append({"source": an, "target": iid})
    if inc.get("case_id"):
        cn = f"case:{inc['case_id']}"
        nodes.append({"id": cn, "kind": "snapshot", "label": f"Snapshot {inc['case_id']}", "ref": {"case_id": inc["case_id"]}})
        edges.append({"source": iid, "target": cn})
    return {"nodes": nodes, "edges": edges}


# ------------------------------------------------------------------ packets
def packet(rt, session_id: str, idx: int) -> Optional[dict]:
    sess = rt.active
    if sess and sess.session_id == session_id:
        ev = sess.pipeline.packets.get(idx)
        if ev:
            return {**ev.summary(), **ev.to_dict()}
    rows = D.query(rt.engine, select(D.mavlink_messages).where(D.mavlink_messages.c.session_id == session_id, D.mavlink_messages.c.idx == idx))
    if not rows:
        return None
    r = rows[0]
    return {"idx": r["idx"], "t": r["t"], "sysid": r["sysid"], "compid": r["compid"], "seq": r["seq"], "msg_id": r["msg_id"],
            "msg": r["msg_name"], "source": r["source"], "link": r["link"], "signed": r["signed"], "sig": r["sig"],
            "err": r["parse_error"], "fields": D.loads(r["fields"]), "raw_hex": r["raw_hex"],
            "ver": 2 if (r["raw_hex"] or "").startswith("fd") else (1 if r["raw_hex"] else None),
            "len": len(r["raw_hex"] or "") // 2}


def packets(rt, session_id: str, msg=None, sysid=None, compid=None, q=None, after_idx=None, before_idx=None, t_from=None,
            t_to=None, errors_only=False, limit=500) -> list[dict]:
    sess = rt.active
    if sess and sess.session_id == session_id and not sess.pipeline.db:
        evs = sess.pipeline.packets.last(200000)
        out = []
        for e in reversed(evs):
            if msg and e.msg_name not in msg.split(","):
                continue
            if sysid is not None and e.sysid != int(sysid):
                continue
            if compid is not None and e.compid != int(compid):
                continue
            if after_idx is not None and e.idx <= int(after_idx):
                continue
            if before_idx is not None and e.idx >= int(before_idx):
                continue
            if t_from and e.t < float(t_from):
                continue
            if errors_only and not e.parse_error:
                continue
            out.append(e.summary())
            if len(out) >= limit:
                break
        return out
    t = D.mavlink_messages
    conds = [t.c.session_id == session_id]
    if msg:
        conds.append(t.c.msg_name.in_(msg.split(",")))
    if sysid is not None:
        conds.append(t.c.sysid == int(sysid))
    if compid is not None:
        conds.append(t.c.compid == int(compid))
    if after_idx is not None:
        conds.append(t.c.idx > int(after_idx))
    if before_idx is not None:
        conds.append(t.c.idx < int(before_idx))
    if t_from:
        conds.append(t.c.t >= float(t_from))
    if t_to:
        conds.append(t.c.t <= float(t_to))
    if errors_only:
        conds.append(t.c.parse_error.is_not(None))
    if q:
        conds.append(or_(t.c.msg_name.ilike(f"%{q}%"), t.c.fields.ilike(f"%{q}%")))
    order = t.c.idx if (after_idx is not None or t_from) else desc(t.c.idx)
    rows = D.query(rt.engine, select(t.c.idx, t.c.t, t.c.sysid, t.c.compid, t.c.seq, t.c.msg_id, t.c.msg_name, t.c.source, t.c.link,
                                      t.c.signed, t.c.sig, t.c.parse_error, t.c.raw_hex).where(and_(*conds)).order_by(order).limit(limit))
    return [{"idx": r["idx"], "t": r["t"], "sysid": r["sysid"], "compid": r["compid"], "seq": r["seq"], "msg_id": r["msg_id"],
             "msg": r["msg_name"], "source": r["source"], "link": r["link"], "signed": r["signed"], "sig": r["sig"], "err": r["parse_error"],
             "len": len(r["raw_hex"] or "") // 2, "ver": 2 if (r["raw_hex"] or "").startswith("fd") else 1} for r in rows]


# ------------------------------------------------------------------ timeline / track
def timeline(rt, session_id: str, t_from=None, t_to=None, types=None, limit=1000) -> list[dict]:
    sess = rt.active
    if sess and sess.session_id == session_id and not sess.pipeline.db:
        items = [e for e in sess.pipeline.timeline if (t_from is None or e["t"] >= t_from) and (t_to is None or e["t"] <= t_to)
                 and (not types or e["type"] in types.split(","))]
        return items[-limit:]
    t = D.system_events
    conds = [t.c.session_id == session_id]
    if t_from is not None:
        conds.append(t.c.t >= float(t_from))
    if t_to is not None:
        conds.append(t.c.t <= float(t_to))
    if types:
        conds.append(t.c.type.in_(types.split(",")))
    rows = _rows(rt, select(t).where(and_(*conds)).order_by(desc(t.c.t)).limit(limit))
    out = [r["data"] for r in rows if isinstance(r.get("data"), dict)]
    if sess and sess.session_id == session_id:
        seen = {e["id"] for e in out}
        for e in list(sess.pipeline.timeline)[-300:]:
            if e["id"] not in seen and (t_from is None or e["t"] >= t_from) and (t_to is None or e["t"] <= t_to) and (not types or e["type"] in types.split(",")):
                out.append(e)
    return sorted(out, key=lambda e: e["t"])[-limit:]


def track_points(rt, session_id: str, t_from=None, t_to=None, kind="EKF", max_points=3000) -> list[list]:
    sess = rt.active
    if sess and sess.session_id == session_id and not sess.pipeline.db:
        pts = [[t, la, lo, al] for t, la, lo, al in sess.pipeline.vstate.track if (t_from is None or t >= t_from) and (t_to is None or t <= t_to)]
    else:
        t = D.gps_points
        conds = [t.c.session_id == session_id, t.c.kind == kind]
        if t_from is not None:
            conds.append(t.c.t >= float(t_from))
        if t_to is not None:
            conds.append(t.c.t <= float(t_to))
        rows = D.query(rt.engine, select(t.c.t, t.c.lat, t.c.lon, t.c.alt).where(and_(*conds)).order_by(t.c.t))
        pts = [[r["t"], r["lat"], r["lon"], r["alt"]] for r in rows]
    if len(pts) > max_points:
        step = math.ceil(len(pts) / max_points)
        pts = pts[::step]
    return pts


# ------------------------------------------------------------------ cases
def case_dir(rt, case_id: str) -> Path:
    if not case_id or "/" in case_id or ".." in case_id:
        raise ValueError("invalid case id")
    return rt.dirs["cases"] / case_id


def case_summary(rt, case_id: str) -> Optional[dict]:
    d = case_dir(rt, case_id)
    st = rt.cases_status.get(case_id, {})
    mf = d / "manifest.json"
    if not mf.exists():
        return {"case_id": case_id, "status": st.get("status", "UNKNOWN"), **({k: v for k, v in st.items() if k in ("incident_id", "window")})} if st or d.exists() else None
    m = json.loads(mf.read_text())
    return {"case_id": case_id, "status": m.get("status"), "incident_id": m.get("incident_id"), "created_at": m.get("created_at"),
            "finalized_at": m.get("finalized_at"), "trigger": m.get("trigger"), "capture_window": m.get("capture_window"),
            "vehicle": m.get("vehicle"), "session": m.get("session"), "evidence_counts": m.get("evidence_counts"),
            "artifact_count": len(m.get("artifacts", [])), "revisions": m.get("revisions", [])}


def cases(rt, q=None, severity=None, detector=None, incident_id=None, sysid=None, date=None, source=None, limit=300) -> list[dict]:
    out = []
    root = rt.dirs["cases"]
    ids = {p.name for p in root.iterdir() if p.is_dir()} | set(rt.cases_status)
    for cid in sorted(ids, reverse=True):
        try:
            s = case_summary(rt, cid)
        except Exception:
            continue
        if not s:
            continue
        trig = s.get("trigger") or {}
        hay = json.dumps(s).lower()
        if q and q.lower() not in hay:
            continue
        if severity and (trig.get("severity") or "") not in severity.split(","):
            continue
        if detector and detector.lower() not in (trig.get("detector") or "").lower():
            continue
        if incident_id and s.get("incident_id") != incident_id:
            continue
        if sysid and str((s.get("vehicle") or {}).get("sysid")) != str(sysid):
            continue
        if date and not (s.get("created_at") or "").startswith(date):
            continue
        if source and source.lower() not in json.dumps(s.get("session") or {}).lower():
            continue
        out.append(s)
        if len(out) >= limit:
            break
    return out


def case_detail(rt, case_id: str) -> Optional[dict]:
    d = case_dir(rt, case_id)
    if not d.exists():
        s = rt.cases_status.get(case_id)
        return {"case_id": case_id, "status": s.get("status") if s else "UNKNOWN", "collecting": True, **(s or {})} if s else None
    m = json.loads((d / "manifest.json").read_text()) if (d / "manifest.json").exists() else None
    files = [{"path": p.relative_to(d).as_posix(), "size": p.stat().st_size} for p in sorted(d.rglob("*")) if p.is_file()]
    inc = json.loads((d / "incident.json").read_text()) if (d / "incident.json").exists() else None
    hist = _rows(rt, select(D.artifact_hashes).where(D.artifact_hashes.c.case_id == case_id).order_by(desc(D.artifact_hashes.c.id)).limit(20))
    return {"case_id": case_id, "manifest": m, "incident": inc, "files": files, "verifications": hist}


def read_case_file(rt, case_id: str, rel: str, max_bytes: int = 2_000_000) -> tuple[bytes, Path]:
    d = case_dir(rt, case_id).resolve()
    p = (d / rel).resolve()
    if not str(p).startswith(str(d) + "/") or not p.is_file():
        raise FileNotFoundError(rel)
    with open(p, "rb") as fh:
        return fh.read(max_bytes), p


# ------------------------------------------------------------------ analytics
def _field_series(rt, session_id: str, msg: str, field: str, max_points: int = 2000, sysid=None) -> list[list]:
    sess = rt.active
    pts = []
    if sess and sess.session_id == session_id and not sess.pipeline.db:
        for e in sess.pipeline.packets.last(300000):
            if e.msg_name == msg and (sysid is None or e.sysid == sysid):
                v = e.fields.get(field)
                if isinstance(v, (int, float)):
                    pts.append([e.t, v])
    else:
        t = D.mavlink_messages
        conds = [t.c.session_id == session_id, t.c.msg_name == msg]
        if sysid is not None:
            conds.append(t.c.sysid == sysid)
        rows = D.query(rt.engine, select(t.c.t, t.c.fields).where(and_(*conds)).order_by(t.c.t))
        for r in rows:
            v = (D.loads(r["fields"]) or {}).get(field)
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                pts.append([r["t"], v])
    if len(pts) > max_points:
        step = math.ceil(len(pts) / max_points)
        pts = pts[::step]
    return pts


DERIVED = {
    "gps_speed": ("GPS_RAW_INT", "vel", 0.01), "ekf_speed": ("GLOBAL_POSITION_INT", None, None),
    "groundspeed": ("VFR_HUD", "groundspeed", 1.0), "altitude_rel": ("GLOBAL_POSITION_INT", "relative_alt", 0.001),
    "battery_v": ("SYS_STATUS", "voltage_battery", 0.001), "ekf_vel_var": ("EKF_STATUS_REPORT", "velocity_variance", 1.0),
    "satellites": ("GPS_RAW_INT", "satellites_visible", 1.0), "hdop": ("GPS_RAW_INT", "eph", 0.01), "rc_rssi": ("RC_CHANNELS", "rssi", 1.0),
}


def series(rt, session_id: str, fields: list[str], max_points: int = 2000) -> dict:
    out = {}
    for f in fields[:12]:
        if f in DERIVED:
            msg, fld, scale = DERIVED[f]
            if f == "ekf_speed":
                vx = _field_series(rt, session_id, msg, "vx", max_points * 4)
                vy = dict((t, v) for t, v in _field_series(rt, session_id, msg, "vy", max_points * 4))
                pts = [[t, math.hypot(v, vy.get(t, 0)) / 100.0] for t, v in vx if t in vy]
                if len(pts) > max_points:
                    pts = pts[::math.ceil(len(pts) / max_points)]
            else:
                pts = [[t, v * scale] for t, v in _field_series(rt, session_id, msg, fld, max_points)]
            out[f] = {"points": pts, "provenance": f"{msg}.{fld or 'vx,vy'} × {scale or '√(vx²+vy²)/100'}"}
        elif "." in f:
            msg, fld = f.split(".", 1)
            if not rt.registry.is_numeric_field(msg, fld):
                out[f] = {"points": [], "error": "unknown or non-numeric field"}
                continue
            out[f] = {"points": _field_series(rt, session_id, msg, fld, max_points), "provenance": f"{msg}.{fld}"}
    return out


def frequency(rt, session_id: str, top: int = 20) -> dict:
    t = D.mavlink_messages
    sess = rt.active
    if sess and sess.session_id == session_id and not sess.pipeline.db:
        rows = [{"s": int(e.t), "m": e.msg_name} for e in sess.pipeline.packets.last(300000)]
    else:
        rows = [{"s": int(r["t"]), "m": r["msg_name"]} for r in D.query(rt.engine, select(t.c.t, t.c.msg_name).where(t.c.session_id == session_id))]
    totals = Counter(r["m"] for r in rows)
    names = [n for n, _ in totals.most_common(top)]
    per = defaultdict(Counter)
    for r in rows:
        if r["m"] in names:
            per[r["s"]][r["m"]] += 1
    secs = sorted(per)
    return {"messages": names, "totals": dict(totals.most_common(60)),
            "series": {n: [[s, per[s][n]] for s in secs] for n in names}}


def correlation_matrix(rt, session_id: str, fields: list[str]) -> dict:
    s = series(rt, session_id, fields, 5000)
    buckets: dict[str, dict[int, float]] = {}
    for f, d in s.items():
        b = defaultdict(list)
        for t, v in d.get("points", []):
            b[int(t)].append(v)
        buckets[f] = {k: sum(v) / len(v) for k, v in b.items()}
    names = [f for f in fields if f in buckets and len(buckets[f]) > 3]
    mat = []
    for a in names:
        row = []
        for b in names:
            common = sorted(set(buckets[a]) & set(buckets[b]))
            if len(common) < 4:
                row.append(None)
                continue
            xa = [buckets[a][k] for k in common]
            xb = [buckets[b][k] for k in common]
            ma, mb = sum(xa) / len(xa), sum(xb) / len(xb)
            va = math.sqrt(sum((x - ma) ** 2 for x in xa))
            vb = math.sqrt(sum((x - mb) ** 2 for x in xb))
            row.append(None if va < 1e-12 or vb < 1e-12 else round(sum((x - ma) * (y - mb) for x, y in zip(xa, xb)) / (va * vb), 3))
        mat.append(row)
    return {"fields": names, "matrix": mat, "method": "Pearson on 1 s means"}


def sources_table(rt, session_id: str) -> list[dict]:
    t = D.mavlink_messages
    sess = rt.active
    if sess and sess.session_id == session_id:
        si = sess.pipeline.engine.get("SOURCE_IDENTITY")
        return si.table(sess.pipeline.ctx) if si else []
    rows = D.query(rt.engine, select(t.c.sysid, t.c.compid, func.count().label("n"), func.min(t.c.t).label("first"))
                   .where(t.c.session_id == session_id).group_by(t.c.sysid, t.c.compid))
    return [{"sysid": r["sysid"], "compid": r["compid"], "count": r["n"], "first_seen": r["first"]} for r in rows]


def detector_history(rt, session_id: str) -> dict:
    t = D.detector_results
    rows = D.query(rt.engine, select(t.c.t, t.c.detector, t.c.state, t.c.confidence, t.c.severity).where(t.c.session_id == session_id, t.c.kind == "alert").order_by(t.c.t))
    if rt.active and rt.active.session_id == session_id and not rt.active.pipeline.db:
        rows = [{"t": r["t"], "detector": r["detector"], "state": r["state"], "confidence": r["confidence"], "severity": r["severity"]}
                for r in rt.active.pipeline.results_buf.items if r.get("kind") == "alert"]
    by = defaultdict(list)
    for r in rows:
        by[r["detector"]].append([r["t"], r["confidence"], r["state"], r["severity"]])
    return dict(by)


def session_list(rt, limit=100) -> list[dict]:
    rows = _rows(rt, select(D.sessions).order_by(desc(D.sessions.c.started_at)).limit(limit))
    act = rt.active
    for r in rows:
        r["active"] = bool(act and act.session_id == r["session_id"])
    if act and not any(r["session_id"] == act.session_id for r in rows):
        rows.insert(0, {"session_id": act.session_id, "kind": act.kind, "source": act.source, "active": True, "packets": act.pipeline.idx})
    return rows
