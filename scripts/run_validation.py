#!/usr/bin/env python3
"""Stage-1 attack/validation runs (TC-01..TC-06) on SIMULATED data.

Every run is varied: new random seed (sensor noise), attack magnitude drawn
from U(0.6, 1.4) and injection time from U(35 s, 60 s). The fixed PUSHPAK Lua
scripts run 'on board' via LuaFlightBridge, so their detections reach the GCS as
real MAVLink STATUSTEXT frames. The GCS pipeline (ground detectors + published
rules + correlation) analyses the combined stream exactly as it would live.

Usage: python scripts/run_validation.py [--runs 10] [--seed 2026]
Outputs: validation/results.json, validation/summary.md, data/captures/VAL-TC-0x.tlog
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.config import Config  # noqa: E402
from app.core.errors import ErrorRegistry  # noqa: E402
from app.core.pipeline import Pipeline  # noqa: E402
from app.ids.builtin_rules import BUILTIN_RULES  # noqa: E402
from app.ids.correlation import IncidentIdAllocator  # noqa: E402
from app.ids.rules import compile_rule  # noqa: E402
from app.lua_runtime import LuaFlightBridge  # noqa: E402
from app.mavlink.decoder import tlog_record  # noqa: E402
from app.mavlink.pushpak import parse_statustext  # noqa: E402
from app.mavlink.registry import DialectRegistry  # noqa: E402
from app.models.events import state_rank  # noqa: E402
from app.sources.files import SourceItem  # noqa: E402
from app.sources.simulation import FlightSimulator  # noqa: E402

TESTS = [
    {"id": "TC-01", "scenario": "NORMAL_FLIGHT", "benign": True,
     "attack": "Benign baseline: armed takeoff, GUIDED→AUTO waypoint mission, RTL; no injected attack (sensor noise varies per run)",
     "ground": [], "lua": None,
     "sources": "All vehicle MAVLink (HEARTBEAT, GPS_RAW_INT, GLOBAL_POSITION_INT, EKF_STATUS_REPORT, RAW_IMU/SCALED_IMU2, SYS_STATUS, RC_CHANNELS, RADIO_STATUS, MISSION_*, PARAM_*); all 8 Lua scripts",
     "expected": "No ANOMALOUS/SUSPECTED alerts, no incident; Lua scripts stay CLEAR (only BRIDGE announcement)",
     "criteria": "0 false-positive alerts and 0 incidents per run; 0 Lua SUSPECTED/CONFIRMED"},
    {"id": "TC-02", "scenario": "GPS_IMU_MISMATCH", "benign": False,
     "attack": "GNSS spoofing: reported GPS velocity raised to 8+10.4·m m/s (m∈[0.6,1.4]) with position drag for 8 s while EKF/inertial velocity stays ≈8 m/s",
     "ground": ["GPS_INTEGRITY", "RULE:GPS-CONSISTENCY-001"], "lua": "GPS", "domain": "GPS_INTEGRITY",
     "sources": "GPS_RAW_INT (vel, fix, sats, HDOP), GLOBAL_POSITION_INT (EKF vx/vy), EKF_STATUS_REPORT (velocity variance); Lua gps_confirm.lua (gps:, ahrs:)",
     "expected": "GPS_INTEGRITY residual/CUSUM alert, rule GPS-CONSISTENCY-001 fires, GPS integrity incident; gps_confirm.lua → PIDS GPS CONFIRMED + 'GPS CONFIRMED' STATUSTEXT",
     "criteria": "Ground alert and incident within 5 s of injection; Lua GPS CONFIRMED; no single-sample alert"},
    {"id": "TC-03", "scenario": "COMMAND_BURST", "benign": False,
     "attack": "Command injection from unknown SYSID 42: burst of COMMAND_LONG for 3·m s (DO_SET_MODE accepted, DISARM-in-flight and REBOOT refused)",
     "ground": ["COMMAND", "SOURCE_IDENTITY", "RULE:CMD-BURST-001"], "lua": "COMMAND", "domain": "MAVLINK_SECURITY",
     "sources": "COMMAND_LONG, COMMAND_ACK, HEARTBEAT (SYSID/COMPID provenance); Lua command_confirm.lua (mode, ModeReason, GCS last-seen)",
     "expected": "Untrusted-source + context-inconsistent command alerts, CMD-BURST-001 rule, correlated MAVLink-security incident; Lua sees GCS-commanded mode changes in flight",
     "criteria": "Incident CONFIRMED (≥2 independent detectors) within 5 s; Lua ≥ SUSPECTED (Lua cannot see packet source on this firmware)"},
    {"id": "TC-04", "scenario": "PARAMETER_CHANGE", "benign": False,
     "attack": "Parameter tampering in flight from SYSID 42: 3–6 PARAM_SET writes (FENCE_ENABLE=0, ARMING_CHECK=0, FS_THR_ENABLE=0, RTL_ALT, WPNAV_SPEED, ANGLE_MAX)",
     "ground": ["PARAMETER", "SOURCE_IDENTITY"], "lua": "PARAMETER", "domain": "MAVLINK_SECURITY",
     "sources": "PARAM_SET, PARAM_VALUE (old/new/original values), HEARTBEAT; Lua parameter_confirm.lua (param:get watch-list)",
     "expected": "Parameter anomaly alerts (sensitive while armed, untrusted writer, large deviation, burst), incident; Lua PARAMETER CONFIRMED",
     "criteria": "Ground alert within 2 s of first write; incident created; Lua PARAMETER CONFIRMED"},
    {"id": "TC-05", "scenario": "RC_DEGRADATION", "benign": False,
     "attack": "RC/telemetry jamming: RSSI falls at 7·m units/s, radio rx-errors and noise rise, RC receiver lost 3× for 4 s (intermittent)",
     "ground": ["RC_LINK"], "lua": "RC_LINK", "domain": "LINK",
     "sources": "RC_CHANNELS (rssi), RADIO_STATUS (rssi, noise, rxerrors), SYS_STATUS (RC receiver health bit); Lua jamming_confirm.lua (rc:has_valid_input)",
     "expected": "Gradual-degradation, low-quality, complete-loss and intermittent-loss RC_LINK alerts; Lua RC_LINK CONFIRMED (JAMMING_OR_LOW_LINK_DEGRADATION)",
     "criteria": "Ground RC_LINK alert before first receiver loss; Lua RC_LINK CONFIRMED by the 3rd loss"},
    {"id": "TC-06", "scenario": "MISSION_CHANGE", "benign": False,
     "attack": "Mission tampering in flight: SYSID 42 uploads a 3-item mission (waypoints scaled by m), vehicle index restarts",
     "ground": ["MISSION", "SOURCE_IDENTITY"], "lua": "MISSION", "domain": "MISSION",
     "sources": "MISSION_COUNT, MISSION_ITEM_INT (SHA-256 fingerprint), MISSION_ACK, MISSION_CURRENT; Lua mission_confirm.lua (mission:get_item fingerprint)",
     "expected": "Mission modification during flight (fingerprint change + untrusted uploader) + index discontinuity, incident; Lua MISSION CONFIRMED (IN_FLIGHT_MISSION_INTEGRITY_ANOMALY)",
     "criteria": "Ground alert within 2 s of upload; incident created; Lua MISSION CONFIRMED"},
]


def run_once(tc: dict, seed: int, rng: random.Random, cfg, reg, keep_tlog: Path | None = None) -> dict:
    mag = round(rng.uniform(0.6, 1.4), 2)
    inj = round(rng.uniform(35.0, 60.0), 1)
    dur = inj + 60.0
    sim = FlightSimulator(tc["scenario"], seed=seed, duration_s=dur, inject_at=inj, t0=1_790_000_000.0, magnitude=mag)
    bridge = LuaFlightBridge(sim)
    err = ErrorRegistry()
    p = Pipeline(session_id=f"VAL-{tc['id']}-{seed}", kind="validation", source_desc=tc["scenario"], config=cfg, registry=reg,
                 errors=err, capabilities={}, allocator=IncidentIdAllocator())
    p.set_rules([compile_rule(dict(r, version=1), reg, list(p.engine.detectors)) for r in BUILTIN_RULES])
    t0 = time.perf_counter()
    raw = bytearray()
    n = 0
    for fr in bridge.frames():
        p.handle_item(SourceItem("frame", fr.t, fr.data, fr.link, "SIMULATION"))
        n += 1
        if keep_tlog is not None:
            raw += tlog_record(fr.t, fr.data)
    elapsed = time.perf_counter() - t0
    t_inj = 1_790_000_000.0 + inj
    alerts = sorted(p.alerts.values(), key=lambda a: a["t"])
    strong = [a for a in alerts if state_rank(a["state"]) >= 2 and a["source"] == "GROUND"]
    pre = [a for a in strong if a["t"] < t_inj]
    post = [a for a in strong if a["t"] >= t_inj and (not tc["ground"] or a["detector"] in tc["ground"])]
    incs = [i for i in p.correlator.incidents.values() if i["first_seen"] >= t_inj - 1]
    inc = next((i for i in incs if not tc.get("domain") or i["domain"] == tc["domain"] or tc["domain"] in ("MISSION",)), incs[0] if incs else None)
    # what the GCS decoded from the Lua-generated STATUSTEXT frames
    lua_recs = [dict(parse_statustext(txt) or {}, t=t, script=sc) for t, sc, txt in bridge.texts]
    lua_pids = [r for r in lua_recs if r.get("kind") == "PIDS" and r.get("origin") == "LUA"]
    lua_alarm = [r for r in lua_pids if r["state"] in ("SUSPECTED", "CONFIRMED")]
    exp = tc["lua"]
    lua_best = None
    lua_lat = None
    if exp:
        mine = [r for r in lua_alarm if r["detector"] == exp and r["t"] >= t_inj]
        if mine:
            lua_best = "CONFIRMED" if any(r["state"] == "CONFIRMED" for r in mine) else "SUSPECTED"
            first = next(r for r in mine if r["state"] == lua_best)
            lua_lat = round(first["t"] - t_inj, 2)
    gcs_lua = p.engine.get("PUSHPAK_FC").lua if p.engine.get("PUSHPAK_FC") else {}
    lua_classes = sorted({r["class"] for r in lua_recs if r.get("kind") == "LUA_CONFIRMATION"})
    return {
        "seed": seed, "magnitude": mag, "inject_at_s": inj, "frames": n, "lua_frames": len(bridge.texts),
        "analysis_s": round(elapsed, 3), "throughput_msg_s": round(n / elapsed),
        "ground_detected": bool(post), "ground_latency_s": round(post[0]["t"] - t_inj, 2) if post else None,
        "ground_first_alert": post[0]["title"] if post else None, "ground_false_alerts_pre_injection": len(pre),
        "ground_alerts_total": len(strong),
        "incident": {"state": inc["state"], "severity": inc["severity"], "confidence": inc["confidence"], "detectors": inc["detectors"],
                     "sources": inc["sources"], "latency_s": round(inc["first_seen"] - t_inj, 2)} if inc else None,
        "incidents_total": len(p.correlator.incidents),
        "lua_state": lua_best, "lua_latency_s": lua_lat, "lua_classes": lua_classes,
        "lua_false_alarms": len([r for r in lua_alarm if r["t"] < t_inj or (exp and r["detector"] != exp)]) if not tc["benign"] else len(lua_alarm),
        "lua_seen_by_gcs": sorted(gcs_lua), "lua_script_errors": bridge.errors(), "detector_errors": len(err.list()),
        "_tlog": bytes(raw) if keep_tlog is not None else None,
    }


def summarize(tc, runs) -> dict:
    n = len(runs)
    if tc["benign"]:
        fp = sum(r["ground_alerts_total"] for r in runs)
        return {"runs": n, "ground_false_positive_alerts": fp, "false_incidents": sum(r["incidents_total"] for r in runs),
                "lua_false_alarms": sum(r["lua_false_alarms"] for r in runs), "pass": fp == 0 and sum(r["lua_false_alarms"] for r in runs) == 0
                and sum(r["incidents_total"] for r in runs) == 0}
    det = [r for r in runs if r["ground_detected"]]
    lat = [r["ground_latency_s"] for r in det]
    inc = [r for r in runs if r["incident"]]
    lua_c = [r for r in runs if r["lua_state"] == "CONFIRMED"]
    lua_s = [r for r in runs if r["lua_state"] in ("SUSPECTED", "CONFIRMED")]
    lua_lat = [r["lua_latency_s"] for r in lua_s if r["lua_latency_s"] is not None]
    return {
        "runs": n, "ground_detection_rate": f"{len(det)}/{n}",
        "ground_latency_s": {"median": round(statistics.median(lat), 2), "min": min(lat), "max": max(lat)} if lat else None,
        "incident_rate": f"{len(inc)}/{n}", "incident_states": {s: sum(1 for r in inc if r["incident"]["state"] == s) for s in {r["incident"]["state"] for r in inc}},
        "lua_confirmed": f"{len(lua_c)}/{n}", "lua_detected": f"{len(lua_s)}/{n}",
        "lua_latency_s": {"median": round(statistics.median(lua_lat), 2), "min": min(lua_lat), "max": max(lua_lat)} if lua_lat else None,
        "lua_classes": sorted({c for r in runs for c in r["lua_classes"]}),
        "false_alerts_before_injection": sum(r["ground_false_alerts_pre_injection"] for r in runs),
        "lua_script_errors": sum(len(r["lua_script_errors"]) for r in runs),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--seed", type=int, default=2026)
    a = ap.parse_args()
    cfg, reg = Config.load(), DialectRegistry()
    rng = random.Random(a.seed)
    out = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "data": "SIMULATED (synthetic MAVLink + Lua 5.4 scripts on simulated state)",
           "runs_per_test": a.runs, "master_seed": a.seed, "tests": []}
    cap = ROOT / "data" / "captures"
    cap.mkdir(parents=True, exist_ok=True)
    for tc in TESTS:
        runs = []
        for i in range(a.runs):
            r = run_once(tc, seed=a.seed * 100 + i, rng=rng, cfg=cfg, reg=reg, keep_tlog=cap if i == 0 else None)
            if r["_tlog"]:
                (cap / f"VAL-{tc['id']}.tlog").write_bytes(r["_tlog"])
            r.pop("_tlog")
            runs.append(r)
        s = summarize(tc, runs)
        out["tests"].append({**{k: v for k, v in tc.items()}, "summary": s, "runs": runs})
        print(tc["id"], tc["scenario"], json.dumps(s))
    vdir = ROOT / "validation"
    vdir.mkdir(exist_ok=True)
    (vdir / "results.json").write_text(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
