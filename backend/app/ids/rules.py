"""Data-driven IDS rule engine for the visual Custom Ruleset (spec §12–17, §61, §83).

Rules are JSON graphs of typed nodes. The GUI manipulates definitions only —
there is no code generation or `eval`: every node type is a fixed, bounded
Python implementation below. Rules are validated (field references against the
backend MAVLink registry, operators, types, durations, thresholds, cycles, graph
size) before they can be tested or published.
"""
from __future__ import annotations

import copy
import math
from collections import deque
from typing import Any, Optional

from ..models.events import DetectorResult, TelemetryEvent, state_rank
from ..mavlink.pushpak import PIDS_DETECTORS
from .stats import CUSUM, EWMA, RollingWindow

MAX_NODES = 120
MAX_EDGES = 300
MAX_WINDOW_S = 3600
MAX_SAMPLES = 5000

COPTER_MODES = ["STABILIZE", "ACRO", "ALT_HOLD", "AUTO", "GUIDED", "LOITER", "RTL", "CIRCLE", "LAND", "DRIFT", "SPORT",
                "FLIP", "AUTOTUNE", "POSHOLD", "BRAKE", "THROW", "AVOID_ADSB", "GUIDED_NOGPS", "SMART_RTL", "FLOWHOLD",
                "FOLLOW", "ZIGZAG", "SYSTEMID", "AUTOROTATE", "AUTO_RTL", "TURTLE"]
PRESET_MSGS = {
    "input_gps": ["GPS_RAW_INT", "GPS2_RAW", "GLOBAL_POSITION_INT"],
    "input_imu": ["RAW_IMU", "SCALED_IMU2", "SCALED_IMU3", "ATTITUDE", "VIBRATION"],
    "input_ekf": ["EKF_STATUS_REPORT", "GLOBAL_POSITION_INT", "LOCAL_POSITION_NED"],
    "input_battery": ["SYS_STATUS", "BATTERY_STATUS"],
    "input_rc": ["RC_CHANNELS", "RADIO_STATUS"],
    "input_mission": ["MISSION_CURRENT", "MISSION_COUNT", "MISSION_ITEM_INT", "MISSION_ACK"],
    "input_command": ["COMMAND_LONG", "COMMAND_INT", "COMMAND_ACK"],
    "input_parameter": ["PARAM_VALUE", "PARAM_SET"],
}
OPS = {">": lambda a, b: a > b, ">=": lambda a, b: a >= b, "<": lambda a, b: a < b, "<=": lambda a, b: a <= b,
       "==": lambda a, b: a == b, "!=": lambda a, b: a != b}
OUTPUT_STATE = {"out_observation": "OBSERVED", "out_anomaly": "ANOMALOUS", "out_suspected": "SUSPECTED",
                "out_incident": "CORRELATED", "out_confirmed": "CONFIRMED", "out_snapshot": "OBSERVED"}
VEHICLE_FIELDS = {"armed": "bool", "airborne": "bool", "relative_alt_m": "num", "groundspeed_ms": "num",
                  "heading_deg": "num", "climb_ms": "num", "battery_remaining_pct": "num"}


def P(name, type_, required=True, default=None, **kw):
    d = {"name": name, "type": type_, "required": required, "default": default}
    d.update(kw)
    return d


_field_params = [P("msg", "message"), P("field", "field"), P("scale", "number", False, 1.0),
                 P("sysid_filter", "enum", False, "vehicle", options=["vehicle", "any", "non_vehicle"]),
                 P("stale_s", "number", False, 5.0, min=0.1, max=MAX_WINDOW_S)]

CATALOG: dict[str, dict] = {
    # ---------------------------------------------------------------- INPUT
    "mavlink_message": {"category": "INPUT", "label": "MAVLink Message", "inputs": [], "output": "any",
                        "params": [P("msg", "message"), P("sysid_filter", "enum", False, "any", options=["vehicle", "any", "non_vehicle"])],
                        "description": "Fires when the message arrives; carries its decoded fields (use Select Field / Rate / Count)."},
    "telemetry_field": {"category": "INPUT", "label": "Telemetry Field", "inputs": [], "output": "num", "params": _field_params,
                        "description": "Numeric field of a MAVLink message (validated against the dialect)."},
    **{k: {"category": "INPUT", "label": k.replace("input_", "").upper() if k != "input_battery" else "Battery", "inputs": [], "output": "num",
           "params": [P("msg", "message", options=v)] + _field_params[1:], "description": f"Field from {', '.join(v)}."}
       for k, v in PRESET_MSGS.items()},
    "flight_mode": {"category": "INPUT", "label": "Flight Mode", "inputs": [], "output": "bool",
                    "params": [P("mode", "enum", options=COPTER_MODES)], "description": "True while the vehicle is in the given mode."},
    "vehicle_state": {"category": "INPUT", "label": "Vehicle State", "inputs": [], "output": "any",
                      "params": [P("field", "enum", options=list(VEHICLE_FIELDS))], "description": "Normalized vehicle state value."},
    "pushpak_fc": {"category": "INPUT", "label": "PUSHPAK FC Detector", "inputs": [], "output": "num",
                   "params": [P("detector", "enum", options=PIDS_DETECTORS), P("stale_s", "number", False, 10.0, min=0.1)],
                   "description": "FC-reported confidence from PIDS STATUSTEXT (N/A when the FC does not report)."},
    "lua_event": {"category": "INPUT", "label": "Lua Event", "inputs": [], "output": "bool",
                  "params": [P("detector", "enum", options=PIDS_DETECTORS), P("window_s", "number", False, 10.0, min=0.1, max=MAX_WINDOW_S)],
                  "description": "True if a Lua confirmation for the detector arrived within the window."},
    "dataflash_event": {"category": "INPUT", "label": "DataFlash Event", "inputs": [], "output": "any",
                        "params": [P("record", "string")], "description": "Fires on a DataFlash record type (offline .bin/.log sources only)."},
    "detector_state": {"category": "INPUT", "label": "Ground Detector State", "inputs": [], "output": "bool",
                       "params": [P("detector", "detector"), P("min_state", "enum", False, "ANOMALOUS", options=["ANOMALOUS", "SUSPECTED", "CONFIRMED"])],
                       "description": "True while a ground detector is at or above the given state."},
    # ---------------------------------------------------------------- TRANSFORM
    "select_field": {"category": "TRANSFORM", "label": "Select Field", "inputs": [{"name": "in", "type": "any"}], "output": "num",
                     "params": [P("field", "string"), P("scale", "number", False, 1.0)], "description": "Pick a numeric field from a MAVLink Message node."},
    "normalize": {"category": "TRANSFORM", "label": "Normalize", "inputs": [{"name": "in", "type": "num"}], "output": "num",
                  "params": [P("min", "number"), P("max", "number")], "description": "(x − min) / (max − min)."},
    "difference": {"category": "TRANSFORM", "label": "Difference", "inputs": [{"name": "a", "type": "num"}, {"name": "b", "type": "num"}],
                   "output": "num", "params": [], "description": "a − b."},
    "abs": {"category": "TRANSFORM", "label": "Absolute Value", "inputs": [{"name": "in", "type": "num"}], "output": "num", "params": [], "description": "|x|."},
    "scale": {"category": "TRANSFORM", "label": "Scale", "inputs": [{"name": "in", "type": "num"}], "output": "num",
              "params": [P("factor", "number", False, 1.0), P("offset", "number", False, 0.0)], "description": "x·factor + offset."},
    "magnitude": {"category": "TRANSFORM", "label": "Magnitude", "inputs": [{"name": "a", "type": "num"}, {"name": "b", "type": "num"}, {"name": "c", "type": "num", "optional": True}],
                  "output": "num", "params": [], "description": "√(a² + b² [+ c²])."},
    "derivative": {"category": "TRANSFORM", "label": "Derivative", "inputs": [{"name": "in", "type": "num"}], "output": "num", "params": [], "description": "dx/dt (per second, monotonic time)."},
    "moving_average": {"category": "TRANSFORM", "label": "Moving Average", "inputs": [{"name": "in", "type": "num"}], "output": "num",
                       "params": [P("window", "int", False, 10, min=2, max=MAX_SAMPLES)], "description": "Mean of the last N samples."},
    "ewma": {"category": "TRANSFORM", "label": "EWMA", "inputs": [{"name": "in", "type": "num"}], "output": "num",
             "params": [P("alpha", "number", False, 0.2, min=0.001, max=1.0)], "description": "Exponentially weighted moving average."},
    "zscore": {"category": "TRANSFORM", "label": "Z-Score", "inputs": [{"name": "in", "type": "num"}], "output": "num",
               "params": [P("window", "int", False, 30, min=5, max=MAX_SAMPLES)], "description": "(x − mean) / std over the window."},
    "robust_zscore": {"category": "TRANSFORM", "label": "Robust Z-Score", "inputs": [{"name": "in", "type": "num"}], "output": "num",
                      "params": [P("window", "int", False, 30, min=5, max=MAX_SAMPLES)], "description": "(x − median) / (1.4826·MAD)."},
    "rate": {"category": "TRANSFORM", "label": "Rate", "inputs": [{"name": "in", "type": "any"}], "output": "num",
             "params": [P("window_s", "number", False, 5.0, min=0.1, max=MAX_WINDOW_S)], "description": "Input updates per second over the window."},
    "frequency": {"category": "TRANSFORM", "label": "Frequency", "inputs": [{"name": "in", "type": "any"}], "output": "num",
                  "params": [P("alpha", "number", False, 0.2, min=0.001, max=1.0)], "description": "EWMA-estimated update frequency (Hz)."},
    "count": {"category": "TRANSFORM", "label": "Count", "inputs": [{"name": "in", "type": "any"}], "output": "num",
              "params": [P("window_s", "number", False, 10.0, min=0.1, max=MAX_WINDOW_S)], "description": "Number of input updates in the window."},
    "delta": {"category": "TRANSFORM", "label": "Delta", "inputs": [{"name": "in", "type": "num"}], "output": "num", "params": [], "description": "x − previous x."},
    "persistence": {"category": "TRANSFORM", "label": "Persistence", "inputs": [{"name": "in", "type": "bool"}], "output": "bool",
                    "params": [P("duration_s", "number", True, 3.0, min=0.0, max=MAX_WINDOW_S)], "description": "True once the input has been true continuously for the duration."},
    "threshold": {"category": "TRANSFORM", "label": "Threshold", "inputs": [{"name": "in", "type": "num"}], "output": "bool",
                  "params": [P("op", "enum", True, ">", options=list(OPS)), P("value", "number")], "description": "Compare with a constant."},
    "range_check": {"category": "TRANSFORM", "label": "Range Check", "inputs": [{"name": "in", "type": "num"}], "output": "bool",
                    "params": [P("min", "number"), P("max", "number"), P("mode", "enum", False, "outside", options=["outside", "inside"])],
                    "description": "True when outside (or inside) [min, max]."},
    "change_detection": {"category": "TRANSFORM", "label": "Change Detection (CUSUM)", "inputs": [{"name": "in", "type": "num"}], "output": "bool",
                         "params": [P("k", "number", False, 0.5, min=0.0), P("h", "number", False, 5.0, min=0.01), P("alpha", "number", False, 0.1, min=0.001, max=1)],
                         "description": "Two-sided CUSUM on the EWMA-standardised input."},
    # ---------------------------------------------------------------- LOGIC
    "and": {"category": "LOGIC", "label": "AND", "inputs": [{"name": f"in{i}", "type": "bool", "optional": i > 2} for i in range(1, 5)], "output": "bool", "params": []},
    "or": {"category": "LOGIC", "label": "OR", "inputs": [{"name": f"in{i}", "type": "bool", "optional": i > 2} for i in range(1, 5)], "output": "bool", "params": []},
    "not": {"category": "LOGIC", "label": "NOT", "inputs": [{"name": "in", "type": "bool"}], "output": "bool", "params": []},
    "xor": {"category": "LOGIC", "label": "XOR", "inputs": [{"name": "in1", "type": "bool"}, {"name": "in2", "type": "bool"}], "output": "bool", "params": []},
    "n_of_m": {"category": "LOGIC", "label": "N-of-M", "inputs": [{"name": f"in{i}", "type": "bool", "optional": i > 2} for i in range(1, 7)], "output": "bool",
               "params": [P("n", "int", True, 2, min=1, max=6)]},
    "sequence": {"category": "LOGIC", "label": "Sequence", "inputs": [{"name": "first", "type": "bool"}, {"name": "then", "type": "bool"}], "output": "bool",
                 "params": [P("window_s", "number", True, 10.0, min=0.1, max=MAX_WINDOW_S)], "description": "True when `then` becomes true within window after `first`."},
    "within_window": {"category": "LOGIC", "label": "Within Time Window", "inputs": [{"name": "in", "type": "bool"}], "output": "bool",
                      "params": [P("window_s", "number", True, 10.0, min=0.1, max=MAX_WINDOW_S)], "description": "True if input was true at any time in the last window."},
    "before": {"category": "LOGIC", "label": "Before", "inputs": [{"name": "a", "type": "bool"}, {"name": "b", "type": "bool"}], "output": "bool",
               "params": [P("window_s", "number", True, 10.0, min=0.1, max=MAX_WINDOW_S)], "description": "a occurred before b (within window)."},
    "after": {"category": "LOGIC", "label": "After", "inputs": [{"name": "a", "type": "bool"}, {"name": "b", "type": "bool"}], "output": "bool",
              "params": [P("window_s", "number", True, 10.0, min=0.1, max=MAX_WINDOW_S)], "description": "a occurred after b (within window)."},
    "until": {"category": "LOGIC", "label": "Until", "inputs": [{"name": "a", "type": "bool"}, {"name": "b", "type": "bool"}], "output": "bool",
              "params": [], "description": "Latched true when a becomes true, until b becomes true."},
    # ---------------------------------------------------------------- CORRELATION
    "cross_sensor": {"category": "CORRELATION", "label": "Cross Sensor", "inputs": [{"name": "a", "type": "num"}, {"name": "b", "type": "num"}], "output": "bool",
                     "params": [P("tolerance", "number", True, 1.0, min=0.0), P("tolerance_ratio", "number", False, 0.0, min=0.0)],
                     "description": "True when |a − b| > tolerance + ratio·|b|."},
    "cross_detector": {"category": "CORRELATION", "label": "Cross Detector", "inputs": [], "output": "bool",
                       "params": [P("detectors", "detectors"), P("min_count", "int", True, 2, min=1, max=20)],
                       "description": "True when at least N listed ground detectors are ANOMALOUS or worse."},
    "fc_ground": {"category": "CORRELATION", "label": "FC + GROUND", "inputs": [{"name": "ground", "type": "bool"}], "output": "bool",
                  "params": [P("detector", "enum", options=PIDS_DETECTORS), P("min_state", "enum", False, "SUSPECTED", options=["SUSPECTED", "CONFIRMED"])],
                  "description": "Ground evidence AND the FC reports the PUSHPAK detector at/above the state."},
    "multi_source": {"category": "CORRELATION", "label": "Multi Source", "inputs": [{"name": f"in{i}", "type": "bool", "optional": i > 2} for i in range(1, 5)], "output": "bool",
                     "params": [P("min_true", "int", True, 2, min=1, max=4)], "description": "At least N inputs true."},
    "temporal_correlation": {"category": "CORRELATION", "label": "Temporal Correlation", "inputs": [{"name": f"in{i}", "type": "bool", "optional": i > 2} for i in range(1, 5)],
                             "output": "bool", "params": [P("window_s", "number", True, 10.0, min=0.1, max=MAX_WINDOW_S)],
                             "description": "Every connected input was true at some point within the window."},
    "evidence_correlation": {"category": "CORRELATION", "label": "Evidence Correlation", "inputs": [{"name": f"in{i}", "type": "bool", "optional": i > 2} for i in range(1, 5)],
                             "output": "bool", "params": [P("weights", "numbers", False, [0.25, 0.25, 0.25, 0.25]), P("threshold", "number", True, 0.5, min=0, max=1)],
                             "description": "Weighted sum of true inputs ≥ threshold."},
    # ---------------------------------------------------------------- OUTPUT
    **{k: {"category": "OUTPUT", "label": {"out_observation": "OBSERVATION", "out_anomaly": "ANOMALY", "out_suspected": "SUSPECTED",
                                          "out_incident": "INCIDENT", "out_confirmed": "CONFIRMED", "out_snapshot": "FORENSIC SNAPSHOT"}[k],
           "inputs": [{"name": "in", "type": "bool"}], "output": "none", "params": [P("title", "string", False, "")],
           "description": f"Emit a {v} result when the input becomes true."} for k, v in OUTPUT_STATE.items()},
}
for _t in CATALOG.values():
    _t.setdefault("description", "")


def catalog() -> dict:
    return {"node_types": CATALOG, "operators": list(OPS), "copter_modes": COPTER_MODES, "vehicle_fields": VEHICLE_FIELDS,
            "pushpak_detectors": PIDS_DETECTORS, "limits": {"max_nodes": MAX_NODES, "max_edges": MAX_EDGES, "max_window_s": MAX_WINDOW_S}}


# ============================================================ validation
RULE_FIELDS = ["rule_id", "name", "description", "enabled", "severity", "confidence", "persistence_s", "cooldown_s",
               "evidence_window_s", "correlation_window_s", "min_evidence", "graph"]
SEVS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def validate_rule(rule: dict, registry, detector_ids: list[str]) -> dict:
    errors: list[dict] = []
    warnings: list[dict] = []

    def err(msg, node=None, field=None):
        errors.append({"node": node, "field": field, "message": msg})

    if not isinstance(rule, dict):
        return {"valid": False, "errors": [{"message": "rule must be an object"}], "warnings": []}
    rid = rule.get("rule_id")
    if not isinstance(rid, str) or not rid or len(rid) > 64 or not all(c.isalnum() or c in "-_" for c in rid):
        err("rule_id must be 1–64 chars [A-Za-z0-9-_]", field="rule_id")
    if not isinstance(rule.get("name"), str) or not rule["name"].strip():
        err("name is required", field="name")
    if rule.get("severity", "MEDIUM") not in SEVS:
        err(f"severity must be one of {SEVS}", field="severity")
    for f in ("persistence_s", "cooldown_s", "evidence_window_s", "correlation_window_s"):
        v = rule.get(f, 0)
        if not _num(v) or v < 0:
            err(f"{f} must be a non-negative number", field=f)
        elif v > MAX_WINDOW_S:
            err(f"{f} exceeds {MAX_WINDOW_S} s", field=f)
    conf = rule.get("confidence") or {}
    if conf.get("method", "weighted_evidence") not in ("weighted_evidence", "fixed"):
        err("confidence.method must be weighted_evidence or fixed", field="confidence")
    for k in ("threshold", "value"):
        if k in conf and (not _num(conf[k]) or not 0 <= conf[k] <= 1):
            err(f"confidence.{k} must be in [0,1]", field="confidence")
    me = rule.get("min_evidence", 0)
    if not isinstance(me, int) or me < 0:
        err("min_evidence must be a non-negative integer", field="min_evidence")

    graph = rule.get("graph") or {}
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    if not isinstance(nodes, list) or not isinstance(edges, list):
        err("graph.nodes and graph.edges must be lists")
        return {"valid": False, "errors": errors, "warnings": warnings}
    if len(nodes) > MAX_NODES:
        err(f"too many nodes ({len(nodes)} > {MAX_NODES})")
    if len(edges) > MAX_EDGES:
        err(f"too many edges ({len(edges)} > {MAX_EDGES})")
    ids = set()
    types: dict[str, str] = {}
    for n in nodes:
        nid, nt = n.get("id"), n.get("type")
        if not isinstance(nid, str) or not nid:
            err("node without id")
            continue
        if nid in ids:
            err(f"duplicate node id {nid}", node=nid)
        ids.add(nid)
        if nt not in CATALOG:
            err(f"unknown node type '{nt}'", node=nid)
            continue
        types[nid] = nt
        spec = CATALOG[nt]
        params = n.get("params") or {}
        for p in spec["params"]:
            v = params.get(p["name"], p.get("default"))
            if v is None or v == "":
                if p["required"] and p["type"] not in ("string",):
                    err(f"parameter '{p['name']}' is required", node=nid, field=p["name"])
                elif p["required"] and p["type"] == "string" and nt == "select_field":
                    err(f"parameter '{p['name']}' is required", node=nid, field=p["name"])
                continue
            t = p["type"]
            if t in ("number", "int"):
                if not _num(v) or (t == "int" and int(v) != v):
                    err(f"'{p['name']}' must be a finite {'integer' if t == 'int' else 'number'}", node=nid, field=p["name"])
                    continue
                if "min" in p and v < p["min"]:
                    err(f"'{p['name']}' must be ≥ {p['min']}" + (" (negative durations are not allowed)" if p["name"].endswith("_s") else ""), node=nid, field=p["name"])
                if "max" in p and v > p["max"]:
                    err(f"'{p['name']}' must be ≤ {p['max']}", node=nid, field=p["name"])
            elif t == "enum" and v not in p.get("options", []):
                err(f"'{p['name']}' must be one of {p.get('options')}", node=nid, field=p["name"])
            elif t == "message":
                if not registry.has_message(v):
                    err(f"unknown MAVLink message '{v}' (not in dialect {registry.dialect_name})", node=nid, field="msg")
                elif p.get("options") and v not in p["options"]:
                    err(f"message must be one of {p['options']} for this input", node=nid, field="msg")
            elif t == "field":
                msg = params.get("msg")
                if msg and registry.has_message(msg):
                    if registry.field_type(msg, v) is None:
                        err(f"'{msg}' has no field '{v}'", node=nid, field="field")
                    elif not registry.is_numeric_field(msg, v):
                        err(f"'{msg}.{v}' is not a numeric scalar (impossible type comparison)", node=nid, field="field")
            elif t == "detector" and v not in detector_ids:
                err(f"unknown ground detector '{v}'", node=nid, field=p["name"])
            elif t == "detectors":
                if not isinstance(v, list) or not v or any(d not in detector_ids for d in v):
                    err(f"'{p['name']}' must list known ground detectors", node=nid, field=p["name"])
            elif t == "numbers":
                if not isinstance(v, list) or not all(_num(x) for x in v):
                    err(f"'{p['name']}' must be a list of numbers", node=nid, field=p["name"])
        if nt == "normalize" and _num(params.get("min")) and _num(params.get("max")) and params["max"] <= params["min"]:
            err("normalize.max must be greater than min", node=nid)
        if nt == "range_check" and _num(params.get("min")) and _num(params.get("max")) and params["max"] < params["min"]:
            err("range_check.max must be ≥ min", node=nid)
        if nt == "select_field":
            pass  # checked against the upstream message below

    # edges
    incoming: dict[str, dict[str, str]] = {nid: {} for nid in ids}
    adj: dict[str, list[str]] = {nid: [] for nid in ids}
    for e in edges:
        s, t, h = e.get("source"), e.get("target"), e.get("targetHandle") or e.get("target_handle") or "in"
        if s not in ids or t not in ids:
            err(f"edge references missing node ({s} → {t})")
            continue
        if s == t:
            err("self-loop edge", node=s)
            continue
        tt = types.get(t)
        if tt is None:
            continue
        handles = {i["name"]: i for i in CATALOG[tt]["inputs"]}
        if h not in handles:
            err(f"node type {tt} has no input '{h}'", node=t)
            continue
        if h in incoming[t]:
            err(f"input '{h}' has more than one connection", node=t)
        incoming[t][h] = s
        adj[s].append(t)
        st = types.get(s)
        if st:
            out_t = CATALOG[st]["output"]
            in_t = handles[h]["type"]
            if out_t == "none":
                err("output nodes cannot feed other nodes", node=s)
            elif in_t != "any" and out_t != "any" and in_t != out_t:
                err(f"type mismatch: {st} outputs {out_t} but {tt}.{h} expects {in_t}", node=t)
    for nid, nt in types.items():
        for i in CATALOG[nt]["inputs"]:
            if not i.get("optional") and i["name"] not in incoming[nid]:
                err(f"required input '{i['name']}' is not connected", node=nid)
        if nt == "select_field":
            src = incoming[nid].get("in")
            if src and types.get(src) != "mavlink_message":
                err("Select Field must be fed by a MAVLink Message node", node=nid)
            elif src:
                msg = next((n.get("params", {}).get("msg") for n in nodes if n.get("id") == src), None)
                fld = (next(n for n in nodes if n.get("id") == nid).get("params") or {}).get("field")
                if msg and registry.has_message(msg) and fld:
                    if registry.field_type(msg, fld) is None:
                        err(f"'{msg}' has no field '{fld}'", node=nid, field="field")
                    elif not registry.is_numeric_field(msg, fld):
                        err(f"'{msg}.{fld}' is not numeric", node=nid, field="field")
    # cycles (Kahn)
    indeg = {n: 0 for n in ids}
    for s, ts in adj.items():
        for t in ts:
            indeg[t] += 1
    q = deque([n for n, d in indeg.items() if d == 0])
    order = []
    while q:
        n = q.popleft()
        order.append(n)
        for t in adj[n]:
            indeg[t] -= 1
            if indeg[t] == 0:
                q.append(t)
    if len(order) != len(ids):
        cyc = sorted(n for n, d in indeg.items() if d > 0)
        err(f"circular rule graph through nodes {cyc}")
    outs = [nid for nid, t in types.items() if CATALOG[t]["category"] == "OUTPUT"]
    if not outs:
        err("rule needs at least one OUTPUT node")
    reachable_inputs = {nid for nid, t in types.items() if CATALOG[t]["category"] == "INPUT"}
    if not reachable_inputs:
        err("rule needs at least one INPUT node")
    for nid, t in types.items():
        if CATALOG[t]["category"] != "OUTPUT" and not adj.get(nid):
            warnings.append({"node": nid, "message": "node output is not used"})
    return {"valid": not errors, "errors": errors, "warnings": warnings, "order": order if not errors else []}


# ============================================================ runtime
class NodeState:
    __slots__ = ("value", "fired", "t", "mono", "extra", "payload")

    def __init__(self):
        self.value: Any = None
        self.fired = False
        self.t: Optional[float] = None
        self.mono: Optional[float] = None
        self.extra: dict = {}
        self.payload: Optional[dict] = None


class RuleRuntime:
    """Compiled, stateful evaluator for one immutable rule version."""

    def __init__(self, rule: dict, order: list[str]):
        self.rule = rule
        self.rule_id = rule["rule_id"]
        self.version = rule.get("version", 0)
        self.nodes = {n["id"]: n for n in rule["graph"]["nodes"]}
        self.order = order
        self.inputs: dict[str, dict[str, str]] = {nid: {} for nid in self.nodes}
        for e in rule["graph"]["edges"]:
            self.inputs[e["target"]][e.get("targetHandle") or e.get("target_handle") or "in"] = e["source"]
        self.st = {nid: NodeState() for nid in self.nodes}
        self.aux: dict[str, Any] = {}
        self.persist_since: dict[str, Optional[float]] = {}
        self.last_fire: dict[str, float] = {}
        self.prev_out: dict[str, bool] = {}
        self.triggers = 0
        self.evaluations = 0
        self.errors = 0
        self.last_trace: Optional[list] = None
        self.upstream_bool = self._upstream_bools()

    def _upstream_bools(self) -> dict[str, list[str]]:
        res = {}
        for nid, n in self.nodes.items():
            if CATALOG[n["type"]]["category"] != "OUTPUT":
                continue
            seen, stack, bools = set(), [nid], []
            while stack:
                cur = stack.pop()
                for src in self.inputs[cur].values():
                    if src in seen:
                        continue
                    seen.add(src)
                    if CATALOG[self.nodes[src]["type"]]["output"] == "bool":
                        bools.append(src)
                    stack.append(src)
            res[nid] = bools
        return res

    def p(self, nid, name):
        n = self.nodes[nid]
        v = (n.get("params") or {}).get(name)
        if v is None:
            spec = next((p for p in CATALOG[n["type"]]["params"] if p["name"] == name), None)
            v = spec.get("default") if spec else None
        return v

    def iv(self, nid, handle):
        src = self.inputs[nid].get(handle)
        return None if src is None else self.st[src]

    # --------------------------------------------------------------- evaluate
    def evaluate(self, ev: Optional[TelemetryEvent], ctx, vstate) -> list[DetectorResult]:
        self.evaluations += 1
        for nid in self.order:
            s = self.st[nid]
            s.fired = False
            try:
                self._eval_node(nid, self.nodes[nid]["type"], s, ev, ctx, vstate)
            except (TypeError, ValueError, ZeroDivisionError, OverflowError) as exc:
                s.value = None
                s.extra["error"] = str(exc)[:120]
                self.errors += 1
        return self._outputs(ev, ctx)

    def _eval_node(self, nid, t, s: NodeState, ev, ctx, vstate):
        mono, now = ctx.mono, ctx.t
        cat = CATALOG[t]["category"]
        if cat == "INPUT":
            self._eval_input(nid, t, s, ev, ctx, vstate)
            return
        ins = {h: self.st[src] for h, src in self.inputs[nid].items()}
        any_fired = any(x.fired for x in ins.values())
        vals = {h: x.value for h, x in ins.items()}

        def upd(v):
            s.value, s.fired, s.t, s.mono = v, True, now, mono

        if t == "select_field":
            if any_fired:
                pl = ins["in"].payload or {}
                v = pl.get(self.p(nid, "field"))
                upd(None if not _num(v) else v * float(self.p(nid, "scale") or 1.0))
        elif t in ("normalize", "abs", "scale", "delta", "derivative", "moving_average", "ewma", "zscore", "robust_zscore", "difference", "magnitude"):
            if not any_fired:
                return
            x = vals.get("in")
            if t == "difference":
                a, b = vals.get("a"), vals.get("b")
                upd(a - b if _num(a) and _num(b) else None)
            elif t == "magnitude":
                comps = [vals.get(k) for k in ("a", "b", "c") if k in vals]
                upd(math.sqrt(sum(c * c for c in comps)) if comps and all(_num(c) for c in comps) else None)
            elif not _num(x):
                upd(None)
            elif t == "normalize":
                lo, hi = float(self.p(nid, "min")), float(self.p(nid, "max"))
                upd((x - lo) / (hi - lo))
            elif t == "abs":
                upd(abs(x))
            elif t == "scale":
                upd(x * float(self.p(nid, "factor")) + float(self.p(nid, "offset")))
            elif t == "delta":
                prev = self.aux.get((nid, "prev"))
                self.aux[(nid, "prev")] = x
                upd(None if prev is None else x - prev)
            elif t == "derivative":
                prev = self.aux.get((nid, "prev"))
                self.aux[(nid, "prev")] = (x, mono)
                upd(None if not prev or mono - prev[1] <= 1e-6 else (x - prev[0]) / (mono - prev[1]))
            elif t == "moving_average":
                w = self.aux.setdefault(nid, deque(maxlen=int(self.p(nid, "window"))))
                w.append(x)
                upd(sum(w) / len(w))
            elif t == "ewma":
                e = self.aux.setdefault(nid, EWMA(float(self.p(nid, "alpha"))))
                upd(e.update(x))
            elif t in ("zscore", "robust_zscore"):
                w = self.aux.setdefault(nid, RollingWindow(int(self.p(nid, "window"))))
                z = w.zscore(x) if t == "zscore" else w.robust_z(x)
                w.push(x)
                upd(z)
        elif t in ("rate", "count", "frequency"):
            q = self.aux.setdefault(nid, deque())
            if any_fired:
                q.append(mono)
            if t == "frequency":
                if any_fired:
                    prev = self.aux.get((nid, "last"))
                    self.aux[(nid, "last")] = mono
                    e = self.aux.setdefault((nid, "e"), EWMA(float(self.p(nid, "alpha"))))
                    if prev is not None and mono > prev:
                        e.update(1.0 / (mono - prev))
                    upd(e.mean)
                return
            win = float(self.p(nid, "window_s"))
            while q and mono - q[0] > win:
                q.popleft()
            upd(len(q) / win if t == "rate" else float(len(q)))
        elif t == "persistence":
            x = vals.get("in") is True
            since = self.persist_since.get(nid)
            if x:
                since = since if since is not None else mono
            else:
                since = None
            self.persist_since[nid] = since
            held = 0.0 if since is None else mono - since
            s.extra = {"held_s": round(held, 3), "duration_s": self.p(nid, "duration_s")}
            upd(bool(x and held >= float(self.p(nid, "duration_s"))))
        elif t == "threshold":
            x = vals.get("in")
            s.extra = {"op": self.p(nid, "op"), "value": self.p(nid, "value"), "input": x}
            upd(None if not _num(x) else OPS[self.p(nid, "op")](x, float(self.p(nid, "value"))))
        elif t == "range_check":
            x = vals.get("in")
            if not _num(x):
                upd(None)
            else:
                inside = float(self.p(nid, "min")) <= x <= float(self.p(nid, "max"))
                upd(inside if self.p(nid, "mode") == "inside" else not inside)
        elif t == "change_detection":
            x = vals.get("in")
            if any_fired and _num(x):
                e = self.aux.setdefault((nid, "e"), EWMA(float(self.p(nid, "alpha"))))
                cp = self.aux.setdefault((nid, "p"), CUSUM(float(self.p(nid, "k")), float(self.p(nid, "h"))))
                cn = self.aux.setdefault((nid, "n"), CUSUM(float(self.p(nid, "k")), float(self.p(nid, "h"))))
                z = e.z(x)
                e.update(x)
                if z is not None:
                    cp.update(z)
                    cn.update(-z)
                s.extra = {"cusum_pos": round(cp.s, 3), "cusum_neg": round(cn.s, 3), "h": cp.h}
                upd(cp.alarm or cn.alarm)
        elif t in ("and", "or", "xor", "n_of_m", "multi_source"):
            bs = [v is True for v in vals.values()]
            if t == "and":
                upd(bool(bs) and all(bs))
            elif t == "or":
                upd(any(bs))
            elif t == "xor":
                upd(sum(bs) == 1)
            elif t == "n_of_m":
                upd(sum(bs) >= int(self.p(nid, "n")))
            else:
                upd(sum(bs) >= int(self.p(nid, "min_true")))
            s.extra = {"true_inputs": sum(bs), "inputs": len(bs)}
        elif t == "not":
            v = vals.get("in")
            upd(None if v is None else not v)
        elif t in ("sequence", "before", "after"):
            win = float(self.p(nid, "window_s"))
            first, second = ("first", "then") if t == "sequence" else (("a", "b") if t == "before" else ("b", "a"))
            if vals.get(first) is True:
                self.aux[(nid, "first")] = mono
            ft = self.aux.get((nid, "first"))
            upd(bool(vals.get(second) is True and ft is not None and 0 <= mono - ft <= win))
        elif t == "within_window":
            if vals.get("in") is True:
                self.aux[nid] = mono
            last = self.aux.get(nid)
            upd(last is not None and mono - last <= float(self.p(nid, "window_s")))
        elif t == "until":
            latched = self.aux.get(nid, False)
            if vals.get("b") is True:
                latched = False
            elif vals.get("a") is True:
                latched = True
            self.aux[nid] = latched
            upd(latched)
        elif t == "cross_sensor":
            a, b = vals.get("a"), vals.get("b")
            if not (_num(a) and _num(b)):
                upd(None)
            else:
                tol = float(self.p(nid, "tolerance")) + float(self.p(nid, "tolerance_ratio") or 0) * abs(b)
                s.extra = {"difference": round(abs(a - b), 4), "tolerance": round(tol, 4)}
                upd(abs(a - b) > tol)
        elif t == "fc_ground":
            fc = ctx.fc_states.get(self.p(nid, "detector"))
            fc_ok = fc is not None and state_rank(fc.get("state")) >= state_rank(self.p(nid, "min_state"))
            s.extra = {"fc_state": fc.get("state") if fc else "N/A (no FC telemetry)"}
            upd(bool(vals.get("ground") is True and fc_ok))
        elif t == "temporal_correlation":
            win = float(self.p(nid, "window_s"))
            lasts = self.aux.setdefault(nid, {})
            for h, v in vals.items():
                if v is True:
                    lasts[h] = mono
            ok = len(vals) > 0 and all(h in lasts and mono - lasts[h] <= win for h in vals)
            s.extra = {"seen": {h: round(mono - lasts[h], 2) for h in lasts}}
            upd(ok)
        elif t == "evidence_correlation":
            ws = self.p(nid, "weights") or []
            score = 0.0
            for i, h in enumerate(sorted(vals)):
                if vals[h] is True:
                    score += float(ws[i]) if i < len(ws) else 0.0
            s.extra = {"score": round(score, 4), "threshold": self.p(nid, "threshold")}
            upd(score >= float(self.p(nid, "threshold")))
        elif cat == "OUTPUT":
            v = vals.get("in")
            upd(v is True)

    def _eval_input(self, nid, t, s: NodeState, ev, ctx, vstate):
        mono, now = ctx.mono, ctx.t

        def upd(v, payload=None):
            s.value, s.fired, s.t, s.mono = v, True, now, mono
            if payload is not None:
                s.payload = payload

        def sys_ok(filt):
            if filt == "vehicle":
                return ev.sysid == ctx.vehicle_sysid
            if filt == "non_vehicle":
                return ev.sysid != ctx.vehicle_sysid
            return True

        if t == "mavlink_message":
            if ev is not None and ev.msg_name == self.p(nid, "msg") and sys_ok(self.p(nid, "sysid_filter")):
                upd(1.0, ev.fields)
                s.extra = {"sysid": ev.sysid, "idx": ev.idx}
        elif t == "telemetry_field" or t in PRESET_MSGS:
            stale = float(self.p(nid, "stale_s") or 5.0)
            if ev is not None and ev.msg_name == self.p(nid, "msg") and sys_ok(self.p(nid, "sysid_filter")):
                v = ev.fields.get(self.p(nid, "field"))
                upd(v * float(self.p(nid, "scale") or 1.0) if _num(v) else None)
                s.extra = {"idx": ev.idx, "raw": v}
            elif s.mono is not None and mono - s.mono > stale:
                s.value = None  # stale → unknown, never a fabricated 0
                s.extra["stale"] = True
        elif t == "flight_mode":
            s.value = (ctx.mode or "") == self.p(nid, "mode") if ctx.mode else None
            s.fired = ev is not None and ev.msg_name == "HEARTBEAT"
            s.t, s.mono = now, mono
        elif t == "vehicle_state":
            f = self.p(nid, "field")
            v = {"armed": ctx.armed, "airborne": ctx.airborne}.get(f) if f in ("armed", "airborne") else vstate.value(f) if vstate else None
            s.fired = s.value != v
            s.value, s.t, s.mono = v, now, mono
        elif t == "pushpak_fc":
            rec = ctx.fc_states.get(self.p(nid, "detector"))
            if rec is None or now - rec.get("t", 0) > float(self.p(nid, "stale_s")):
                s.value = None
                s.extra = {"status": "N/A — no PIDS telemetry"}
            else:
                s.fired = ev is not None and ev.msg_name == "STATUSTEXT"
                s.value = rec["confidence"]
                s.extra = {"state": rec["state"], "evidence": rec.get("evidence", {}).get("bits")}
        elif t == "lua_event":
            rec = ctx.lua_states.get(self.p(nid, "detector"))
            s.value = rec is not None and now - rec.get("t", -1e18) <= float(self.p(nid, "window_s"))
            s.fired = ev is not None and ev.msg_name == "STATUSTEXT"
            s.extra = {"class": rec.get("class")} if rec else {"status": "no Lua confirmation"}
        elif t == "dataflash_event":
            if ev is not None and ev.origin == self.p(nid, "record"):
                upd(1.0, ev.fields)
        elif t == "detector_state":
            st = ctx.detector_states.get(self.p(nid, "detector"))
            s.value = state_rank(st) >= state_rank(self.p(nid, "min_state"))
            s.fired = True
            s.extra = {"state": st or "N/A"}

    # --------------------------------------------------------------- outputs
    def _outputs(self, ev, ctx) -> list[DetectorResult]:
        out = []
        rule = self.rule
        for nid, n in self.nodes.items():
            t = n["type"]
            if CATALOG[t]["category"] != "OUTPUT":
                continue
            active = self.st[nid].value is True
            # rule-level persistence
            since = self.persist_since.get(("out", nid))
            since = (since if since is not None else ctx.mono) if active else None
            self.persist_since[("out", nid)] = since
            held = 0.0 if since is None else ctx.mono - since
            ready = active and held >= float(rule.get("persistence_s", 0) or 0)
            was = self.prev_out.get(nid, False)
            self.prev_out[nid] = ready
            if not ready or was:
                continue
            if ctx.mono - self.last_fire.get(nid, -1e18) < float(rule.get("cooldown_s", 0) or 0):
                continue
            bools = self.upstream_bool.get(nid, [])
            true_n = sum(1 for b in bools if self.st[b].value is True)
            if true_n < int(rule.get("min_evidence", 0) or 0):
                continue
            cm = rule.get("confidence") or {"method": "weighted_evidence", "threshold": 0.0}
            if cm.get("method") == "fixed":
                conf = float(cm.get("value", 0.5))
            else:
                conf = true_n / len(bools) if bools else 1.0
                if conf < float(cm.get("threshold", 0) or 0):
                    continue
            self.last_fire[nid] = ctx.mono
            self.triggers += 1
            trace = self.trace(held)
            self.last_trace = trace
            state = OUTPUT_STATE[t]
            title = (n.get("params") or {}).get("title") or rule.get("name") or self.rule_id
            refs = sorted({x.extra.get("idx") for x in self.st.values() if isinstance(x.extra, dict) and x.extra.get("idx") is not None})
            r = DetectorResult(detector=f"RULE:{self.rule_id}", state=state, title=title, t=ctx.t,
                               severity=rule.get("severity", "MEDIUM"), confidence=round(conf, 3), source="GROUND",
                               domain=rule.get("domain", "RULE"), method="Custom Ruleset rule graph",
                               parameters={"persistence_s": rule.get("persistence_s"), "cooldown_s": rule.get("cooldown_s"),
                                           "confidence": cm, "min_evidence": rule.get("min_evidence", 0)},
                               inputs={row["label"]: row["value"] for row in trace if row["category"] == "INPUT"},
                               score=round(conf, 3), threshold=cm.get("threshold"), rule_id=self.rule_id, rule_version=self.version,
                               detector_version=f"rule-v{self.version}", packet_refs=refs[-30:] or ([ev.idx] if ev else []),
                               trace=trace, kind="alert")
            r.explanation = {
                "what": title, "why": " → ".join(f"{row['label']}={_fmt(row['value'])}" for row in trace),
                "when": r.to_dict()["ts"], "source": f"Custom Ruleset rule {self.rule_id} v{self.version}",
                "evidence": [f"{row['label']}: {_fmt(row['value'])}" + (f" ({row['detail']})" if row.get("detail") else "") for row in trace],
                "rule": f"{self.rule_id} v{self.version}: persistence {rule.get('persistence_s', 0)} s, cooldown {rule.get('cooldown_s', 0)} s",
                "confidence": f"{round(conf * 100)}% ({true_n}/{len(bools)} boolean conditions true)" if cm.get("method") != "fixed" else f"fixed {conf}",
                "contributors": [{"label": self.nodes[b].get("label") or self.nodes[b]["type"], "value": 1.0 / max(len(bools), 1)} for b in bools if self.st[b].value is True],
                "limitations": [rule.get("limitations") or "Rule output is only as good as its inputs; review the trace."],
            }
            r.actions = {"snapshot": t == "out_snapshot", "incident": t in ("out_incident", "out_confirmed")}
            out.append(r)
        return out

    def trace(self, held: float = 0.0) -> list[dict]:
        rows = []
        for nid in self.order:
            n = self.nodes[nid]
            st = self.st[nid]
            spec = CATALOG[n["type"]]
            detail = ""
            ex = st.extra or {}
            if n["type"] == "threshold":
                detail = f"{ex.get('op')} {ex.get('value')}"
            elif n["type"] == "persistence":
                detail = f"{ex.get('held_s')} s ≥ {ex.get('duration_s')} s?"
            elif ex:
                detail = ", ".join(f"{k}={_fmt(v)}" for k, v in ex.items() if k not in ("idx",))[:160]
            rows.append({"node_id": nid, "type": n["type"], "category": spec["category"],
                         "label": n.get("label") or self._auto_label(n), "value": _round(st.value),
                         "inputs": {h: _round(self.st[src].value) for h, src in self.inputs[nid].items()},
                         "detail": detail})
        rows.append({"node_id": "_result", "type": "result", "category": "RESULT", "label": "RESULT", "value": "TRIGGERED",
                     "inputs": {}, "detail": f"rule persistence held {held:.2f} s"})
        return rows

    def _auto_label(self, n) -> str:
        p = n.get("params") or {}
        spec = CATALOG[n["type"]]
        if "msg" in p and "field" in p:
            return f"{p['msg']}.{p['field']}"
        if n["type"] == "threshold":
            return f"{p.get('op', '>')} {p.get('value')}"
        return spec["label"]

    def node_values(self) -> dict:
        return {nid: {"value": _round(st.value), "fired": st.fired, "extra": {k: _round(v) for k, v in (st.extra or {}).items()}}
                for nid, st in self.st.items()}


def _round(v):
    if isinstance(v, float):
        return round(v, 4)
    if isinstance(v, dict):
        return {k: _round(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_round(x) for x in v]
    return v


def _fmt(v) -> str:
    if v is None:
        return "N/A"
    if isinstance(v, bool):
        return "TRUE" if v else "FALSE"
    if isinstance(v, float):
        return f"{v:.3f}".rstrip("0").rstrip(".")
    return str(v)


def compile_rule(rule: dict, registry, detector_ids) -> RuleRuntime:
    v = validate_rule(rule, registry, detector_ids)
    if not v["valid"]:
        raise ValueError(f"invalid rule {rule.get('rule_id')}: {v['errors'][:3]}")
    return RuleRuntime(copy.deepcopy(rule), v["order"])
