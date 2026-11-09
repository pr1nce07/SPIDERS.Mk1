"""BASELINE detector: compare the vehicle against an approved, signed manifest (GAP-11).

Runtime detectors learn normal behaviour from what they first observe. This one
does not learn: it only reports `BASELINE_MISMATCH` against an engineer-approved
manifest, so a value that was already wrong at boot is still caught.
"""
from __future__ import annotations

from typing import Optional

from ..models.events import TelemetryEvent
from ..security.baseline import mission_digest, verify_doc
from .base import AnalysisContext, Detector
from .mission import _item_key
from .parameter import _pname


class BaselineDetector(Detector):
    detector_id = "BASELINE"
    name = "Approved Baseline"
    domain = "MAVLINK_SECURITY"
    data_sources = ("PARAM_VALUE", "MISSION_COUNT", "MISSION_ITEM_INT", "MISSION_ITEM", "HEARTBEAT")
    methods = ("signed manifest comparison", "pre-arm baseline check")
    description = "Compares reported parameters and the downloaded mission with a signed, approved baseline manifest."
    limitations = ("Only parameters and mission items that cross a link visible to this GCS can be compared.",
                   "The GCS sees the mission only when it is uploaded or downloaded on a visible link.")

    def __init__(self, cfg, doc: Optional[dict] = None, trusted: Optional[dict] = None):
        super().__init__(cfg)
        self.doc = doc
        self.trusted = trusted or {}
        self.check = verify_doc(doc, self.trusted) if doc else {"status": "NO_APPROVED_BASELINE"}
        body = (doc or {}).get("body", {}) if self.check["status"] == "VALID" else {}
        self.params: dict[str, float] = body.get("parameters") or {}
        self.mission: Optional[dict] = body.get("mission")
        tol = body.get("tolerance") or {}
        self.tol_rel, self.tol_abs = float(tol.get("relative", 1e-4)), float(tol.get("absolute", 1e-6))
        self.vehicle = body.get("vehicle") or {}
        self.param_state: dict[str, dict] = {}
        self.mission_state: Optional[dict] = None
        self.transfer: Optional[dict] = None
        self.was_armed = None
        self.vehicle_checked = False
        self.reported: set = set()
        if self.check["status"] == "NO_APPROVED_BASELINE":
            self.health_state = "DISABLED"  # nothing to compare against until an engineer approves a baseline
        elif self.check["status"] != "VALID":
            self.health_state = "ERROR"
            self.last_error = f"approved baseline rejected: {self.check['status']}"

    @property
    def active(self) -> bool:
        return self.check["status"] == "VALID"

    def accepts(self, ev):
        return self.active and ev.msg_name in self.data_sources

    def _matches(self, approved: float, value: float) -> bool:
        return abs(value - approved) <= max(self.tol_abs, self.tol_rel * abs(approved))

    def process(self, ev: TelemetryEvent, ctx: AnalysisContext):
        if ev.sysid != ctx.vehicle_sysid and ev.msg_name not in ("MISSION_COUNT", "MISSION_ITEM_INT", "MISSION_ITEM"):
            return []
        self.mark_data(ctx)
        out = []
        if not self.vehicle_checked and ctx.vehicle_sysid is not None:
            self.vehicle_checked = True
            want = self.vehicle.get("sysid")
            if want is not None and want != ctx.vehicle_sysid:
                self.check = {"status": "WRONG_VEHICLE", "field": "sysid", "manifest": want, "observed": ctx.vehicle_sysid}
                self.health_state, self.last_error = "ERROR", "approved baseline is for another vehicle"
                return [self.result(ctx, "OBSERVED", "Approved baseline is for another vehicle", kind="health", severity="MEDIUM",
                                    ev=ev, method="signed manifest comparison", inputs=dict(self.check),
                                    why="The manifest's vehicle SYSID does not match this vehicle; no comparison is made.")]
        f, n = ev.fields, ev.msg_name
        if n == "PARAM_VALUE":
            name, val = _pname(f.get("param_id")), f.get("param_value")
            if name in self.params and val is not None:
                ok = self._matches(self.params[name], float(val))
                prev = self.param_state.get(name)
                self.param_state[name] = {"value": float(val), "approved": self.params[name], "match": ok}
                if not ok and (prev is None or prev["value"] != float(val)):
                    out.append(self._mismatch(ctx, ev, f"Parameter {name} differs from approved baseline",
                                              {"param": name, "observed": float(val), "approved": self.params[name]}))
        elif n == "MISSION_COUNT" and f.get("mission_type") in (None, 0):
            self.transfer = {"count": f.get("count"), "sysid": ev.sysid, "items": {}}
            if f.get("count") == 0:
                out += self._mission_done(ctx, ev)
        elif n in ("MISSION_ITEM_INT", "MISSION_ITEM") and self.transfer and ev.sysid == self.transfer["sysid"]:
            if f.get("mission_type") in (None, 0):
                self.transfer["items"][f.get("seq")] = _item_key(f)
                if len(self.transfer["items"]) == self.transfer["count"]:
                    out += self._mission_done(ctx, ev)
        elif n == "HEARTBEAT":
            armed = bool(ctx.armed)
            if armed and self.was_armed is False:
                out += self._arming_check(ctx, ev)
            self.was_armed = armed
        return out

    def _mission_done(self, ctx, ev) -> list:
        tr, self.transfer = self.transfer, None
        if self.mission is None:
            return []
        items = [tr["items"][k] for k in sorted(k for k in tr["items"] if k is not None)]
        digest = mission_digest(items) if items else mission_digest([])
        ok = digest == self.mission["digest"]
        self.mission_state = {"digest": digest, "count": len(items), "match": ok}
        if ok:
            return []
        return [self._mismatch(ctx, ev, "Mission differs from approved baseline",
                               {"observed_count": len(items), "approved_count": self.mission["count"],
                                "observed_digest": digest, "approved_digest": self.mission["digest"]})]

    def _arming_check(self, ctx, ev) -> list:
        bad = sorted(k for k, v in self.param_state.items() if not v["match"])
        unseen = sorted(set(self.params) - set(self.param_state))
        mission_bad = self.mission is not None and (self.mission_state is None or not self.mission_state["match"])
        if not bad and not (self.mission_state and not self.mission_state["match"]):
            return []
        return [self.result(ctx, "SUSPECTED", "Vehicle armed with baseline mismatches", ev=ev, severity="HIGH", confidence=0.7,
                            method="pre-arm baseline check",
                            inputs={"mismatched_parameters": bad, "unverified_parameters": unseen[:50],
                                    "mission_mismatch": bool(self.mission_state and not self.mission_state["match"]),
                                    "mission_unverified": mission_bad and self.mission_state is None},
                            why="The vehicle armed while reporting values that differ from the approved baseline.")]

    def _mismatch(self, ctx, ev, title, inputs) -> object:
        st = "SUSPECTED" if ctx.armed else "ANOMALOUS"
        return self.result(ctx, st, f"BASELINE_MISMATCH: {title}", ev=ev, severity="HIGH" if ctx.armed else "MEDIUM",
                           confidence=0.6 if ctx.armed else 0.45, method="signed manifest comparison", inputs=inputs,
                           why="The approved baseline is not updated automatically; approve a new baseline if this change is legitimate.",
                           evidence=[f"{k} = {v}" for k, v in inputs.items()] +
                                    [f"approved by {self.doc['body']['approval']['approved_by']} "
                                     f"({self.doc['body']['approval']['reason']})"])

    def tick(self, ctx):
        self.metrics = {"baseline": self.check.get("status"), "profile_version": self.check.get("profile_version"),
                        "parameters_approved": len(self.params),
                        "parameters_verified": sum(1 for v in self.param_state.values() if v["match"]),
                        "parameters_mismatched": sorted(k for k, v in self.param_state.items() if not v["match"]),
                        "parameters_not_yet_observed": len(set(self.params) - set(self.param_state)),
                        "mission": self.mission_state or ("not yet observed" if self.mission else "not in baseline")}
        return []
