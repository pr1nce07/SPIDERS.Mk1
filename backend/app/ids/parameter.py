"""Parameter anomaly detector (spec §23). The original value is always kept."""
from __future__ import annotations

from collections import deque
from typing import Optional

from ..models.events import TelemetryEvent
from .base import AnalysisContext, Detector
from .stats import EWMA, CUSUM, clamp01


def _pname(v) -> str:
    if isinstance(v, (bytes, bytearray)):
        v = v.decode(errors="ignore")
    return str(v or "").rstrip("\x00")


class ParameterDetector(Detector):
    detector_id = "PARAMETER"
    name = "Parameter Anomaly"
    domain = "MAVLINK_SECURITY"
    data_sources = ("PARAM_VALUE", "PARAM_SET")
    methods = ("original-value baseline", "sensitive-while-armed context", "write-burst rate", "relative deviation",
               "source provenance", "EWMA/CUSUM low-and-slow drift")
    description = "Sensitive, rapid, large, or unexplained runtime parameter changes."
    limitations = ("A parameter may be changed from another GCS link or a Lua script the GCS cannot see.",)

    def __init__(self, cfg):
        super().__init__(cfg)
        self.burst_n = int(self.cfg.get("burst_count", 5))
        self.burst_w = float(self.cfg.get("burst_window_s", 10))
        self.ratio = float(self.cfg.get("large_deviation_ratio", 0.5))
        self.sensitive = tuple(self.cfg.get("sensitive_prefixes", []))
        self.values: dict[str, float] = {}
        self.original: dict[str, float] = {}
        self.sets: dict[str, dict] = {}
        self.changes: deque = deque()
        self.drift: dict[str, tuple[EWMA, CUSUM]] = {}
        self.history: deque = deque(maxlen=2000)
        self.cool: dict = {}

    def is_sensitive(self, name: str) -> bool:
        return name.startswith(self.sensitive)

    def process(self, ev: TelemetryEvent, ctx: AnalysisContext):
        self.mark_data(ctx)
        f = ev.fields
        name = _pname(f.get("param_id"))
        val = f.get("param_value")
        if not name:
            return []
        if ev.msg_name == "PARAM_SET":
            self.sets[name] = {"t": ctx.mono, "sysid": ev.sysid, "compid": ev.compid, "value": val, "idx": ev.idx}
            trusted = ctx.is_trusted_gcs(ev.sysid)
            if not trusted or (self.is_sensitive(name) and ctx.airborne):
                conf = clamp01((0.35 if not trusted else 0) + (0.3 if self.is_sensitive(name) else 0.1) + (0.2 if ctx.armed else 0))
                return [self.result(ctx, "SUSPECTED" if not trusted else "ANOMALOUS",
                                    "Parameter write from untrusted source" if not trusted else "Sensitive parameter write while airborne",
                                    ev=ev, confidence=conf, method="source provenance + sensitive-while-armed context",
                                    inputs={"param": name, "requested_value": val, "current_value": self.values.get(name),
                                            "sysid": ev.sysid, "armed": ctx.armed, "airborne": ctx.airborne, "sensitive": self.is_sensitive(name)},
                                    why=f"PARAM_SET {name}={val} from SYSID {ev.sysid}.",
                                    contributors=[c for c in [
                                        {"label": "untrusted writer", "value": 0.35} if not trusted else None,
                                        {"label": "sensitive parameter", "value": 0.3} if self.is_sensitive(name) else None,
                                        {"label": "vehicle armed", "value": 0.2} if ctx.armed else None] if c])]
            return []
        # PARAM_VALUE from the vehicle
        if ev.sysid != ctx.vehicle_sysid or val is None:
            return []
        old = self.values.get(name)
        self.values[name] = val
        if old is None:
            self.original.setdefault(name, val)
            return []
        if val == old:
            return []
        # a change
        rec = {"t": ctx.t, "name": name, "old": old, "new": val, "original": self.original.get(name), "idx": ev.idx}
        self.history.append(rec)
        self.changes.append(ctx.mono)
        while self.changes and ctx.mono - self.changes[0] > self.burst_w:
            self.changes.popleft()
        req = self.sets.get(name)
        explained = req is not None and ctx.mono - req["t"] < 5
        requester = req["sysid"] if explained else None
        dev = abs(val - old) / max(abs(old), 1e-6)
        ew, cu = self.drift.setdefault(name, (EWMA(0.3), CUSUM(0.5, 4.0)))
        ew.update(val)
        cu.update(dev * 10)
        evid, reasons = [], []
        if self.is_sensitive(name) and ctx.armed:
            evid.append({"label": "sensitive change while armed", "value": 0.30}); reasons.append("sensitive parameter changed while armed")
        if not explained:
            evid.append({"label": "no observed PARAM_SET (unexpected runtime modification)", "value": 0.25}); reasons.append("no matching PARAM_SET observed")
        elif not ctx.is_trusted_gcs(requester):
            evid.append({"label": "untrusted writer", "value": 0.35}); reasons.append(f"written by SYSID {requester}")
        if dev > self.ratio:
            evid.append({"label": "large deviation", "value": 0.15}); reasons.append(f"relative change {dev:.0%}")
        if len(self.changes) >= self.burst_n:
            evid.append({"label": "parameter write burst", "value": 0.20}); reasons.append(f"{len(self.changes)} changes in {self.burst_w:.0f} s")
        if cu.alarm:
            evid.append({"label": "low-and-slow drift (CUSUM)", "value": 0.15}); reasons.append("cumulative drift exceeded CUSUM limit"); cu.reset()
        inputs = {"param": name, "old_value": old, "new_value": val, "original_value": self.original.get(name),
                  "relative_change": round(dev, 4), "writer_sysid": requester, "armed": ctx.armed, "sensitive": self.is_sensitive(name)}
        refs = [ev.idx] + ([req["idx"]] if explained else [])
        if not evid:
            return [self.result(ctx, "OBSERVED", f"Parameter changed: {name}", kind="observation", ev=ev, refs=refs,
                                inputs=inputs, method="original-value baseline", why=f"{name}: {old} → {val} (requested by trusted GCS).")]
        conf = clamp01(sum(e["value"] for e in evid))
        state = "SUSPECTED" if len(evid) >= 2 and conf >= 0.45 else "ANOMALOUS"
        if not self._cool((name, state), ctx, 3):
            return []
        return [self.result(ctx, state, f"Parameter anomaly: {name}", ev=ev, refs=refs, confidence=conf,
                            method="weighted evidence (context/provenance/deviation/burst/drift)",
                            parameters={"burst_count": self.burst_n, "burst_window_s": self.burst_w, "large_deviation_ratio": self.ratio},
                            inputs=inputs, why="; ".join(reasons), contributors=evid,
                            evidence=[f"{e['label']} (+{round(e['value'] * 100)})" for e in evid])]

    def _cool(self, key, ctx, s):
        if ctx.mono - self.cool.get(key, -1e9) < s:
            return False
        self.cool[key] = ctx.mono
        return True

    def tick(self, ctx):
        self.metrics = {"known_parameters": len(self.values), "changes": len(self.history)}
        return []
