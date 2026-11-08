"""Offboard / external-control detector."""
from __future__ import annotations

from collections import deque
from typing import Optional

from ..models.events import TelemetryEvent
from .base import AnalysisContext, Detector
from .stats import Persistence, clamp01, haversine_m

SETPOINT_MSGS = ("SET_POSITION_TARGET_LOCAL_NED", "SET_POSITION_TARGET_GLOBAL_INT", "SET_ATTITUDE_TARGET")


class OffboardDetector(Detector):
    detector_id = "OFFBOARD"
    name = "Offboard / External Control"
    domain = "MAVLINK_SECURITY"
    data_sources = SETPOINT_MSGS + ("POSITION_TARGET_GLOBAL_INT", "GLOBAL_POSITION_INT")
    methods = ("stream freshness", "setpoint-rate burst", "source novelty", "commanded-vs-observed kinematic divergence")
    description = "External setpoint streams: staleness, flooding, unexpected sources and target/position divergence."
    limitations = ("Setpoints sent on links invisible to this GCS are only seen through the vehicle's POSITION_TARGET echo.",)

    def __init__(self, cfg):
        super().__init__(cfg)
        self.stale_s = float(self.cfg.get("stale_s", 1.5))
        self.burst_hz = float(self.cfg.get("burst_hz", 60))
        self.div_m = float(self.cfg.get("divergence_m", 25))
        self.p_div = Persistence(float(self.cfg.get("divergence_s", 5)))
        self.times: deque = deque()
        self.stream_active = False
        self.sources: set = set()
        self.target: Optional[dict] = None
        self.last_dist: Optional[float] = None
        self.cool: dict = {}

    def process(self, ev: TelemetryEvent, ctx: AnalysisContext):
        n, f, out = ev.msg_name, ev.fields, []
        if n in SETPOINT_MSGS:
            self.mark_data(ctx)
            self.times.append(ctx.mono)
            while self.times and ctx.mono - self.times[0] > 2:
                self.times.popleft()
            rate = len(self.times) / 2
            if rate >= 2:
                self.stream_active = True
            if ev.sysid not in self.sources:
                self.sources.add(ev.sysid)
                if not ctx.is_trusted_gcs(ev.sysid) and ev.sysid != ctx.vehicle_sysid:
                    out.append(self.result(ctx, "SUSPECTED", "External-control setpoints from unexpected source", ev=ev, confidence=0.55,
                                           method="source novelty", inputs={"sysid": ev.sysid, "compid": ev.compid, "msg": n, "mode": ctx.mode},
                                           why="Setpoints arrived from a SYSID that is neither the vehicle nor a trusted GCS."))
            if rate > self.burst_hz and self._cool("burst", ctx, 10):
                out.append(self.result(ctx, "ANOMALOUS", "Setpoint flooding", ev=ev, method="setpoint-rate burst", score=rate,
                                       threshold=self.burst_hz, inputs={"rate_hz": rate, "sysid": ev.sysid},
                                       why=f"Setpoint rate {rate:.0f} Hz exceeds {self.burst_hz:.0f} Hz."))
        elif n == "POSITION_TARGET_GLOBAL_INT" and ev.sysid == ctx.vehicle_sysid:
            self.mark_data(ctx)
            self.target = {"lat": f.get("lat_int"), "lon": f.get("lon_int"), "mono": ctx.mono, "idx": ev.idx}
        elif n == "GLOBAL_POSITION_INT" and ev.sysid == ctx.vehicle_sysid and self.target and (ctx.mode or "").upper() == "GUIDED":
            if ctx.mono - self.target["mono"] < 3 and self.target["lat"]:
                d = haversine_m(f["lat"] / 1e7, f["lon"] / 1e7, self.target["lat"] / 1e7, self.target["lon"] / 1e7)
                closing = self.last_dist is not None and d < self.last_dist - 0.05
                self.last_dist = d
                ok, held = self.p_div.update(d > self.div_m and not closing, ctx.mono)
                self.metrics["target_distance_m"] = round(d, 1)
                if ok and self._cool("div", ctx, 20):
                    out.append(self.result(ctx, "ANOMALOUS", "Commanded vs observed kinematic divergence", ev=ev,
                                           refs=[self.target["idx"], ev.idx], method="commanded-vs-observed kinematic divergence",
                                           score=round(d, 1), threshold=self.div_m, confidence=clamp01(d / (4 * self.div_m)),
                                           inputs={"distance_to_target_m": round(d, 1), "persisted_s": round(held, 1)},
                                           why="Vehicle is not converging on its reported GUIDED target."))
        return out

    def tick(self, ctx):
        out = []
        if self.stream_active and self.times and (ctx.mode or "").upper() == "GUIDED":
            gap = ctx.mono - self.times[-1]
            if gap > self.stale_s:
                self.stream_active = False
                out.append(self.result(ctx, "ANOMALOUS", "Stale external-control stream", method="stream freshness",
                                       threshold=self.stale_s, score=round(gap, 2), inputs={"gap_s": round(gap, 2), "mode": ctx.mode},
                                       why=f"Setpoint stream stopped for {gap:.1f} s while in GUIDED."))
        self.metrics.update({"stream_active": self.stream_active, "sources": sorted(s for s in self.sources if s is not None)})
        return out

    def _cool(self, key, ctx, s):
        if ctx.mono - self.cool.get(key, -1e9) < s:
            return False
        self.cool[key] = ctx.mono
        return True
