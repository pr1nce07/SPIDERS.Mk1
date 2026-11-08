"""RC / link detector (spec §25): distinguishes temporary, intermittent and
complete loss plus recovery; correlates RSSI trend, radio errors, receiver health."""
from __future__ import annotations

from collections import deque
from typing import Optional

from ..models.events import TelemetryEvent
from .base import AnalysisContext, Detector
from .stats import EWMA, Persistence, clamp01

RC_RECEIVER_BIT = 65536  # MAV_SYS_STATUS_SENSOR_RC_RECEIVER


class RCLinkDetector(Detector):
    detector_id = "RC_LINK"
    name = "RC / Link"
    domain = "LINK"
    data_sources = ("RC_CHANNELS", "RC_CHANNELS_RAW", "RADIO_STATUS", "SYS_STATUS")
    methods = ("RSSI EWMA + slope", "abrupt-loss detector", "radio rx-error/noise trend", "RC receiver health bit",
               "intermittency classification", "persistence")
    description = "RC/telemetry link degradation classes: temporary, intermittent, complete loss, recovery."
    limitations = ("Range loss, antenna faults and interference all degrade RSSI; this detector does not prove jamming.",)

    def __init__(self, cfg):
        super().__init__(cfg)
        self.rssi_low = float(self.cfg.get("rssi_low", 60))
        self.slope_thr = float(self.cfg.get("degrade_slope_per_s", -1.5))
        self.ew = EWMA(float(self.cfg.get("ewma_alpha", 0.2)))
        self.hist: deque = deque(maxlen=60)
        self.p_low = Persistence(3.0)
        self.losses: deque = deque(maxlen=50)
        self.phase = "OK"
        self.last_rssi: Optional[tuple] = None
        self.radio_prev: Optional[dict] = None
        self.rc_unhealthy_since: Optional[float] = None
        self.cool: dict = {}

    def process(self, ev: TelemetryEvent, ctx: AnalysisContext):
        if ctx.vehicle_sysid is not None and ev.sysid != ctx.vehicle_sysid and ev.msg_name != "RADIO_STATUS":
            return []
        f, n, out = ev.fields, ev.msg_name, []
        if n in ("RC_CHANNELS", "RC_CHANNELS_RAW"):
            rssi = f.get("rssi")
            if rssi is None or rssi == 255:
                self.metrics["rssi"] = "N/A (receiver reports 255 = unknown)"
                return []
            self.mark_data(ctx)
            out += self._rssi(ev, ctx, float(rssi))
        elif n == "RADIO_STATUS":
            self.mark_data(ctx)
            out += self._radio(ev, ctx, f)
        elif n == "SYS_STATUS":
            present = f.get("onboard_control_sensors_present") or 0
            if present & RC_RECEIVER_BIT:
                self.mark_data(ctx)
                healthy = bool((f.get("onboard_control_sensors_health") or 0) & RC_RECEIVER_BIT)
                if not healthy and self.rc_unhealthy_since is None:
                    self.rc_unhealthy_since = ctx.mono
                    self.losses.append(ctx.mono)
                    recent = sum(1 for x in self.losses if ctx.mono - x < 60)
                    out.append(self.result(ctx, "SUSPECTED" if recent >= 3 else "ANOMALOUS",
                                           "RC link: intermittent loss" if recent >= 3 else "RC link: complete loss (receiver unhealthy)",
                                           ev=ev, confidence=clamp01(0.4 + 0.15 * recent), method="RC receiver health bit + intermittency",
                                           inputs={"rc_receiver_healthy": False, "losses_last_60s": recent,
                                                   "rssi_ewma": None if self.ew.mean is None else round(self.ew.mean, 1),
                                                   "drop_rate_comm": f.get("drop_rate_comm")},
                                           why="SYS_STATUS reports the RC receiver present but unhealthy (failsafe condition)."))
                    self.phase = "LOST"
                elif healthy and self.rc_unhealthy_since is not None:
                    dur = ctx.mono - self.rc_unhealthy_since
                    self.rc_unhealthy_since = None
                    self.phase = "OK"
                    out.append(self.result(ctx, "OBSERVED", "RC link recovery", kind="recovery", ev=ev,
                                           inputs={"outage_s": round(dur, 1)}, method="RC receiver health bit",
                                           why=f"RC receiver healthy again after {dur:.1f} s."))
        return out

    def _rssi(self, ev, ctx, rssi) -> list:
        out = []
        prev = self.last_rssi
        self.last_rssi = (rssi, ctx.mono)
        self.ew.update(rssi)
        self.hist.append((ctx.mono, self.ew.mean))
        slope = self._slope()
        self.metrics.update({"rssi": rssi, "rssi_ewma": round(self.ew.mean, 1), "slope_per_s": None if slope is None else round(slope, 2), "phase": self.phase})
        if prev and prev[0] > 80 and rssi < prev[0] * 0.5 and ctx.mono - prev[1] < 1.5 and self._cool("abrupt", ctx, 10):
            self.losses.append(ctx.mono)
            out.append(self.result(ctx, "ANOMALOUS", "RC link: abrupt RSSI loss", ev=ev, method="abrupt-loss detector",
                                   inputs={"rssi_before": prev[0], "rssi_after": rssi, "dt_s": round(ctx.mono - prev[1], 2)},
                                   why="RSSI fell by more than half within one update (disconnect/hardware or strong interference candidate)."))
        low, held = self.p_low.update((self.ew.mean or 255) < self.rssi_low, ctx.mono)
        if slope is not None and slope < self.slope_thr and (self.ew.mean or 255) < 200 and self._cool("grad", ctx, 20):
            out.append(self.result(ctx, "ANOMALOUS", "RC link: gradual degradation", ev=ev, method="RSSI EWMA + slope",
                                   parameters={"degrade_slope_per_s": self.slope_thr}, score=round(slope, 2), threshold=self.slope_thr,
                                   inputs={"rssi_ewma": round(self.ew.mean, 1), "slope_per_s": round(slope, 2)},
                                   confidence=clamp01(slope / (self.slope_thr * 3)),
                                   why="RSSI is trending down steadily (range loss or jamming candidate)."))
        if low and self._cool("low", ctx, 15):
            out.append(self.result(ctx, "ANOMALOUS", "RC link: low quality (temporary degradation)", ev=ev,
                                   method="RSSI EWMA + persistence", threshold=self.rssi_low, score=round(self.ew.mean, 1),
                                   inputs={"rssi_ewma": round(self.ew.mean, 1), "persisted_s": round(held, 1)},
                                   why=f"RSSI EWMA below {self.rssi_low:.0f} for {held:.1f} s."))
        return out

    def _radio(self, ev, ctx, f) -> list:
        prev, self.radio_prev = self.radio_prev, dict(f, mono=ctx.mono)
        self.metrics.update({"radio_rssi": f.get("rssi"), "radio_remrssi": f.get("remrssi"), "noise": f.get("noise"),
                             "rxerrors": f.get("rxerrors")})
        if not prev:
            return []
        dt = max(ctx.mono - prev["mono"], 1e-3)
        err_rate = ((f.get("rxerrors") or 0) - (prev.get("rxerrors") or 0)) / dt
        noise_up = (f.get("noise") or 0) - (prev.get("noise") or 0)
        if (err_rate > 5 or noise_up > 20) and self._cool("radio", ctx, 15):
            return [self.result(ctx, "ANOMALOUS", "Telemetry radio errors / noise rising", ev=ev, severity="LOW",
                                method="radio rx-error/noise trend",
                                inputs={"rxerrors_per_s": round(err_rate, 1), "noise_delta": noise_up, "rssi": f.get("rssi"), "remrssi": f.get("remrssi")},
                                why="Radio receive errors or noise floor rising (RF interference candidate).")]
        return []

    def _slope(self) -> Optional[float]:
        pts = [(t, v) for t, v in self.hist if v is not None]
        if len(pts) < 8 or pts[-1][0] - pts[0][0] < 3:
            return None
        n = len(pts)
        mt = sum(t for t, _ in pts) / n
        mv = sum(v for _, v in pts) / n
        den = sum((t - mt) ** 2 for t, _ in pts)
        return sum((t - mt) * (v - mv) for t, v in pts) / den if den > 1e-9 else None

    def _cool(self, key, ctx, s):
        if ctx.mono - self.cool.get(key, -1e9) < s:
            return False
        self.cool[key] = ctx.mono
        return True
