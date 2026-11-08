"""GPS integrity engine (spec §21).

Layers: rule → statistical → cross-sensor → persistence → correlation.
A single GPS jump is never reported as confirmed spoofing: the ground detector
maximum is SUSPECTED; confirmation requires correlation with other sources.
"""
from __future__ import annotations

import math
from typing import Optional

from ..models.events import TelemetryEvent
from .base import AnalysisContext, Detector
from .stats import CUSUM, EWMA, Persistence, RollingWindow, clamp01, haversine_m

WEIGHTS = {"position_residual": 0.25, "velocity_residual": 0.20, "robust_z": 0.15, "cusum_drift": 0.15,
           "ekf_innovation": 0.15, "quality_mismatch": 0.10}


class GPSIntegrityDetector(Detector):
    detector_id = "GPS_INTEGRITY"
    name = "GPS Integrity"
    domain = "GPS_INTEGRITY"
    data_sources = ("GPS_RAW_INT", "GLOBAL_POSITION_INT", "EKF_STATUS_REPORT", "GPS2_RAW")
    methods = ("fix/sats/HDOP rules", "GPS↔EKF position residual", "GPS↔EKF velocity residual", "rolling median + MAD robust z",
               "EWMA", "one-sided CUSUM slow-drift", "position-jump implied speed", "EKF innovation variance",
               "quality-vs-navigation mismatch", "receiver disagreement", "persistence")
    description = "Multi-indicator GNSS integrity: residuals, drift, jumps, EKF innovations and receiver quality."
    limitations = ("This evidence alone does not prove intentional spoofing.", "No independent RF measurement is available.",
                   "The EKF fuses GPS, so sustained spoofing can drag the EKF and shrink residuals; innovations and transients carry most signal.")

    def __init__(self, cfg):
        super().__init__(cfg)
        c = self.cfg
        self.pos_thr = float(c.get("position_residual_m", 15))
        self.vel_thr = float(c.get("velocity_residual_ms", 3.0))
        self.jump_factor = float(c.get("jump_speed_factor", 3.0))
        self.jump_min = float(c.get("jump_min_m", 30))
        self.rz_thr = float(c.get("robust_z", 4.0))
        self.var_thr = float(c.get("ekf_variance_threshold", 0.8))
        self.min_sats = int(c.get("min_sats", 6))
        self.max_hdop = float(c.get("max_hdop", 2.5))
        self.persist_s = float(c.get("persistence_s", 3.0))
        self.window = RollingWindow(int(c.get("window", 30)))
        self.ewma = EWMA(float(c.get("ewma_alpha", 0.15)))
        self.cusum = CUSUM(float(c.get("cusum_k", 1.0)), float(c.get("cusum_h", 12.0)))
        self.persist = Persistence(self.persist_s)
        self.persist_short = Persistence(min(1.0, self.persist_s))
        self.ekf_pos: Optional[dict] = None
        self.ekf: Optional[dict] = None
        self.gps2: Optional[dict] = None
        self.prev_fix: Optional[dict] = None
        self.prev_quality: Optional[tuple] = None
        self.last_emit: dict = {}
        self.series: dict = {}

    def process(self, ev: TelemetryEvent, ctx: AnalysisContext):
        if ctx.vehicle_sysid is not None and ev.sysid != ctx.vehicle_sysid:
            return []
        self.mark_data(ctx)
        f = ev.fields
        if ev.msg_name == "GLOBAL_POSITION_INT":
            self.ekf_pos = {"lat": f.get("lat"), "lon": f.get("lon"), "vx": f.get("vx"), "vy": f.get("vy"),
                            "alt": f.get("alt"), "mono": ctx.mono, "idx": ev.idx}
            return []
        if ev.msg_name == "EKF_STATUS_REPORT":
            self.ekf = {"vel_var": f.get("velocity_variance"), "pos_var": f.get("pos_horiz_variance"),
                        "hgt_var": f.get("pos_vert_variance"), "flags": f.get("flags"), "mono": ctx.mono, "idx": ev.idx}
            return []
        if ev.msg_name == "GPS2_RAW":
            self.gps2 = {"lat": f.get("lat"), "lon": f.get("lon"), "fix": f.get("fix_type"), "mono": ctx.mono}
            return []
        return self._evaluate(ev, ctx)

    def _evaluate(self, ev, ctx) -> list:
        f = ev.fields
        fix = f.get("fix_type")
        sats = f.get("satellites_visible")
        sats = None if sats in (None, 255) else sats
        eph = f.get("eph")
        hdop = None if eph in (None, 65535, 0xFFFF) else eph / 100.0
        vel = f.get("vel")
        gps_speed = None if vel in (None, 65535) else vel / 100.0
        lat, lon = f.get("lat"), f.get("lon")
        out = []
        indicators: dict[str, float] = {}
        inputs: dict = {"fix_type": fix, "satellites": sats, "hdop": hdop, "gps_speed_ms": gps_speed}

        # ---- layer 1: rules (quality)
        quality = (fix, sats, hdop)
        degraded = (fix is not None and fix < 3) or (sats is not None and sats < self.min_sats) or (hdop is not None and hdop > self.max_hdop)
        if self.prev_quality is not None and degraded and not self._prev_degraded:
            out.append(self.result(ctx, "OBSERVED", "GPS quality change", kind="alert", severity="LOW", ev=ev,
                                   method="fix/sats/HDOP rules", parameters={"min_sats": self.min_sats, "max_hdop": self.max_hdop},
                                   inputs=dict(inputs, previous=self.prev_quality),
                                   why="Fix type, satellite count or HDOP crossed a quality limit."))
        self._prev_degraded = degraded
        self.prev_quality = quality
        if fix is None or fix < 2 or lat in (None, 0) or lon in (None, 0):
            return out
        glat, glon = lat / 1e7, lon / 1e7

        # ---- layer 3a: jump detection (implied speed between fixes)
        if self.prev_fix is not None:
            dt = max(ctx.mono - self.prev_fix["mono"], 1e-3)
            d = haversine_m(self.prev_fix["lat"], self.prev_fix["lon"], glat, glon)
            implied = d / dt
            ref_speed = max(gps_speed or 0, self._ekf_speed() or 0, 2.0)
            inputs["jump_m"] = round(d, 1)
            if d > self.jump_min and implied > self.jump_factor * ref_speed + 5 and dt < 5:
                out.append(self.result(ctx, "ANOMALOUS", "GPS position jump", ev=ev, method="position-jump implied speed",
                                       parameters={"jump_speed_factor": self.jump_factor, "jump_min_m": self.jump_min},
                                       score=round(implied, 1), threshold=round(self.jump_factor * ref_speed + 5, 1),
                                       confidence=clamp01(implied / (4 * self.jump_factor * ref_speed + 20)),
                                       inputs={"distance_m": round(d, 1), "dt_s": round(dt, 2), "implied_speed_ms": round(implied, 1),
                                               "reported_speed_ms": round(ref_speed, 1)},
                                       why=f"Consecutive fixes are {d:.0f} m apart in {dt:.2f} s ({implied:.0f} m/s) while the vehicle reports ≈{ref_speed:.1f} m/s. "
                                           "A single jump is not treated as spoofing."))
        self.prev_fix = {"lat": glat, "lon": glon, "mono": ctx.mono}

        # ---- layer 2/3: residuals vs EKF
        ekf_fresh = self.ekf_pos is not None and ctx.mono - self.ekf_pos["mono"] < 1.5 and self.ekf_pos["lat"] not in (None, 0)
        if not ekf_fresh:
            self.metrics = {"status": "EKF position unavailable — residual layers inactive", **inputs}
            return out
        e = self.ekf_pos
        pos_res = haversine_m(glat, glon, e["lat"] / 1e7, e["lon"] / 1e7)
        ekf_speed = self._ekf_speed()
        vel_res = abs(gps_speed - ekf_speed) if (gps_speed is not None and ekf_speed is not None) else None
        rz = self.window.robust_z(pos_res)
        med = self.window.median() or 0.0
        mad = self.window.mad() or 0.0
        self.window.push(pos_res)
        self.ewma.update(pos_res)
        self.cusum.update((pos_res - med) / max(1.4826 * mad, 1.0))
        inputs.update({"position_residual_m": round(pos_res, 2), "ekf_speed_ms": None if ekf_speed is None else round(ekf_speed, 2),
                       "velocity_residual_ms": None if vel_res is None else round(vel_res, 2),
                       "robust_z": None if rz is None else round(rz, 2), "ewma_residual_m": round(self.ewma.mean or 0, 2),
                       "cusum": round(self.cusum.s, 2)})
        if pos_res > self.pos_thr:
            indicators["position_residual"] = clamp01(pos_res / (2 * self.pos_thr))
        if vel_res is not None and vel_res > self.vel_thr:
            indicators["velocity_residual"] = clamp01(vel_res / (2 * self.vel_thr))
        if rz is not None and abs(rz) > self.rz_thr and pos_res > 3:
            indicators["robust_z"] = clamp01(abs(rz) / (2 * self.rz_thr))
        if self.cusum.alarm:
            indicators["cusum_drift"] = clamp01(self.cusum.s / (2 * self.cusum.h))
        ekf_fresh2 = self.ekf is not None and ctx.mono - self.ekf["mono"] < 3
        if ekf_fresh2:
            vv, pv = self.ekf.get("vel_var") or 0, self.ekf.get("pos_var") or 0
            inputs.update({"ekf_velocity_variance": round(vv, 3), "ekf_pos_horiz_variance": round(pv, 3)})
            if max(vv, pv) > self.var_thr:
                indicators["ekf_innovation"] = clamp01(max(vv, pv) / (2 * self.var_thr))
        if pos_res > self.pos_thr * 0.6 and ((sats or 0) >= 10 or (hdop is not None and hdop < 1.5)) and not degraded:
            indicators["quality_mismatch"] = 0.8
        if self.gps2 and ctx.mono - self.gps2["mono"] < 2 and self.gps2["lat"]:
            dd = haversine_m(glat, glon, self.gps2["lat"] / 1e7, self.gps2["lon"] / 1e7)
            inputs["receiver_disagreement_m"] = round(dd, 1)
            if dd > 10:
                indicators["receiver_disagreement"] = clamp01(dd / 30)

        # ---- layer 4: persistence
        active = len(indicators) >= 1
        persistent, held = self.persist.update(active, ctx.mono)
        short_ok, _ = self.persist_short.update(active, ctx.mono)
        inputs["persistence_s"] = round(held, 2)
        contributors = [{"label": k.replace("_", " "), "value": round(WEIGHTS.get(k, 0.05) * v * 2, 3)} for k, v in indicators.items()]
        conf = clamp01(sum(c["value"] for c in contributors))
        self.series = {"t": ctx.t, **inputs, "confidence": conf}
        self.metrics = {k: v for k, v in inputs.items()}
        self.metrics["indicators"] = sorted(indicators)
        if not active or not short_ok:  # single-sample blips are never reported
            return out
        state = "SUSPECTED" if (persistent and len(indicators) >= 2 and conf >= 0.45) else "ANOMALOUS"
        key = ("gps", state)
        if ctx.mono - self.last_emit.get(key, -1e9) < 5:
            return out
        self.last_emit[key] = ctx.mono
        title = self._title(indicators)
        why = self._why(inputs, indicators, held)
        refs = [ev.idx, e["idx"]] + ([self.ekf["idx"]] if ekf_fresh2 else [])
        out.append(self.result(ctx, state, title, ev=ev, refs=refs, confidence=conf,
                               method="layered: rule→statistical→cross-sensor→persistence",
                               parameters={"position_residual_m": self.pos_thr, "velocity_residual_ms": self.vel_thr,
                                           "robust_z": self.rz_thr, "ekf_variance_threshold": self.var_thr,
                                           "persistence_s": self.persist_s, **self.cusum.describe()},
                               inputs=inputs, score=conf, threshold=0.45, window=f"{len(self.window)} samples",
                               why=why, contributors=contributors,
                               evidence=[f"{c['label']} (+{round(c['value'] * 100)})" for c in contributors]))
        return out

    _prev_degraded = False

    def _ekf_speed(self) -> Optional[float]:
        e = self.ekf_pos
        if not e or e.get("vx") is None or e.get("vy") is None:
            return None
        return math.hypot(e["vx"], e["vy"]) / 100.0

    @staticmethod
    def _title(ind: dict) -> str:
        if "velocity_residual" in ind and ("ekf_innovation" in ind or "position_residual" in ind):
            return "GPS / EKF velocity consistency anomaly"
        if "cusum_drift" in ind and "velocity_residual" not in ind:
            return "Slow GPS drift (CUSUM)"
        if "quality_mismatch" in ind:
            return "GPS quality-vs-navigation mismatch"
        if "receiver_disagreement" in ind:
            return "GPS receiver disagreement"
        if "ekf_innovation" in ind:
            return "EKF innovation anomaly"
        return "GPS / EKF position consistency anomaly"

    @staticmethod
    def _why(i: dict, ind: dict, held: float) -> str:
        parts = []
        if i.get("gps_speed_ms") is not None and i.get("ekf_speed_ms") is not None:
            parts.append(f"GPS velocity = {i['gps_speed_ms']:.1f} m/s, EKF velocity = {i['ekf_speed_ms']:.1f} m/s, difference = {i.get('velocity_residual_ms')} m/s")
        parts.append(f"GPS↔EKF position residual = {i.get('position_residual_m')} m")
        if "ekf_innovation" in ind:
            parts.append(f"EKF velocity variance = {i.get('ekf_velocity_variance')}, position variance = {i.get('ekf_pos_horiz_variance')}")
        parts.append(f"indicators: {', '.join(sorted(ind))}; persisted {held:.1f} s")
        return "; ".join(parts) + "."
