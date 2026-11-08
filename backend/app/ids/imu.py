"""IMU / sensor consistency (spec §26): IMU↔IMU, IMU↔AHRS, baro/EKF↔GPS altitude."""
from __future__ import annotations

import math
from typing import Optional

from ..models.events import TelemetryEvent
from .base import AnalysisContext, Detector
from .stats import EWMA, CUSUM, Persistence, RollingWindow, clamp01

IMU_MSGS = {"RAW_IMU": 0, "SCALED_IMU": 0, "SCALED_IMU2": 1, "SCALED_IMU3": 2}


def _vec(f, keys):
    vals = [f.get(k) for k in keys]
    return None if any(v is None for v in vals) else tuple(float(v) for v in vals)


def _dist(a, b):
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


class IMUConsistencyDetector(Detector):
    detector_id = "IMU_CONSISTENCY"
    name = "IMU / Sensor Consistency"
    domain = "SENSOR"
    data_sources = ("RAW_IMU", "SCALED_IMU", "SCALED_IMU2", "SCALED_IMU3", "ATTITUDE", "GPS_RAW_INT",
                    "GLOBAL_POSITION_INT", "VIBRATION")
    methods = ("pairwise accel/gyro residual", "leave-one-out consensus (3 IMUs)", "EWMA-normalised residual",
               "CUSUM drift", "IMU gyro ↔ AHRS body rates", "EKF(baro) ↔ GPS altitude residual", "persistence")
    description = "Cross-IMU divergence, IMU vs AHRS disagreement and barometric/GPS altitude divergence."
    limitations = ("Vibration and aggressive manoeuvres increase residuals; persistence is required before reporting.",
                   "Pixhawk 6C has a single barometer and magnetometer: no redundant cross-check for those.")

    def __init__(self, cfg):
        super().__init__(cfg)
        self.acc_thr = float(self.cfg.get("accel_residual_mg", 350))
        self.gyr_thr = float(self.cfg.get("gyro_residual_mrads", 150))
        self.alt_thr = float(self.cfg.get("baro_gps_alt_residual_m", 25))
        ps = float(self.cfg.get("persistence_s", 2.0))
        self.imu: dict[int, dict] = {}
        self.acc_ewma = EWMA(0.3)
        self.gyr_ewma = EWMA(0.3)
        self.drift = CUSUM(0.5, 10)
        self.p_imu = Persistence(ps)
        self.p_ahrs = Persistence(ps * 1.5)
        self.p_alt = Persistence(ps * 2)
        self.att: Optional[dict] = None
        self.gps_alt: Optional[tuple[float, float]] = None
        self.alt_offset = RollingWindow(40)
        self.cool: dict = {}
        self.clip_prev: Optional[tuple] = None

    def process(self, ev: TelemetryEvent, ctx: AnalysisContext):
        if ctx.vehicle_sysid is not None and ev.sysid != ctx.vehicle_sysid:
            return []
        self.mark_data(ctx)
        f, n, out = ev.fields, ev.msg_name, []
        if n in IMU_MSGS:
            acc = _vec(f, ("xacc", "yacc", "zacc"))
            gyr = _vec(f, ("xgyro", "ygyro", "zgyro"))
            if acc and gyr:
                self.imu[IMU_MSGS[n]] = {"acc": acc, "gyr": gyr, "mono": ctx.mono, "idx": ev.idx}
                out += self._cross_imu(ev, ctx)
                out += self._imu_vs_ahrs(ev, ctx)
        elif n == "ATTITUDE":
            self.att = {"p": f.get("rollspeed"), "q": f.get("pitchspeed"), "r": f.get("yawspeed"), "mono": ctx.mono}
        elif n == "GPS_RAW_INT" and (f.get("fix_type") or 0) >= 3 and f.get("alt") is not None:
            self.gps_alt = (f["alt"] / 1000.0, ctx.mono)
        elif n == "GLOBAL_POSITION_INT" and f.get("alt") is not None:
            out += self._alt(ev, ctx, f["alt"] / 1000.0)
        elif n == "VIBRATION":
            clips = (f.get("clipping_0"), f.get("clipping_1"), f.get("clipping_2"))
            if self.clip_prev and any(c is not None and p is not None and c > p for c, p in zip(clips, self.clip_prev)):
                if self._cool("clip", ctx, 30):
                    out.append(self.result(ctx, "OBSERVED", "Accelerometer clipping increased", kind="observation", ev=ev,
                                           inputs={"clipping": clips, "previous": self.clip_prev,
                                                   "vibration": (f.get("vibration_x"), f.get("vibration_y"), f.get("vibration_z"))},
                                           method="VIBRATION clipping counters", why="Clipping counters incremented (context for IMU residuals)."))
            self.clip_prev = clips
        return out

    def _cross_imu(self, ev, ctx):
        fresh = {k: v for k, v in self.imu.items() if ctx.mono - v["mono"] < 0.5}
        if len(fresh) < 2:
            return []
        keys = sorted(fresh)
        pairs = [(a, b) for i, a in enumerate(keys) for b in keys[i + 1:]]
        acc_res = {f"{a}-{b}": _dist(fresh[a]["acc"], fresh[b]["acc"]) for a, b in pairs}
        gyr_res = {f"{a}-{b}": _dist(fresh[a]["gyr"], fresh[b]["gyr"]) for a, b in pairs}
        amax, gmax = max(acc_res.values()), max(gyr_res.values())
        self.acc_ewma.update(amax)
        self.gyr_ewma.update(gmax)
        self.drift.update((self.acc_ewma.mean or 0) / self.acc_thr * 2 - 1)
        outlier = None
        if len(keys) >= 3:  # leave-one-out consensus
            scores = {}
            for k in keys:
                others = [o for o in keys if o != k]
                scores[k] = sum(_dist(fresh[k]["acc"], fresh[o]["acc"]) for o in others) / len(others)
            outlier = max(scores, key=scores.get)
        bad = (self.acc_ewma.mean or 0) > self.acc_thr or (self.gyr_ewma.mean or 0) > self.gyr_thr
        ok, held = self.p_imu.update(bad, ctx.mono)
        self.metrics.update({"imus": keys, "accel_residual_mg": round(amax, 1), "gyro_residual_mrads": round(gmax, 1),
                             "accel_ewma": round(self.acc_ewma.mean or 0, 1), "gyro_ewma": round(self.gyr_ewma.mean or 0, 1)})
        if ok and self._cool("imu", ctx, 10):
            conf = clamp01(0.3 + 0.35 * ((self.acc_ewma.mean or 0) / self.acc_thr - 1) + 0.35 * ((self.gyr_ewma.mean or 0) / self.gyr_thr - 1))
            return [self.result(ctx, "SUSPECTED" if self.drift.alarm else "ANOMALOUS",
                                "IMU bias drift (CUSUM)" if self.drift.alarm else "Cross-IMU divergence",
                                ev=ev, refs=[v["idx"] for v in fresh.values()], confidence=max(conf, 0.3),
                                method="pairwise residual + EWMA + persistence",
                                parameters={"accel_residual_mg": self.acc_thr, "gyro_residual_mrads": self.gyr_thr, "persistence_s": self.p_imu.duration},
                                inputs={"accel_residuals_mg": {k: round(v, 1) for k, v in acc_res.items()},
                                        "gyro_residuals_mrads": {k: round(v, 1) for k, v in gyr_res.items()},
                                        "persisted_s": round(held, 1), "leave_one_out_outlier": outlier},
                                why=f"IMU residual EWMA accel {self.acc_ewma.mean:.0f} mg / gyro {self.gyr_ewma.mean:.0f} mrad/s exceeded limits for {held:.1f} s."
                                    + (f" Leave-one-out points at IMU{outlier}." if outlier is not None else ""))]
        return []

    def _imu_vs_ahrs(self, ev, ctx):
        imu0 = self.imu.get(0)
        if not imu0 or not self.att or ctx.mono - self.att["mono"] > 0.5 or None in (self.att["p"], self.att["q"], self.att["r"]):
            return []
        ahrs = (self.att["p"] * 1000, self.att["q"] * 1000, self.att["r"] * 1000)
        res = _dist(imu0["gyr"], ahrs)
        bad = res > self.gyr_thr * 2
        ok, held = self.p_ahrs.update(bad, ctx.mono)
        self.metrics["imu_ahrs_gyro_residual_mrads"] = round(res, 1)
        if ok and self._cool("ahrs", ctx, 15):
            return [self.result(ctx, "ANOMALOUS", "IMU ↔ AHRS rate disagreement", ev=ev, severity="LOW",
                                method="IMU gyro ↔ AHRS body rates", threshold=self.gyr_thr * 2, score=round(res, 1),
                                inputs={"imu_gyro_mrads": [round(x, 1) for x in imu0["gyr"]], "ahrs_rates_mrads": [round(x, 1) for x in ahrs],
                                        "persisted_s": round(held, 1)},
                                why="Primary IMU gyro and AHRS-reported body rates disagree persistently.")]
        return []

    def _alt(self, ev, ctx, ekf_alt):
        if not self.gps_alt or ctx.mono - self.gps_alt[1] > 2:
            return []
        diff = self.gps_alt[0] - ekf_alt
        if len(self.alt_offset) < self.alt_offset.n:
            self.alt_offset.push(diff)  # learn the static GPS/baro offset
            return []
        res = abs(diff - (self.alt_offset.median() or 0))
        ok, held = self.p_alt.update(res > self.alt_thr, ctx.mono)
        self.metrics["baro_gps_alt_residual_m"] = round(res, 1)
        if ok and self._cool("alt", ctx, 20):
            return [self.result(ctx, "ANOMALOUS", "Barometer/EKF ↔ GPS altitude divergence", ev=ev, domain="GPS_INTEGRITY",
                                method="EKF(baro) ↔ GPS altitude residual (offset-corrected)", threshold=self.alt_thr,
                                score=round(res, 1), confidence=clamp01(res / (3 * self.alt_thr)),
                                inputs={"gps_alt_m": round(self.gps_alt[0], 1), "ekf_alt_m": round(ekf_alt, 1),
                                        "learned_offset_m": round(self.alt_offset.median() or 0, 1), "persisted_s": round(held, 1)},
                                why=f"GPS altitude diverged {res:.1f} m from the barometer-driven EKF altitude after removing the learned offset.")]
        return []

    def _cool(self, key, ctx, s):
        if ctx.mono - self.cool.get(key, -1e9) < s:
            return False
        self.cool[key] = ctx.mono
        return True
