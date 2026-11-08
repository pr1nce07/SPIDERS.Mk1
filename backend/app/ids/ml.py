"""Optional ML baseline detector (spec §46). ML is supplementary: it can only
raise OBSERVED/ANOMALOUS results, always with model provenance and the feature
evidence that drove the score. It never opens an incident on its own."""
from __future__ import annotations

import hashlib
import math
from typing import Optional

from ..models.events import TelemetryEvent
from .base import AnalysisContext, Detector
from .stats import RollingWindow

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    SKLEARN = True
except Exception:  # optional dependency
    SKLEARN = False

FEATURE_VERSION = "fv1"
FEATURES = ["gps_speed", "ekf_speed", "velocity_residual", "climb_rate", "satellites", "hdop", "msg_rate",
            "seq_gaps", "command_rate", "battery_voltage", "rc_rssi", "ekf_vel_variance"]


class MLBaselineDetector(Detector):
    detector_id = "ML_BASELINE"
    name = "ML Baseline (Isolation Forest)"
    domain = "ML"
    methods = ("Isolation Forest on per-second feature vectors",)
    description = "Unsupervised per-session baseline; supplementary evidence only."
    limitations = ("Trained on the first minute of this session: if that period is already anomalous, the baseline is too.",
                   "An ML score is not evidence of an attack on its own.")

    def __init__(self, cfg):
        super().__init__(cfg)
        if not SKLEARN:
            self.enabled = False
            self.health_state = "DISABLED"
            self.last_error = "scikit-learn not installed"
        self.train_s = float(self.cfg.get("training_seconds", 60))
        self.contam = float(self.cfg.get("contamination", 0.02))
        self.thr = float(self.cfg.get("score_threshold", -0.15))
        self.min_samples = int(self.cfg.get("min_samples", 40))
        self.cur: dict[str, Optional[float]] = {k: None for k in FEATURES}
        self.counts = {"msgs": 0, "cmds": 0}
        self.train: list[list[Optional[float]]] = []
        self.model = None
        self.model_meta: dict = {}
        self.feature_idx: list[int] = []
        self.stats: dict[int, RollingWindow] = {}
        self.cool = -1e9
        self.session_id = "unknown"
        self.train_t: list[float] = []

    def process(self, ev: TelemetryEvent, ctx: AnalysisContext):
        self.counts["msgs"] += 1
        f = ev.fields
        if ev.sysid != ctx.vehicle_sysid:
            if ev.msg_name in ("COMMAND_LONG", "COMMAND_INT"):
                self.counts["cmds"] += 1
            return []
        n = ev.msg_name
        if n == "GPS_RAW_INT":
            self.cur["gps_speed"] = None if f.get("vel") in (None, 65535) else f["vel"] / 100
            self.cur["satellites"] = None if f.get("satellites_visible") in (None, 255) else f["satellites_visible"]
            self.cur["hdop"] = None if f.get("eph") in (None, 65535) else f["eph"] / 100
        elif n == "GLOBAL_POSITION_INT" and f.get("vx") is not None:
            self.cur["ekf_speed"] = math.hypot(f["vx"], f["vy"]) / 100
            self.cur["climb_rate"] = -(f.get("vz") or 0) / 100
        elif n == "SYS_STATUS" and f.get("voltage_battery") not in (None, 65535):
            self.cur["battery_voltage"] = f["voltage_battery"] / 1000
        elif n == "RC_CHANNELS" and f.get("rssi") not in (None, 255):
            self.cur["rc_rssi"] = f["rssi"]
        elif n == "EKF_STATUS_REPORT":
            self.cur["ekf_vel_variance"] = f.get("velocity_variance")
        if self.cur["gps_speed"] is not None and self.cur["ekf_speed"] is not None:
            self.cur["velocity_residual"] = abs(self.cur["gps_speed"] - self.cur["ekf_speed"])
        self.mark_data(ctx)
        return []

    def tick(self, ctx: AnalysisContext, seq_gaps: int = 0):
        if not self.enabled:
            return []
        vec = dict(self.cur)
        vec["msg_rate"] = float(self.counts["msgs"])
        vec["command_rate"] = float(self.counts["cmds"])
        vec["seq_gaps"] = float(seq_gaps)
        self.counts = {"msgs": 0, "cmds": 0}
        row = [vec[k] for k in FEATURES]
        if self.model is None:
            if ctx.vehicle_sysid is None:
                return []
            self.train.append(row)
            self.train_t.append(ctx.t)
            self.metrics = {"phase": "TRAINING", "samples": len(self.train), "needed": self.min_samples}
            if ctx.elapsed >= self.train_s and len(self.train) >= self.min_samples:
                self._fit()
            return []
        x = [row[i] if row[i] is not None else self.medians[i] for i in self.feature_idx]
        score = float(self.model.decision_function(np.array([x]))[0])
        self.metrics = {"phase": "SCORING", "score": round(score, 4), "threshold": self.thr, **self.model_meta}
        if score < self.thr and ctx.mono - self.cool > 15:
            self.cool = ctx.mono
            contrib = []
            for j, i in enumerate(self.feature_idx):
                w = self.stats[i]
                z = w.robust_z(x[j])
                if z is not None:
                    contrib.append((abs(z), FEATURES[i], x[j], w.median()))
            contrib.sort(reverse=True)
            top = contrib[:4]
            return [self.result(ctx, "ANOMALOUS", "ML baseline outlier", severity="LOW", method="Isolation Forest",
                                parameters={**self.model_meta, "threshold": self.thr}, score=round(score, 4), threshold=self.thr,
                                inputs={name: {"value": round(v, 3), "baseline_median": round(m or 0, 3), "robust_z": round(z, 2)} for z, name, v, m in top},
                                why="Isolation-Forest score below threshold. Driving features: " +
                                    ", ".join(f"{n} ({v:.2f} vs {m or 0:.2f})" for _z, n, v, m in top) + ".",
                                evidence=[f"model_id={self.model_meta['model_id']}", f"model_version={self.model_meta['model_version']}",
                                          f"feature_version={FEATURE_VERSION}", f"training_dataset_id={self.model_meta['training_dataset_id']}"])]
        return []

    def _fit(self) -> None:
        cols = list(zip(*self.train))
        self.feature_idx = [i for i, c in enumerate(cols) if sum(v is not None for v in c) >= 0.8 * len(c)]
        if len(self.feature_idx) < 3:
            self.metrics = {"phase": "INSUFFICIENT_FEATURES", "available": [FEATURES[i] for i in self.feature_idx]}
            self.train = self.train[-self.min_samples:]
            return
        self.medians = {}
        for i in self.feature_idx:
            vals = [v for v in cols[i] if v is not None]
            self.medians[i] = sorted(vals)[len(vals) // 2]
            w = RollingWindow(len(vals))
            for v in vals:
                w.push(v)
            self.stats[i] = w
        X = np.array([[r[i] if r[i] is not None else self.medians[i] for i in self.feature_idx] for r in self.train])
        self.model = IsolationForest(n_estimators=100, contamination=self.contam, random_state=0).fit(X)
        ds = hashlib.sha256(X.tobytes()).hexdigest()[:16]
        self.model_meta = {"model_id": f"IFOREST-{ds}", "model_version": "1", "feature_version": FEATURE_VERSION,
                           "features": [FEATURES[i] for i in self.feature_idx],
                           "training_dataset_id": f"{self.session_id}:{self.train_t[0]:.0f}-{self.train_t[-1]:.0f}:{ds}",
                           "training_samples": len(X), "contamination": self.contam}
