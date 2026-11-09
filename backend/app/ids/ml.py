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
    description = ("Isolation Forest baseline; supplementary evidence only. Uses an approved per-airframe profile when one is "
                   "configured, otherwise an untrusted session-local baseline.")
    limitations = ("A session-local baseline is trained on this session's first minute; training pauses while other "
                   "detectors are alarmed, but a subtle attack present from boot can still be learned.",
                   "An ML score is not evidence of an attack on its own and can never open or confirm an incident.")

    ALARM_STATES = ("ANOMALOUS", "SUSPECTED", "CONFIRMED")

    def __init__(self, cfg, profile: Optional[dict] = None, profile_status: str = "NOT_CONFIGURED"):
        super().__init__(cfg)
        # GAP-16 modes: "profile" (approved corpus), "session" (untrusted, gated), "collect" (gather rows, never score)
        self.mode = str(self.cfg.get("mode") or ("profile" if self.cfg.get("profile") else "session")).lower()
        self.profile = profile or {}
        self.profile_status = profile_status
        self.ood_frac = float(self.cfg.get("ood_feature_fraction", 0.5))
        self.ood_z = float(self.cfg.get("ood_robust_z", 8.0))
        self.skipped_contaminated = 0
        self.collected: list[list[Optional[float]]] = []
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
        if self.enabled and self.mode == "profile":
            if profile_status != "VALID":
                # Never fall back silently to an untrusted session baseline.
                self.enabled = False
                self.health_state = "ERROR"
                self.last_error = f"approved ML profile unavailable: {profile_status}"
            else:
                if list(self.profile.get("features", [])) != FEATURES or self.profile.get("feature_version") != FEATURE_VERSION:
                    self.enabled, self.health_state = False, "ERROR"
                    self.last_error = "ML profile feature set/version does not match this detector"
                else:
                    self.train = [list(r) for r in self.profile["rows"]]
                    self.train_t = [0.0, 0.0]
                    self._fit(trust="approved-profile")
                    if self.model is None:
                        self.enabled, self.health_state = False, "ERROR"
                        self.last_error = "ML profile has too few populated features to fit"

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
        alarmed = sorted(d for d, st in ctx.detector_states.items() if st in self.ALARM_STATES and d != self.detector_id)
        if self.mode == "collect":
            if ctx.vehicle_sysid is not None:
                if alarmed:
                    self.skipped_contaminated += 1
                else:
                    self.collected.append(row)
            self.metrics = {"phase": "COLLECTING", "rows": len(self.collected), "skipped_while_alarmed": self.skipped_contaminated}
            return []
        if self.model is None:
            if ctx.vehicle_sysid is None or self.mode == "profile":
                return []  # profile mode never learns from live traffic
            if alarmed:
                # Contamination guard: never learn "normal" while another detector is alarmed.
                self.skipped_contaminated += 1
                self.metrics = {"phase": "TRAINING_PAUSED", "samples": len(self.train), "needed": self.min_samples,
                                "paused_because": alarmed, "skipped_rows": self.skipped_contaminated}
                return []
            self.train.append(row)
            self.train_t.append(ctx.t)
            self.metrics = {"phase": "TRAINING", "samples": len(self.train), "needed": self.min_samples}
            if ctx.elapsed >= self.train_s and len(self.train) >= self.min_samples:
                self._fit()
            return []
        x = [row[i] if row[i] is not None else self.medians[i] for i in self.feature_idx]
        score = float(self.model.decision_function(np.array([x]))[0])
        zs = [self.stats[i].robust_z(x[j]) for j, i in enumerate(self.feature_idx)]
        ood = [FEATURES[i] for (j, i), z in zip(enumerate(self.feature_idx), zs) if z is not None and abs(z) > self.ood_z]
        self.metrics = {"phase": "SCORING", "score": round(score, 4), "threshold": self.thr, "out_of_distribution": ood, **self.model_meta}
        if len(ood) >= max(2, self.ood_frac * len(self.feature_idx)):
            # Input unlike anything in the training corpus: the score is not meaningful, so do not call it an anomaly.
            if ctx.mono - self.cool > 60:
                self.cool = ctx.mono
                return [self.result(ctx, "OBSERVED", "ML input outside training distribution", kind="observation", severity="INFO",
                                    method="out-of-distribution check", inputs={"features": ood},
                                    parameters={**self.model_meta, "ood_robust_z": self.ood_z},
                                    why="Most features are far outside the baseline corpus (new airframe, firmware, calibration or "
                                        "flight regime?). The anomaly score is suppressed until the baseline covers this regime.")]
            return []
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
                                          f"feature_version={FEATURE_VERSION}", f"training_dataset_id={self.model_meta['training_dataset_id']}",
                                          f"baseline_trust={self.model_meta['trust']}",
                                          f"profile={self.model_meta.get('profile_id')} corpus={self.model_meta.get('corpus_version')}"])]
        return []

    def _fit(self, trust: str = "session-local (untrusted)") -> None:
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
        prof = self.profile if trust == "approved-profile" else {}
        self.model_meta = {"model_id": f"IFOREST-{ds}", "model_version": "2", "feature_version": FEATURE_VERSION,
                           "features": [FEATURES[i] for i in self.feature_idx],
                           "training_dataset_id": (f"profile:{prof.get('profile_id')}:{prof.get('rows_sha256', '')[:16]}" if prof
                                                   else f"{self.session_id}:{self.train_t[0]:.0f}-{self.train_t[-1]:.0f}:{ds}"),
                           "training_samples": len(X), "contamination": self.contam, "trust": trust,
                           "profile_id": prof.get("profile_id"), "corpus_version": prof.get("corpus_version"),
                           "airframe": prof.get("airframe"), "skipped_contaminated_rows": self.skipped_contaminated}
