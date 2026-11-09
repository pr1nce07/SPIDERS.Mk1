"""IDS engine: independently loadable detectors, each under its own fault boundary.

A detector exception marks that detector ERROR, records a structured error and
is otherwise contained: ingestion, recording, other detectors and the GUI keep
running (spec §48, §51).
"""
from __future__ import annotations

import time
from typing import Iterable

from ..models.events import DetectorResult, TelemetryEvent
from .base import AnalysisContext, Detector
from .baseline import BaselineDetector
from .command import CommandDetector
from .gps import GPSIntegrityDetector
from .imu import IMUConsistencyDetector
from .mavlink import (HeartbeatDetector, MavlinkRateDetector, MavlinkSequenceDetector, SigningDetector,
                      SourceIdentityDetector)
from .mission import MissionDetector
from .ml import MLBaselineDetector
from .offboard import OffboardDetector
from .parameter import ParameterDetector
from .pushpak_fc import PushpakFCDetector
from .rc import RCLinkDetector
from .vehicle import BatteryDetector, FlightModeDetector, SensorHealthDetector

def _baseline(c, cfg, **k):
    """Load the approved manifest once per session; detectors never write it (GAP-11)."""
    from ..security.baseline import BaselineStore
    store = BaselineStore.from_config(c)
    doc = store.active()
    return BaselineDetector(cfg, doc, store.keys.trusted_public_keys("approval") if doc else {})


def _ml(c, cfg):
    """Approved per-airframe profile when configured (GAP-16); otherwise an untrusted, gated session baseline."""
    prof = cfg.get("profile")
    if not prof:
        return MLBaselineDetector(cfg)
    from ..security.keys import KeyStore
    from .ml_profiles import load_profile
    path = c.resolve_path("ids.ml_profile_dir", "data/ml_profiles") / f"{prof}.json"
    keys = KeyStore(c.resolve_path("security.keystore_dir", "data/keys"))
    body, status = load_profile(path, keys.trusted_public_keys("approval"))
    return MLBaselineDetector(cfg, body, status)


# Plugin registry: detector id → factory(config, context-free kwargs)
DETECTOR_PLUGINS = {
    "HEARTBEAT": lambda c, cfg, **k: HeartbeatDetector(cfg, stale_s=c.get("mavlink.heartbeat_stale_s", 3.0), loss_s=c.get("mavlink.heartbeat_loss_s", 6.0)),
    "MAVLINK_SEQUENCE": lambda c, cfg, **k: MavlinkSequenceDetector(cfg),
    "SOURCE_IDENTITY": lambda c, cfg, **k: SourceIdentityDetector(cfg),
    "MAVLINK_RATE": lambda c, cfg, **k: MavlinkRateDetector(cfg),
    "MAVLINK_SIGNING": lambda c, cfg, **k: SigningDetector(cfg, expected=bool(c.get("mavlink.signing_expected", False)), policy=c.get("mavlink.signing_policy"), key_configured=k.get("key_configured", False)),
    "GPS_INTEGRITY": lambda c, cfg, **k: GPSIntegrityDetector(cfg),
    "COMMAND": lambda c, cfg, **k: CommandDetector(cfg),
    "PARAMETER": lambda c, cfg, **k: ParameterDetector(cfg),
    "MISSION": lambda c, cfg, **k: MissionDetector(cfg),
    "RC_LINK": lambda c, cfg, **k: RCLinkDetector(cfg),
    "IMU_CONSISTENCY": lambda c, cfg, **k: IMUConsistencyDetector(cfg),
    "OFFBOARD": lambda c, cfg, **k: OffboardDetector(cfg),
    "BATTERY": lambda c, cfg, **k: BatteryDetector(cfg),
    "FLIGHT_MODE": lambda c, cfg, **k: FlightModeDetector(cfg),
    "SENSOR_HEALTH": lambda c, cfg, **k: SensorHealthDetector(cfg, registry=k.get("registry")),
    "PUSHPAK_FC": lambda c, cfg, **k: PushpakFCDetector(cfg),
    "ML_BASELINE": lambda c, cfg, **k: _ml(c, cfg),
    "BASELINE": _baseline,
}


class IDSEngine:
    def __init__(self, config, errors, registry, key_configured: bool = False, enabled_ids: Iterable[str] | None = None):
        self.config = config
        self.errors = errors
        self.detectors: dict[str, Detector] = {}
        self.fault_injection: set[str] = set()
        self.enabled = bool(config.get("ids.enabled", True))
        for det_id, factory in DETECTOR_PLUGINS.items():
            if enabled_ids is not None and det_id not in enabled_ids:
                continue
            cfg = config.detector(det_id)
            try:
                self.detectors[det_id] = factory(config, cfg, registry=registry, key_configured=key_configured)
            except Exception as exc:  # a detector that fails to load must not stop the others
                errors.record(det_id, "LOAD_FAILED", str(exc), recoverable=False, exc=exc)

    def get(self, det_id: str) -> Detector | None:
        return self.detectors.get(det_id)

    def process(self, ev: TelemetryEvent, ctx: AnalysisContext) -> list[DetectorResult]:
        out: list[DetectorResult] = []
        if not self.enabled:
            return out
        for det in self.detectors.values():
            if not det.enabled or not det.accepts(ev):
                continue
            t0 = time.perf_counter()
            try:
                if det.detector_id in self.fault_injection:
                    raise RuntimeError(f"injected fault in {det.detector_id}")
                res = det.process(ev, ctx)
                det.events += 1
                if det.health_state == "ERROR" and det.events % 10 == 0:
                    det.health_state = "ONLINE"
                if res:
                    out.extend(res)
            except Exception as exc:
                self._fail(det, exc, ev)
            det.latency_ms = 0.9 * det.latency_ms + 0.1 * (time.perf_counter() - t0) * 1000
        for r in out:
            ctx.detector_states[r.detector] = r.state
        return out

    def tick(self, ctx: AnalysisContext) -> list[DetectorResult]:
        out: list[DetectorResult] = []
        if not self.enabled:
            return out
        seq = self.detectors.get("MAVLINK_SEQUENCE")
        gaps = sum(s["lost"] for s in seq.st.values()) if seq else 0
        for det in self.detectors.values():
            if not det.enabled:
                continue
            try:
                if det.detector_id in self.fault_injection:
                    raise RuntimeError(f"injected fault in {det.detector_id}.tick")
                if det.detector_id == "ML_BASELINE":
                    res = det.tick(ctx, seq_gaps=gaps - getattr(self, "_last_gaps", 0))
                else:
                    res = det.tick(ctx)
                det.decay(ctx)
                if res:
                    out.extend(res)
            except Exception as exc:
                self._fail(det, exc, None)
        self._last_gaps = gaps
        for d in self.detectors.values():
            ctx.detector_states[d.detector_id] = d.state
        return out

    def _fail(self, det: Detector, exc: Exception, ev: TelemetryEvent | None) -> None:
        det.errors += 1
        det.health_state = "ERROR"
        det.last_error = f"{type(exc).__name__}: {exc}"[:300]
        if det.errors <= 20 or det.errors % 100 == 0:  # bounded error spam
            self.errors.record(det.detector_id, "DETECTOR_ERROR", det.last_error, recoverable=True, exc=exc,
                               context={"msg": ev.msg_name if ev else "tick", "idx": ev.idx if ev else None})

    def health(self, ctx: AnalysisContext | None = None) -> list[dict]:
        return [d.health(ctx) for d in self.detectors.values()]

    def set_enabled(self, det_id: str, enabled: bool) -> bool:
        d = self.detectors.get(det_id)
        if not d:
            return False
        d.enabled = enabled
        d.health_state = "WAITING_FOR_DATA" if enabled else "DISABLED"
        return True
