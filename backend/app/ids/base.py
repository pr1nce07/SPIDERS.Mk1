"""Detector plugin interface (spec §82) and shared analysis context."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from ..models.events import DetectorResult, TelemetryEvent, iso_from_epoch, state_rank


@dataclass
class AnalysisContext:
    """Vehicle/flight context shared by detectors. Owned by the pipeline."""
    registry: Any
    config: Any
    vehicle_sysid: Optional[int] = None
    vehicle_compid: Optional[int] = None
    trusted_gcs: set = field(default_factory=set)
    armed: Optional[bool] = None
    mode: Optional[str] = None
    airborne: Optional[bool] = None
    t: float = 0.0
    mono: float = 0.0
    session_start_mono: Optional[float] = None
    fc_states: dict = field(default_factory=dict)     # PUSHPAK FC detector → record
    lua_states: dict = field(default_factory=dict)    # PUSHPAK detector → last Lua confirmation
    detector_states: dict = field(default_factory=dict)  # ground detector id → state string

    @property
    def elapsed(self) -> float:
        return 0.0 if self.session_start_mono is None else self.mono - self.session_start_mono

    def is_vehicle(self, ev: TelemetryEvent) -> bool:
        return self.vehicle_sysid is not None and ev.sysid == self.vehicle_sysid and ev.compid in (1, self.vehicle_compid)

    def is_trusted_gcs(self, sysid: Optional[int]) -> bool:
        return sysid in self.trusted_gcs


class Detector:
    detector_id: str = "BASE"
    name: str = "Base detector"
    version: str = "1.0.0"
    domain: str = "GENERAL"
    data_sources: tuple[str, ...] = ()
    methods: tuple[str, ...] = ()
    description: str = ""
    limitations: tuple[str, ...] = ()
    clear_after_s: float = 20.0

    def __init__(self, cfg: dict):
        self.cfg = cfg or {}
        self.enabled = bool(self.cfg.get("enabled", True))
        self.severity = str(self.cfg.get("severity", "MEDIUM")).upper()
        self.events = 0
        self.results = 0
        self.errors = 0
        self.latency_ms = 0.0
        self.last_update_t: Optional[float] = None
        self.last_data_mono: Optional[float] = None
        self.state = "NORMAL"
        self.confidence: Optional[float] = None
        self.last_result: Optional[DetectorResult] = None
        self.last_alert_mono: Optional[float] = None
        self.health_state = "WAITING_FOR_DATA" if self.enabled else "DISABLED"
        self.last_error: Optional[str] = None
        self.metrics: dict[str, Any] = {}

    # ----------------------------------------------------------- plugin hooks
    def accepts(self, ev: TelemetryEvent) -> bool:
        return not self.data_sources or ev.msg_name in self.data_sources

    def process(self, ev: TelemetryEvent, ctx: AnalysisContext) -> list[DetectorResult]:
        return []

    def tick(self, ctx: AnalysisContext) -> list[DetectorResult]:
        return []

    def reset(self) -> None:
        pass

    # ----------------------------------------------------------- helpers
    def result(self, ctx: AnalysisContext, state: str, title: str, *, severity: Optional[str] = None,
               confidence: Optional[float] = None, method: Optional[str] = None, parameters: dict | None = None,
               inputs: dict | None = None, score: Optional[float] = None, threshold: Optional[float] = None,
               window: Optional[str] = None, ev: Optional[TelemetryEvent] = None, refs: list[int] | None = None,
               why: str = "", evidence: list[str] | None = None, limitations: list[str] | None = None,
               kind: str = "alert", domain: Optional[str] = None, source: str = "GROUND",
               contributors: list[dict] | None = None) -> DetectorResult:
        sev = (severity or (self.severity if state_rank(state) >= 2 else "INFO")).upper()
        r = DetectorResult(
            detector=self.detector_id, state=state, title=title, t=ctx.t, severity=sev,
            confidence=None if confidence is None else round(float(confidence), 3), source=source,
            domain=domain or self.domain, method=method, parameters=parameters or {}, inputs=inputs or {},
            score=None if score is None else round(float(score), 4), threshold=threshold, window=window,
            detector_version=self.version, packet_refs=list(refs or ([ev.idx] if ev else [])),
            sysid=ev.sysid if ev else None, compid=ev.compid if ev else None, kind=kind,
        )
        r.explanation = {
            "what": title,
            "why": why,
            "when": iso_from_epoch(ctx.t),
            "source": f"{source} detector {self.detector_id} v{self.version}",
            "evidence": evidence or [f"{k} = {v}" for k, v in (inputs or {}).items()],
            "rule": f"{method or 'n/a'} {parameters or {}}",
            "confidence": ("not computed by this detector" if confidence is None else f"{round(confidence * 100)}%"),
            "contributors": contributors or [],
            "limitations": list(limitations or self.limitations),
        }
        if kind == "alert" and state_rank(state) >= 2:
            self.state = state if state_rank(state) >= state_rank(self.state) or self._stale(ctx) else self.state
            self.confidence = r.confidence
            self.last_alert_mono = ctx.mono
        self.last_result = r
        self.results += 1
        return r

    def _stale(self, ctx: AnalysisContext) -> bool:
        return self.last_alert_mono is None or ctx.mono - self.last_alert_mono > self.clear_after_s

    def decay(self, ctx: AnalysisContext) -> None:
        if self.state != "NORMAL" and self._stale(ctx):
            self.state = "NORMAL"
            self.confidence = None

    def mark_data(self, ctx: AnalysisContext) -> None:
        self.last_data_mono = ctx.mono
        self.last_update_t = ctx.t
        if self.health_state in ("WAITING_FOR_DATA", "DEGRADED") and self.enabled:
            self.health_state = "ONLINE"

    def health(self, ctx: Optional[AnalysisContext] = None) -> dict:
        hs = self.health_state
        if ctx is not None and hs == "ONLINE" and self.last_data_mono is not None and ctx.mono - self.last_data_mono > 10:
            hs = "DEGRADED"  # data sources stopped arriving
        return {
            "detector": self.detector_id, "name": self.name, "version": self.version, "health": hs,
            "state": self.state if self.enabled else "DISABLED", "confidence": self.confidence,
            "last_update": iso_from_epoch(self.last_update_t), "events": self.events, "results": self.results,
            "errors": self.errors, "last_error": self.last_error, "latency_ms": round(self.latency_ms, 3),
            "data_sources": list(self.data_sources), "methods": list(self.methods), "domain": self.domain,
            "enabled": self.enabled, "severity": self.severity, "description": self.description,
            "metrics": self.metrics,
        }

    def explain(self, result: DetectorResult) -> dict:
        return result.explanation
