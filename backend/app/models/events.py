"""Normalized event model shared by every live/offline source.

Nothing in the GUI or detectors touches pymavlink objects directly: sources
produce TelemetryEvent instances and everything downstream consumes them.
"""
from __future__ import annotations

import itertools
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

# ---------------------------------------------------------------- state enums
ANALYTIC_STATES = [
    "OBSERVED", "NORMAL", "ANOMALOUS", "SUSPECTED", "CORRELATED",
    "CONFIRMED", "RESOLVED", "FALSE_POSITIVE",
]
STATE_RANK = {"NORMAL": 0, "OBSERVED": 1, "ANOMALOUS": 2, "SUSPECTED": 3, "CORRELATED": 4, "CONFIRMED": 5}
RESULT_SOURCES = ["FC", "LUA", "GROUND", "CORRELATED"]
DETECTOR_HEALTH = ["ONLINE", "DEGRADED", "WAITING_FOR_DATA", "ERROR", "DISABLED"]


def state_rank(s: str | None) -> int:
    return STATE_RANK.get((s or "NORMAL").upper(), 0)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def iso_from_epoch(t: float | None) -> Optional[str]:
    if t is None:
        return None
    return datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(slots=True)
class TelemetryEvent:
    """One decoded (or undecodable) MAVLink/log record.

    t          analysis time in seconds. Live: wall-clock receive time; offline:
               the log's own timestamp. Used for ordering/display.
    mono_ns    monotonic receive time (live) or synthetic monotonic derived from
               log timestamps (offline). Used for persistence/rate maths.
    """
    idx: int
    t: float
    mono_ns: int
    source: str                  # LIVE | TLOG | DATAFLASH | JSONL | CSV | SIMULATION | CASE
    link: str
    sysid: Optional[int]
    compid: Optional[int]
    msg_id: Optional[int]
    msg_name: str
    sequence: Optional[int]
    fields: dict[str, Any]
    raw: Optional[bytes] = None
    mavlink_version: Optional[int] = None
    signed: Optional[bool] = None
    signature_status: Optional[str] = None   # VALID | INVALID | UNVERIFIED | None
    link_id: Optional[int] = None
    parse_error: Optional[str] = None
    origin: Optional[str] = None             # original log record type when mapped (DataFlash)
    boot_ms: Optional[int] = None            # FC boot time when the message carries time_boot_ms

    @property
    def timestamp_utc(self) -> str:
        return iso_from_epoch(self.t) or ""

    def summary(self) -> dict:
        return {
            "idx": self.idx, "t": self.t, "ts": self.timestamp_utc, "sysid": self.sysid,
            "compid": self.compid, "seq": self.sequence, "msg_id": self.msg_id,
            "msg": self.msg_name, "source": self.source, "link": self.link,
            "signed": self.signed, "sig": self.signature_status, "ver": self.mavlink_version,
            "err": self.parse_error, "len": len(self.raw) if self.raw else 0,
        }

    def to_dict(self, include_raw: bool = True) -> dict:
        d = self.summary()
        d.update({
            "timestamp_utc": self.timestamp_utc, "mono_ns": self.mono_ns, "fields": self.fields,
            "link_id": self.link_id, "origin": self.origin, "boot_ms": self.boot_ms,
        })
        if include_raw:
            d["raw_hex"] = self.raw.hex() if self.raw else None
        return d


@dataclass(slots=True)
class DetectorResult:
    """Output of a detector or rule. Evidence is kept, never collapsed."""
    detector: str
    state: str                               # OBSERVED/NORMAL/ANOMALOUS/SUSPECTED/CONFIRMED
    title: str
    t: float
    severity: str = "INFO"
    confidence: Optional[float] = None       # None when the source does not provide one
    source: str = "GROUND"                   # FC | LUA | GROUND | CORRELATED
    domain: str = "GENERAL"
    method: Optional[str] = None
    parameters: dict[str, Any] = field(default_factory=dict)
    inputs: dict[str, Any] = field(default_factory=dict)
    score: Optional[float] = None
    threshold: Optional[float] = None
    window: Optional[str] = None
    rule_id: Optional[str] = None
    rule_version: Optional[int] = None
    detector_version: Optional[str] = None
    packet_refs: list[int] = field(default_factory=list)
    sysid: Optional[int] = None
    compid: Optional[int] = None
    explanation: dict[str, Any] = field(default_factory=dict)
    trace: Optional[list[dict]] = None
    kind: str = "alert"                      # alert | observation | recovery | health
    actions: dict[str, Any] = field(default_factory=dict)  # e.g. {"snapshot": True, "incident": True}
    result_id: str = field(default_factory=lambda: f"R-{uuid.uuid4().hex[:12]}")

    def to_dict(self) -> dict:
        return {
            "result_id": self.result_id, "detector": self.detector, "state": self.state,
            "title": self.title, "t": self.t, "ts": iso_from_epoch(self.t), "severity": self.severity,
            "confidence": self.confidence, "source": self.source, "domain": self.domain,
            "method": self.method, "parameters": self.parameters, "inputs": self.inputs,
            "score": self.score, "threshold": self.threshold, "window": self.window,
            "rule_id": self.rule_id, "rule_version": self.rule_version,
            "detector_version": self.detector_version, "packet_refs": self.packet_refs[-50:],
            "sysid": self.sysid, "compid": self.compid, "explanation": self.explanation,
            "trace": self.trace, "kind": self.kind, "actions": self.actions,
        }


_bus_counter = itertools.count(1)


@dataclass(slots=True)
class BusEvent:
    type: str          # RAW_MAVLINK | MAVLINK_DECODED | TELEMETRY_UPDATE | VEHICLE_STATE | DETECTOR_RESULT | IDS_ALERT | INCIDENT_CREATED | INCIDENT_UPDATED | FORENSIC_SNAPSHOT | SYSTEM_HEALTH | CONNECTION_STATE | SYSTEM_EVENT | TIMELINE
    payload: Any
    source: str = "core"
    event_id: str = field(default_factory=lambda: f"EV-{next(_bus_counter):09d}")
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {"event_id": self.event_id, "timestamp": self.timestamp, "ts": iso_from_epoch(self.timestamp),
                "source": self.source, "type": self.type, "payload": self.payload}
