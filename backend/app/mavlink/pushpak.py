"""PUSHPAK IDS STATUSTEXT adapters — formats taken verbatim from the supplied source.

Source evidence (ROMFS_custom/scripts, identical sizes/CRC-listed in the build's
ap_romfs_embedded.h):

* ids_gcs_bridge.lua  → gcs:send_text(6, "PIDS|1|FC|%s|%d|%.3f|%d|0.000|0")
      fields: version | origin | detector | state | confidence | evidence | metric | instance
* ids_common.safe_report → gcs:send_text(4, "PUSHPAK IDS: " .. text)
      *_confirm.lua text:  "<CLASS> conf=%.2f evidence=0x%04X"
      gps_confirm.lua text: "GPS CONFIRMED conf=%.2f pos=%.1fm vel=%.1fm/s robust=%.2f cusum=%.2f"
* ArduPilot scripting reports runtime errors as STATUSTEXT beginning "Lua:" /
  "Scripting:" — used here for Lua-layer health.

Firmware facts come from configs/capabilities.json (regenerated from the build
by scripts/discover_firmware.py), not from this file. The parsers are defensive
and keep the original text either way.
"""
from __future__ import annotations

import re
from typing import Optional

PIDS_DETECTORS = ["GPS", "MAVLINK", "COMMAND", "RC_LINK", "IMU", "MISSION", "PARAMETER", "OFFBOARD"]

# Integer state → name. The values cannot be recovered from a stripped binary; the
# runtime sets PIDS_STATE_MAP_VERIFIED from capabilities.json, which verifies them
# from the AP_IDS.h static_asserts (build_v3: CLEAR=0, SUSPECTED=1, CONFIRMED=2).
PIDS_STATE_MAP = {0: "CLEAR", 1: "SUSPECTED", 2: "CONFIRMED"}
PIDS_STATE_MAP_VERIFIED = False

# Evidence bits as named by the Lua scripts' EVID_* constants.
EVIDENCE_BITS = {
    1: "PERSISTENCE", 2: "ROBUST", 8: "CUSUM", 16: "CROSS", 32: "KINEMATIC",
    128: "SOURCE", 256: "SEQUENCE", 512: "CONTEXT", 1024: "RATE", 2048: "INTEGRITY",
    16384: "DEGRADED",
}

# Lua classification string → PUSHPAK detector family (from each *_confirm.lua).
LUA_CLASS_TO_DETECTOR = {
    "GPS CONFIRMED": "GPS",
    "COMMAND_ANOMALY": "COMMAND", "COMMAND_INJECTION_CANDIDATE": "COMMAND",
    "COMMAND_REPLAY_OR_DUPLICATE_CANDIDATE": "COMMAND", "COMMAND_FLOOD_OR_LOW_AND_SLOW_CANDIDATE": "COMMAND",
    "COMMAND_INTEGRITY_ANOMALY": "COMMAND",
    "MAVLINK_ANOMALY": "MAVLINK", "MAVLINK_REPLAY_OR_SOURCE_ANOMALY": "MAVLINK",
    "MAVLINK_INTEGRITY_ANOMALY": "MAVLINK", "MAVLINK_LOW_RATE_OR_DOS_CANDIDATE": "MAVLINK",
    "JAMMING_OR_LOW_LINK_DEGRADATION": "RC_LINK", "LINK_FAILURE_CANDIDATE": "RC_LINK",
    "PERSISTENT_RF_DEGRADATION_CANDIDATE": "RC_LINK",
    "IMU_BIAS_DRIFT_CANDIDATE": "IMU", "IMU_CONSISTENCY_ANOMALY": "IMU", "IMU_SINGLE_SENSOR_OUTLIER_CANDIDATE": "IMU",
    "MISSION_TAMPERING_CANDIDATE": "MISSION", "IN_FLIGHT_MISSION_INTEGRITY_ANOMALY": "MISSION",
    "PARAMETER_TAMPERING_CANDIDATE": "PARAMETER", "AIRBORNE_PARAMETER_SOURCE_ANOMALY": "PARAMETER",
    "LOW_AND_SLOW_PARAMETER_DRIFT": "PARAMETER", "PARAMETER_WRITE_BURST": "PARAMETER",
    "EXTERNAL_CONTROL_ANOMALY": "OFFBOARD", "EXTERNAL_CONTROL_SOURCE_AND_KINEMATIC_ANOMALY": "OFFBOARD",
    "EXTERNAL_CONTROL_STALE_STREAM": "OFFBOARD", "EXTERNAL_CONTROL_RATE_ANOMALY": "OFFBOARD",
}
LUA_SCRIPT_FOR_DETECTOR = {
    "GPS": "gps_confirm.lua", "COMMAND": "command_confirm.lua", "MAVLINK": "mavlink_confirm.lua",
    "RC_LINK": "jamming_confirm.lua", "IMU": "imu_confirm.lua", "MISSION": "mission_confirm.lua",
    "PARAMETER": "parameter_confirm.lua", "OFFBOARD": "offboard_confirm.lua",
}
LUA_CONFIRM_THRESHOLD = 0.78  # `combined >= 0.78` in every *_confirm.lua

_PIDS_RE = re.compile(r"^PIDS\|(\d+)\|([A-Z_]+)\|([A-Z_]+)\|(-?\d+)\|(-?[0-9.]+)\|(\d+)\|(-?[0-9.]+)\|(\d+)(?:\|(\d+)\|(\d+))?\s*$")
_LUA_PREFIX = "PUSHPAK IDS: "
_GPS_RE = re.compile(r"^GPS CONFIRMED conf=([0-9.]+) pos=([0-9.]+)m vel=([0-9.]+)m/s robust=([0-9.]+) cusum=([0-9.]+)")
_CLASS_RE = re.compile(r"^([A-Z_]+) conf=([0-9.]+) evidence=0x([0-9A-Fa-f]{1,4})")
_LUA_ERR_RE = re.compile(r"^(Lua|Scripting)\s*:\s*(.*)$", re.IGNORECASE)
_SCRIPT_NAME_RE = re.compile(r"([A-Za-z0-9_]+\.lua)")


def decode_evidence(mask: Optional[int]) -> dict:
    if mask is None:
        return {"mask": None, "bits": [], "undocumented": []}
    bits, undoc = [], []
    for b in range(16):
        v = 1 << b
        if mask & v:
            if v in EVIDENCE_BITS:
                bits.append(EVIDENCE_BITS[v])
            else:
                undoc.append(f"BIT{b}")
    return {"mask": mask, "hex": f"0x{mask:04X}", "bits": bits, "undocumented": undoc}


def parse_statustext(text: str) -> Optional[dict]:
    """Return a structured PUSHPAK record, or None if the text is not PUSHPAK/Lua."""
    if text is None:
        return None
    s = text.rstrip("\x00").strip()
    m = _PIDS_RE.match(s)
    if m:
        ver, origin, det, st, conf, ev, metric, inst, boot, seq = m.groups()
        st_i = int(st)
        return {"boot_id": int(boot) if boot else None, "seq": int(seq) if seq else None,
            "kind": "PIDS", "format_version": int(ver), "origin": origin, "detector": det,
            "state_raw": st_i, "state": PIDS_STATE_MAP.get(st_i, f"UNKNOWN({st_i})"),
            "state_map_verified": PIDS_STATE_MAP_VERIFIED,
            "confidence": float(conf), "evidence": decode_evidence(int(ev)),
            "metric": float(metric), "instance": int(inst),
            "known_detector": det in PIDS_DETECTORS, "original": text,
        }
    if s.startswith(_LUA_PREFIX):
        body = s[len(_LUA_PREFIX):]
        b = re.match(r"^BRIDGE binding=([a-z_,]+)(?: v=(\d+))?", body)
        if b:
            return {"kind": "BRIDGE", "detector": None, "binding": b.group(1).split(","),
                    "protocol_version": int(b.group(2)) if b.group(2) else 1, "original": text}
        sm = re.match(r"^STATEMAP ((?:-?\d+=[A-Z_]+,?)+)\s*$", body)
        if sm:
            mapping = {int(k): v for k, v in (p.split("=", 1) for p in sm.group(1).strip(",").split(","))}
            return {"kind": "STATEMAP", "detector": None, "state_map": mapping, "original": text}
        sy = re.match(r"^SYNC up=(\d+) seq=(\d+) ev=(\d+)(?: boot=(\d+))?(?: drop=(\d+))?", body)
        if sy:
            return {"kind": "SYNC", "detector": None, "uptime_s": int(sy.group(1)), "sequence": int(sy.group(2)),
                    "events_sent": int(sy.group(3)), "boot_id": int(sy.group(4)) if sy.group(4) else None,
                    "ring_dropped": int(sy.group(5)) if sy.group(5) else None, "original": text}
        fe = re.match(r"^FC_EVENT seq=(\d+) delta=(-?\d+)", body)
        if fe:
            return {"kind": "FC_EVENT", "detector": None, "sequence": int(fe.group(1)), "delta": int(fe.group(2)), "original": text}
        g = _GPS_RE.match(body)
        if g:
            conf, pos, vel, robust, cusum = map(float, g.groups())
            return {"kind": "LUA_CONFIRMATION", "class": "GPS CONFIRMED", "detector": "GPS",
                    "script": "gps_confirm.lua", "confidence": conf,
                    "metrics": {"position_residual_m": pos, "velocity_residual_ms": vel,
                                "robust_z_score": robust, "cusum_score": cusum},
                    "evidence": decode_evidence(None), "original": text}
        c = _CLASS_RE.match(body)
        if c:
            cls, conf, ev = c.groups()
            det = LUA_CLASS_TO_DETECTOR.get(cls)
            return {"kind": "LUA_CONFIRMATION", "class": cls, "detector": det or "UNKNOWN",
                    "script": LUA_SCRIPT_FOR_DETECTOR.get(det or "", None), "confidence": float(conf),
                    "evidence": decode_evidence(int(ev, 16)), "known_class": det is not None,
                    "original": text}
        return {"kind": "LUA_UNPARSED", "detector": "UNKNOWN", "original": text}
    e = _LUA_ERR_RE.match(s)
    if e:
        script = _SCRIPT_NAME_RE.search(e.group(2))
        missing = re.search(r"method '([a-z_]+)'", e.group(2))
        return {"kind": "LUA_RUNTIME", "script": script.group(1) if script else None,
                "message": e.group(2), "missing_method": missing.group(1) if missing else None,
                "is_error": bool(re.search(r"error|attempt|nil|fail|bad|memory", e.group(2), re.I)),
                "original": text}
    return None


class EventDeliveryTracker:
    """Bridge protocol state and event-loss accounting (GAP-07).

    Delivery is one-way and best-effort: the GCS never acknowledges. Loss is made
    *visible* instead: the bridge's SYNC line says how many FC_EVENT lines it sent
    since boot, and an uptime drop marks a new boot epoch. FC_EVENTs are keyed by
    (boot_epoch, seq) so repeats are ignored.
    """

    def __init__(self):
        self.protocol_version: Optional[int] = None
        self.binding: list[str] = []
        self.state_map: Optional[dict[int, str]] = None
        self.boot_epoch = 0
        self.reboots = 0
        self.last_uptime: Optional[int] = None
        self.last_seq: Optional[int] = None
        self.received = 0                 # FC_EVENT lines received this boot epoch
        self.baseline_sent: Optional[int] = None  # bridge's count at our first SYNC of the epoch (pre-connection history)
        self.missed_total = 0
        self.missed_reported = 0
        self.duplicates = 0
        self.seq_jumps = 0
        self._seen: set[tuple] = set()
        self.last_sync: Optional[dict] = None
        self.native_boot: Optional[int] = None    # AP_IDS boot ID, when the firmware provides one (FW-06)
        self.ring_dropped = 0                     # AP_IDS event-ring overflow count (FW-06)
        self.native_duplicates = 0

    @property
    def state_map_matches_assumed(self) -> Optional[bool]:
        return None if self.state_map is None else self.state_map == PIDS_STATE_MAP

    def on_bridge(self, rec: dict) -> None:
        self.protocol_version = rec.get("protocol_version", 1)
        self.binding = rec.get("binding") or []

    def on_statemap(self, rec: dict) -> None:
        self.state_map = dict(rec["state_map"])

    def _new_epoch(self) -> None:
        self.boot_epoch += 1
        self.reboots += 1
        self.last_seq = None
        self.received = 0
        self.baseline_sent = None
        self.missed_reported = 0

    def on_sync(self, rec: dict) -> dict:
        """Returns {"reboot": bool, "new_missing": int, "pre_connection_events": int|None}."""
        out = {"reboot": False, "new_missing": 0, "pre_connection_events": None, "new_ring_drops": 0}
        up = rec["uptime_s"]
        boot = rec.get("boot_id")
        if boot is not None and self.native_boot is not None and boot != self.native_boot:
            self._new_epoch()               # explicit boot ID beats the uptime heuristic
            out["reboot"] = True
        elif boot is None and self.last_uptime is not None and up + 2 < self.last_uptime:
            self._new_epoch()
            out["reboot"] = True
        if boot is not None:
            self.native_boot = boot
        if rec.get("ring_dropped") is not None:
            if rec["ring_dropped"] > self.ring_dropped:
                out["new_ring_drops"] = rec["ring_dropped"] - self.ring_dropped
            self.ring_dropped = rec["ring_dropped"]
        self.last_uptime = up
        self.last_sync = rec
        if self.baseline_sent is None:
            # Events the bridge sent before this GCS saw a SYNC were never deliverable to us.
            self.baseline_sent = max(0, rec["events_sent"] - self.received)
            out["pre_connection_events"] = self.baseline_sent
        missing = max(0, rec["events_sent"] - self.baseline_sent - self.received)
        if missing > self.missed_reported:
            out["new_missing"] = missing - self.missed_reported
            self.missed_total += out["new_missing"]
            self.missed_reported = missing
        return out

    def on_native_event(self, boot_id: int, seq: int) -> bool:
        """True if this (boot, seq) AP_IDS event was already seen (STATUSTEXT repeat or DataFlash replay)."""
        key = ("native", boot_id, seq)
        if key in self._seen:
            self.native_duplicates += 1
            return True
        self._seen.add(key)
        return False

    def on_fc_event(self, rec: dict) -> dict:
        """Returns {"duplicate": bool, "gap": bool}."""
        key = (self.boot_epoch, rec["sequence"])
        if key in self._seen:
            self.duplicates += 1
            return {"duplicate": True, "gap": False}
        self._seen.add(key)
        if len(self._seen) > 5000:
            self._seen = {k for k in self._seen if k[0] == self.boot_epoch}
        gap = self.last_seq is not None and rec["sequence"] - rec["delta"] != self.last_seq
        if gap:
            self.seq_jumps += 1
        self.last_seq = rec["sequence"]
        self.received += 1
        return {"duplicate": False, "gap": gap}

    def status(self) -> dict:
        return {"protocol_version": self.protocol_version, "binding": self.binding, "state_map": self.state_map,
                "state_map_matches_assumed": self.state_map_matches_assumed, "boot_epoch": self.boot_epoch,
                "reboots_seen": self.reboots, "last_uptime_s": self.last_uptime, "last_event_seq": self.last_seq,
                "events_received_this_boot": self.received, "events_before_connection": self.baseline_sent,
                "events_missed_total": self.missed_total, "duplicates_ignored": self.duplicates,
                "sequence_discontinuities": self.seq_jumps, "native_boot_id": self.native_boot,
                "native_ring_dropped": self.ring_dropped, "native_duplicates_ignored": self.native_duplicates,
                "delivery_model": "one-way best-effort telemetry; durable onboard record requires AP_IDS DataFlash logging (firmware)"}


class StatusTextAssembler:
    """Reassembles MAVLink 2 chunked STATUSTEXT (id / chunk_seq, 50-byte chunks).

    Texts longer than 50 characters (e.g. the gps_confirm.lua report, 81 chars)
    arrive as several STATUSTEXT frames sharing a non-zero `id`. Returns the full
    text on the final chunk (a chunk shorter than 50 chars), else None.
    """

    CHUNK = 50

    def __init__(self, timeout_s: float = 2.0):
        self.timeout = timeout_s
        self.parts: dict[tuple, dict] = {}

    def push(self, sysid, compid, fields: dict, mono: float) -> tuple[Optional[str], list[int]]:
        text = str(fields.get("text") or "").rstrip("\x00")
        mid = fields.get("id") or 0
        for k in [k for k, v in self.parts.items() if mono - v["mono"] > self.timeout]:
            self.parts.pop(k, None)
        if not mid:
            return text, []
        key = (sysid, compid, mid)
        buf = self.parts.setdefault(key, {"chunks": {}, "mono": mono})
        buf["chunks"][fields.get("chunk_seq") or 0] = text
        buf["mono"] = mono
        if len(text) < self.CHUNK:
            self.parts.pop(key, None)
            return "".join(buf["chunks"][i] for i in sorted(buf["chunks"])), sorted(buf["chunks"])
        return None, []
