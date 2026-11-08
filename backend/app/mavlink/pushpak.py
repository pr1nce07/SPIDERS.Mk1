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

Firmware finding (see configs/capabilities.json): the compiled `ids` Lua binding
exposes only `report_confirmed()` and `event_sequence()`. The accessor methods
the scripts call (e.g. `ids:gps_confidence()`) are absent, so on this build the
scripts are expected to stop with a Lua runtime error rather than emit the
formats above. The parsers are defensive and keep the original text either way.
"""
from __future__ import annotations

import re
from typing import Optional

PIDS_DETECTORS = ["GPS", "MAVLINK", "COMMAND", "RC_LINK", "IMU", "MISSION", "PARAMETER", "OFFBOARD"]

# Integer state → name. The bridge forwards ids:<det>_state() integers. The enum
# ordering CLEAR/SUSPECTED/CONFIRMED comes from DETECTION_METHODS.md; the numeric
# values are not provable from the stripped binary and are flagged as such.
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

_PIDS_RE = re.compile(r"^PIDS\|(\d+)\|([A-Z_]+)\|([A-Z_]+)\|(-?\d+)\|(-?[0-9.]+)\|(\d+)\|(-?[0-9.]+)\|(\d+)\s*$")
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
        ver, origin, det, st, conf, ev, metric, inst = m.groups()
        st_i = int(st)
        return {
            "kind": "PIDS", "format_version": int(ver), "origin": origin, "detector": det,
            "state_raw": st_i, "state": PIDS_STATE_MAP.get(st_i, f"UNKNOWN({st_i})"),
            "state_map_verified": PIDS_STATE_MAP_VERIFIED,
            "confidence": float(conf), "evidence": decode_evidence(int(ev)),
            "metric": float(metric), "instance": int(inst),
            "known_detector": det in PIDS_DETECTORS, "original": text,
        }
    if s.startswith(_LUA_PREFIX):
        body = s[len(_LUA_PREFIX):]
        b = re.match(r"^BRIDGE binding=([a-z_,]+)", body)
        if b:
            return {"kind": "BRIDGE", "detector": None, "binding": b.group(1).split(","), "original": text}
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
