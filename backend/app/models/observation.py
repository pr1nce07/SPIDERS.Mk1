"""Platform-neutral SecurityObservation contract (GAP-15).

Detectors today consume ArduPilot/MAVLink TelemetryEvents. Before a second
flight stack is supported, every adapter must emit this canonical record.
Fields an adapter cannot provide are the string "UNAVAILABLE" — never a
fabricated zero. Only the ArduPilot/MAVLink adapter below exists; PX4 and
vendor adapters are not implemented and must not be claimed.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional, Union

SCHEMA_VERSION = 1
UNAVAILABLE = "UNAVAILABLE"
Maybe = Union[Any, str]


@dataclass
class SecurityObservation:
    schema_version: int
    vehicle_id: Maybe
    boot_id: Maybe
    monotonic_timestamp_ns: int
    wall_time: Maybe
    source_platform: str             # "ArduPilot" | "PX4" | vendor name
    source_subsystem: str            # "MAVLink" | "DataFlash" | "ULog" | "Lua" | ...
    source_identity: Maybe           # e.g. {"sysid": 255, "compid": 190}
    event_type: str                  # canonical type, see EVENT_TYPES
    normalized_fields: dict = field(default_factory=dict)
    raw_reference: Maybe = UNAVAILABLE
    data_quality: str = "OK"         # OK | PARSE_ERROR | PARTIAL
    authentication_status: str = "NOT_APPLICABLE"   # NONE | PRESENT_UNVERIFIED | VERIFIED | INVALID | NOT_APPLICABLE
    provenance: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# Canonical event types and the ArduPilot/MAVLink messages that map to them.
EVENT_TYPES = {
    "HEARTBEAT": ("HEARTBEAT",),
    "GNSS_FIX": ("GPS_RAW_INT", "GPS2_RAW"),
    "NAV_ESTIMATE": ("GLOBAL_POSITION_INT", "LOCAL_POSITION_NED", "EKF_STATUS_REPORT"),
    "ATTITUDE": ("ATTITUDE",),
    "IMU_SAMPLE": ("RAW_IMU", "SCALED_IMU", "SCALED_IMU2", "SCALED_IMU3"),
    "COMMAND": ("COMMAND_LONG", "COMMAND_INT", "SET_MODE"),
    "COMMAND_RESULT": ("COMMAND_ACK",),
    "PARAM_WRITE_REQUEST": ("PARAM_SET",),
    "PARAM_VALUE": ("PARAM_VALUE",),
    "MISSION_TRANSFER": ("MISSION_COUNT", "MISSION_ITEM_INT", "MISSION_ITEM", "MISSION_ACK", "MISSION_CLEAR_ALL"),
    "MISSION_PROGRESS": ("MISSION_CURRENT",),
    "OFFBOARD_SETPOINT": ("SET_POSITION_TARGET_LOCAL_NED", "SET_POSITION_TARGET_GLOBAL_INT", "SET_ATTITUDE_TARGET"),
    "RC_INPUT": ("RC_CHANNELS", "RC_CHANNELS_RAW"),
    "LINK_QUALITY": ("RADIO_STATUS",),
    "POWER": ("SYS_STATUS", "BATTERY_STATUS"),
    "ONBOARD_IDS_REPORT": ("STATUSTEXT",),
}
_BY_MSG = {m: t for t, ms in EVENT_TYPES.items() for m in ms}

# What the ArduPilot/MAVLink adapter can provide. Unlisted capabilities are UNAVAILABLE.
ARDUPILOT_MAVLINK_CAPABILITIES = {
    "vehicle_id": "MAVLink SYSID (not a cryptographic identity)",
    "boot_id": UNAVAILABLE + " — needs the AP_IDS boot ID (firmware work item FW-07)",
    "authentication_status": "MAVLink 2 signature state; VERIFIED only with the GCS key configured",
    "wall_time": "GCS receive time (live) or log time (offline)",
    "accepted_setpoint_observation": UNAVAILABLE + " — needs the firmware setpoint hook (FW-05)",
    "param_write_sender_onboard": UNAVAILABLE + " — needs the firmware PARAM_SET hook (FW-04)",
}


def _auth(ev) -> str:
    if ev.signature_status == "INVALID":
        return "INVALID"
    if ev.signed:
        return "VERIFIED" if ev.signature_status == "VALID" else "PRESENT_UNVERIFIED"
    return "NONE" if ev.mavlink_version == 2 else "NOT_APPLICABLE"


def from_mavlink_event(ev, boot_id: Optional[str] = None, platform: str = "ArduPilot") -> SecurityObservation:
    """ArduPilot/MAVLink adapter: TelemetryEvent → SecurityObservation."""
    subsystem = {"DATAFLASH": "DataFlash", "TLOG": "MAVLink", "LIVE": "MAVLink", "CASE": "MAVLink",
                 "SIMULATION": "MAVLink (simulated)"}.get(ev.source, ev.source)
    return SecurityObservation(
        schema_version=SCHEMA_VERSION,
        vehicle_id=ev.sysid if ev.sysid is not None else UNAVAILABLE,
        boot_id=boot_id or UNAVAILABLE,
        monotonic_timestamp_ns=int(ev.mono_ns),
        wall_time=ev.t if ev.t is not None else UNAVAILABLE,
        source_platform=platform,
        source_subsystem=subsystem,
        source_identity={"sysid": ev.sysid, "compid": ev.compid} if ev.sysid is not None else UNAVAILABLE,
        event_type=_BY_MSG.get(ev.msg_name, "PARSE_ERROR" if ev.msg_name == "BAD_DATA" else f"UNMAPPED:{ev.msg_name}"),
        normalized_fields=dict(ev.fields or {}),
        raw_reference={"link": ev.link, "index": ev.idx, "msg_id": ev.msg_id, "sequence": ev.sequence},
        data_quality="PARSE_ERROR" if ev.parse_error else "OK",
        authentication_status=_auth(ev),
        provenance={"adapter": "ardupilot-mavlink/1", "source": ev.source, "link": ev.link},
    )
