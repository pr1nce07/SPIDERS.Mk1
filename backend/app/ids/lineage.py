"""Evidence lineage (GAP-09 / DET-02).

Each detector result is mapped to the *physical evidence groups* it depends on.
The correlator uses this to tell corroboration (several tiers re-deriving the
same GPS/EKF residual) from independent evidence (different sensor modalities
or message streams agreeing).

Two results are independent only when their groups are disjoint. Results whose
groups overlap form one "line of evidence"; within a line only the strongest
contributor gets full weight.
"""
from __future__ import annotations

from typing import Iterable, Optional

# Physical / data-path evidence groups. Estimator outputs (EKF) are their own
# group because the EKF fuses GNSS + IMU: anything using EKF shares that path.
GROUPS = {
    "GNSS": "Primary GNSS receiver (GPS_RAW_INT / gps: binding)",
    "GNSS2": "Second, independent GNSS receiver chain (GPS2_RAW)",
    "EKF": "Navigation estimator output (fuses GNSS + IMU + baro)",
    "IMU": "Inertial sensors (RAW_IMU / SCALED_IMU*)",
    "BARO": "Barometric altitude",
    "RC": "RC receiver channels",
    "LINK_RF": "Telemetry/RC radio link quality",
    "MAVLINK_TRAFFIC": "MAVLink packet headers, rates, sequence and source IDs on the visible link",
    "MAVLINK_SIGNATURE": "MAVLink 2 signature fields",
    "COMMAND_STREAM": "COMMAND_* / SET_MODE traffic",
    "PARAM_STREAM": "PARAM_* traffic and parameter values",
    "MISSION_STREAM": "MISSION_* traffic and mission contents",
    "SETPOINT_STREAM": "External-control setpoint traffic",
    "POWER": "Battery / power monitor",
    "VEHICLE_STATE": "HEARTBEAT mode/arming state",
}

DETECTOR_LINEAGE: dict[str, tuple[str, ...]] = {
    "GPS_INTEGRITY": ("GNSS", "EKF"),
    "IMU_CONSISTENCY": ("IMU",),
    "HEARTBEAT": ("MAVLINK_TRAFFIC",),
    "MAVLINK_SEQUENCE": ("MAVLINK_TRAFFIC",),
    "SOURCE_IDENTITY": ("MAVLINK_TRAFFIC",),
    "MAVLINK_RATE": ("MAVLINK_TRAFFIC",),
    "MAVLINK_SIGNING": ("MAVLINK_SIGNATURE",),
    "COMMAND": ("COMMAND_STREAM",),
    "MISSION": ("MISSION_STREAM",),
    "PARAMETER": ("PARAM_STREAM",),
    "OFFBOARD": ("SETPOINT_STREAM",),
    "RC_LINK": ("RC", "LINK_RF"),
    "BATTERY": ("POWER",),
    "FLIGHT_MODE": ("VEHICLE_STATE", "COMMAND_STREAM"),
    "SENSOR_HEALTH": ("VEHICLE_STATE",),
    "BASELINE": ("PARAM_STREAM", "MISSION_STREAM"),
    "EVENT_DELIVERY": ("MAVLINK_TRAFFIC",),
}

# Results whose method shows a different dependency than the detector default.
METHOD_LINEAGE: dict[str, tuple[str, ...]] = {
    "EKF(baro) ↔ GPS altitude residual (offset-corrected)": ("BARO", "GNSS", "EKF"),
    "IMU gyro ↔ AHRS body rates": ("IMU", "EKF"),
    "commanded-vs-observed kinematic divergence": ("SETPOINT_STREAM", "EKF"),
    "EKF status flags": ("EKF",),
}

# PUSHPAK FC (PIDS) and Lua results carry the onboard detector family in inputs["detector"].
# The onboard tiers read the same sensors as the ground tier (Lua gps_confirm uses gps: + ahrs:).
PUSHPAK_LINEAGE: dict[str, tuple[str, ...]] = {
    "GPS": ("GNSS", "EKF"),
    "IMU": ("IMU",),
    "MAVLINK": ("MAVLINK_TRAFFIC",),
    "COMMAND": ("COMMAND_STREAM", "VEHICLE_STATE"),
    "RC_LINK": ("RC", "LINK_RF"),
    "MISSION": ("MISSION_STREAM",),
    "PARAMETER": ("PARAM_STREAM",),
    "OFFBOARD": ("SETPOINT_STREAM", "EKF"),
}

# Rules evaluate on telemetry already seen by the ground detectors; fall back to the domain.
DOMAIN_LINEAGE: dict[str, tuple[str, ...]] = {
    "GPS_INTEGRITY": ("GNSS", "EKF"),
    "SENSOR": ("IMU",),
    "LINK": ("RC", "LINK_RF"),
    "MISSION": ("MISSION_STREAM",),
    "MAVLINK_SECURITY": ("MAVLINK_TRAFFIC",),
}

# Derived from many inputs at once: adds no independent evidence of its own.
DERIVED_ONLY = {"ML_BASELINE"}


def lineage_for(r) -> Optional[tuple[str, ...]]:
    """Evidence groups for a DetectorResult (None = derived-only, never independent)."""
    explicit = getattr(r, "lineage", None)
    if explicit:
        return tuple(sorted(explicit))
    if r.detector in DERIVED_ONLY:
        return None
    if r.method in METHOD_LINEAGE:
        return tuple(sorted(METHOD_LINEAGE[r.method]))
    if r.detector == "SENSOR_HEALTH" and "GPS" in (r.title or ""):
        return ("GNSS",)
    if r.detector == "PUSHPAK_FC":
        fam = (r.inputs or {}).get("detector")
        if fam in PUSHPAK_LINEAGE:
            return tuple(sorted(PUSHPAK_LINEAGE[fam]))
    if r.detector in DETECTOR_LINEAGE:
        return tuple(sorted(DETECTOR_LINEAGE[r.detector]))
    if r.domain in DOMAIN_LINEAGE:
        return tuple(sorted(DOMAIN_LINEAGE[r.domain]))
    return (f"UNMAPPED:{r.detector}",)


def evidence_lines(lineages: Iterable[Optional[tuple[str, ...]]]) -> list[set[str]]:
    """Merge overlapping group sets into independent lines of evidence."""
    lines: list[set[str]] = []
    for lin in lineages:
        if not lin:
            continue
        cur = set(lin)
        merged = [ln for ln in lines if ln & cur]
        for ln in merged:
            cur |= ln
            lines.remove(ln)
        lines.append(cur)
    return lines
