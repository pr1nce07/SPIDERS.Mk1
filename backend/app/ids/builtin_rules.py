"""Seed rules shipped with the builder. They use only standard ardupilotmega
messages/fields (validated at load time against the registry)."""
from __future__ import annotations


def _n(id_, type_, x, y, label=None, **params):
    d = {"id": id_, "type": type_, "position": {"x": x, "y": y}, "params": params}
    if label:
        d["label"] = label
    return d


def _e(s, t, h="in"):
    return {"id": f"{s}->{t}:{h}", "source": s, "target": t, "targetHandle": h}


BUILTIN_RULES = [
    {
        "rule_id": "GPS-CONSISTENCY-001",
        "name": "GPS / EKF Velocity Divergence",
        "description": "Spec §14 example. GPS ground speed vs EKF horizontal speed (GLOBAL_POSITION_INT vx/vy); "
                       "|difference| > 5 m/s for > 3 s AND EKF velocity-variance anomaly → GPS incident. "
                       "(MAVLink carries no raw 'IMU velocity'; the EKF solution is the inertial-aided velocity.)",
        "severity": "HIGH", "enabled": True, "domain": "GPS_INTEGRITY",
        "persistence_s": 0, "cooldown_s": 30, "evidence_window_s": 30, "correlation_window_s": 10, "min_evidence": 2,
        "confidence": {"method": "weighted_evidence", "threshold": 0.75},
        "limitations": "This evidence alone does not prove intentional spoofing.",
        "graph": {"nodes": [
            _n("gps_vel", "input_gps", 40, 40, "GPS velocity", msg="GPS_RAW_INT", field="vel", scale=0.01, sysid_filter="vehicle"),
            _n("ekf_vx", "input_ekf", 40, 170, "EKF vx", msg="GLOBAL_POSITION_INT", field="vx", scale=0.01, sysid_filter="vehicle"),
            _n("ekf_vy", "input_ekf", 40, 270, "EKF vy", msg="GLOBAL_POSITION_INT", field="vy", scale=0.01, sysid_filter="vehicle"),
            _n("ekf_speed", "magnitude", 280, 210, "EKF velocity"),
            _n("diff", "difference", 500, 110, "Difference"),
            _n("absd", "abs", 700, 110, "Absolute Value"),
            _n("thr", "threshold", 890, 110, "> 5 m/s", op=">", value=5.0),
            _n("pers", "persistence", 1080, 110, "> 3 s", duration_s=3.0),
            _n("ekf_var", "input_ekf", 700, 330, "EKF velocity variance", msg="EKF_STATUS_REPORT", field="velocity_variance", sysid_filter="vehicle"),
            _n("var_thr", "threshold", 890, 330, "EKF innovation anomaly", op=">", value=0.5),
            _n("and", "and", 1270, 200, "AND"),
            _n("out", "out_incident", 1450, 200, "GPS INCIDENT", title="GPS / EKF velocity divergence (rule)"),
        ], "edges": [
            _e("ekf_vx", "ekf_speed", "a"), _e("ekf_vy", "ekf_speed", "b"),
            _e("gps_vel", "diff", "a"), _e("ekf_speed", "diff", "b"), _e("diff", "absd"), _e("absd", "thr"), _e("thr", "pers"),
            _e("ekf_var", "var_thr"), _e("pers", "and", "in1"), _e("var_thr", "and", "in2"), _e("and", "out"),
        ]},
        "tests": [{"dataset": "scenario:GPS_IMU_MISMATCH", "expect": "trigger"},
                  {"dataset": "scenario:NORMAL_FLIGHT", "expect": "no_trigger"}],
    },
    {
        "rule_id": "HEARTBEAT-RATE-001",
        "name": "Vehicle Heartbeat Rate Low",
        "description": "Vehicle HEARTBEAT rate below 0.5 Hz for 3 s (link degradation).",
        "severity": "MEDIUM", "enabled": True, "domain": "LINK",
        "persistence_s": 0, "cooldown_s": 20, "evidence_window_s": 30, "correlation_window_s": 10, "min_evidence": 1,
        "confidence": {"method": "fixed", "value": 0.5},
        "graph": {"nodes": [
            _n("hb", "mavlink_message", 40, 80, "Vehicle HEARTBEAT", msg="HEARTBEAT", sysid_filter="vehicle"),
            _n("sys", "mavlink_message", 40, 220, "Vehicle SYS_STATUS", msg="SYS_STATUS", sysid_filter="vehicle"),
            _n("rate", "rate", 260, 80, "Rate (5 s)", window_s=5.0),
            _n("low", "threshold", 460, 80, "< 0.5 Hz", op="<", value=0.5),
            _n("pers", "persistence", 660, 80, "for 3 s", duration_s=3.0),
            _n("out", "out_anomaly", 860, 80, "WARN", title="Heartbeat rate low (rule)"),
        ], "edges": [_e("hb", "rate"), _e("rate", "low"), _e("low", "pers"), _e("pers", "out")]},
        "tests": [{"dataset": "scenario:HEARTBEAT_LOSS", "expect": "trigger"}, {"dataset": "scenario:NORMAL_FLIGHT", "expect": "no_trigger"}],
    },
    {
        "rule_id": "CMD-BURST-001",
        "name": "Command Burst From Non-Vehicle Source",
        "description": "≥ 5 COMMAND_LONG in 5 s from any non-vehicle source while armed.",
        "severity": "HIGH", "enabled": True, "domain": "MAVLINK_SECURITY",
        "persistence_s": 0, "cooldown_s": 30, "evidence_window_s": 30, "correlation_window_s": 10, "min_evidence": 2,
        "confidence": {"method": "weighted_evidence", "threshold": 1.0},
        "graph": {"nodes": [
            _n("cmd", "mavlink_message", 40, 80, "COMMAND_LONG", msg="COMMAND_LONG", sysid_filter="non_vehicle"),
            _n("cnt", "count", 260, 80, "Count (5 s)", window_s=5.0),
            _n("thr", "threshold", 460, 80, "≥ 5", op=">=", value=5),
            _n("armed", "vehicle_state", 260, 220, "Armed", field="armed"),
            _n("and", "and", 660, 140, "AND"),
            _n("out", "out_suspected", 860, 140, "SUSPECTED", title="Command burst while armed (rule)"),
        ], "edges": [_e("cmd", "cnt"), _e("cnt", "thr"), _e("thr", "and", "in1"), _e("armed", "and", "in2"), _e("and", "out")]},
        "tests": [{"dataset": "scenario:COMMAND_BURST", "expect": "trigger"}, {"dataset": "scenario:NORMAL_FLIGHT", "expect": "no_trigger"}],
    },
    {
        "rule_id": "MAVSEC-CORR-001",
        "name": "Correlated MAVLink Security Pattern",
        "description": "Spec §30 example: unknown source + command anomaly + parameter anomaly within 30 s → snapshot.",
        "severity": "CRITICAL", "enabled": True, "domain": "MAVLINK_SECURITY",
        "persistence_s": 0, "cooldown_s": 60, "evidence_window_s": 60, "correlation_window_s": 30, "min_evidence": 3,
        "confidence": {"method": "weighted_evidence", "threshold": 0.9},
        "graph": {"nodes": [
            _n("src", "detector_state", 40, 40, "Source identity", detector="SOURCE_IDENTITY", min_state="SUSPECTED"),
            _n("cmd", "detector_state", 40, 160, "Command anomaly", detector="COMMAND", min_state="ANOMALOUS"),
            _n("par", "detector_state", 40, 280, "Parameter anomaly", detector="PARAMETER", min_state="ANOMALOUS"),
            _n("tc", "temporal_correlation", 320, 160, "Within 30 s", window_s=30.0),
            _n("out", "out_snapshot", 560, 160, "FORENSIC SNAPSHOT", title="Correlated MAVLink security pattern (rule)"),
        ], "edges": [_e("src", "tc", "in1"), _e("cmd", "tc", "in2"), _e("par", "tc", "in3"), _e("tc", "out")]},
        "tests": [{"dataset": "scenario:MULTI_SIGNAL_INCIDENT", "expect": "trigger"}, {"dataset": "scenario:NORMAL_FLIGHT", "expect": "no_trigger"}],
    },
]
