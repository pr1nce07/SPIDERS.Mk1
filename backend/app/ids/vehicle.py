"""Vehicle-state detectors: battery anomaly, flight-mode transitions, sensor health."""
from __future__ import annotations

from collections import deque
from typing import Optional

from ..models.events import TelemetryEvent
from .base import AnalysisContext, Detector
from .stats import clamp01


def sensor_bits(registry) -> dict[int, str]:
    out = {}
    try:
        for val, entry in registry.enums["MAV_SYS_STATUS_SENSOR"].items():
            if isinstance(val, int) and val > 0 and (val & (val - 1)) == 0:
                out[val] = entry.name.replace("MAV_SYS_STATUS_", "")
    except Exception:
        pass
    return out


class BatteryDetector(Detector):
    detector_id = "BATTERY"
    name = "Battery Anomaly"
    domain = "SENSOR"
    data_sources = ("SYS_STATUS", "BATTERY_STATUS")
    methods = ("voltage step vs current step", "remaining-percentage jump", "plausibility")
    description = "Voltage/current/remaining changes not explained by load; implausible readings."
    limitations = ("Battery monitor calibration errors and connector faults produce the same signatures.",)

    def __init__(self, cfg):
        super().__init__(cfg)
        self.v_step = float(self.cfg.get("voltage_step_v", 1.2))
        self.i_step = float(self.cfg.get("current_step_a", 15))
        self.rem_jump = float(self.cfg.get("remaining_jump_pct", 15))
        self.prev: Optional[dict] = None
        self.cool: dict = {}

    def process(self, ev: TelemetryEvent, ctx: AnalysisContext):
        if ev.sysid != ctx.vehicle_sysid:
            return []
        f = ev.fields
        if ev.msg_name == "SYS_STATUS":
            v = f.get("voltage_battery"); i = f.get("current_battery"); r = f.get("battery_remaining")
            v = None if v in (None, 65535, 0xFFFF) else v / 1000.0
            i = None if i in (None, -1) else i / 100.0
            r = None if r in (None, -1) else float(r)
        else:
            vs = f.get("voltages") or []
            cells = [c for c in vs if c not in (None, 65535)]
            v = sum(cells) / 1000.0 if cells else None
            i = f.get("current_battery"); i = None if i in (None, -1) else i / 100.0
            r = f.get("battery_remaining"); r = None if r in (None, -1) else float(r)
        if v is None:
            return []
        self.mark_data(ctx)
        cur = {"v": v, "i": i, "r": r, "mono": ctx.mono}
        prev, self.prev = self.prev, cur
        self.metrics = {"voltage_v": round(v, 2), "current_a": i, "remaining_pct": r}
        if not prev or ctx.mono - prev["mono"] > 5:
            return []
        out = []
        dv = v - prev["v"]
        di = (i or 0) - (prev["i"] or 0)
        if abs(dv) > self.v_step and abs(di) < self.i_step and self._cool("v", ctx):
            out.append(self.result(ctx, "ANOMALOUS", "Battery voltage step without load change", ev=ev,
                                   method="voltage step vs current step", score=round(dv, 2), threshold=self.v_step,
                                   inputs={"voltage_before": round(prev["v"], 2), "voltage_after": round(v, 2),
                                           "current_before": prev["i"], "current_after": i},
                                   confidence=clamp01(abs(dv) / (3 * self.v_step)),
                                   why=f"Voltage changed {dv:+.2f} V in one update while current changed only {di:+.1f} A."))
        if r is not None and prev["r"] is not None and abs(r - prev["r"]) > self.rem_jump and self._cool("r", ctx):
            out.append(self.result(ctx, "ANOMALOUS", "Battery remaining jump", ev=ev, severity="LOW",
                                   method="remaining-percentage jump", inputs={"before_pct": prev["r"], "after_pct": r},
                                   why=f"Remaining capacity jumped {r - prev['r']:+.0f} %."))
        if ctx.armed and v < 3.0 and self._cool("impl", ctx):
            out.append(self.result(ctx, "ANOMALOUS", "Implausible battery voltage while armed", ev=ev,
                                   method="plausibility", inputs={"voltage_v": v}, why="Armed vehicle reports < 3 V pack voltage."))
        return out

    def _cool(self, key, ctx, s=15):
        if ctx.mono - self.cool.get(key, -1e9) < s:
            return False
        self.cool[key] = ctx.mono
        return True


class FlightModeDetector(Detector):
    detector_id = "FLIGHT_MODE"
    name = "Flight Mode Transition"
    domain = "MAVLINK_SECURITY"
    data_sources = ("HEARTBEAT", "COMMAND_LONG", "COMMAND_INT", "SET_MODE", "STATUSTEXT")
    methods = ("transition log", "mode flapping window", "command attribution", "disarm-in-flight check")
    description = "Arm/disarm and mode transitions, mode flapping, and mode changes with no observed command."
    limitations = ("RC mode switches and failsafes change modes without any MAVLink command.",)

    def __init__(self, cfg):
        super().__init__(cfg)
        self.flap_n = int(self.cfg.get("flap_count", 4))
        self.flap_w = float(self.cfg.get("flap_window_s", 10))
        self.mode: Optional[str] = None
        self.armed: Optional[bool] = None
        self.changes: deque = deque()
        self.last_cmd: Optional[float] = None
        self.last_failsafe: Optional[float] = None
        self.transitions: deque = deque(maxlen=500)

    def process(self, ev: TelemetryEvent, ctx: AnalysisContext):
        n, f = ev.msg_name, ev.fields
        if n in ("COMMAND_LONG", "COMMAND_INT") and f.get("command") in (176, 400) or n == "SET_MODE":
            self.last_cmd = ctx.mono
            return []
        if n == "STATUSTEXT" and ev.sysid == ctx.vehicle_sysid:
            txt = str(f.get("text") or "").lower()
            if "failsafe" in txt or "fence" in txt or "ekf" in txt:
                self.last_failsafe = ctx.mono
            return []
        if n != "HEARTBEAT" or not ctx.is_vehicle(ev) or ev.compid != 1:
            return []
        self.mark_data(ctx)
        out = []
        mode, armed = ctx.mode, ctx.armed
        if self.armed is not None and armed != self.armed:
            airborne = bool(self._prev_airborne)
            st = "ANOMALOUS" if (not armed and airborne) else "OBSERVED"
            out.append(self.result(ctx, st, "DISARM while airborne" if st == "ANOMALOUS" else ("Armed" if armed else "Disarmed"),
                                   kind="alert" if st == "ANOMALOUS" else "observation", ev=ev,
                                   method="transition log", inputs={"armed": armed, "mode": mode, "airborne_before": airborne},
                                   why="Arming state changed." + (" Vehicle was airborne." if st == "ANOMALOUS" else "")))
            self.transitions.append({"t": ctx.t, "type": "ARM" if armed else "DISARM", "mode": mode})
        if self.mode is not None and mode != self.mode:
            self.transitions.append({"t": ctx.t, "type": "MODE_CHANGE", "from": self.mode, "to": mode})
            self.changes.append(ctx.mono)
            while self.changes and ctx.mono - self.changes[0] > self.flap_w:
                self.changes.popleft()
            commanded = self.last_cmd is not None and ctx.mono - self.last_cmd < 3
            failsafe = self.last_failsafe is not None and ctx.mono - self.last_failsafe < 3
            out.append(self.result(ctx, "OBSERVED", f"Mode {self.mode} → {mode}", kind="observation", ev=ev,
                                   method="transition log + command attribution",
                                   inputs={"from": self.mode, "to": mode, "commanded": commanded, "failsafe_context": failsafe, "armed": armed},
                                   why="Flight mode changed" + (" following an observed mode command." if commanded else
                                                                 " during a failsafe/EKF event." if failsafe else
                                                                 " with no observed MAVLink command (RC switch or failsafe possible).")))
            if len(self.changes) >= self.flap_n:
                out.append(self.result(ctx, "ANOMALOUS", "Flight-mode flapping", ev=ev, method="mode flapping window",
                                       parameters={"flap_count": self.flap_n, "flap_window_s": self.flap_w},
                                       inputs={"changes_in_window": len(self.changes)},
                                       why=f"{len(self.changes)} mode changes in {self.flap_w:.0f} s."))
                self.changes.clear()
        self.mode, self.armed = mode, armed
        self._prev_airborne = ctx.airborne
        self.metrics = {"mode": mode, "armed": armed, "transitions": len(self.transitions)}
        return out

    _prev_airborne = False


class SensorHealthDetector(Detector):
    detector_id = "SENSOR_HEALTH"
    name = "Sensor Health"
    domain = "SENSOR"
    data_sources = ("SYS_STATUS", "EKF_STATUS_REPORT")
    methods = ("SYS_STATUS present/enabled/health bitmask", "EKF status flags", "persistence")
    description = "Enabled sensors reporting unhealthy; EKF solution flags lost."
    limitations = ("Health bits are the autopilot's own assessment.",)

    EKF_FLAGS = {1: "ATTITUDE", 2: "VELOCITY_HORIZ", 4: "VELOCITY_VERT", 8: "POS_HORIZ_REL", 16: "POS_HORIZ_ABS",
                 32: "POS_VERT_ABS", 64: "POS_VERT_AGL", 128: "CONST_POS_MODE", 1024: "UNINITIALIZED",
                 32768: "GPS_GLITCHING"}

    def __init__(self, cfg, registry=None):
        super().__init__(cfg)
        self.persist = float(self.cfg.get("persistence_s", 2.0))
        self.bits = sensor_bits(registry) if registry is not None else {}
        self.bad_since: dict[int, float] = {}
        self.reported: set = set()
        self.ekf_prev: Optional[int] = None

    def process(self, ev: TelemetryEvent, ctx: AnalysisContext):
        if ev.sysid != ctx.vehicle_sysid:
            return []
        f, out = ev.fields, []
        if ev.msg_name == "SYS_STATUS":
            present, enabled, health = (f.get("onboard_control_sensors_present"), f.get("onboard_control_sensors_enabled"),
                                        f.get("onboard_control_sensors_health"))
            if present is None or health is None:
                return []
            self.mark_data(ctx)
            unhealthy = []
            for bit, name in self.bits.items():
                if present & bit and (enabled or 0) & bit and not health & bit:
                    unhealthy.append(name)
                    since = self.bad_since.setdefault(bit, ctx.mono)
                    if ctx.mono - since >= self.persist and bit not in self.reported and bit != 65536:
                        self.reported.add(bit)
                        out.append(self.result(ctx, "ANOMALOUS", f"Sensor unhealthy: {name}", ev=ev,
                                               domain="GPS_INTEGRITY" if "GPS" in name else "SENSOR",
                                               method="SYS_STATUS health bitmask + persistence",
                                               inputs={"sensor": name, "unhealthy_for_s": round(ctx.mono - since, 1)},
                                               why=f"{name} is present and enabled but reported unhealthy."))
                else:
                    if bit in self.bad_since and bit in self.reported:
                        out.append(self.result(ctx, "OBSERVED", f"Sensor recovered: {name}", kind="recovery", ev=ev,
                                               inputs={"sensor": name}, why=f"{name} reports healthy again."))
                    self.bad_since.pop(bit, None)
                    self.reported.discard(bit)
            self.metrics["unhealthy"] = unhealthy
        elif ev.msg_name == "EKF_STATUS_REPORT":
            flags = f.get("flags")
            if flags is None:
                return []
            self.mark_data(ctx)
            self.metrics["ekf_flags"] = [n for b, n in self.EKF_FLAGS.items() if flags & b]
            if self.ekf_prev is not None:
                lost = [n for b, n in self.EKF_FLAGS.items() if b <= 64 and self.ekf_prev & b and not flags & b]
                if flags & 32768 and not self.ekf_prev & 32768:
                    lost.append("GPS_GLITCHING set")
                if lost and ctx.airborne:
                    out.append(self.result(ctx, "ANOMALOUS", "EKF solution degraded", ev=ev, domain="GPS_INTEGRITY",
                                           method="EKF status flags", inputs={"lost_flags": lost, "flags": flags},
                                           why=f"EKF flags changed in flight: {', '.join(lost)}."))
            self.ekf_prev = flags
        return out
