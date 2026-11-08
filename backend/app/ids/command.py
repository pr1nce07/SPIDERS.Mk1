"""Command anomaly detector (spec §22). Observational only."""
from __future__ import annotations

from collections import defaultdict, deque
from typing import Optional

from ..models.events import TelemetryEvent
from .base import AnalysisContext, Detector
from .stats import EWMA, clamp01

# MAV_CMD numeric IDs (common.xml)
ARM_DISARM = 400
FLIGHT_TERMINATION = 185
REBOOT = 246
DO_SET_MODE = 176
DO_SET_HOME = 179
PREFLIGHT_CAL = 241
MOTOR_TEST = 209
DO_SET_PARAMETER = 180
MISSION_START = 300
NAV_TAKEOFF = 22
SENSITIVE = {ARM_DISARM, FLIGHT_TERMINATION, REBOOT, DO_SET_MODE, DO_SET_HOME, PREFLIGHT_CAL, MOTOR_TEST,
             DO_SET_PARAMETER, MISSION_START}
REQUEST_LIKE = {512, 511, 520, 519, 2504, 2505}  # REQUEST_MESSAGE, SET_MESSAGE_INTERVAL, REQUEST_AUTOPILOT_CAPABILITIES, ...

MAV_RESULT = {0: "ACCEPTED", 1: "TEMPORARILY_REJECTED", 2: "DENIED", 3: "UNSUPPORTED", 4: "FAILED",
              5: "IN_PROGRESS", 6: "CANCELLED"}


class CommandDetector(Detector):
    detector_id = "COMMAND"
    name = "Command Anomaly"
    domain = "MAVLINK_SECURITY"
    data_sources = ("COMMAND_LONG", "COMMAND_INT", "COMMAND_ACK", "SET_MODE")
    methods = ("source trust", "flight-state context", "sensitive-command classification", "burst count",
               "repeat/replay matching", "per-command inter-arrival EWMA", "command/ACK pairing")
    description = "Unexpected sources, bursts, repeats, context-inconsistent commands and ACK mismatches."
    limitations = ("Commands sent on links the GCS cannot see are not observed; an ACK without a visible command is therefore only an observation.",)

    def __init__(self, cfg):
        super().__init__(cfg)
        self.burst_n = int(self.cfg.get("burst_count", 6))
        self.burst_w = float(self.cfg.get("burst_window_s", 5))
        self.repeat_n = int(self.cfg.get("repeat_count", 3))
        self.ack_timeout = float(self.cfg.get("ack_timeout_s", 3))
        self.times: dict[int, deque] = defaultdict(deque)
        self.repeats: dict[tuple, deque] = defaultdict(deque)
        self.pending: dict[int, dict] = {}
        self.inter: dict[int, EWMA] = defaultdict(lambda: EWMA(0.2))
        self.last_cmd_t: dict[int, float] = {}
        self.cool: dict = {}
        self.log: deque = deque(maxlen=500)

    def _cool(self, key, ctx, s=5.0):
        if ctx.mono - self.cool.get(key, -1e9) < s:
            return False
        self.cool[key] = ctx.mono
        return True

    def process(self, ev: TelemetryEvent, ctx: AnalysisContext):
        self.mark_data(ctx)
        f = ev.fields
        if ev.msg_name == "COMMAND_ACK":
            return self._ack(ev, ctx)
        if ev.msg_name == "SET_MODE":
            cmd, params = DO_SET_MODE, [f.get("base_mode"), f.get("custom_mode")]
        else:
            cmd = f.get("command")
            params = [f.get(k) for k in ("param1", "param2", "param3", "param4", "param5", "param6", "param7", "x", "y", "z") if k in f]
        if cmd is None:
            return []
        # the vehicle does not command itself; ignore traffic from the vehicle to peripherals
        if ev.sysid == ctx.vehicle_sysid and ev.compid == 1:
            return []
        name = ctx.registry.command_name(cmd) if ev.msg_name != "SET_MODE" else "SET_MODE"
        trusted = ctx.is_trusted_gcs(ev.sysid)
        airborne = bool(ctx.airborne)
        armed = bool(ctx.armed)
        self.log.append({"t": ctx.t, "cmd": cmd, "name": name, "sysid": ev.sysid, "compid": ev.compid, "idx": ev.idx})
        self.pending[cmd] = {"t": ctx.mono, "idx": ev.idx, "sysid": ev.sysid, "name": name}
        if cmd in REQUEST_LIKE:
            return []

        evid: list[dict] = []
        reasons: list[str] = []
        if not trusted:
            evid.append({"label": "unexpected source", "value": 0.35})
            reasons.append(f"sender SYSID {ev.sysid} is not a trusted GCS")
        ctx_bad = self._contextual(cmd, params, armed, airborne)
        if ctx_bad:
            evid.append({"label": "context-inconsistent command", "value": 0.30})
            reasons.append(ctx_bad)
        q = self.times[ev.sysid or -1]
        q.append(ctx.mono)
        while q and ctx.mono - q[0] > self.burst_w:
            q.popleft()
        if len(q) >= self.burst_n:
            evid.append({"label": "command burst", "value": 0.20})
            reasons.append(f"{len(q)} commands in {self.burst_w:.0f} s from SYSID {ev.sysid}")
        rk = (ev.sysid, cmd, tuple(round(p, 4) if isinstance(p, float) else p for p in params))
        rq = self.repeats[rk]
        rq.append(ctx.mono)
        while rq and ctx.mono - rq[0] > 30:
            rq.popleft()
        if len(rq) >= self.repeat_n:
            evid.append({"label": "repeated identical command (replay-like)", "value": 0.15})
            reasons.append(f"identical {name} repeated {len(rq)}× in 30 s")
        last = self.last_cmd_t.get(cmd)
        if last is not None:
            self.inter[cmd].update(ctx.mono - last)
        self.last_cmd_t[cmd] = ctx.mono

        inputs = {"command": name, "command_id": cmd, "sysid": ev.sysid, "compid": ev.compid,
                  "target_system": f.get("target_system"), "params": params[:7], "armed": ctx.armed,
                  "airborne": ctx.airborne, "mode": ctx.mode, "trusted_source": trusted}
        if not evid:
            return [self.result(ctx, "OBSERVED", f"Command {name}", kind="observation", ev=ev, inputs=inputs,
                                method="source trust + context", why="Command observed from a trusted source in a consistent context.")]
        conf = clamp01(sum(e["value"] for e in evid) + (0.1 if cmd in SENSITIVE and armed else 0))
        state = "SUSPECTED" if (len(evid) >= 2 or (ctx_bad and not trusted)) else "ANOMALOUS"
        sev = "CRITICAL" if cmd == FLIGHT_TERMINATION and airborne else None
        title = {"unexpected source": "Command from unexpected source",
                 "context-inconsistent command": "Context-inconsistent command",
                 "command burst": "Command burst",
                 "repeated identical command (replay-like)": "Repeated command (replay-like)"}[evid[0]["label"]]
        if not self._cool((title, ev.sysid, cmd), ctx, 3):
            return []
        return [self.result(ctx, state, f"{title}: {name}", ev=ev, severity=sev, confidence=conf,
                            method="weighted evidence (source/context/burst/repeat)",
                            parameters={"burst_count": self.burst_n, "burst_window_s": self.burst_w, "repeat_count": self.repeat_n},
                            inputs=inputs, why="; ".join(reasons), contributors=evid,
                            evidence=[f"{e['label']} (+{round(e['value'] * 100)})" for e in evid])]

    @staticmethod
    def _contextual(cmd, params, armed, airborne) -> Optional[str]:
        p1 = params[0] if params else None
        if cmd == ARM_DISARM and airborne and p1 == 0:
            return "DISARM while airborne"
        if cmd == FLIGHT_TERMINATION and (p1 or 0) > 0.5:
            return "flight termination requested"
        if cmd == REBOOT and armed:
            return "reboot requested while armed"
        if cmd == PREFLIGHT_CAL and armed:
            return "calibration requested while armed"
        if cmd == MOTOR_TEST and armed:
            return "motor test while armed"
        if cmd == DO_SET_HOME and airborne:
            return "home position changed while airborne"
        return None

    def _ack(self, ev, ctx):
        f = ev.fields
        cmd = f.get("command")
        res = MAV_RESULT.get(f.get("result"), str(f.get("result")))
        pend = self.pending.pop(cmd, None)
        name = ctx.registry.command_name(cmd) if cmd is not None else "?"
        if pend is None and cmd not in REQUEST_LIKE and cmd in SENSITIVE and self._cool(("ack", cmd), ctx, 10):
            return [self.result(ctx, "OBSERVED", f"ACK without observed command: {name}", kind="alert", severity="LOW",
                                ev=ev, method="command/ACK pairing", inputs={"command": name, "result": res},
                                why="The vehicle acknowledged a sensitive command that this GCS did not observe being sent.",
                                limitations=list(self.limitations))]
        if pend is not None and res in ("DENIED", "FAILED") and cmd in SENSITIVE:
            return [self.result(ctx, "OBSERVED", f"Sensitive command rejected: {name}", kind="observation", ev=ev,
                                refs=[pend["idx"], ev.idx], inputs={"command": name, "result": res, "sender": pend["sysid"]},
                                method="command/ACK pairing", why=f"Vehicle answered {res}.")]
        return []

    def tick(self, ctx):
        out = []
        for cmd, p in list(self.pending.items()):
            if ctx.mono - p["t"] > self.ack_timeout:
                self.pending.pop(cmd, None)
                if cmd in SENSITIVE:
                    out.append(self.result(ctx, "OBSERVED", f"No ACK for {p['name']}", kind="observation",
                                           refs=[p["idx"]], method="command/ACK pairing",
                                           inputs={"command": p["name"], "sender": p["sysid"], "timeout_s": self.ack_timeout},
                                           why="No COMMAND_ACK was observed within the timeout."))
        self.metrics = {"commands_logged": len(self.log), "pending_acks": len(self.pending)}
        return out
