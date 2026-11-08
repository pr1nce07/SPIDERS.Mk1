"""Monte-Carlo calibration harness for the ground IDS. SIMULATION / DEMO DATA ONLY.

Wraps the stock FlightSimulator with randomised, physically plausible nuisance
factors (GPS latency/multipath/altitude wander, satellite/HDOP variation, EKF
variance spikes, IMU vibration and inter-IMU bias, RSSI fading, radio errors,
current spikes, benign packet loss, arrival jitter, a busy trusted operator)
and randomised attack magnitudes, then runs every flight through the real
Pipeline and classifies each alert/incident as TP, collateral or FP.

  PYTHONPATH=. python -m calibration.sweep --benign 300 --attack 40 --out ../data/simulations/phase1.json
  PYTHONPATH=. python -m calibration.sweep ... --set ids.detectors.COMMAND.burst_count=10
"""
from __future__ import annotations

import argparse
import copy
import json
import math
import random
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import yaml
from pymavlink.dialects.v20 import ardupilotmega as mav

from app.config import Config, _deep_merge
from app.core.errors import ErrorRegistry
from app.core.pipeline import Pipeline
from app.ids.builtin_rules import BUILTIN_RULES
from app.ids.correlation import IncidentIdAllocator
from app.ids.rules import compile_rule
from app.mavlink.registry import DialectRegistry
from app.models.events import state_rank
from app.sources.files import SourceItem
from app.sources.simulation import M_PER_DEG, FlightSimulator, Frame, _Enc

# detector(s) an attack scenario must raise, and detectors that legitimately react to it
EXPECTED = {
    "GPS_DRIFT": {"GPS_INTEGRITY"}, "GPS_JUMP": {"GPS_INTEGRITY"}, "GPS_IMU_MISMATCH": {"GPS_INTEGRITY"},
    "MAVLINK_SEQUENCE_GAP": {"MAVLINK_SEQUENCE"}, "HEARTBEAT_LOSS": {"HEARTBEAT"}, "COMMAND_BURST": {"COMMAND"},
    "PARAMETER_CHANGE": {"PARAMETER"}, "MISSION_CHANGE": {"MISSION"}, "RC_DEGRADATION": {"RC_LINK"},
    "MULTI_SIGNAL_INCIDENT": {"COMMAND", "PARAMETER", "GPS_INTEGRITY"}, "PUSHPAK_CONFIRMATION": {"PUSHPAK_FC", "GPS_INTEGRITY"},
    "UNKNOWN_SOURCE": set(), "LUA_BINDING_MISMATCH": set(),
}
_ROGUE = {"SOURCE_IDENTITY", "MAVLINK_RATE", "COMMAND", "FLIGHT_MODE", "ML_BASELINE"}
_GPS = {"IMU_CONSISTENCY", "ML_BASELINE", "RULE:GPS-CONSISTENCY-001", "RULE:MAVSEC-CORR-001"}
COLLATERAL = {
    "GPS_DRIFT": _GPS, "GPS_JUMP": _GPS, "GPS_IMU_MISMATCH": _GPS, "PUSHPAK_CONFIRMATION": _GPS,
    "MAVLINK_SEQUENCE_GAP": {"MAVLINK_RATE", "ML_BASELINE", "RULE:HEARTBEAT-RATE-001"},
    "HEARTBEAT_LOSS": {"MAVLINK_SEQUENCE", "MAVLINK_RATE", "RC_LINK", "OFFBOARD", "SENSOR_HEALTH", "ML_BASELINE",
                       "GPS_INTEGRITY", "IMU_CONSISTENCY", "RULE:HEARTBEAT-RATE-001"},
    "UNKNOWN_SOURCE": _ROGUE, "COMMAND_BURST": _ROGUE | {"RULE:CMD-BURST-001", "RULE:MAVSEC-CORR-001"},
    "PARAMETER_CHANGE": _ROGUE | {"RULE:MAVSEC-CORR-001"}, "MISSION_CHANGE": _ROGUE | {"RULE:MAVSEC-CORR-001"},
    "MULTI_SIGNAL_INCIDENT": _ROGUE | _GPS | {"RULE:CMD-BURST-001"},
    "RC_DEGRADATION": {"SENSOR_HEALTH", "ML_BASELINE"}, "LUA_BINDING_MISMATCH": set(),
}
ATTACKS = [s for s in EXPECTED if s != "NORMAL_FLIGHT"]
JUSTIFIED_LOSS = 0.08   # true windowed loss at which a loss alert is a correct report

REG = DialectRegistry()


# ======================================================================= environment
def sample_env(rng: random.Random, harsh: float = 1.0, extended: bool = False) -> dict:
    """One plausible operating environment. `harsh` scales the nuisance ranges."""
    u = lambda a, b: rng.uniform(a, a + (b - a) * harsh)  # noqa: E731
    chance = lambda p: rng.random() < p * harsh  # noqa: E731
    env = {
        "home": (rng.uniform(-60, 65), rng.uniform(-180, 180), rng.uniform(0, 2500)),
        "noise_scale": u(0.5, 4.0),            # GPS/attitude noise multiplier
        "gps_lag_s": u(0.0, 0.35),             # receiver latency vs EKF
        "multipath_p": u(0.0, 0.012),          # per GPS sample
        "multipath_m": u(3.0, 25.0),
        "gps_alt_walk": u(0.02, 0.18),         # m per sample random walk, bounded to +/-10 m
        "sats": rng.randint(7, 22), "sat_dip_p": u(0.0, 0.01),
        "hdop": u(0.6, 2.2),
        "ekf_base": u(0.05, 0.45), "ekf_spike_p": u(0.0, 0.03), "ekf_spike_max": u(0.5, 1.1),
        "imu_vib_mg": u(10, 120), "imu_bias_mg": u(0, 80), "gyro_bias": u(0, 15), "gyro_noise": u(8, 40),
        "rssi_base": rng.randint(110, 254), "rssi_fade": u(0, 15),
        "rxerr_p": u(0.0, 0.15), "radio_noise_jit": u(0, 8),
        "batt_v_noise": u(0.0, 0.15), "current_spike_p": u(0.0, 0.08),
        "link_loss": u(0.0, 0.06), "burst_per_min": u(0.0, 1.5),   # 0.2–1.5 s outages (range edge / antenna masking)
        "ts_jitter": u(0.0, 0.03),
        "busy_operator": rng.random() < 0.5,   # QGC-style connect burst + in-flight mode/speed commands
        "operator_param_edits": rng.random() < 0.25,   # trusted GCS tunes a sensitive param in flight (policy)
        "operator_mission_edit": rng.random() < 0.15,  # trusted GCS re-uploads mission in flight (policy)
        "gust_mps": 0.0, "gps_fix_drop_p": 0.0, "gps2_offset_m": 0.0, "gps2_noise_m": 0.0,
        "rtk_transitions": False, "aggressive_maneuvers": False, "aggressive_accel_ms2": 0.0,
        "aggressive_attitude_rate_rads": 0.0, "hover_loiter": False,
        "repeated_flight_cycles": 0, "rate_change_scale": 0.0, "companion_link": False,
        "gcs_reconnect": False, "radio_reboot": False, "low_battery_sag_v": 0.0,
        "pack_swap": False, "pack_voltage_offset_v": 0.0, "rtl_commands": False,
    }
    if extended:
        aggressive = chance(0.35)
        rate_change = rng.choice((0.5, 2.0)) if chance(2 / 3) else 0.0
        env.update({
            "gust_mps": u(0.3, 8.0), "gps_fix_drop_p": u(0.005, 0.03),
            "gps2_offset_m": u(0.5, 3.0), "gps2_noise_m": u(0.2, 1.5),
            "rtk_transitions": chance(0.35), "aggressive_maneuvers": aggressive,
            "aggressive_accel_ms2": u(2.0, 4.0) if aggressive else 0.0,
            "aggressive_attitude_rate_rads": u(1.0, 2.0) if aggressive else 0.0,
            "hover_loiter": chance(0.35),
            "repeated_flight_cycles": rng.randint(2, 4) if chance(0.2) else 0,
            "rate_change_scale": rate_change,
            "companion_link": chance(0.25), "gcs_reconnect": chance(0.2),
            "radio_reboot": chance(0.2), "low_battery_sag_v": u(0.3, 1.5),
            "pack_swap": chance(0.15), "pack_voltage_offset_v": u(-1.0, 1.0),
            "rtl_commands": chance(0.25),
        })
    return env


def sample_attack(rng: random.Random, boundary: bool = False) -> dict:
    """Sample the existing nominal attack strength or the weaker ROC boundary profile."""
    attack = {"drift_rate": rng.uniform(0.2, 2.0), "jump_m": rng.uniform(20, 300), "mismatch_vel": rng.uniform(9, 25)}
    if boundary:
        attack.update({"drift_rate": rng.uniform(0.05, 2.0), "jump_m": rng.uniform(5, 300),
                       "mismatch_vel": rng.uniform(3, 25), "command_burst_count": rng.randint(2, 15),
                       "param_interval_s": rng.choice((1.0, 5.0, 15.0, 60.0)), "unknown_hz": rng.uniform(0.01, 1.0)})
    return attack


class _HookEnc(_Enc):
    def __init__(self, sim, who, sysid, compid):
        super().__init__(sysid, compid)
        self.sim, self.who = sim, who

    def pack(self, msg) -> bytes:
        self.sim._mutate(self.who, msg)
        return super().pack(msg)


class PerturbedSimulator(FlightSimulator):
    def __init__(self, scenario, env: dict, attack: dict | None = None, pseed: int = 0, **kw):
        super().__init__(scenario, home=env["home"], **kw)
        self.env, self.atk = env, attack or {}
        if scenario in ("COMMAND_BURST", "MULTI_SIGNAL_INCIDENT") and "command_burst_count" in self.atk:
            self.mag = max(self.mag, self.atk["command_burst_count"] / 12)
        self.p = random.Random(pseed)
        base_rng = self.rng
        scale = env["noise_scale"]

        class _ScaledRng(random.Random):   # scales every gaussian draw of the stock simulator
            def gauss(self_, mu=0.0, sigma=1.0):
                return base_rng.gauss(mu, sigma * scale)

            def random(self_):
                return base_rng.random()

            def randint(self_, a, b):
                return base_rng.randint(a, b)
        self.rng = _ScaledRng()
        self.veh = _HookEnc(self, "veh", 1, 1)
        self.gcs = _HookEnc(self, "gcs", 255, 190)
        self.radio = _HookEnc(self, "radio", 51, 68)
        self.imu_bias = [[self.p.gauss(0, env["imu_bias_mg"] / 2) for _ in range(3)] for _ in range(2)]
        self.gyro_bias = [[self.p.gauss(0, env["gyro_bias"] / 2) for _ in range(3)] for _ in range(2)]
        self.alt_bias = 0.0
        self.rssi_fade = 0.0
        self.ekf_spike_until = -1.0
        self.ekf_spike_val = 0.0
        self.sat_dip_until = -1.0
        self.current_spike_until = -1.0
        self.burst_until = -1.0
        self._burst_checked = -1.0
        self.veh_log: list[tuple[float, bool]] = []   # ground truth for loss-alert classification
        d = self.duration
        self.gps_drop_until = -1.0
        self.gps_drop_fix = 3
        self.companion = _Enc(1, 191)
        self._last_companion_tick = -1
        self.source_log: dict[tuple[int, int], list[tuple[float, bool]]] = defaultdict(list)
        self._rate_schedule = False
        if env.get("pack_swap"):
            self.batt_v = max(13.0, min(17.2, self.batt_v + env.get("pack_voltage_offset_v", 0.0)))
        cycles = int(env.get("repeated_flight_cycles", 0))
        self.cycle_starts = ([20 + i * max(1.0, (d - 50) / max(1, cycles - 1)) for i in range(cycles)] if cycles else [])
        self.rate_change_at, self.mode_change_at, self.rtl_at = d * 0.35, d * 0.3, d * 0.72
        self.op_connect_t = self.p.uniform(15, max(16, d - 20))
        self.op_cmd_ts = sorted(self.p.uniform(15, d - 30) for _ in range(self.p.randint(2, 6)))
        self.op_param_t = self.p.uniform(20, d - 30)
        self.op_mission_t = self.p.uniform(20, d - 40)

    # ---------------------------------------------------------------- attack magnitude
    def _physics(self):
        super()._physics()
        e = self.env
        if e.get("gust_mps", 0) > 0:
            gust, phase = e["gust_mps"], self.t * 0.7
            self.vn += gust * 0.02 * math.sin(phase)
            self.ve += gust * 0.02 * math.cos(phase * 0.73)
            self.ekf_var = max(self.ekf_var, 0.08 + gust * 0.025 * abs(math.sin(phase)))
        if e.get("aggressive_maneuvers") and 12 <= self.t < self.duration - 10:
            self.ve += e.get("aggressive_accel_ms2", 3.0) * self.DT * math.sin(self.t * 1.9)
        if e.get("hover_loiter") and self.duration * 0.3 <= self.t < self.duration * 0.42:
            self.vn *= 0.2
            self.ve *= 0.2
            self.vd = 0.0
        for start in self.cycle_starts:
            phase = self.t - start
            if 0 <= phase < 16:
                if phase < 4:
                    self.armed, self.mode, self.vd, self.alt = True, 4, -3.5, min(14.0, phase * 3.5)
                elif phase < 9:
                    self.armed, self.mode, self.vd, self.alt = True, 5, 0.0, 14.0
                elif phase < 13:
                    self.armed, self.mode, self.vd, self.alt = True, 9, 3.5, max(0.0, 14.0 - (phase - 9) * 3.5)
                else:
                    self.armed, self.mode, self.vd, self.alt = False, 6, 0.0, 0.0
                break
        sag = e.get("low_battery_sag_v", 0.0)
        if sag and self.t >= self.duration * 0.8:
            progress = (self.t - self.duration * 0.8) / max(self.duration * 0.2, 1e-6)
            self.batt_v = max(10.0, self.batt_v - sag * progress * self.DT)
            self.batt_rem = max(0.0, self.batt_rem - sag * progress * 0.03 * self.DT)
        s, t, a = self.scenario, self.t, self.atk
        if not a:
            return
        if s in ("GPS_DRIFT", "PUSHPAK_CONFIRMATION") and t >= self.inj:
            self.gps_off_e = min(a["drift_rate"] * (t - self.inj), 75 * a["drift_rate"])
        elif s == "GPS_JUMP" and self.gps_off_n == 180.0 * self.mag:
            self.gps_off_n = a["jump_m"]
        if self.gps_vel_override is not None:
            self.gps_vel_override = a["mismatch_vel"]

    def _every(self, k, period):
        rate = self.env.get("rate_change_scale", 0.0)
        if self._rate_schedule and rate and self.t >= self.rate_change_at:
            period /= rate  # 2 doubles stream frequency; 0.5 halves it
        return super()._every(k, period)

    def _schedule(self, k, out):
        self._rate_schedule = True
        try:
            super()._schedule(k, out)
            if self.env.get("gps2_offset_m", 0.0) > 0 and self._every(k, 0.2):
                offset = self.env["gps2_offset_m"]
                north = self.n + offset + self.p.gauss(0, self.env.get("gps2_noise_m", 0.0))
                east = self.e + self.p.gauss(0, self.env.get("gps2_noise_m", 0.0))
                lat, lon = self.latlon(north, east)
                msg = mav.MAVLink_gps2_raw_message(int((self.t0 + self.t) * 1e6), 3,
                    int(lat * 1e7), int(lon * 1e7), int((self.alt0 + self.alt) * 1000), 80, 120,
                    int(max(0, math.hypot(self.vn, self.ve)) * 100), int(math.degrees(self.yaw) % 36000), 14, 0, 0)
                out.append(("veh", self.veh.pack(msg)))
        finally:
            self._rate_schedule = False

    # ---------------------------------------------------------------- nuisance injection
    def _mutate(self, who, m):
        e, p, t = self.env, self.p, self.t
        name = m.get_type()
        if name == "GPS_RAW_INT":
            if t >= self.gps_drop_until and p.random() < e.get("gps_fix_drop_p", 0.0):
                self.gps_drop_until = t + p.uniform(1.0, 5.0)
                self.gps_drop_fix = p.choice((2, 1, 0))
            if t < self.gps_drop_until:
                m.fix_type = self.gps_drop_fix
            elif e.get("rtk_transitions"):
                m.fix_type = (3, 6, 7)[int(t // 25) % 3]
            lag = e["gps_lag_s"]
            dn, de = -self.vn * lag, -self.ve * lag
            if p.random() < e["multipath_p"]:
                ang = p.uniform(0, 2 * math.pi)
                dn += e["multipath_m"] * math.cos(ang)
                de += e["multipath_m"] * math.sin(ang)
            m.lat += int(dn / M_PER_DEG * 1e7)
            m.lon += int(de / (M_PER_DEG * math.cos(math.radians(self.lat0))) * 1e7)
            self.alt_bias = max(-10.0, min(10.0, self.alt_bias + p.gauss(0, e["gps_alt_walk"])))
            m.alt += int(self.alt_bias * 1000)
            if p.random() < e["sat_dip_p"]:
                self.sat_dip_until = t + p.uniform(1, 6)
            sats = e["sats"] + p.choice((-1, 0, 0, 1))
            hdop = e["hdop"] * p.uniform(0.9, 1.1)
            if t < self.sat_dip_until:
                sats, hdop = max(5, sats - p.randint(3, 8)), hdop * p.uniform(1.3, 2.0)
            if m.fix_type >= 3:
                m.satellites_visible = max(0, min(30, sats))
                m.eph = int(hdop * 100)
            elif m.fix_type < 3:
                m.satellites_visible = max(0, min(30, sats - p.randint(2, 6)))
            m.vel = max(0, int(m.vel + p.gauss(0, 10 * e["noise_scale"])))
            if e.get("gust_mps", 0) > 0:
                m.vel = max(0, int(m.vel + math.sin(t * 0.7) * e["gust_mps"] * 100))
        elif name == "EKF_STATUS_REPORT":
            if t >= self.ekf_spike_until and p.random() < e["ekf_spike_p"]:
                self.ekf_spike_until = t + p.uniform(0.5, 3.0)
                self.ekf_spike_val = p.uniform(0.3, e["ekf_spike_max"])
            extra = e["ekf_base"] * p.uniform(0.7, 1.3) - 0.08
            if t < self.ekf_spike_until:
                extra += self.ekf_spike_val
            if e.get("gust_mps", 0) > 0:
                extra += e["gust_mps"] * 0.025 * abs(math.sin(t * 0.7))
            m.velocity_variance = max(0.0, m.velocity_variance + extra)
            m.pos_horiz_variance = max(0.0, m.pos_horiz_variance + extra * p.uniform(0.6, 1.0))
        elif name in ("RAW_IMU", "SCALED_IMU2"):
            i = 0 if name == "RAW_IMU" else 1
            vib, gn = e["imu_vib_mg"], e["gyro_noise"]
            m.xacc = int(m.xacc + self.imu_bias[i][0] + p.gauss(0, vib))
            m.yacc = int(m.yacc + self.imu_bias[i][1] + p.gauss(0, vib))
            m.zacc = int(m.zacc + self.imu_bias[i][2] + p.gauss(0, vib * 1.3))
            m.xgyro = int(m.xgyro + self.gyro_bias[i][0] + p.gauss(0, gn))
            m.ygyro = int(m.ygyro + self.gyro_bias[i][1] + p.gauss(0, gn))
            m.zgyro = int(m.zgyro + self.gyro_bias[i][2] + p.gauss(0, gn))
        elif name == "ATTITUDE":
            for f in ("rollspeed", "pitchspeed", "yawspeed"):
                setattr(m, f, getattr(m, f) + p.gauss(0, e["gyro_noise"] / 1000))
            if e.get("gust_mps", 0) > 0:
                m.rollspeed += p.gauss(0, e["gust_mps"] * 0.08)
                m.pitchspeed += p.gauss(0, e["gust_mps"] * 0.08)
            if e.get("aggressive_maneuvers"):
                m.roll = max(-0.65, min(0.65, m.roll + 0.35 * math.sin(t * 1.7)))
                m.pitch = max(-0.45, min(0.45, m.pitch + 0.25 * math.cos(t * 1.3)))
                rate = e.get("aggressive_attitude_rate_rads", 1.5)
                m.rollspeed += rate * math.sin(t * 1.7)
                m.pitchspeed += rate * 0.7 * math.cos(t * 1.3)
                m.yawspeed += rate * 0.5 * math.sin(t * 1.1)
        elif name == "RC_CHANNELS":
            self.rssi_fade = 0.9 * self.rssi_fade + p.gauss(0, e["rssi_fade"])
            if not self._sc("RC_DEGRADATION") or t < self.inj:
                m.rssi = int(max(0, min(254, e["rssi_base"] + self.rssi_fade)))
            else:
                m.rssi = int(max(0, min(254, m.rssi * e["rssi_base"] / 220 + self.rssi_fade)))
        elif name == "RADIO_STATUS":
            if p.random() < e["rxerr_p"]:
                self.rxerrors += p.randint(1, 6)
                m.rxerrors = min(65535, self.rxerrors)
            m.noise = int(max(0, min(250, m.noise + p.gauss(0, e["radio_noise_jit"]))))
            scale = e["rssi_base"] / 220
            m.rssi = int(max(0, min(254, m.rssi * scale)))
            m.remrssi = int(max(0, min(254, m.remrssi * scale)))
        elif name in ("SYS_STATUS", "BATTERY_STATUS"):
            if self.alt > 0.5 and t >= self.current_spike_until and p.random() < e["current_spike_p"]:
                self.current_spike_until = t + p.uniform(1, 5)
                self.current_spike_a = p.uniform(8, 22)
            spike = self.current_spike_a if t < self.current_spike_until else 0.0
            sag = 0.012 * spike + p.gauss(0, e["batt_v_noise"])
            if e.get("low_battery_sag_v", 0.0) and t >= self.duration * 0.8:
                sag += e["low_battery_sag_v"] * min(1.0, (t - self.duration * 0.8) / max(self.duration * 0.2, 1e-6))
            if name == "SYS_STATUS":
                m.current_battery = int(m.current_battery + spike * 100)
                m.voltage_battery = int(m.voltage_battery - sag * 1000)
            else:
                m.current_battery = int(m.current_battery + spike * 100)
                m.voltages = [int(v - sag * 250) if v != 65535 else v for v in m.voltages]

    current_spike_a = 0.0

    def _inject(self, k, out):
        super()._inject(k, out)
        e, t, G, dt = self.env, self.t, self.gcs, self.DT
        at = lambda x: abs(t - x) < dt / 2  # noqa: E731
        if e.get("rate_change_scale") and at(self.rate_change_at):
            rate = 4 if e["rate_change_scale"] > 1 else 2
            out.append(("gcs", G.pack(mav.MAVLink_request_data_stream_message(1, 1, 0, rate, 1))))
            out.append(("gcs", G.pack(mav.MAVLink_param_set_message(1, 1, b"SR1_EXTRA1", float(rate), 9))))
            self.params["SR1_EXTRA1"] = float(rate)
        if e.get("hover_loiter") and at(self.mode_change_at):
            out.extend(self._cmd(G, 176, [1, 5, 0, 0, 0, 0, 0], ack=0))
            self.mode_override = 5
        if e.get("hover_loiter") and at(self.mode_change_at + self.duration * 0.12):
            out.extend(self._cmd(G, 176, [1, 3, 0, 0, 0, 0, 0], ack=0))
            self.mode_override = 3
        if e.get("rtl_commands") and at(self.rtl_at):
            out.extend(self._cmd(G, 20, [0, 0, 0, 0, 0, 0, 0], ack=0))
            self.mode_override = 6
        for start in self.cycle_starts:
            for offset, mode in ((0, 4), (4, 5), (9, 9), (13, 6)):
                if at(start + offset):
                    out.extend(self._cmd(G, 176, [1, mode, 0, 0, 0, 0, 0], ack=0))
                    self.mode_override = mode
        if self.atk.get("param_interval_s") and self.scenario in ("PARAMETER_CHANGE", "MULTI_SIGNAL_INCIDENT"):
            n_writes = max(3, min(6, round(3 + 3 * self.mag)))
            par_t = self.inj + (6 if self.scenario == "MULTI_SIGNAL_INCIDENT" else 2)
            writes = [("FENCE_ENABLE", 0.0), ("ARMING_CHECK", 0.0), ("FS_THR_ENABLE", 0.0),
                      ("RTL_ALT", 300.0), ("WPNAV_SPEED", 2000.0), ("ANGLE_MAX", 4500.0)]
            kept = []
            for who, data in out:
                msgid = data[7] | data[8] << 8 | data[9] << 16 if data[0] == 0xFD else data[5]
                if msgid in (22, 23) and who in ("rogue", "veh"):
                    continue
                kept.append((who, data))
            out[:] = kept
            for i, (name, val) in enumerate(writes[:n_writes]):
                if at(par_t + i * self.atk["param_interval_s"]):
                    out.append(("rogue", self.rogue.pack(mav.MAVLink_param_set_message(1, 1, name.encode(), val, 9))))
                    out.append(("veh", self.veh.pack(mav.MAVLink_param_value_message(name.encode(), val, 9, len(self.params),
                                                                                         list(self.params).index(name)))))
                    self.params[name] = val
        if e["busy_operator"]:
            # QGC-style connect: REQUEST_MESSAGE / SET_MESSAGE_INTERVAL burst over ~1.5 s from the trusted GCS
            for j in range(10):
                if at(self.op_connect_t + j * 0.15):
                    out += self._cmd(G, 512 if j % 2 else 511, [float(30 + j), 200000, 0, 0, 0, 0, 0], ack=0)
            if at(self.op_connect_t):
                out.append(("gcs", G.pack(mav.MAVLink_param_request_list_message(1, 1))))
            for ts in self.op_cmd_ts:
                if at(ts):
                    if self.p.random() < 0.5:
                        out += self._cmd(G, 178, [1, self.p.uniform(4, 12), -1, 0, 0, 0, 0], ack=0)   # DO_CHANGE_SPEED
                    else:
                        out += self._cmd(G, 176, [1, 3, 0, 0, 0, 0, 0], ack=0)                        # set AUTO
        if e["operator_param_edits"] and at(self.op_param_t):
            name, val = self.p.choice([("WPNAV_SPEED", 1000.0), ("RTL_ALT", 2500.0), ("ANGLE_MAX", 3500.0)])
            out.append(("gcs", G.pack(mav.MAVLink_param_set_message(1, 1, name.encode(), val, 9))))
            self.params[name] = val
            out.append(("veh", self.veh.pack(mav.MAVLink_param_value_message(name.encode(), val, 9, len(self.params),
                                                                              list(self.params).index(name)))))
        if e["operator_mission_edit"] and at(self.op_mission_t):
            items = self._mission_items()
            items[-1] = (items[-1][0], 16, items[-1][2] + 200, items[-1][3], 25.0)
            self._upload_mission(out, G, items)

    # ---------------------------------------------------------------- link effects
    def frames(self):
        e, p = self.env, self.p
        for fr in super().frames():
            data = fr.data
            if data[0] == 0xFD:
                msgid = data[7] | data[8] << 8 | data[9] << 16
                sysid, compid = data[5], data[6]
            else:
                msgid, sysid, compid = data[5], data[3], data[4]
            if (self.scenario == "UNKNOWN_SOURCE" and "unknown_hz" in self.atk
                    and sysid == 42 and msgid == mav.MAVLink_heartbeat_message.id):
                period = 1.0 / max(self.atk["unknown_hz"], 0.01)
                if self.t % period >= self.DT:
                    continue
            if (self.scenario == "UNKNOWN_SOURCE" and "unknown_hz" in self.atk
                    and sysid == 42 and msgid == mav.MAVLink_heartbeat_message.id):
                period = 1.0 / max(self.atk["unknown_hz"], 0.01)
                if self.t % period >= self.DT:
                    continue
            if (self.scenario in ("COMMAND_BURST", "MULTI_SIGNAL_INCIDENT")
                    and "command_burst_count" in self.atk and sysid == 42
                    and msgid == mav.MAVLink_command_long_message.id):
                burst_t = self.inj + (3 if self.scenario == "MULTI_SIGNAL_INCIDENT" else 2)
                if self.t >= burst_t and round((self.t - burst_t) / 0.25) >= self.atk["command_burst_count"]:
                    continue
            dropped = False
            if sysid == 255 and e.get("gcs_reconnect"):
                center = self.duration * 0.55
                if center <= self.t < center + 3.0:
                    dropped = True
            if sysid == 51 and e.get("radio_reboot"):
                center = self.duration * 0.7
                if center <= self.t < center + 4.0:
                    dropped = True
            if sysid == 1 and compid == 1:
                if self.t >= self.burst_until and self.t >= self._burst_checked + 1.0:
                    self._burst_checked = self.t
                    if p.random() < e["burst_per_min"] / 60:
                        self.burst_until = self.t + p.uniform(0.2, 1.5)
                dropped = dropped or self.t < self.burst_until or p.random() < e["link_loss"]
            self.source_log[(sysid, compid)].append((round(self.t, 3), dropped))
            if sysid == 1 and compid == 1:
                self.veh_log.append((round(self.t, 3), dropped))
            if dropped:
                continue
            shifted = Frame(fr.t + abs(p.gauss(0, e["ts_jitter"])), data, fr.link)
            yield shifted
            if e.get("companion_link") and int(self.t // 5) != self._last_companion_tick:
                self._last_companion_tick = int(self.t // 5)
                msg = mav.MAVLink_heartbeat_message(6, 8, 0, 0, 0, 3)
                yield Frame(shifted.t, self.companion.pack(msg), "sim_companion")


# ======================================================================= run + classify
def build_config(overrides: dict | None) -> Config:
    base = Config.load()
    return Config(_deep_merge(base.data, overrides or {}), base.path)


# ----------------------------------------------------------------------- candidate code patches
# Evaluated only when a job lists them; they model proposed code changes that config cannot express.
def _patch_rc_radio(on: bool):
    from app.ids import rc
    from app.ids.stats import clamp01  # noqa: F401
    if not hasattr(rc.RCLinkDetector, "_orig_radio"):
        rc.RCLinkDetector._orig_radio = rc.RCLinkDetector._radio

    def _radio(self, ev, ctx, f):
        """Apply an opt-in configurable persistence patch to radio error/noise alerts."""
        prev, self.radio_prev = self.radio_prev, dict(f, mono=ctx.mono)
        if not prev:
            return []
        dt = max(ctx.mono - prev["mono"], 1e-3)
        err_rate = ((f.get("rxerrors") or 0) - (prev.get("rxerrors") or 0)) / dt
        noise = f.get("noise") or 0
        err_limit = float(self.cfg.get("radio_err_rate_per_s", 10.0))
        noise_rise = float(self.cfg.get("radio_noise_rise", 25.0))
        persist_s = float(self.cfg.get("radio_persistence_s", 3.0))
        base = getattr(self, "_noise_base", None)
        self._noise_base = noise if base is None else (0.95 * base + 0.05 * noise if noise - base < noise_rise else base)
        bad = err_rate > err_limit or (base is not None and noise - base > noise_rise)
        from app.ids.stats import Persistence
        self._p_radio = getattr(self, "_p_radio", None) or Persistence(persist_s)
        ok, _ = self._p_radio.update(bad, ctx.mono)
        if ok and self._cool("radio", ctx, 15):
            return [self.result(ctx, "ANOMALOUS", "Telemetry radio errors / noise rising", ev=ev, severity="LOW",
                                method="radio rx-error/noise trend", inputs={"rxerrors_per_s": round(err_rate, 1), "noise": noise},
                                why="Radio receive errors or noise floor persistently elevated.")]
        return []
    rc.RCLinkDetector._radio = _radio if on else rc.RCLinkDetector._orig_radio


def _patch_gps_cusum_clip(on: bool):
    from app.ids import gps
    if not hasattr(gps.GPSIntegrityDetector, "_orig_init"):
        gps.GPSIntegrityDetector._orig_init = gps.GPSIntegrityDetector.__init__

    def __init__(self, cfg):
        gps.GPSIntegrityDetector._orig_init(self, cfg)
        raw = self.cusum.update
        self.cusum.update = lambda z: raw(max(-4.0, min(4.0, z)))   # one multipath spike can no longer trip it
    gps.GPSIntegrityDetector.__init__ = __init__ if on else gps.GPSIntegrityDetector._orig_init


PATCHES = {"rc_radio": _patch_rc_radio, "gps_cusum_clip": _patch_gps_cusum_clip}


def _rules(patch: dict | None) -> list[dict]:
    """BUILTIN_RULES with node params overridden: {"CMD-BURST-001": {"thr": {"value": 8}}}."""
    rules = copy.deepcopy(BUILTIN_RULES)
    for r in rules:
        for nid, params in (patch or {}).get(r["rule_id"], {}).items():
            for n in r["graph"]["nodes"]:
                if n["id"] == nid:
                    n["params"].update(params)
    return rules


def run_one(job: dict) -> dict:
    for name, fn in PATCHES.items():
        fn(name in (job.get("patches") or ()))
    cfg = build_config(job.get("overrides"))
    sc, env, seed = job["scenario"], job["env"], job["seed"]
    err = ErrorRegistry()
    p = Pipeline(session_id="CAL", kind="calibration", source_desc=sc, config=cfg, registry=REG, errors=err,
                 capabilities={}, allocator=IncidentIdAllocator())
    p.set_rules([compile_rule(dict(r, version=1), REG, list(p.engine.detectors)) for r in _rules(job.get("rule_patch"))])
    policies = set(job.get("patches") or ())
    policy_audit = []
    if "trusted_cmd_rule" in policies:
        for runtime in p.rules:
            if runtime.rule_id != "CMD-BURST-001":
                continue
            original_evaluate = runtime.evaluate

            def ignore_trusted_commands(ev, ctx, vstate, original=original_evaluate):
                if ev is not None and ev.msg_name == "COMMAND_LONG" and ctx.is_trusted_gcs(ev.sysid):
                    ev = copy.copy(ev)
                    ev.sysid = ctx.vehicle_sysid
                return original(ev, ctx, vstate)

            runtime.evaluate = ignore_trusted_commands
    if "trusted_edits_observed" in policies:
        for detector_id in ("PARAMETER", "MISSION"):
            detector = p.engine.detectors.get(detector_id)
            if detector is None:
                continue
            original_process = detector.process

            def observe_trusted_edits(ev, ctx, original=original_process, name=detector_id):
                results = original(ev, ctx)
                if ev is not None and ctx.is_trusted_gcs(ev.sysid):
                    for result in results:
                        if result.state in ("ANOMALOUS", "SUSPECTED", "CONFIRMED"):
                            policy_audit.append({"detector": name, "title": result.title,
                                                 "sysid": ev.sysid, "t": result.t,
                                                 "original_state": result.state,
                                                 "original_severity": result.severity,
                                                 "inputs": result.inputs})
                            result.state = "OBSERVED"
                            result.severity = "INFO"
                            result.kind = "observation"
                return results

            detector.process = observe_trusted_edits
    sim = PerturbedSimulator(sc, env, job.get("attack"), pseed=seed * 7919 + 1, seed=seed,
                             duration_s=job["duration"], inject_at=job["inject"])
    t0 = None
    for fr in sim.frames():
        t0 = fr.t if t0 is None else t0
        p.handle_item(SourceItem("frame", fr.t, fr.data, fr.link, "SIMULATION"))
    base_t = sim.t0
    alerts = [{"t": round(a["t"] - base_t, 2), "detector": a["detector"] if not a.get("rule_id") else f"RULE:{a['rule_id']}",
               "state": a["state"], "severity": a["severity"], "title": a["title"], "sysid": a.get("sysid")}
              for a in p.alerts.values() if state_rank(a["state"]) >= 2]
    incs = [{"t": round(i["first_seen"] - base_t, 2), "state": i["state"], "domain": i["domain"], "severity": i["severity"],
             "detectors": i["detectors"], "reason": i["creation_reason"]} for i in p.correlator.incidents.values()]
    win = float(cfg.detector("MAVLINK_SEQUENCE").get("window_s", 10))
    for a in alerts:   # true vehicle-link loss ratio in the detector window ending at the alert
        if a["detector"] == "MAVLINK_SEQUENCE":
            sel = [d for t, d in sim.veh_log if a["t"] - win <= t <= a["t"]]
            a["true_loss"] = round(sum(sel) / len(sel), 3) if sel else None
    return {**{k: job[k] for k in ("scenario", "seed", "duration", "inject", "boundary_attacks")},
            "env": env, "attack": job.get("attack"),
            "alerts": alerts, "incidents": incs, "policy_audit": policy_audit,
            "errors": len(err.list())}


def classify(r: dict) -> dict:
    sc, inj = r["scenario"], r["inject"]
    exp, col = EXPECTED.get(sc, set()), COLLATERAL.get(sc, set())
    out = {"tp": set(), "fp": [], "collateral": [], "justified": [], "latency": {}}
    for a in r["alerts"]:
        d = a["detector"]
        attack_phase = sc != "NORMAL_FLIGHT" and a["t"] >= inj - 0.5
        if attack_phase and d in exp:
            out["tp"].add(d)
            out["latency"][d] = min(out["latency"].get(d, 1e9), a["t"] - inj)
        elif attack_phase and d in col:
            out["collateral"].append(a)
        elif a.get("true_loss") is not None and a["true_loss"] >= JUSTIFIED_LOSS:
            out["justified"].append(a)    # the link really was losing packets: correct report, not an FP
        else:
            out["fp"].append(a)
    out["missed"] = exp - out["tp"]
    out["fp_incidents"] = [i for i in r["incidents"] if sc in ("NORMAL_FLIGHT", "UNKNOWN_SOURCE", "LUA_BINDING_MISMATCH") or i["t"] < inj - 0.5]
    return out


def make_jobs(n_benign: int, n_attack: int, seed0: int, overrides: dict | None, harsh: float = 1.0,
              scenarios: list[str] | None = None, rule_patch: dict | None = None, patches: list | None = None,
              duration_range: tuple[int, int] = (120, 300), extended: bool = False,
              boundary_attacks: bool = False) -> list[dict]:
    jobs, rng = [], random.Random(seed0)
    if duration_range[0] <= 0 or duration_range[1] < duration_range[0]:
        raise ValueError("duration_range must be positive and ordered")
    plan = [("NORMAL_FLIGHT", n_benign)] + [(s, n_attack) for s in (scenarios or ATTACKS)]
    for sc, n in plan:
        for _ in range(n):
            dur = round(rng.uniform(*duration_range), 1)
            inj_lo, inj_hi = ((30.0, dur - 60.0) if duration_range == (120, 300)
                              else (min(30.0, dur * 0.1), max(min(30.0, dur * 0.1), dur - 60.0)))
            jobs.append({"scenario": sc, "seed": rng.randrange(1, 10 ** 9), "duration": dur,
                         "inject": round(rng.uniform(inj_lo, inj_hi), 1), "boundary_attacks": boundary_attacks,
                         "env": sample_env(rng, harsh, extended), "attack": sample_attack(rng, boundary_attacks),
                         "overrides": overrides, "rule_patch": rule_patch, "patches": patches})
    return jobs


def summarize(results: list[dict]) -> dict:
    by_sc = defaultdict(list)
    for r in results:
        by_sc[r["scenario"]].append(r)
    benign = by_sc.get("NORMAL_FLIGHT", [])
    hours = sum(r["duration"] for r in benign) / 3600 or 1e-9
    fp_det, fp_title, fp_inc = Counter(), Counter(), Counter()
    flights_with_fp = flights_with_inc = justified = 0
    for r in benign:
        c = classify(r)
        justified += len(c["justified"])
        flights_with_fp += bool(c["fp"])
        flights_with_inc += bool(c["fp_incidents"])
        for a in c["fp"]:
            fp_det[a["detector"]] += 1
            fp_title[f"{a['detector']} | {a['title']}"] += 1
        for i in c["fp_incidents"]:
            fp_inc[f"{i['domain']} {i['state']} [{','.join(i['detectors'])}]"] += 1
    attack = {}
    att_fp = Counter()
    for sc, rs in by_sc.items():
        if sc == "NORMAL_FLIGHT":
            continue
        det_hits, lat, miss = Counter(), defaultdict(list), 0
        inc_ok = conf_ok = 0
        for r in rs:
            c = classify(r)
            for d in c["tp"]:
                det_hits[d] += 1
                lat[d].append(c["latency"][d])
            miss += bool(c["missed"])
            for a in c["fp"]:
                att_fp[f"{sc}: {a['detector']} | {a['title']}"] += 1
            post = [i for i in r["incidents"] if i["t"] >= r["inject"] - 0.5]
            inc_ok += bool(post)
            conf_ok += any(i["state"] == "CONFIRMED" for i in post)
        attack[sc] = {"runs": len(rs), "all_expected_detected": len(rs) - miss,
                      "detector_hit_rate": {d: round(det_hits[d] / len(rs), 3) for d in EXPECTED[sc]},
                      "median_latency_s": {d: round(sorted(v)[len(v) // 2], 2) for d, v in lat.items()},
                      "incident_rate": round(inc_ok / len(rs), 3), "confirmed_rate": round(conf_ok / len(rs), 3)}
    return {"benign": {"flights": len(benign), "flight_hours": round(hours, 3), "flights_with_fp_alert": flights_with_fp,
                       "flights_with_fp_incident": flights_with_inc, "fp_alerts_per_hour": round(sum(fp_det.values()) / hours, 2), "justified_loss_alerts": justified,
                       "fp_by_detector": dict(fp_det.most_common()), "fp_by_title": dict(fp_title.most_common(40)),
                       "fp_incidents": dict(fp_inc.most_common(20))},
            "attack": attack, "attack_fp_top": dict(att_fp.most_common(40))}


def parse_set(items: list[str]) -> dict:
    out: dict = {}
    for it in items or []:
        key, val = it.split("=", 1)
        cur = out
        parts = key.split(".")
        for part in parts[:-1]:
            cur = cur.setdefault(part, {})
        cur[parts[-1]] = yaml.safe_load(val)
    return out


def append_checkpoint(path: str | Path, index: int, result: dict) -> None:
    """Persist one completed flight so an interrupted batch leaves usable raw data."""
    with Path(path).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"index": index, "result": result}, default=list) + "\n")


def run_jobs(jobs: list[dict], workers: int, checkpoint: str | Path | None = None) -> list[dict]:
    results = [None] * len(jobs)
    if checkpoint is None:
        with ProcessPoolExecutor(max_workers=workers) as ex:
            for i, result in enumerate(ex.map(run_one, jobs, chunksize=2)):
                results[i] = result
        return results
    checkpoint = Path(checkpoint)
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    with checkpoint.open("w", encoding="utf-8") as stream, ProcessPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(run_one, job): i for i, job in enumerate(jobs)}
        for completed, future in enumerate(as_completed(futures), 1):
            index = futures[future]
            result = future.result()
            results[index] = result
            stream.write(json.dumps({"index": index, "result": result}, default=list) + "\n")
            stream.flush()
            if completed == 1 or completed % 100 == 0 or completed == len(jobs):
                print(f"completed {completed}/{len(jobs)} flights", flush=True)
    return results


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign", type=int, default=100)
    ap.add_argument("--attack", type=int, default=20)
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--harsh", type=float, default=1.0)
    ap.add_argument("--scenarios", nargs="*")
    ap.add_argument("--extended", action="store_true", help="enable optional field-profile disturbances")
    ap.add_argument("--boundary-attacks", action="store_true", help="sample weaker attack strengths for ROC runs")
    ap.add_argument("--duration-min", type=int, default=120)
    ap.add_argument("--duration-max", type=int, default=300)
    ap.add_argument("--set", nargs="*", default=[], help="config override dotted.key=value")
    ap.add_argument("--workers", type=int, default=14)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    ov = parse_set(a.set)
    jobs = make_jobs(a.benign, a.attack, a.seed, ov, a.harsh, a.scenarios,
                     duration_range=(a.duration_min, a.duration_max), extended=a.extended,
                     boundary_attacks=a.boundary_attacks)
    t = time.time()
    out_path = Path(a.out)
    checkpoint = out_path.with_name(f"{out_path.name}.{time.time_ns()}.partial.jsonl")
    results = run_jobs(jobs, a.workers, checkpoint)
    summ = summarize(results)
    summ["meta"] = {"runs": len(jobs), "seconds": round(time.time() - t, 1), "overrides": ov,
                    "seed": a.seed, "harsh": a.harsh, "extended": a.extended,
                    "boundary_attacks": a.boundary_attacks,
                    "duration_range": [a.duration_min, a.duration_max]}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"summary": summ, "results": results}, default=list, indent=1), encoding="utf-8")
    checkpoint.unlink(missing_ok=True)
    json.dump(summ, sys.stdout, indent=1, default=list)


if __name__ == "__main__":
    main()
