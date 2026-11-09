"""Synthetic test mode (spec §75). SIMULATION / DEMO DATA ONLY.

Generates genuine MAVLink v2 wire frames with pymavlink encoders for a simulated
ArduCopter, a GCS (SYSID 255) and a SiK radio (SYSID 51). Frames are handed to
the same decoder/normalizer/detector path as live data. Nothing is ever
transmitted: the simulator has no transport and cannot reach a vehicle.

PUSHPAK STATUSTEXT in PUSHPAK_CONFIRMATION uses the exact formats found in the
supplied Lua sources; LUA_BINDING_MISMATCH reproduces the runtime error the
*original* scripts hit on the 26 Sep 2026 build (2-method `ids` binding). It is a
health-path test only: build_v3 has the accessors and the current scripts no
longer call them.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Iterator, Optional

from pymavlink.dialects.v20 import ardupilotmega as mav

SCENARIOS = {
    "NORMAL_FLIGHT": "Benign mission flight; no injected anomalies (expected: no incidents).",
    "GPS_DRIFT": "Slow GNSS drift (0.8 m/s) with partial EKF drag — CUSUM/residual layers.",
    "GPS_JUMP": "180 m GNSS position jump for 6 s with EKF variance spike.",
    "GPS_IMU_MISMATCH": "GPS velocity 18.4 m/s vs EKF 7.2 m/s for 8 s + EKF velocity-variance anomaly.",
    "MAVLINK_SEQUENCE_GAP": "30% frame loss, duplicated (replayed) and out-of-order frames.",
    "HEARTBEAT_LOSS": "All vehicle telemetry stops for 9 s, then recovers.",
    "UNKNOWN_SOURCE": "SYSID 42 appears and sends read-only traffic (expected: NEW SOURCE OBSERVED only).",
    "COMMAND_BURST": "SYSID 42 sends a burst of COMMAND_LONG incl. DISARM while airborne.",
    "PARAMETER_CHANGE": "SYSID 42 writes sensitive parameters in flight (FENCE_ENABLE, ARMING_CHECK, …).",
    "MISSION_CHANGE": "SYSID 42 replaces the mission mid-flight; mission index jumps.",
    "RC_DEGRADATION": "Gradual RSSI decline, rising radio errors, intermittent RC receiver loss.",
    "MULTI_SIGNAL_INCIDENT": "Unknown source + command burst + parameter change + GPS/EKF mismatch.",
    "PUSHPAK_CONFIRMATION": "GPS drift + FC PIDS + Lua confirmation STATUSTEXT (formats from supplied Lua).",
    "LUA_BINDING_MISMATCH": "Lua runtime errors as seen with the original scripts on the 26 Sep 2026 build (ids:<method> missing).",
}

M_PER_DEG = 111_320.0


class _Enc:
    def __init__(self, sysid, compid):
        self.m = mav.MAVLink(None, srcSystem=sysid, srcComponent=compid)
        self.m.robust_parsing = True

    def pack(self, msg) -> bytes:
        b = bytes(msg.pack(self.m))
        self.m.seq = (self.m.seq + 1) % 256
        return b


@dataclass
class Frame:
    t: float
    data: bytes
    link: str = "sim0"


class FlightSimulator:
    DT = 0.02

    def __init__(self, scenario: str = "NORMAL_FLIGHT", home=(12.9716, 77.5946, 920.0), seed: int = 7,
                 duration_s: float = 150.0, inject_at: float = 45.0, t0: float = 1_790_000_000.0,
                 magnitude: float = 1.0):
        if scenario not in SCENARIOS:
            raise ValueError(f"unknown scenario {scenario}")
        self.scenario = scenario
        self.lat0, self.lon0, self.alt0 = home
        self.rng = random.Random(seed)
        self.duration = duration_s
        self.inj = inject_at
        self.mag = magnitude          # attack-strength scale used for varied validation runs
        self.mode_override = None     # set when an (injected) DO_SET_MODE is accepted
        self.mode_reason = 0          # ArduPilot ModeReason of the last mode change (2 = GCS_COMMAND)
        self.step_hook = None         # callable(sim) -> [(severity, text)]
        self.t0 = t0
        self.veh = _Enc(1, 1)
        self.gcs = _Enc(255, 190)
        self.radio = _Enc(51, 68)
        self.rogue = _Enc(42, 1)
        # state
        self.n = self.e = 0.0
        self.alt = 0.0
        self.vn = self.ve = self.vd = 0.0
        self.yaw = 0.0
        self.armed = False
        self.mode = 0  # STABILIZE
        self.batt_v = 16.8
        self.batt_rem = 100.0
        self.wp = [(0, 0), (120, 0), (120, 120), (0, 120), (-80, 60)]
        self.wp_i = 0
        self.mission_seq = 0
        self.laps = 20
        self.mission_len = 1 + (len(self.wp) - 1) * self.laps
        self.history: list[Frame] = []
        self.params = {"FENCE_ENABLE": 1.0, "ARMING_CHECK": 1.0, "FS_THR_ENABLE": 1.0, "RTL_ALT": 1500.0,
                       "WPNAV_SPEED": 800.0, "ANGLE_MAX": 3000.0, "SYSID_THISMAV": 1.0, "BATT_FS_LOW_ACT": 2.0,
                       "GPS_TYPE": 1.0, "EK3_SRC1_POSXY": 3.0, "SCR_ENABLE": 1.0, "LOG_BACKEND_TYPE": 1.0,
                       "SERIAL1_PROTOCOL": 2.0, "MAV_GCS_SYSID": 255.0, "RC_OPTIONS": 32.0, "DISARM_DELAY": 10.0,
                       "INS_ACCEL_FILTER": 20.0, "INS_GYRO_FILTER": 20.0, "PILOT_SPEED_UP": 250.0, "LAND_SPEED": 50.0}
        self.rc_unhealthy = False
        self.rssi = 220.0
        self.rxerrors = 0
        self.gps_off_n = self.gps_off_e = 0.0
        self.gps_vel_override: Optional[float] = None
        self.ekf_var = 0.08
        self.ekf_pos_var = 0.06

    # ------------------------------------------------------------------ helpers
    def latlon(self, n, e):
        return self.lat0 + n / M_PER_DEG, self.lon0 + e / (M_PER_DEG * math.cos(math.radians(self.lat0)))

    def _in(self, a, b) -> bool:
        return a <= self.t < b

    def _sc(self, *names) -> bool:
        return self.scenario in names

    # ------------------------------------------------------------------ main loop
    def frames(self) -> Iterator[Frame]:
        steps = int(self.duration / self.DT)
        for k in range(steps):
            self.t = k * self.DT
            self._physics()
            out: list[tuple[str, bytes]] = []
            self._schedule(k, out)
            self._inject(k, out)
            if self.step_hook is not None:  # on-board software (e.g. Lua) emitting STATUSTEXT, packed in order
                for sev, text in self.step_hook(self):
                    out += [("veh", x) for x in self._text(sev, text)]
            for who, data in out:
                if self._suppressed(who):
                    continue
                if who == "veh" and self._sc("MAVLINK_SEQUENCE_GAP") and self._in(self.inj, self.inj + 10) and self.rng.random() < 0.3:
                    continue
                fr = Frame(self.t0 + self.t, data)
                if who == "veh":
                    self.history.append(fr)
                    del self.history[:-400]
                yield fr
            # replay / out-of-order injection
            if self._sc("MAVLINK_SEQUENCE_GAP") and self._in(self.inj + 3, self.inj + 3 + self.DT):
                for old in self.history[-60:-40]:
                    yield Frame(self.t0 + self.t, old.data)
            if self._sc("MAVLINK_SEQUENCE_GAP") and k % 150 == 0 and self._in(self.inj, self.inj + 10) and len(self.history) > 5:
                yield Frame(self.t0 + self.t, self.history[-4].data)

    def _suppressed(self, who) -> bool:
        return who in ("veh", "radio") and self._sc("HEARTBEAT_LOSS") and self._in(self.inj, self.inj + 9)

    # ------------------------------------------------------------------ physics
    def _physics(self):
        t = self.t
        if t < 6:
            self.armed = t >= 5.0
            self.vn = self.ve = self.vd = 0.0
        elif t < 12:
            if self.mode != 4:
                self.mode_reason = 2  # GCS DO_SET_MODE
            self.mode = 4  # GUIDED takeoff
            self.vd = -3.5 if self.alt < 20 else 0.0
        else:
            planned = 3 if t < self.duration - 25 else 6  # AUTO then RTL
            if self.mode_override is not None:
                planned = self.mode_override
            elif planned != self.mode:
                self.mode_reason = 2 if planned == 3 else 8  # GCS command / mission end
            self.mode = planned
            target = self.wp[1 + self.wp_i % (len(self.wp) - 1)] if self.mode == 3 else (0.0, 0.0)
            dn, de = target[0] - self.n, target[1] - self.e
            d = math.hypot(dn, de)
            spd = 8.0
            if d < 6 and self.mode == 3 and not getattr(self, "mission_override", False):
                self.wp_i += 1
                self.mission_seq = min(1 + self.wp_i, self.mission_len - 1)
            tvn, tve = (spd * dn / d, spd * de / d) if d > 0.5 else (0.0, 0.0)
            amax = 2.5 * self.DT
            dvn, dve = tvn - self.vn, tve - self.ve
            dv = math.hypot(dvn, dve)
            if dv > amax:
                dvn, dve = dvn * amax / dv, dve * amax / dv
            self.vn += dvn
            self.ve += dve
            if math.hypot(self.vn, self.ve) > 0.3:
                self.yaw = math.atan2(self.ve, self.vn)
            self.vd = 0.0 if self.mode == 3 else (1.5 if (self.alt > 0.2 and d < 3) else 0.0)
        self.n += self.vn * self.DT
        self.e += self.ve * self.DT
        self.alt = max(0.0, self.alt - self.vd * self.DT)
        airborne = self.alt > 0.5
        if airborne:
            self.batt_v = max(13.2, self.batt_v - 0.0009 * self.DT * 60)
            self.batt_rem = max(0.0, self.batt_rem - 0.0006)
        if self.mode == 6 and self.alt <= 0.21 and t > 12:
            self.armed = False
        # scenario physics
        s = self.scenario
        self.gps_vel_override = None
        if s in ("GPS_DRIFT", "PUSHPAK_CONFIRMATION") and t >= self.inj:
            self.gps_off_e = min(0.8 * self.mag * (t - self.inj), 60.0)
            self.ekf_pos_var = min(0.06 + 0.02 * (t - self.inj), 0.95)
        elif s == "GPS_JUMP" and self._in(self.inj, self.inj + 6):
            self.gps_off_n = 180.0 * self.mag
            self.ekf_pos_var = 1.2
        elif s in ("GPS_IMU_MISMATCH",) and self._in(self.inj, self.inj + 8) or (s == "MULTI_SIGNAL_INCIDENT" and self._in(self.inj + 10, self.inj + 18)):
            self.gps_vel_override = 8.0 + 10.4 * self.mag
            self.gps_off_n += 10.0 * self.mag * self.DT
            self.ekf_var = 0.9
        else:
            if s == "GPS_JUMP":
                self.gps_off_n = 0.0
                self.ekf_pos_var = 0.06
            if s in ("GPS_IMU_MISMATCH", "MULTI_SIGNAL_INCIDENT"):
                self.gps_off_n = max(0.0, self.gps_off_n - 20.0 * self.DT)
                self.ekf_var = 0.08
        if s == "RC_DEGRADATION" and t >= self.inj:
            r = t - self.inj
            self.rssi = max(40.0, 220 - 7.0 * self.mag * r)
            self.rc_unhealthy = any(self._in(self.inj + a, self.inj + a + 4) for a in (26, 36, 46))

    # ------------------------------------------------------------------ periodic telemetry
    def _every(self, k, period) -> bool:
        return k % max(1, int(round(period / self.DT))) == 0

    def _schedule(self, k, out):
        V, G, R = self.veh, self.gcs, self.radio
        r = self.rng
        lat, lon = self.latlon(self.n, self.e)
        airborne = self.alt > 0.5
        base_mode = 89 | (128 if self.armed else 0)
        if self._every(k, 1.0):
            out.append(("veh", V.pack(mav.MAVLink_heartbeat_message(2, 3, base_mode, self.mode, 4 if self.armed else 3, 3))))
            out.append(("gcs", G.pack(mav.MAVLink_heartbeat_message(6, 8, 0, 0, 0, 3))))
            health = 0x3F | 32 | 65536 | (1 << 21)
            present = health | 65536
            if self.rc_unhealthy:
                health &= ~65536
            out.append(("veh", V.pack(mav.MAVLink_sys_status_message(present, present, health, 250 if airborne else 50,
                                                                      int(self.batt_v * 1000), int((1250 if airborne else 60) + r.gauss(0, 20)),
                                                                      int(self.batt_rem), 0, 0, 0, 0, 0, 0))))
            out.append(("veh", V.pack(mav.MAVLink_system_time_message(int((self.t0 + self.t) * 1e6), int(self.t * 1000)))))
            out.append(("veh", V.pack(mav.MAVLink_extended_sys_state_message(0, 2 if airborne else 1))))
            out.append(("veh", V.pack(mav.MAVLink_mission_current_message(self.mission_seq))))
            out.append(("veh", V.pack(mav.MAVLink_vibration_message(int(self.t * 1e6), 3 + r.random(), 3 + r.random(), 4 + r.random(), 0, 0, 0))))
            cells = [int(self.batt_v * 1000 / 4)] * 4 + [65535] * 6
            out.append(("veh", V.pack(mav.MAVLink_battery_status_message(0, 0, 0, 3000, cells, int(1250 if airborne else 60), -1, -1, int(self.batt_rem)))))
            self.rxerrors += (r.randint(8, 20) if (self._sc("RC_DEGRADATION") and self.t > self.inj + 10) else 0)
            noise = 40 + (int((self.t - self.inj) * 1.5) if self._sc("RC_DEGRADATION") and self.t > self.inj else 0)
            out.append(("radio", R.pack(mav.MAVLink_radio_status_message(int(self.rssi * 0.8), int(self.rssi * 0.78), 100, min(noise, 250), 38,
                                                                         min(self.rxerrors, 65535), 0))))
        if self._every(k, 0.2):
            gn, ge = self.n + self.gps_off_n + r.gauss(0, 0.4), self.e + self.gps_off_e + r.gauss(0, 0.4)
            glat, glon = self.latlon(gn, ge)
            spd = math.hypot(self.vn, self.ve)
            gvel = self.gps_vel_override if self.gps_vel_override is not None else spd + r.gauss(0, 0.08)
            out.append(("veh", V.pack(mav.MAVLink_gps_raw_int_message(int((self.t0 + self.t) * 1e6), 3 if self.t > 1 else 1, int(glat * 1e7), int(glon * 1e7),
                                                                       int((self.alt0 + self.alt + r.gauss(0, 0.5)) * 1000), 80, 120, int(max(gvel, 0) * 100),
                                                                       int((math.degrees(self.yaw) % 360) * 100), 14))))
            # EKF drags partially toward the spoofed/drifted GPS (0.3), never fully
            en, ee = self.n + r.gauss(0, 0.1), self.e + 0.3 * self.gps_off_e + r.gauss(0, 0.1)
            elat, elon = self.latlon(en, ee)
            out.append(("veh", V.pack(mav.MAVLink_global_position_int_message(int(self.t * 1000), int(elat * 1e7), int(elon * 1e7),
                                                                               int((self.alt0 + self.alt) * 1000), int(self.alt * 1000),
                                                                               int(self.vn * 100), int(self.ve * 100), int(self.vd * 100),
                                                                               int((math.degrees(self.yaw) % 360) * 100)))))
            out.append(("veh", V.pack(mav.MAVLink_raw_imu_message(int(self.t * 1e6), *self._imu(0), 0, 0))))
            out.append(("veh", V.pack(mav.MAVLink_scaled_imu2_message(int(self.t * 1000), *self._imu(1), 0))))
            out.append(("veh", V.pack(mav.MAVLink_vfr_hud_message(math.hypot(self.vn, self.ve), math.hypot(self.vn, self.ve),
                                                                   int(math.degrees(self.yaw) % 360), 55 if airborne else 0,
                                                                   self.alt0 + self.alt, -self.vd))))
            if self.mode == 4:
                tlat, tlon = self.latlon(0, 0)
                out.append(("veh", V.pack(mav.MAVLink_position_target_global_int_message(int(self.t * 1000), 6, 0xFF8, int(tlat * 1e7), int(tlon * 1e7), 20, 0, 0, 0, 0, 0, 0, 0, 0))))
        if self._every(k, 0.1):
            roll = 0.02 * math.sin(self.t) + r.gauss(0, 0.003)
            pitch = -0.05 * (1 if math.hypot(self.vn, self.ve) > 1 else 0) + r.gauss(0, 0.003)
            out.append(("veh", V.pack(mav.MAVLink_attitude_message(int(self.t * 1000), roll, pitch, self.yaw, r.gauss(0, 0.01), r.gauss(0, 0.01), r.gauss(0, 0.01)))))
        if self._every(k, 0.5):
            flags = 831
            out.append(("veh", V.pack(mav.MAVLink_ekf_status_report_message(flags, self.ekf_var + abs(r.gauss(0, 0.02)), self.ekf_pos_var + abs(r.gauss(0, 0.02)),
                                                                             0.05, 0.04, 0.0))))
            chans = [1500] * 18
            out.append(("veh", V.pack(mav.MAVLink_rc_channels_message(int(self.t * 1000), 16, *chans, int(self.rssi)))))
            out.append(("veh", V.pack(mav.MAVLink_scaled_pressure_message(int(self.t * 1000), 1013.25 - self.alt * 0.12, 0.0, 2500))))
        # one-off GCS/vehicle exchanges
        if k == int(0.3 / self.DT):
            out += [("veh", x) for x in self._text(6, b"ArduCopter V4.7.1 (dbe79216)".decode())]
            out += [("veh", x) for x in self._text(6, b"Pixhawk6C 003A0036 3131510A 34383539".decode())]
            if self._sc("LUA_BINDING_MISMATCH"):
                out += [("veh", x) for x in self._text(3, b"Lua: @ROMFS/scripts/ids_gcs_bridge.lua:10: attempt to call a nil value (method 'gps_confidence')".decode())]
                out += [("veh", x) for x in self._text(3, b"Lua: @ROMFS/scripts/gps_confirm.lua:104: attempt to call a nil value (method 'gps_confidence')".decode())]
                out += [("veh", x) for x in self._text(3, b"Lua: @ROMFS/scripts/mavlink_confirm.lua:31: attempt to call a nil value (method 'mavlink_confidence')".decode())]
        if 1 <= self.t < 3 and k % 5 == 0:  # parameter download
            i = (k // 5) % len(self.params)
            name = list(self.params)[i]
            out.append(("veh", V.pack(mav.MAVLink_param_value_message(name.encode(), self.params[name], 9, len(self.params), i))))
        if k == int(3.2 / self.DT):
            self._upload_mission(out, self.gcs, self._mission_items())
        if k == int(5.0 / self.DT):
            out += self._cmd(G, 400, [1, 0, 0, 0, 0, 0, 0], ack=0)
            lat0, lon0 = self.latlon(0, 0)
            out.append(("veh", V.pack(mav.MAVLink_home_position_message(int(lat0 * 1e7), int(lon0 * 1e7), int(self.alt0 * 1000), 0, 0, 0, [1, 0, 0, 0], 0, 0, 0))))
        if k == int(5.5 / self.DT):
            out += self._cmd(G, 176, [1, 4, 0, 0, 0, 0, 0], ack=0)
        if k == int(6.0 / self.DT):
            out += self._cmd(G, 22, [0, 0, 0, 0, 0, 0, 20], ack=0)
        if k == int(12.0 / self.DT):
            out += self._cmd(G, 176, [1, 3, 0, 0, 0, 0, 0], ack=0)

    def _text(self, sev: int, text: str) -> list[bytes]:
        """ArduPilot-style STATUSTEXT: >50 chars are split into chunks sharing an id."""
        b = text.encode()
        if len(b) <= 50:
            return [self.veh.pack(mav.MAVLink_statustext_message(sev, b, 0, 0))]
        self._text_id = getattr(self, "_text_id", 0) % 65535 + 1
        chunks = [b[i:i + 50] for i in range(0, len(b), 50)]
        if len(chunks[-1]) == 50:
            chunks.append(b"")
        return [self.veh.pack(mav.MAVLink_statustext_message(sev, c, self._text_id, i)) for i, c in enumerate(chunks)]

    def _imu(self, inst):
        r = self.rng
        acc = (int(r.gauss(0, 15)), int(r.gauss(0, 15)), int(-1000 + r.gauss(0, 15)))
        gyr = (int(r.gauss(0, 8)), int(r.gauss(0, 8)), int(r.gauss(0, 8)))
        mag = (200, -50, 400)
        return acc + gyr + mag

    def _mission_items(self, rogue=False):
        pts = [(0, 0)] + self.wp[1:] * self.laps if not rogue else [(0, 0), (300 * self.mag, -200 * self.mag), (500 * self.mag, 400 * self.mag)]
        items = []
        for i, (n, e) in enumerate(pts):
            lat, lon = self.latlon(n, e)
            items.append((i, 16 if i else 22, int(lat * 1e7), int(lon * 1e7), 20.0))
        return items

    def _upload_mission(self, out, enc: _Enc, items):
        out.append(("gcs" if enc is self.gcs else "rogue", enc.pack(mav.MAVLink_mission_count_message(1, 1, len(items), 0))))
        for seq, cmd, lat, lon, alt in items:
            out.append(("gcs" if enc is self.gcs else "rogue",
                        enc.pack(mav.MAVLink_mission_item_int_message(1, 1, seq, 6, cmd, 0, 1, 0, 0, 0, 0, lat, lon, alt, 0))))
        out.append(("veh", self.veh.pack(mav.MAVLink_mission_ack_message(enc.m.srcSystem, enc.m.srcComponent, 0, 0))))

    def _cmd(self, enc: _Enc, cmd, p, ack=0, who=None):
        who = who or ("gcs" if enc is self.gcs else "rogue")
        res = [(who, enc.pack(mav.MAVLink_command_long_message(1, 1, cmd, 0, *p)))]
        if ack is not None:
            res.append(("veh", self.veh.pack(mav.MAVLink_command_ack_message(cmd, ack))))
        return res

    # ------------------------------------------------------------------ injections
    def _inject(self, k, out):
        s, t, R = self.scenario, self.t, self.rogue
        at = lambda x: k == int(x / self.DT)  # noqa: E731
        rogue_active = s in ("UNKNOWN_SOURCE", "COMMAND_BURST", "PARAMETER_CHANGE", "MISSION_CHANGE", "MULTI_SIGNAL_INCIDENT")
        if rogue_active and t >= self.inj and self._every(k, 1.0):
            out.append(("rogue", R.pack(mav.MAVLink_heartbeat_message(6, 8, 0, 0, 0, 3))))
        if s == "UNKNOWN_SOURCE" and at(self.inj + 2):
            out.append(("rogue", R.pack(mav.MAVLink_param_request_list_message(1, 1))))
            out.append(("rogue", R.pack(mav.MAVLink_request_data_stream_message(1, 1, 0, 4, 1))))
        burst_t = self.inj + (3 if s == "MULTI_SIGNAL_INCIDENT" else 2)
        if s in ("COMMAND_BURST", "MULTI_SIGNAL_INCIDENT") and burst_t <= t < burst_t + 3 * max(self.mag, 0.5) and self._every(k, 0.25):
            seqn = int((t - burst_t) / 0.25)
            # unauthenticated MAVLink: DO_SET_MODE is accepted (ACK 0); DISARM in flight / reboot are refused (ACK 4)
            plan = [(176, [1, 9, 0, 0, 0, 0, 0], 0), (400, [0, 0, 0, 0, 0, 0, 0], 4), (176, [1, 5, 0, 0, 0, 0, 0], 0),
                    (400, [0, 21196, 0, 0, 0, 0, 0], 4), (176, [1, 6, 0, 0, 0, 0, 0], 0), (246, [1, 0, 0, 0, 0, 0, 0], 4)]
            cmd, p, ack = plan[seqn % len(plan)]
            out += self._cmd(R, cmd, p, ack=ack)
            if cmd == 176 and ack == 0:
                self.mode_override, self.mode_reason = int(p[1]), 2
        par_t = self.inj + (6 if s == "MULTI_SIGNAL_INCIDENT" else 2)
        if s in ("PARAMETER_CHANGE", "MULTI_SIGNAL_INCIDENT"):
            writes = [("FENCE_ENABLE", 0.0), ("ARMING_CHECK", 0.0), ("FS_THR_ENABLE", 0.0), ("RTL_ALT", 300.0), ("WPNAV_SPEED", 2000.0), ("ANGLE_MAX", 4500.0)]
            n_writes = max(3, min(len(writes), round(3 + 3 * self.mag)))
            for i, (name, val) in enumerate(writes[:n_writes]):
                if at(par_t + i * 0.8):
                    out.append(("rogue", R.pack(mav.MAVLink_param_set_message(1, 1, name.encode(), val, 9))))
                    self.params[name] = val
                    out.append(("veh", self.veh.pack(mav.MAVLink_param_value_message(name.encode(), val, 9, len(self.params), list(self.params).index(name)))))
        if s == "MISSION_CHANGE" and at(self.inj + 2):
            self._upload_mission(out, R, self._mission_items(rogue=True))
        if s == "MISSION_CHANGE" and at(self.inj + 3):
            self.mission_override = True      # vehicle now flies the rogue mission: index restarts
            self.mission_seq = 1
            self.wp = [(0, 0), (300 * self.mag, -200 * self.mag), (500 * self.mag, 400 * self.mag)]
            self.wp_i = 0
        if s == "PUSHPAK_CONFIRMATION":
            V = self.veh
            if at(self.inj + 6):
                out += [("veh", x) for x in self._text(6, b"PIDS|1|FC|GPS|1|0.620|265|0.000|0".decode())]
            if at(self.inj + 14):
                out += [("veh", x) for x in self._text(6, b"PIDS|1|FC|GPS|2|0.870|32777|0.000|0".decode())]
            if at(self.inj + 15):
                out += [("veh", x) for x in self._text(4, b"PUSHPAK IDS: GPS CONFIRMED conf=0.86 pos=14.2m vel=3.1m/s robust=0.91 cusum=0.77".decode())]
            if at(self.inj + 16):
                out += [("veh", x) for x in self._text(6, b"PIDS|1|FC|MAVLINK|0|0.050|0|0.000|0".decode())]


def scenario_list() -> list[dict]:
    return [{"id": k, "description": v} for k, v in SCENARIOS.items()]
