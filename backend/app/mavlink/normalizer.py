"""Vehicle state model (spec §88/§89). Every field carries source, timestamp,
quality and availability; unknown values are never shown as 0."""
from __future__ import annotations

import math
from typing import Any, Optional

from pymavlink import mavutil

from ..models.events import TelemetryEvent, iso_from_epoch

MODE_NAMES = dict(mavutil.mode_mapping_acm)
MAV_STATE = {0: "UNINIT", 1: "BOOT", 2: "CALIBRATING", 3: "STANDBY", 4: "ACTIVE", 5: "CRITICAL", 6: "EMERGENCY",
             7: "POWEROFF", 8: "FLIGHT_TERMINATION"}
GPS_FIX = {0: "NO_GPS", 1: "NO_FIX", 2: "2D", 3: "3D", 4: "DGPS", 5: "RTK_FLOAT", 6: "RTK_FIXED", 7: "STATIC", 8: "PPP"}
MAV_TYPE_GCS = 6
MAV_AUTOPILOT_INVALID = 8
STALE_S = {"default": 3.0, "battery": 5.0, "rc": 5.0, "home": 1e9, "mission": 30.0, "gps": 3.0}


class Field:
    __slots__ = ("value", "source", "t", "mono", "quality")

    def __init__(self, value, source, t, mono, quality="OK"):
        self.value, self.source, self.t, self.mono, self.quality = value, source, t, mono, quality


class VehicleState:
    def __init__(self, ctx, config):
        self.ctx = ctx
        self.config = config
        self.f: dict[str, Field] = {}
        cfg_sysid = config.get("mavlink.vehicle_sysid")
        if cfg_sysid is not None:
            ctx.vehicle_sysid = int(cfg_sysid)
            ctx.vehicle_compid = 1
        self.landed_state_seen = False
        self.home: Optional[dict] = None
        self.track: list[tuple] = []

    def _set(self, name, value, ev: TelemetryEvent, quality="OK"):
        self.f[name] = Field(value, ev.origin or ev.msg_name, ev.t, self.ctx.mono, quality)

    def value(self, name) -> Any:
        fld = self.f.get(name)
        return None if fld is None else fld.value

    def update(self, ev: TelemetryEvent) -> bool:
        """Return True when the event changed vehicle state."""
        n, f = ev.msg_name, ev.fields
        ctx = self.ctx
        if n == "HEARTBEAT":
            if ctx.vehicle_sysid is None and f.get("type") != MAV_TYPE_GCS and f.get("autopilot") != MAV_AUTOPILOT_INVALID:
                ctx.vehicle_sysid, ctx.vehicle_compid = ev.sysid, ev.compid
            if ev.sysid != ctx.vehicle_sysid or ev.compid != (ctx.vehicle_compid or 1):
                return False
            armed = bool((f.get("base_mode") or 0) & 128)
            mode = MODE_NAMES.get(f.get("custom_mode"), f"MODE_{f.get('custom_mode')}")
            ctx.armed, ctx.mode = armed, mode
            self._set("armed", armed, ev)
            self._set("mode", mode, ev)
            self._set("system_status", MAV_STATE.get(f.get("system_status"), str(f.get("system_status"))), ev)
            self._set("mavlink_version", f.get("mavlink_version"), ev)
            self._airborne()
            return True
        if ev.origin in ("MODE",) and "mode" in f:
            ctx.mode = f["mode"]
            self._set("mode", f["mode"], ev)
            return True
        if ev.origin == "EV" and f.get("armed") is not None:
            ctx.armed = f["armed"]
            self._set("armed", f["armed"], ev)
            self._airborne()
            return True
        if ctx.vehicle_sysid is not None and ev.sysid is not None and ev.sysid != ctx.vehicle_sysid:
            return False
        if n == "GLOBAL_POSITION_INT":
            lat, lon = f.get("lat"), f.get("lon")
            q = "OK" if lat not in (None, 0) and lon not in (None, 0) else "INVALID"
            self._set("lat", lat / 1e7 if lat is not None else None, ev, q)
            self._set("lon", lon / 1e7 if lon is not None else None, ev, q)
            if f.get("alt") is not None:
                self._set("altitude_m", f["alt"] / 1000.0, ev)
            if f.get("relative_alt") is not None:
                self._set("relative_alt_m", f["relative_alt"] / 1000.0, ev)
            if f.get("vx") is not None and f.get("vy") is not None:
                self._set("ekf_speed_ms", math.hypot(f["vx"], f["vy"]) / 100.0, ev)
            if f.get("vz") is not None:
                self._set("climb_ms", -f["vz"] / 100.0, ev)
            hdg = f.get("hdg")
            if hdg is not None and hdg != 65535:
                self._set("heading_deg", hdg / 100.0, ev)
            if q == "OK":
                self.track.append((ev.t, lat / 1e7, lon / 1e7, (f.get("relative_alt") or 0) / 1000.0))
                del self.track[:-3000]
            self._airborne()
            return True
        if n == "VFR_HUD":
            self._set("groundspeed_ms", f.get("groundspeed"), ev)
            self._set("airspeed_ms", f.get("airspeed"), ev)
            self._set("throttle_pct", f.get("throttle"), ev)
            if "climb_ms" not in self.f or self.f["climb_ms"].source == "VFR_HUD":
                self._set("climb_ms", f.get("climb"), ev)
            self._airborne()
            return True
        if n == "ATTITUDE":
            for k, name in (("roll", "roll_deg"), ("pitch", "pitch_deg"), ("yaw", "yaw_deg")):
                v = f.get(k)
                self._set(name, None if v is None else math.degrees(v), ev)
            return True
        if n == "GPS_RAW_INT":
            fix = f.get("fix_type")
            self._set("gps_fix", GPS_FIX.get(fix, str(fix)), ev)
            self._set("gps_fix_type", fix, ev)
            sats = f.get("satellites_visible")
            self._set("gps_sats", None if sats in (None, 255) else sats, ev, "OK" if sats not in (None, 255) else "UNKNOWN")
            eph = f.get("eph")
            self._set("gps_hdop", None if eph in (None, 65535) else eph / 100.0, ev, "OK" if eph not in (None, 65535) else "UNKNOWN")
            vel = f.get("vel")
            self._set("gps_speed_ms", None if vel in (None, 65535) else vel / 100.0, ev)
            if f.get("lat") not in (None, 0):
                self._set("gps_lat", f["lat"] / 1e7, ev)
                self._set("gps_lon", f["lon"] / 1e7, ev)
            return True
        if n == "SYS_STATUS":
            v = f.get("voltage_battery")
            self._set("battery_voltage_v", None if v in (None, 65535) else v / 1000.0, ev, "OK" if v not in (None, 65535) else "UNKNOWN")
            c = f.get("current_battery")
            self._set("battery_current_a", None if c in (None, -1) else c / 100.0, ev, "OK" if c not in (None, -1) else "UNKNOWN")
            r = f.get("battery_remaining")
            self._set("battery_remaining_pct", None if r in (None, -1) else r, ev, "OK" if r not in (None, -1) else "UNKNOWN")
            if f.get("drop_rate_comm") is not None:
                self._set("fc_drop_rate_pct", f["drop_rate_comm"] / 100.0, ev)
            return True
        if n == "RC_CHANNELS":
            rssi = f.get("rssi")
            self._set("rc_rssi", None if rssi in (None, 255) else rssi, ev, "OK" if rssi not in (None, 255) else "UNKNOWN")
            self._set("rc_channels", f.get("chancount"), ev)
            return True
        if n == "RADIO_STATUS":
            self._set("radio_rssi", f.get("rssi"), ev)
            self._set("radio_remrssi", f.get("remrssi"), ev)
            return True
        if n == "HOME_POSITION" and f.get("latitude"):
            self.home = {"lat": f["latitude"] / 1e7, "lon": f["longitude"] / 1e7, "alt_m": (f.get("altitude") or 0) / 1000.0}
            self._set("home", self.home, ev)
            return True
        if n == "EXTENDED_SYS_STATE":
            ls = f.get("landed_state")
            if ls in (1, 2, 3, 4):
                self.landed_state_seen = True
                ctx.airborne = ls in (2, 3, 4)
                self._set("airborne", ctx.airborne, ev)
                self._set("landed_state", {1: "ON_GROUND", 2: "IN_AIR", 3: "TAKEOFF", 4: "LANDING"}[ls], ev)
            return True
        if n == "MISSION_CURRENT":
            self._set("mission_seq", f.get("seq"), ev)
            if f.get("total") not in (None, 0, 65535):
                self._set("mission_total", f.get("total"), ev)
            return True
        if n == "EKF_STATUS_REPORT":
            self._set("ekf_flags", f.get("flags"), ev)
            self._set("ekf_velocity_variance", f.get("velocity_variance"), ev)
            return True
        return False

    def _airborne(self):
        if self.landed_state_seen:
            return
        ctx = self.ctx
        rel = self.value("relative_alt_m")
        gs = self.value("groundspeed_ms") or self.value("ekf_speed_ms")
        if ctx.armed is None:
            return
        ctx.airborne = bool(ctx.armed and ((rel is not None and rel > 1.5) or (gs is not None and gs > 2.0)))
        self.f["airborne"] = Field(ctx.airborne, "derived: armed ∧ (rel_alt>1.5 m ∨ speed>2 m/s)", ctx.t, ctx.mono, "DERIVED")

    def snapshot(self) -> dict:
        now = self.ctx.mono
        out = {}
        for name, fld in self.f.items():
            limit = STALE_S.get(name.split("_")[0], STALE_S["default"])
            if fld.value is None:
                avail = "UNAVAILABLE" if fld.quality != "INVALID" else "INVALID"
            elif fld.quality == "INVALID":
                avail = "INVALID"
            elif now - fld.mono > limit:
                avail = "STALE"
            else:
                avail = "AVAILABLE"
            v = fld.value
            if isinstance(v, float):
                v = round(v, 7 if name in ("lat", "lon", "gps_lat", "gps_lon") else 3)
            out[name] = {"value": v, "source": fld.source, "t": iso_from_epoch(fld.t), "age_s": round(now - fld.mono, 2),
                         "quality": fld.quality, "availability": avail}
        return out
