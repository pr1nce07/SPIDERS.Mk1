"""Lua 5.4 runtime that mimics the Pixhawk6C ArduCopter V4.7.1 (dbe79216) scripting
sandbox: only binding methods present in the ELF exist, `dofile` is absent,
`require` searches scripts/modules, and uint8/uint16 arguments must be integers.

Used by the tests and by `LuaFlightBridge`, which runs the real PUSHPAK Lua
scripts against simulated vehicle state and turns everything they print with
gcs:send_text() into genuine MAVLink STATUSTEXT frames from the vehicle.
"""
from __future__ import annotations

import math
from pathlib import Path

try:
    import lupa.lua54 as lupa
except Exception:  # optional dependency
    lupa = None

SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "firmware" / "scripts"

HARNESS = r"""
W = {now=0, texts={}, reports={}, seq=0,
     gps_n=0, gps_e=0, ekf_n=0, ekf_e=0, gps_v=8, ekf_v=8, vel_var=0.05, pos_var=0.05,
     gcs_last=1, rc_valid=true, mode=3, flying=true, armed=true, reason=0,
     acc_off=0, gyr_off=0, mission_n=5, mission_shift=0, nav_index=1, params={}, target_off=0}

local function strict(name, methods)
  local obj = {}
  return setmetatable(obj, {__index=function(_, k)
    if methods[k] then return methods[k] end
    error(string.format("attempt to call a nil value (method '%s') on %s", k, name), 2)
  end})
end

local V = {}
V.__index = {length=function(self) return math.sqrt(self.x^2+self.y^2+self.z^2) end}
V.__sub = function(a,b) return setmetatable({x=a.x-b.x,y=a.y-b.y,z=a.z-b.z}, V) end
local function vec(x,y,z) return setmetatable({x=x,y=y,z=z}, V) end
local L = {}
L.__index = {get_distance=function(a,b) return math.sqrt((a.n-b.n)^2+(a.e-b.e)^2) end}
local function loc(n,e) return setmetatable({n=n,e=e}, L) end
local U = {}; U.__index = {toint=function(self) return self.v end}
local function u32(v) return setmetatable({v=v}, U) end

function millis() return u32(W.now) end

ids = strict("ids", {
  report_confirmed=function(_, name, state, conf, ev, metric, inst, seq)
    assert(type(name)=="string" and math.type(state)=="integer" and state>=0 and state<=255)
    assert(ev>=0 and ev<=65535); W.seq = W.seq + 1
    W.reports[#W.reports+1] = {name=name, state=state, conf=conf, ev=ev}; return false end,
  event_sequence=function(_) return u32(W.seq) end})
gps = strict("gps", {primary_sensor=function() return 0 end, status=function() return 3 end,
  location=function(_, i) return loc(W.gps_n, W.gps_e) end, velocity=function() return vec(W.gps_v,0,0) end,
  horizontal_accuracy=function() return 1.2 end, num_sats=function() return 14 end, get_hdop=function() return 80 end,
  num_sensors=function() return 1 end})
ahrs = strict("ahrs", {get_location=function() return loc(W.ekf_n, W.ekf_e) end, get_velocity_NED=function() return vec(W.ekf_v,0,0) end,
  get_variances=function() return true, W.vel_var, W.pos_var, 0.05, vec(0,0,0), 0 end})
ins = strict("ins", {get_accel=function(_, i) return vec(0 + (i==1 and W.acc_off or 0), 0, -9.8) end,
  get_gyro=function(_, i) return vec(0 + (i==1 and W.gyr_off or 0), 0, 0) end,
  get_accel_health=function() return true end, get_gyro_health=function() return true end,
  accels_consistent=function() return W.acc_off < 3 end, gyros_consistent=function() return W.gyr_off < 0.15 end})
gcs = strict("gcs", {send_text=function(_, sev, t) W.texts[#W.texts+1] = t end,
  last_seen=function() return u32(W.gcs_last) end})  -- Lua name of GCS::sysid_mygcs_last_seen_time_ms (bindings.desc rename)
rc = strict("rc", {has_valid_input=function() return W.rc_valid end})
vehicle = strict("vehicle", {get_mode=function() return W.mode end, get_likely_flying=function() return W.flying end,
  get_control_mode_reason=function() return W.reason end,
  get_target_location=function() if W.target_n then return loc(W.target_n, W.target_e) end return loc(100 + W.target_off, 0) end})
arming = strict("arming", {is_armed=function() return W.armed end})
local MI = {}
MI.__index = {command=function(s) return 16 end, x=function(s) return s.i*1000 + W.mission_shift end, y=function(s) return s.i end,
  z=function() return 20 end, param1=function() return 0 end, param2=function() return 0 end}
mission = strict("mission", {num_commands=function() return W.mission_n end,
  get_item=function(_, i) return setmetatable({i=i}, MI) end, get_current_nav_index=function() return W.nav_index end})
param = strict("param", {get=function(_, n) return W.params[n] end})

-- ArduPilot sandbox: no dofile/loadfile; require() searches scripts/modules only
-- (firmware package.path: @ROMFS/scripts/modules/?.lua;...;/APM/scripts/modules/?.lua)
dofile = nil
loadfile = nil
package.path = SCRIPT_DIR .. "/modules/?.lua;" .. SCRIPT_DIR .. "/modules/?/init.lua"
package.cpath = ""

-- the C bindings reject non-integers for uint8_t/uint16_t arguments
local function u8(v, what) if math.type(v) ~= "integer" or v < 0 or v > 255 then error("bad argument (uint8) to " .. what, 3) end end
local function u16(v, what) if math.type(v) ~= "integer" or v < 0 or v > 65535 then error("bad argument (uint16) to " .. what, 3) end end
local function wrap(obj, name, spec)
  local mt = getmetatable(obj)
  local idx = mt.__index
  mt.__index = function(t, k)
    local f = idx(t, k)
    local kinds = spec[k]
    if not kinds then return f end
    return function(self, ...)
      local args = {...}
      for i, kind in ipairs(kinds) do
        if kind == "u8" then u8(args[i], name .. ":" .. k) elseif kind == "u16" then u16(args[i], name .. ":" .. k) end
      end
      return f(self, ...)
    end
  end
end
wrap(ins, "ins", {get_accel={"u8"}, get_gyro={"u8"}, get_accel_health={"u8"}, get_gyro_health={"u8"}, gyros_consistent={"u8"}})
wrap(gps, "gps", {status={"u8"}, location={"u8"}, velocity={"u8"}, horizontal_accuracy={"u8"}, num_sats={"u8"}, get_hdop={"u8"}})
wrap(mission, "mission", {get_item={"u16"}})
wrap(ids, "ids", {report_confirmed={"s", "u8", "f", "u16", "f", "u8"}})
"""


class LuaScript:
    """One ArduPilot script in its own Lua state (the `update, delay` protocol)."""

    def __init__(self, name: str, directory: Path = SCRIPTS_DIR):
        if lupa is None:
            raise RuntimeError("lupa (Lua 5.4) is not installed")
        self.name = name
        self.lua = lupa.LuaRuntime(unpack_returned_tuples=True)
        self.lua.globals().SCRIPT_DIR = str(directory)
        self.lua.execute(HARNESS)
        self.W = self.lua.globals().W
        fn, first = self.lua.execute((directory / name).read_text())
        self.fn = fn
        self.next_ms = int(first)
        self.error: str | None = None

    def step_until(self, now_ms: int) -> None:
        """Run every scheduled update whose time has come (ArduPilot scheduler semantics)."""
        while self.error is None and self.next_ms <= now_ms:
            self.W.now = self.next_ms
            try:
                fn, delay = self.fn()
            except Exception as exc:  # ArduPilot stops a script on a runtime error
                self.error = str(exc).splitlines()[0][:200]
                return
            self.fn = fn
            self.next_ms += int(delay)

    def drain_texts(self) -> list[tuple[int, str]]:
        out = [(0, self.W.texts[i]) for i in range(1, len(self.W.texts) + 1)]
        self.lua.execute("W.texts = {}")
        return out

    def drain_reports(self) -> list[dict]:
        out = [dict(self.W.reports[i]) for i in range(1, len(self.W.reports) + 1)]
        self.lua.execute("W.reports = {}")
        return out


DEFAULT_SCRIPTS = ["gps_confirm.lua", "mavlink_confirm.lua", "command_confirm.lua", "jamming_confirm.lua", "imu_confirm.lua",
                   "mission_confirm.lua", "parameter_confirm.lua", "offboard_confirm.lua", "ids_gcs_bridge.lua"]


class LuaFlightBridge:
    """Runs the PUSHPAK Lua scripts 'on board' a FlightSimulator.

    Each 100 ms of sim time the vehicle state is copied into the Lua binding
    mocks, due scripts run, and their gcs:send_text() output is packed as
    (chunked) MAVLink STATUSTEXT by the simulated vehicle, so the GCS receives
    exactly what a Pixhawk would send.
    """

    def __init__(self, sim, scripts=DEFAULT_SCRIPTS, directory: Path = SCRIPTS_DIR):
        self.sim = sim
        self.scripts = [LuaScript(n, directory) for n in scripts]
        self.reports: list[dict] = []
        self.texts: list[tuple[float, str, str]] = []
        self._native_seq = 0

    def _sync(self, W, now_ms: int) -> None:
        s = self.sim
        spd = math.hypot(s.vn, s.ve)
        W.now = now_ms
        W.gps_n, W.gps_e = s.n + s.gps_off_n, s.e + s.gps_off_e
        W.ekf_n, W.ekf_e = s.n, s.e + 0.3 * s.gps_off_e
        W.gps_v = s.gps_vel_override if s.gps_vel_override is not None else spd
        W.ekf_v = spd
        W.vel_var, W.pos_var = s.ekf_var, s.ekf_pos_var
        W.gcs_last = now_ms          # the configured GCS (SYSID 255) heartbeats at 1 Hz throughout
        W.rc_valid = not s.rc_unhealthy
        W.mode, W.reason = int(s.mode), int(s.mode_reason)
        W.flying = s.alt > 0.5
        W.armed = bool(s.armed)
        W.nav_index = int(s.mission_seq)
        W.target_n, W.target_e = (0.0, 0.0) if s.mode == 4 else (s.n, s.e)  # GUIDED target = takeoff point
        if getattr(s, "mission_override", False):
            W.mission_n, W.mission_shift = 3, int(round(500 * s.mag))
        else:
            W.mission_n, W.mission_shift = int(s.mission_len), 0
        for k, v in s.params.items():
            W.params[k] = float(v)

    def _hook(self, sim) -> list[tuple[int, str]]:
        t = sim.t
        if t + 1e-9 < self._next_tick:
            return []
        self._next_tick = t + 0.1
        now_ms = int(t * 1000)
        out = []
        for sc in self.scripts:
            self._sync(sc.W, now_ms)
            sc.step_until(now_ms)
            for _, text in sc.drain_texts():
                self.texts.append((sim.t0 + t, sc.name, text))
                out.append((4 if text.startswith("PUSHPAK IDS:") and "BRIDGE" not in text else 6, text))
            for r in sc.drain_reports():
                self.reports.append({"t": sim.t0 + t, "script": sc.name, **r})
        return out

    def frames(self):
        """The simulator's frames, with Lua STATUSTEXT packed in-order by the vehicle."""
        self._next_tick = 0.0
        self.sim.step_hook = self._hook
        yield from self.sim.frames()

    def errors(self) -> dict:
        return {s.name: s.error for s in self.scripts if s.error}
