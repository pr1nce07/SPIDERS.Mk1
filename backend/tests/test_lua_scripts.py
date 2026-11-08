"""Run the PUSHPAK Lua scripts under Lua 5.4 against strict mocks that expose ONLY
the scripting bindings present in the supplied Pixhawk6C ArduCopter V4.7.1
(dbe79216) ELF. Calling any other method (e.g. ids:gps_confidence(),
ahrs:get_position()) raises, reproducing the runtime failure of the original
scripts. The emitted STATUSTEXT is parsed with the GCS's own parser."""
from pathlib import Path

import pytest

lupa = pytest.importorskip("lupa.lua54")

from app.mavlink.pushpak import parse_statustext  # noqa: E402
from app.lua_runtime import HARNESS  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
FIXED = ROOT / "firmware" / "scripts"

# Methods verified in the ELF symbol table (_ZL..<Class>_<method>P9lua_State)
ALLOWED = {
    "ids": ["report_confirmed", "event_sequence"],
    "gps": ["primary_sensor", "status", "location", "velocity", "horizontal_accuracy", "num_sats", "get_hdop", "num_sensors"],
    "ahrs": ["get_location", "get_velocity_NED", "get_variances"],
    "ins": ["get_accel", "get_gyro", "get_accel_health", "get_gyro_health", "accels_consistent", "gyros_consistent"],
    "gcs": ["send_text", "sysid_mygcs_last_seen_time_ms"],
    "rc": ["has_valid_input"],
    "vehicle": ["get_mode", "get_likely_flying", "get_control_mode_reason", "get_target_location"],
    "arming": ["is_armed"],
    "mission": ["num_commands", "get_item", "get_current_nav_index"],
    "param": ["get"],
}




class Script:
    def __init__(self, name: str, directory: Path = FIXED):
        self.lua = lupa.LuaRuntime(unpack_returned_tuples=True)
        self.lua.globals().SCRIPT_DIR = str(directory)
        self.lua.execute(HARNESS)
        self.W = self.lua.globals().W
        for k, v in {"FENCE_ENABLE": 1.0, "ARMING_CHECK": 1.0, "RTL_ALT": 1500.0, "WPNAV_SPEED": 800.0}.items():
            self.W.params[k] = v
        fn, first = self.lua.execute((directory / name).read_text())
        self.fn = fn
        self.W.now = first

    def run(self, seconds: float, step=None):
        end = self.W.now + seconds * 1000
        while self.W.now < end:
            if step:
                step(self.W)
            fn, delay = self.fn()
            self.fn = fn
            self.W.now = self.W.now + delay

    def texts(self) -> list[str]:
        return [self.W.texts[i] for i in range(1, len(self.W.texts) + 1)]

    def parsed(self) -> list[dict]:
        return [r for r in (parse_statustext(t) for t in self.texts()) if r]

    def confirmed(self, det: str) -> bool:
        return any(r["kind"] == "LUA_CONFIRMATION" and r["detector"] == det for r in self.parsed()) and \
            any(r["kind"] == "PIDS" and r["origin"] == "LUA" and r["detector"] == det and r["state"] == "CONFIRMED" for r in self.parsed())


def test_original_scripts_fail_on_this_binding():
    orig = ROOT.parent / "shareable_progress" / "ROMFS_custom.zip"
    if not orig.exists():
        pytest.skip("original ROMFS not present")
    import tempfile
    import zipfile
    with tempfile.TemporaryDirectory() as d:
        zipfile.ZipFile(orig).extractall(d)
        sd = Path(d) / "ROMFS_custom" / "scripts"
        # fails immediately: dofile is not available in the ArduPilot sandbox
        with pytest.raises(Exception, match="dofile"):
            Script("gps_confirm.lua", sd).run(3)
        # even with the helper reachable, the missing binding methods fail
        with pytest.raises(Exception, match="gps_confidence|get_position"):
            Script("ids_gcs_bridge.lua", sd).run(3)


@pytest.mark.parametrize("name", [p.name for p in sorted(FIXED.glob("*_confirm.lua"))] + ["ids_gcs_bridge.lua"])
def test_benign_run_is_quiet(name):
    s = Script(name)
    s.run(60)  # strict mocks raise on any non-existent binding method
    assert not any(r["kind"] == "LUA_CONFIRMATION" for r in s.parsed()), s.texts()


def test_gps_spoof_confirmed():
    s = Script("gps_confirm.lua")
    s.run(10)
    s.run(20, lambda W: (setattr(W, "gps_n", W.gps_n + 0.2), setattr(W, "gps_v", 14.0), setattr(W, "vel_var", 0.9)))
    assert s.confirmed("GPS")
    assert any(r["name"] == "GPS" and r["state"] == 2 for r in s.W.reports.values())


def test_mavlink_intermittent_link():
    s = Script("mavlink_confirm.lua")
    def step(W):
        W.gcs_last = W.gcs_last if (W.now % 12000) >= 4000 else W.now  # 4 s on / 8 s off
    s.run(60, step)
    assert s.confirmed("MAVLINK")


def test_command_mode_change_from_other_sender():
    s = Script("command_confirm.lua")
    s.run(5, lambda W: setattr(W, "gcs_last", W.now))
    s.W.gcs_last = 1           # configured GCS silent
    s.W.reason, s.W.mode = 2, 9  # GCS_COMMAND → LAND while flying
    s.run(3)
    assert s.confirmed("COMMAND")


def test_rc_intermittent_loss():
    s = Script("jamming_confirm.lua")
    s.run(40, lambda W: (setattr(W, "rc_valid", (W.now // 4000) % 2 == 0), setattr(W, "gcs_last", W.now)))
    assert s.confirmed("RC_LINK")


def test_imu_divergence():
    s = Script("imu_confirm.lua")
    s.run(5)
    s.W.acc_off = 6.0
    s.run(10)
    assert s.confirmed("IMU")


def test_mission_change_in_flight():
    s = Script("mission_confirm.lua")
    s.run(5)
    s.W.mission_shift, s.W.mission_n, s.W.nav_index = 500, 3, 1
    s.run(3)
    s.W.nav_index = 0
    s.run(5)
    assert s.confirmed("MISSION")


def test_parameter_change_while_armed():
    s = Script("parameter_confirm.lua")
    s.run(3)
    s.W.params["FENCE_ENABLE"] = 0.0
    s.W.params["ARMING_CHECK"] = 0.0
    s.W.params["WPNAV_SPEED"] = 2000.0
    s.run(3)
    assert s.confirmed("PARAMETER")


def test_offboard_divergence():
    s = Script("offboard_confirm.lua")
    s.run(3, lambda W: setattr(W, "gcs_last", W.now))
    s.W.gcs_last, s.W.reason, s.W.mode = 1, 2, 4   # GUIDED entered by a GCS command while the configured GCS is silent
    s.run(3)
    s.run(12, lambda W: setattr(W, "target_off", W.target_off + 1))
    assert s.confirmed("OFFBOARD")


def test_bridge_reports_native_events():
    s = Script("ids_gcs_bridge.lua")
    s.run(3)
    s.W.seq = 5
    s.run(2)
    kinds = [r["kind"] for r in s.parsed()]
    assert "BRIDGE" in kinds and "FC_EVENT" in kinds


def test_layout_matches_firmware_module_path():
    assert (FIXED / "modules" / "ids_common.lua").exists()
    assert not (FIXED / "ids_common.lua").exists(), "helper in scripts/ would be run as a standalone script"
    for f in FIXED.glob("*.lua"):
        src = f.read_text()
        assert "dofile" not in src and 'require("ids_common")' in src, f.name
