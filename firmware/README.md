# Fixed PUSHPAK Lua scripts

The build has ArduCopter V4.7.1, git `dbe79216`, board Pixhawk6C. On that build the `ids` binding exposes only these two methods:

* `ids:report_confirmed(name, state, confidence, evidence, metric, instance, sequence)`
* `ids:event_sequence()`

It also has no `ahrs:get_position()`. The original scripts call `ids:<det>_confidence/_evidence/_state()` and `ahrs:get_position()`, so they stop with a runtime error (DISC-001).

## What changed
* **Evidence comes from each script, not from native AP_IDS.** No script reads native AP_IDS state any more. Each `*_confirm.lua` derives its own evidence from standard bindings that are verified to exist in the ELF: `gps`, `ahrs`, `ins`, `rc`, `vehicle`, `arming`, `mission`, `param` and `gcs`.
* **One shared state machine.** All scripts use the same hysteresis state machine in `ids_common.lua`. States are CLEAR 0, SUSPECTED 1 and CONFIRMED 2. Suspected starts at 0.45 and confirmed at 0.78, and confirmed must hold for N cycles.
* **Results are sent two ways:**
  * a `PIDS|1|LUA|<DET>|<state>|<conf>|<evidence>|<metric>|<instance>` STATUSTEXT line for the GCS
  * `ids:report_confirmed(...)`, which feeds the native AP_IDS
* **Unchanged:** the evidence-bit meanings and the `PUSHPAK IDS: <CLASS> conf=… evidence=0x…` / `GPS CONFIRMED …` report formats.
* **`ids_gcs_bridge.lua` works differently now.** It can no longer mirror native detector states. Instead it announces which binding methods are available and reports changes in `ids:event_sequence()` as `PUSHPAK IDS: FC_EVENT seq=… delta=…`.
* **Fixed an existing bug in the GPS script.** `gps:get_hdop()` returns centi-HDOP, so the threshold is now compared correctly.

## Coverage limits
These limits come from the bindings available on this build:
* **MAVLink:** packets aren't visible to Lua. The script judges only the configured GCS's link freshness and intermittency.
* **Commands:** there's no command stream. The script infers from mode/arming changes plus `get_control_mode_reason()` and GCS silence.
* **RC:** there's no RSSI binding. The script classifies RC-loss patterns only.
* **Parameters:** Lua can't see who changed a parameter, so the SOURCE bit is never set.
* **Offboard:** setpoints aren't visible. The script uses GUIDED target-vs-position divergence.

Still note that `AP_IDSGCS::report_confirmed` is a stub (DISC-002). This means `report_confirmed()` currently returns false, but the call itself is valid.

## Verification
Run `backend/tests/test_lua_scripts.py`. It runs every script under Lua 5.4 against strict mocks of this firmware's sandbox. The mocks allow only the binding methods found in the ELF. They also remove `dofile`, restrict `require` to `modules/`, and reject non-integer values for `uint8_t`/`uint16_t` arguments.
* It shows that the original scripts fail.
* It checks that each fixed script stays quiet on benign data.
* It checks that each fixed script confirms its attack scenario, with output parsed by the GCS parser.

## Loading the shared helper (hardware fix)
The firmware's Lua sandbox has no `dofile`; only `require` is available. The original scripts all start with `dofile('/APM/scripts/ids_common.lua')`, so they would stop at line 1.

The firmware's `package.path` (read from the ELF) is:
`@ROMFS/scripts/modules/?.lua;@ROMFS/scripts/modules/?/init.lua;/APM/scripts/modules/?.lua;/APM/scripts/modules/?/init.lua`

To match it:
* The helper now lives at `scripts/modules/ids_common.lua`.
* Every script loads it with `require("ids_common")`.
* The helper is no longer in `scripts/`, so ArduPilot no longer runs it as a standalone script.

`imu_confirm.lua` had a second bug. It passed `8.59` to `ins:gyros_consistent()`, but the binding reads that argument as `uint8_t`. It now passes an integer (`9`).

## Install
Copy the `scripts/` folder, including `scripts/modules/`, to one of these:
* `APM/scripts/` on the SD card
* the ROMFS scripts directory (`@ROMFS/scripts/` and `@ROMFS/scripts/modules/`), then rebuild

Set `SCR_ENABLE=1` and reboot.
