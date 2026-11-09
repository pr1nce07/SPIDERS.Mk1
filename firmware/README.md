# PUSHPAK Lua scripts

All PUSHPAK builds are ArduCopter V4.7.1, git `dbe79216` plus local AP_IDS patches, board Pixhawk6C. Three builds exist, and their `ids` Lua binding differs (see `BUILD_AND_LINKING.md` → *Build history*):

| Build | `ids` binding methods |
|---|---|
| 26 Sep 2026 | 2: `report_confirmed`, `event_sequence` |
| build_v3, 4 Oct 2026 (APJ `223c26f8…`, the one in the technical reference) | 26: the two above plus `<det>_confidence/_evidence/_state()` for all 8 detectors |
| 14 Oct 2026 patch build (APJ `3fab3632…`) | 3: the two above plus `get_channel()` |

These scripts call only the two methods every build has:

* `ids:report_confirmed(name, state, confidence, evidence, metric, instance, sequence)`
* `ids:event_sequence()`

so the same scripts run on all three builds. No build has `ahrs:get_position()` (only `ahrs:get_location()`).

The *original* scripts called `ids:<det>_confidence/_evidence/_state()` and `ahrs:get_position()`. On the 26 Sep build that stopped them with a runtime error (DISC-001, resolved). On build_v3 the accessors exist, but `ahrs:get_position()` would still fail.

## What changed
* **Evidence comes from each script, not from native AP_IDS.** No script reads native AP_IDS state any more. Each `*_confirm.lua` derives its own evidence from standard bindings that are verified to exist in the ELF: `gps`, `ahrs`, `ins`, `rc`, `vehicle`, `arming`, `mission`, `param` and `gcs`.
* **One shared state machine.** All scripts use the same hysteresis state machine in `ids_common.lua`. States are CLEAR 0, SUSPECTED 1 and CONFIRMED 2. Suspected starts at 0.45 and confirmed at 0.78, and confirmed must hold for N cycles.
* **Results are sent two ways:**
  * a `PIDS|1|LUA|<DET>|<state>|<conf>|<evidence>|<metric>|<instance>` STATUSTEXT line for the GCS
  * `ids:report_confirmed(...)`, which feeds the native AP_IDS
* **Unchanged:** the evidence-bit meanings and the `PUSHPAK IDS: <CLASS> conf=… evidence=0x…` / `GPS CONFIRMED …` report formats.
* **`ids_gcs_bridge.lua` works differently now (protocol v2).** It does not mirror native detector states, because not every build has the accessors. Instead it reports changes in `ids:event_sequence()` as `PUSHPAK IDS: FC_EVENT seq=… delta=…`. It announces `BRIDGE … v=2` and `STATEMAP` at start, whenever the GCS (re)connects and every 60 s, and sends `SYNC up=… seq=… ev=…` every 10 s so the GCS can see reboots and missed events.
* **Fixed an existing bug in the GPS script.** `gps:get_hdop()` returns centi-HDOP, so the threshold is now compared correctly.

## Coverage limits
These limits come from the standard ArduPilot bindings, which are the same on all three builds (checked in the build_v3 ELF):
* **MAVLink:** packets aren't visible to Lua. The script judges only the configured GCS's link freshness and intermittency.
* **Commands:** there's no command stream. The script infers from mode/arming changes plus `get_control_mode_reason()` and GCS silence.
* **RC:** there's no RSSI binding. The script classifies RC-loss patterns only.
* **Parameters:** Lua can't see who changed a parameter, so the SOURCE bit is never set.
* **Offboard:** setpoints aren't visible. The script uses GUIDED target-vs-position divergence.

`ids:report_confirmed()` returns false on the 26 Sep build, where `AP_IDSGCS::report_confirmed` was a stub (DISC-002, resolved). On build_v3 and the 14 Oct build it is implemented. The scripts ignore the return value either way, so their STATUSTEXT output is the same.

## Verification
Run `backend/tests/test_lua_scripts.py` (needs the `lupa` package). It runs every script under Lua 5.4 against strict mocks of the firmware's sandbox. The mocks allow only the methods the scripts may rely on: the two `ids` methods and the standard bindings listed above. They also remove `dofile`, restrict `require` to `modules/`, and reject non-integer values for `uint8_t`/`uint16_t` arguments.
* It shows that the original scripts fail on the 26 Sep binding. This test is skipped unless the original `ROMFS_custom.zip` is present.
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

**Note (DISC-005):** build_v3 embeds older ROMFS copies of `command_confirm.lua`, `ids_gcs_bridge.lua`, `jamming_confirm.lua`, `mavlink_confirm.lua`, `offboard_confirm.lua` and `modules/ids_common.lua` (the last differs only in a comment). An SD-card copy does not replace a ROMFS script; the firmware runs both. Either put the current scripts on the SD card **and set `SCR_DIR_DISABLE=1`** so ROMFS scripts are skipped (`BUILD_AND_LINKING.md` §4), or rebuild the firmware with `ROMFS_custom_fixed.zip`.
