# PUSHPAK firmware — build & script linking

How the **compiled firmware** (native AP_IDS in C++) and the **Lua confirmation scripts**
fit together, and how to link the scripts to a build — either by copying to the SD card
(no rebuild) or by baking them into the firmware image (rebuild).

Target build (verified from the supplied artifacts): **ArduCopter V4.7.1, git `dbe79216`,
board Pixhawk6C**. See `../configs/capabilities.json` for the machine-checked facts.

---

## 1. The two firmware pieces and how they link

```
        ┌──────────────────────────── FLIGHT CONTROLLER (Pixhawk 6C) ────────────────────────────┐
        │                                                                                          │
        │   libraries/AP_IDS/  (native C++, first stage)          AP_Scripting  (Lua, second stage)│
        │   ┌───────────────────────────┐                         ┌──────────────────────────────┐│
        │   │ AP_IDS.cpp   AP_IDSGCS.cpp │      Lua binding        │ scripts/*_confirm.lua         ││
        │   │ GPSDetector  IMUDetector   │◄──────────────────────►│ scripts/modules/ids_common.lua││
        │   │ MAVLinkDetector Mission…   │  ids:report_confirmed()│                                ││
        │   │ Command/Param/RC/Offboard  │  ids:event_sequence()  │ standard bindings:            ││
        │   └─────────────┬──────────────┘                         │  gps: ahrs: ins: rc: vehicle:││
        │                 │ AP_IDSGCS (STATUSTEXT)                  │  arming: mission: param: gcs:││
        │                 ▼                                         └───────────────┬──────────────┘│
        │           MAVLink STATUSTEXT  ◄──────── gcs:send_text()  (PIDS / PUSHPAK IDS lines) ──────┘
        └─────────────────┬────────────────────────────────────────────────────────────────────────┘
                          │  telemetry link (UDP/TCP/serial)
                          ▼
                   SPIDERS.Mk1 GCS  (parses PIDS|… and PUSHPAK IDS: … lines)
```

**The link between the two is the `ids` Lua binding.** ArduPilot's scripting generator
turns a *binding descriptor* into C++ glue (`libraries/AP_Scripting/lua_generated_bindings.cpp`)
so Lua can call into the `AP_IDS` singleton. On the supplied build that binding exposes
**only two methods** (confirmed from the ELF symbol table):

| Lua call | C++ target | Purpose |
|---|---|---|
| `ids:report_confirmed(name,state,conf,evidence,metric,instance,seq)` | `AP_IDS::report_confirmed(...)` | Lua pushes a confirmed result back into native AP_IDS |
| `ids:event_sequence()` | `AP_IDS::event_sequence()` | native event counter Lua can read |

The per-detector accessors the original scripts assumed (`ids:gps_confidence()`,
`ids:gps_state()`, …) **do not exist** in this binding, so the scripts here don't use them —
they derive their own evidence from the standard `gps:`/`ahrs:`/`ins:`/… bindings. See
`README.md` in this folder for the per-script detail.

---

## 2. What's in the supplied build (`shareable_progress/build.zip`)

This is a **compiled artifact**, not a source tree — you can flash it, but you can't
`waf`-build from it alone.

```
build/Pixhawk6C/
├── bin/arducopter.apj          ← flashable image (Mission Planner / QGC / uploader)
├── bin/arducopter.bin          ← raw binary
├── bin/arducopter              ← ELF (used for source-of-truth discovery)
├── ap_romfs_embedded.h         ← the scripts CURRENTLY baked into ROMFS (the OLD, broken ones)
└── libraries/AP_IDS/*.o        ← compiled native detectors:
        AP_IDS  AP_IDSGCS  GPSDetector  IMUDetector  MAVLinkDetector
        MissionDetector  CommandDetector  ParameterDetector  RCDetector  OffboardDetector
```

Two facts that decide how you link the scripts:

* **The old scripts are embedded in this image's ROMFS** (`ap_romfs_embedded.h`). If you
  drop new scripts on the SD card without disabling ROMFS scripts, the firmware runs
  **both**, and the old ROMFS ones fail with `dofile`/nil-method errors.
* **`AP_IDSGCS::report_confirmed` is a stub returning `false`** on this build (DISC-002).
  `ids:report_confirmed(...)` is a valid call, but native → GCS reporting does nothing
  until firmware is rebuilt with a real transport. The scripts' own `gcs:send_text()`
  STATUSTEXT lines reach the GCS regardless.

---

## 3. Scripts in this folder

```
firmware/
├── scripts/
│   ├── gps_confirm.lua        mavlink_confirm.lua    command_confirm.lua
│   ├── jamming_confirm.lua    imu_confirm.lua        mission_confirm.lua
│   ├── parameter_confirm.lua  offboard_confirm.lua   ids_gcs_bridge.lua
│   └── modules/
│       └── ids_common.lua     ← shared helpers + hysteresis state machine (require()d)
└── ROMFS_custom_fixed.zip     ← the same tree, zipped, ready to drop into ROMFS
```

`ids_common.lua` **must** live in `scripts/modules/` (not next to the scripts). ArduPilot
runs every `.lua` in `scripts/` as a standalone script, and its `package.path` for
`require()` is `@ROMFS/scripts/modules/?.lua;…;/APM/scripts/modules/?.lua`. Each script
loads it with `require("ids_common")` (this firmware has no `dofile`).

---

## 4. Link path A — SD card (no rebuild, recommended for testing)

Fastest way to run the fixed scripts on the existing firmware.

1. Power off, remove the microSD card, and copy the tree so the card contains:

   ```
   APM/scripts/
       gps_confirm.lua  mavlink_confirm.lua  command_confirm.lua  jamming_confirm.lua
       imu_confirm.lua  mission_confirm.lua  parameter_confirm.lua  offboard_confirm.lua
       ids_gcs_bridge.lua
       modules/
           ids_common.lua
   ```

2. Set parameters (Mission Planner / QGroundControl → Config → Full Parameter List):

   | Parameter | Value | Why |
   |---|---|---|
   | `SCR_ENABLE` | `1` | enable Lua scripting |
   | `SCR_DIR_DISABLE` | `1` | **skip the OLD scripts baked into ROMFS** (critical — see §2) |
   | `SCR_HEAP_SIZE` | raise if you see `not enough mem, increase SCR_HEAP_SIZE` | 9 scripts need more than the default heap |

3. Reboot the flight controller.

4. Verify (GCS messages tab): you should see
   `PUSHPAK IDS: BRIDGE binding=report_confirmed,event_sequence` and **no** `Lua: … error`
   lines. In SPIDERS.Mk1, the IDS page shows the scripts as RUNNING under Lua script health.

No firmware rebuild is needed; ArduPilot loads SD-card scripts at boot.

---

## 5. Link path B — bake into the firmware (ROMFS, needs a rebuild)

Use this when you want the scripts inside the flashed image (no SD dependency), or to
also fix the native side (the `AP_IDSGCS` stub and the un-wired detectors).

You need the **ArduPilot source tree at the exact commit** `dbe79216` (the supplied
`build.zip` is a compiled artifact and can't be built from):

```bash
git clone https://github.com/ArduPilot/ardupilot
cd ardupilot && git checkout dbe79216
git submodule update --init --recursive
```

1. **Place the AP_IDS library and scripts** in the tree:
   * `libraries/AP_IDS/` — the native detector sources (the same ones compiled in `build.zip`).
   * `libraries/AP_IDS/ROMFS/scripts/` (or the board's ROMFS scripts dir) — copy this
     folder's `scripts/` **including `modules/`**, replacing the old scripts.
2. **Link the Lua binding** (from the project's integration artifacts, per `VALIDATION.md`):
   ```
   git apply ArduCopter_IDS_integration.patch      # registers AP_IDS + hooks AP_IDS::update()
   cat AP_IDS_bindings.desc.append >> libraries/AP_Scripting/generator/description/bindings.desc
   ```
   The appended lines declare the `ids` singleton and its methods; `waf` regenerates
   `lua_generated_bindings.cpp`. To also expose the per-detector accessors, add them here.
3. **Build** (SITL first to validate, then the board):
   ```bash
   ./waf configure --board sitl && ./waf copter        # test in SITL
   ./waf configure --board Pixhawk6C && ./waf copter    # → build/Pixhawk6C/bin/arducopter.apj
   ```
   With scripts in ROMFS, `ap_romfs_embedded.h` is regenerated with the **new** scripts,
   so you don't need `SCR_DIR_DISABLE`. Still set `SCR_ENABLE=1`.
4. **Flash** `build/Pixhawk6C/bin/arducopter.apj` and reboot.

Recommended production sequence (from `VALIDATION.md`): apply patch → append binding desc →
`./waf distclean` → build SITL → install scripts → wire remaining native adapters → replay
benign+attack traces and tune thresholds → build for Pixhawk6C and check flash/RAM deltas →
HIL/bench test before flight.

---

## 6. Verify the link (SITL, no hardware)

```bash
# build & run SITL with scripting + the scripts (path B), or point SITL at SD-style scripts:
Tools/autotest/sim_vehicle.py -v ArduCopter --out=udp:127.0.0.1:14550
# then connect the GCS:  SPIDERS.Mk1 → Connection → udp:127.0.0.1:14550
```

Offline, run the script test harness (Lua 5.4 with firmware-accurate binding mocks):

```bash
cd ../backend && PYTHONPATH=. ../.venv/bin/python -m pytest -q tests/test_lua_scripts.py
```

It proves the original scripts fail on this binding, each fixed script stays quiet on
benign data and confirms its attack, and the GCS parses their output.

---

## 7. Firmware discrepancies to keep in mind (from `configs/capabilities.json`)

| ID | Finding | Effect on linking |
|---|---|---|
| DISC-001 | old scripts call non-existent `ids:*` accessors | fixed here; use these scripts |
| DISC-002 | `AP_IDSGCS::report_confirmed` is a stub | native→GCS path silent until rebuilt (path B); Lua STATUSTEXT still works |
| DISC-003 | `AP_IDS::update()` drives only GPS/IMU/Mission | other native detectors need wiring (path B, step 2) |
| DISC-004 | PIDS state int→name mapping unverified | GCS labels 0/1/2 as CLEAR/SUSPECTED/CONFIRMED with an "unverified" flag |

---

## 8. File map (quick reference)

| File / dir | Role |
|---|---|
| `scripts/*_confirm.lua` | eight per-detector Lua confirmation scripts (second stage) |
| `scripts/ids_gcs_bridge.lua` | announces binding + reports native `event_sequence()` changes |
| `scripts/modules/ids_common.lua` | shared helpers + hysteresis state machine |
| `ROMFS_custom_fixed.zip` | zipped copy of `scripts/` for ROMFS drop-in |
| `README.md` | what each script detects and why (the fix detail) |
| `../configs/capabilities.json` | machine-checked firmware facts + discrepancies |
| `shareable_progress/build.zip` | the compiled firmware artifact (flashable, not buildable) |
