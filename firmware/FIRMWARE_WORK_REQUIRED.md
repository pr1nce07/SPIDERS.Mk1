# PUSHPAK / AP_IDS — firmware work required

This document lists the firmware changes needed to close the onboard gaps in *SPIDERS_Mk1_Gap_Analysis_and_Implementation_Blueprint.md*. The GCS side of every item is already implemented in this repository. Where a wire format is given here, the GCS already parses it and has tests for it (`backend/tests/test_firmware_contract.py`). Treat those formats as the contract: if the firmware needs a different layout, change both sides together.

**Baseline:** ArduCopter 4.7.1, commit `dbe79216`, Pixhawk 6C (STM32H743), native `libraries/AP_IDS/` plus the Lua scripts in `firmware/scripts/`. The `AP_IDS` C++ source is **not** in this repository. Every file and function name below must be checked against your fork at the pinned commit, not against ArduPilot `master`.

**Rule for every item:** the IDS stays passive. No firmware change may modify, drop or delay a MAVLink message, or change mode, arming, navigation, actuator output or failsafe behaviour. Item FW-12 adds a check that enforces this.

---

## Summary

| ID | Work item | Gap | Priority | GCS side |
|---|---|---|---|---|
| FW-00 | Release baseline: APJ/ELF/source/ROMFS identity | GAP-14 | P0 | `scripts/make_release_manifest.py` ready |
| FW-01 | Bench + HITL validation and timing instrumentation | GAP-01 | P0 | `IDST` record format below; evaluation harness ready |
| FW-02 | Resolve PreArm `flow_of_ctrl` | GAP-03 | P0 | — |
| FW-03 | Native DataFlash IDS records `IDSE/IDSH/IDSC/IDSF` | GAP-05 | P1 | **Parses `IDSE/IDSH/IDSF` today** |
| FW-04 | Passive `PARAM_SET` receive hook + `IDSW` record | GAP-06 | P1 | **Parses `IDSW` today** (sender, result) |
| FW-05 | Accepted offboard setpoint observation + `IDSO` record | GAP-10 | P1 | Format reserved; consumer to add |
| FW-06 | Boot ID, event sequence, ring overflow, PIDS v2 | GAP-07 | P1 | **Parses PIDS v2 and SYNC `boot=`/`drop=` today** |
| FW-07 | ROMFS drift (DISC-005), binding choice, missing Lua inputs | GAP-07/breadth | P1 | Bridge v2 already shipped in `firmware/scripts` |
| FW-08 | MAVLink signing on the vehicle: provisioning, policy, replay | GAP-08 | P1 | Keyring, export file and per-link policy ready |
| FW-09 | Onboard approved-baseline check, replacing FNV-1a | GAP-11 | P1 | Signed GCS baseline ready |
| FW-10 | Firmware root of trust, signed update, anti-rollback, recovery | GAP-04 | P0 | Release key and manifest ready |
| FW-11 | Independent navigation evidence (second GNSS, streams) | GAP-09 | P1 | `GNSS2` lineage group ready |
| FW-12 | Safety invariants, fault-injection build, CI checks | GAP-01/03, SAFE-01 | P0 | — |

Recommended order (it follows the blueprint's sprints): FW-00 → FW-02 → FW-12 → FW-01 → FW-06 → FW-03 → FW-04 → FW-05 → FW-07 → FW-08 → FW-10 → FW-09 → FW-11.

---

## FW-00 — Release baseline and identity (Sprint 0, GAP-14)

**Problem.** Three PUSHPAK builds exist, and no artifact in this repository is the release:

| Build | APJ SHA-256 | Notes |
|---|---|---|
| 26 Sep 2026 | — | 2-method binding, stub `report_confirmed`, 3 of 8 detectors driven (the old DISC-001–004) |
| build_v3, 4 Oct 2026 | `223c26f8…` | The technical reference's image. 26-method binding, all 8 detectors driven, `report_confirmed` implemented, state enum pinned by `static_assert`s. `configs/capabilities.json` was regenerated from it on 9 Nov 2026. Its ROMFS embeds older copies of 6 scripts (DISC-005). |
| 14 Oct 2026 patch build | `3fab3632…` | `pushpak_ap_ids_Copter-4.7.1.patch`: all 8 detectors, real `report_confirmed`, but a 3-method binding (`get_channel` instead of the 24 accessors) |

The build_v3 tree also has uncommitted changes outside AP_IDS (`git status` shows modified `Tools/` scripts), so even it is not tied to a clean, reviewed commit.

**Do:**
1. Pick the exact APJ/ELF pair under test. Archive the ArduPilot source at that commit, **including** `libraries/AP_IDS/`, every local patch and submodule revisions (`git submodule status`).
2. Rebuild the ROMFS with the current scripts. `firmware/ROMFS_custom_fixed.zip` was regenerated on 2026-11-09 from `firmware/scripts/` (bridge protocol v2), and the firmware image must embed exactly this package:
   ```bash
   python scripts/make_release_manifest.py --rebuild-romfs --version <ver>
   ```
3. Generate the signed manifest from the real binaries:
   ```bash
   python scripts/make_release_manifest.py --version <ver> --apj build/Pixhawk6C/bin/arducopter.apj --elf build/Pixhawk6C/bin/arducopter --source-archive ardupilot-<commit>-pushpak.tar.gz --patch "AP_IDS: <summary>" --patch "..."
   ```
4. Extract the ROMFS from the built ELF and confirm it is byte-identical to the package. Re-run `scripts/discover_firmware.py --build-zip … --romfs-zip firmware/ROMFS_custom_fixed.zip --ap-ids-source <tree>/libraries/AP_IDS` against the release build so `configs/capabilities.json` matches the binding actually compiled in, with no DISC-005.
5. Replace `BUILD_AND_LINKING.md` and the technical reference's version tables with a pointer to `release/manifest.json`.

**Done when:** `make_release_manifest.py` reports `release_ready: true`, the project is under version control, and every test report cites `gcs_tree_sha256` and the APJ/ELF SHA-256 values.

---

## FW-01 — Bench and HITL validation (GAP-01)

**Problem.** All evidence so far comes from SITL. The 5 Hz `SCHED_TASK(update_ids, 5, 900, 170)` budget, RAM and stack, and SD/DataFlash behaviour have never been measured on an STM32H743.

**Firmware changes (test and release builds):**
- Measure `update_ids()` with `AP_HAL::micros()` at entry and exit. Keep the maximum, a 64-bin histogram (for p99) and the overrun count (> 900 µs). Log them once per second as `IDST`:

  | Name | Format | Fields |
  |---|---|---|
  | `IDST` | `QIIIIH` | `TimeUS, Boot, MaxUs, P99Us, Overruns, Det` (`Det` = detector with the longest last run) |

- Record the `AP_IDS` heap allocation at init and stack high-water marks. Compare against `@SYS/tasks.txt` and `@SYS/threads.txt` (scheduler task and thread statistics; check these exist at the pinned commit).

**Test procedure.** Write it into `docs/test_and_validation_plan.md`. Bench test with propellers off and actuators disconnected:
1. Run with AP_IDS disabled to get a baseline (CPU load, loop rate, `PM` records, telemetry loss).
2. Repeat with AP_IDS plus all 9 scripts enabled, at minimum and maximum `SRx_*` stream rates, with the GCS connected and disconnected.
3. Inject faults (requires FW-12): detector exception, invalid input, full queue, SD write error, script restart, IDS restart.
4. Run HITL on the exact release before any controlled flight.
5. Repeat on at least two boards.

**Done when (V-001..V-003):** no IDS-attributable reset or scheduler miss; `IDST.MaxUs` < 900 µs for every profile (report the maximum and p99, not the mean); RAM, stack and flash stay inside a written budget with margin.

---

## FW-02 — PreArm `flow_of_ctrl` (GAP-03)

**Problem.** SITL reports internal error `0x100000 flow_of_ctrl`, including with `SCR_ENABLE=0`, so Lua alone does not explain it. In ArduPilot, `flow_of_ctrl` is raised by `INTERNAL_ERROR(AP_InternalError::error_t::flow_of_control)` on code paths that "should never happen".

**Do:**
1. Build each configuration at the pinned commit:
   - stock ArduCopter (no AP_IDS);
   - AP_IDS compiled in but disabled;
   - AP_IDS fully enabled;
   - AP_IDS with one detector disabled at a time;
   - each of the above with Lua on and with Lua off.
2. For each, capture the full PreArm text, `AP_InternalError` bits, the reporting line (`INTERNAL_ERROR` records the line number; read it from `@SYS/` or MAVLink `SYS_STATUS`/`STATUSTEXT`), the boot log and scheduler statistics.
3. Grep the AP_IDS sources and its integration points (`Copter::` scheduler table, `AP_Vehicle`, `GCS_MAVLink_Copter.cpp`, `AP_Scripting` binding glue) for `INTERNAL_ERROR(` and for `switch` statements without a default.
4. Fix the responsible path. If the cause is upstream, record the upstream issue or commit and get a written risk disposition.

**Done when (V-006):** the release configuration shows no unexplained PreArm error, and a regression test (SITL autotest step) covers the fix.

---

## FW-03 — Native DataFlash IDS records (GAP-05)

**Problem.** AP_IDS writes nothing to DataFlash. Its 8-slot event ring is RAM only, so if the link drops the events are gone.

**Do.** Add `libraries/AP_IDS/AP_IDS_Log.cpp/.h` behind `#if HAL_LOGGING_ENABLED && AP_IDS_LOGGING_ENABLED`, using `AP::logger().Write(...)` or registered `LOG_PACKET` structures (see *Adding a new DataFlash Log Message* in the ArduPilot dev docs). Put `TimeUS` first. Write on material state transitions and at a bounded health interval only, never per sample. Never log key material.

**Naming.** ArduPilot already logs a DataFlash message called `PIDS` (the PID-steering log), and `PID*` is ArduPilot's PID-controller family. The IDS records therefore use the unused `IDS*` names. `discover_firmware.py` checks the ELF for `IDS*` log names.

**Wire contract.** The GCS already decodes these from imported `.bin`/`.log` files (`backend/app/ids/pushpak_fc.py::_dataflash`):

| Name | Format | Fields | GCS behaviour |
|---|---|---|---|
| `IDSE` | `QIIBBHffB` | `TimeUS, Boot, Seq, Det, St, Ev, Conf, Met, Inst` | Becomes an FC detector result, identical to a live PIDS STATUSTEXT line. Duplicates are removed by `(Boot, Seq)`. |
| `IDSH` | `QIIHBIIH` | `TimeUS, Boot, Health, Scr, QOcc, QDrop, LogDrop, Age` | An increase in `QDrop`/`LogDrop` raises an "event loss on board" health result. |
| `IDSC` | `QIIII` | `TimeUS, Boot, CfgVer, ThrProf, BuildId` | Kept as `DF_IDSC` with configuration and build identity (case metadata). |
| `IDSF` | `QIHBB` | `TimeUS, Boot, Code, Sub, Rec` | Raises an AP_IDS fault health result. |

- `Det` indexes `GPS=0, MAVLINK=1, COMMAND=2, RC_LINK=3, IMU=4, MISSION=5, PARAMETER=6, OFFBOARD=7` (the order of `PIDS_DETECTORS` in `backend/app/mavlink/pushpak.py`).
- `St` values: `0=CLEAR, 1=SUSPECTED, 2=CONFIRMED`, as pinned by the `static_assert`s in build_v3's `AP_IDS.h`. They must match what the Lua bridge announces in `STATEMAP`.
- `Health`: one bit per detector (1 = running), with bit 31 set for logging-degraded.
- `QOcc` / `QDrop`: ring occupancy and cumulative overflow count. `LogDrop`: records the logger refused.

**Done when (V-010):** after normal, disconnected and fault-injected sessions, importing the `.bin` into SPIDERS rebuilds the IDS timeline. Every state transition is either present or counted in `QDrop`/`LogDrop`. Logging stays within the FW-01 budget, and filling or failing the logger never crashes the autopilot.

---

## FW-04 — Passive PARAM_SET receive hook (GAP-06)

**Problem.** The onboard parameter adapter polls 2 of 12 parameters per 5 Hz tick, about 1.2 s per parameter. The 4-writes-in-1.5-s burst rule can never fire, and polling cannot tell who wrote a value.

**Do.**
1. At the pinned commit, find the MAVLink receive path. Copter overrides `GCS_MAVLINK_Copter::packetReceived()`, and parameter writes are handled in `GCS_MAVLINK::handle_param_set()`.
2. Add a **passive** observer that does not modify the message or return early.
3. For `MAVLINK_MSG_ID_PARAM_SET` addressed to this vehicle, record:
   - source `sysid`/`compid` and the receiving channel;
   - `param_id`, value and type, plus a monotonic receive time;
   - signing status from the receive path (`NONE/VALID/INVALID`), if available.
4. Record the outcome separately: hook the point after `handle_param_set()` validates and applies the value, or compare against the stored value on the next tick. Report `REQUESTED`, `APPLIED` or `REJECTED`. **Never report a rejected request as applied.**
5. Parameter changes not made over MAVLink (Lua `param:set`, CLI) have no trustworthy sender. Report them as `UNKNOWN/LOCAL`.
6. Feed `ParameterDetector` from this observer. Keep polling as a slow consistency check.

**Wire contract.** The GCS maps this record to `PARAM_SET` with the real sender SYSID (`backend/app/sources/files.py`):

| Name | Format | Fields |
|---|---|---|
| `IDSW` | `QIBBBBNfBB` | `TimeUS, Boot, Sys, Comp, Chan, Sig, Name, Val, Typ, Res` — `Sig`: 0 none/1 valid/2 invalid; `Res`: 0 requested/1 applied/2 rejected |

**Tests (V-011, V-012):** cover these cases:
- one write;
- 4 writes inside 1.5 s, and 4 writes outside that window;
- wrong target;
- unknown source;
- unsigned request when the policy requires signing;
- invalid parameter name;
- accepted write and rejected write;
- a Lua or local write with no sender.

Show that existing parameter handling is byte-for-byte unchanged (same ACK/PARAM_VALUE replies).

---

## FW-05 — Accepted offboard setpoint observation (GAP-10)

**Problem.** The onboard detector infers external control from changes to the GUIDED target. It cannot see the setpoint stream itself, who sent it, or whether ArduPilot accepted it.

**Do.**
1. Add passive hooks for `SET_POSITION_TARGET_LOCAL_NED`, `SET_POSITION_TARGET_GLOBAL_INT` and `SET_ATTITUDE_TARGET`, at receive and at acceptance (Copter handles these in `GCS_MAVLINK_Copter`; confirm the functions at the pinned commit).
2. Use one `OffboardObservation` structure with: sender, signing status, target, message ID, frame, type mask, inter-arrival time, `accepted`/`ignored` plus the reason, mode and armed state.
3. Keep receive-time and acceptance observations separate.

**Wire contract (reserved; the GCS keeps it as `DF_IDSO` until a consumer is added):**

| Name | Format | Fields |
|---|---|---|
| `IDSO` | `QIBBBBHBHBf` | `TimeUS, Boot, Sys, Comp, Chan, Sig, MsgId, Frame, Mask, Acc, RateHz` |

**Done when (V-018):** accepted setpoint sender, rate and freshness are recorded. Stale, bursty, unexpected-source and invalid-frame cases can be told apart. A static target is not taken to mean "no traffic", and GUIDED behaviour is unchanged.

---

## FW-06 — Boot ID, event sequence and overflow visibility (GAP-07)

**Problem.** Events carry no boot or sequence identity, so the GCS cannot tell a repeat from a new event or see ring overflow. The bridge's startup announcement used to be sent only once, which was fixed in the Lua bridge v2 shipped here.

**Do.**
1. At AP_IDS init, generate a 32-bit `boot_id`, for example from `hal.util->get_hw_rtc()` mixed with a persistent boot counter. Keep a monotonic `event_seq` per boot.
2. Add an overflow counter to the 8-slot ring (`EVENT_RING_SIZE = 8` in build_v3) and increment it whenever an unread event is overwritten.
3. Emit native PIDS STATUSTEXT in **version 2**. The GCS parser already accepts it, and v1 still parses:
   ```text
   PIDS|2|FC|<DET>|<state>|<conf>|<evidence>|<metric>|<instance>|<boot_id>|<seq>
   ```
4. Add Lua bindings `ids:boot_id()` and `ids:dropped_events()` (binding descriptor in `libraries/AP_Scripting/generator/description/bindings.desc`; regenerate). Then extend the bridge's SYNC line, which the GCS already parses:
   ```text
   PUSHPAK IDS: SYNC up=<s> seq=<n> ev=<k> boot=<boot_id> drop=<ring_overflows>
   ```
   With `boot=` present, the GCS detects reboots from the boot ID instead of from uptime going backwards. A rising `drop=` raises an "event ring overflow" health result.
5. Delivery model: **one-way, best effort**. Do not add an acknowledgement channel unless a separate safety and security review approves a strictly allowlisted ACK message that cannot carry commands (blueprint GAP-07). Durability comes from FW-03, not from retransmission.

**Done when (V-013, V-014):** a GCS that connects after boot learns the bridge version and state map, which the shipped bridge v2 already provides. Duplicate events do not create duplicate incidents. Ring overflow and sequence gaps show in the IDS page's FC EVENT DELIVERY strip.

---

## FW-07 — ROMFS drift, binding choice and missing Lua inputs

DISC-001 to DISC-004 described the 26 Sep 2026 build and are **resolved in build_v3**, as checked against its ELF and source on 9 Nov 2026:
- 26-method binding;
- `AP_IDSGCS::report_confirmed` implemented (372 bytes, not `return false`);
- all 8 detectors driven: GPS, IMU and Mission from `AP_IDS::update`; RC from `update_rc_link`; Parameter from `update_parameters`; Offboard from `Copter::update_ids_offboard`; MAVLink and Command from `GCS_MAVLINK_Copter::packetReceived`;
- state enum fixed by `static_assert`s.

What is still open:

| Item | Work |
|---|---|
| DISC-005 — build_v3's ROMFS embeds older `command_confirm`, `ids_gcs_bridge`, `jamming_confirm`, `mavlink_confirm`, `offboard_confirm`, `modules/ids_common` (comment-only) | Rebuild with `firmware/ROMFS_custom_fixed.zip` (bridge protocol v2). Until then load the scripts from the SD card with `SCR_DIR_DISABLE=1` so the ROMFS copies don't also run. |
| Binding differs between build_v3 (26 methods) and the 14 Oct build (3 methods, `get_channel`) | Pick one for the release (FW-00). The shipped scripts use only `report_confirmed` and `event_sequence`, so they work with either; keep it that way, or update the strict test mocks (`backend/tests/test_lua_scripts.py::ALLOWED`) if the scripts start using accessors. |
| `report_confirmed` from Lua | Confirm that Lua confirmations end up in the AP_IDS event ring and, once FW-03 lands, in `IDSE` records with `Inst` marking Lua origin. |
| Missing Lua inputs (README "Coverage limits"; also true on build_v3) | Add read-only bindings for: per-channel MAVLink packet/drop statistics; RC RSSI; a command-received event (from the FW-04 / FW-05 observers); offboard setpoint stats. Add each to the strict test mocks. |

**Test environment note.** The Lua tests (`test_lua_scripts.py`, the bridge tests in `test_event_delivery.py`) need the `lupa` package (Lua 5.4). It is not in `backend/requirements.txt` and is not installed in the current venv, so those tests are **skipped**. Install it in CI before relying on them.

---

## FW-08 — MAVLink signing on the vehicle (GAP-08)

**GCS side (done).**
- **Keyring:** Settings → Security generates a key, activates it (with rotation), revokes it (the secret is destroyed) and exports it.
- **Export file:** written to `data/keys/provisioning/<key_id>-<ts>.key` as 64 hex characters. The secret never appears in the API, the UI or the audit log.
- **Signing policy:** set per link with `mavlink.signing_policy` in the config.
- **Four separate facts:** signature present, signature verified, source authorised, and command expected are reported separately.

**Firmware and vehicle work:**
1. **Provisioning.** Load the exported key over a wired or otherwise secure maintenance connection. ArduPilot accepts a key through `SETUP_SIGNING` and stores it in persistent storage; confirm the handler and storage location at the pinned commit. Never send `SETUP_SIGNING` over the telemetry radio. SPIDERS is receive-only and never sends it.
2. **Per-link policy.** Decide, for each serial or MAVLink channel, whether unsigned traffic is accepted, and document why (RC override, ADS-B or companion links may need exceptions). Configure it with the ArduPilot signing and channel options available at the pinned commit. Make sure a recovery and maintenance path still works when signing is required.
3. **Replay protection across reboot.** Confirm that the signing timestamp is persisted, or restored from a GNSS/RTC time, so frames replayed after a power cycle are rejected. Test reboot, power loss and link switching.
4. **Key storage.** The H743 has no protected key store, so the key sits in flash readable over SWD unless readout protection is set (see FW-10). Record this as residual risk, or add a secure element.
5. **Rotation and recovery.** Write and test procedures for scheduled rotation, a lost GCS, a replaced vehicle and a suspected key compromise. On the GCS this means generate → export → load onto the vehicle → activate → revoke the old key.
6. **Redaction.** Make sure the key never appears in DataFlash, crash dumps (`@SYS/crash_dump.bin`) or parameter exports.

**Done when (V-015, V-016):** frames with an invalid signature are rejected by the autopilot *and* reported by SPIDERS; stale or replayed frames are rejected across reboot; unsigned behaviour matches the written per-link policy; rotation and recovery have been demonstrated in a lab.

---

## FW-09 — Onboard approved baseline (GAP-11)

**GCS side (done).** An engineer approves a signed (Ed25519) manifest of expected parameter values and mission digest under Settings → Security → Approved baseline. The `BASELINE` detector reports `BASELINE_MISMATCH` and flags arming with mismatches as HIGH. It never re-learns the baseline, and approvals are chained by previous digest. This covers only what crosses a link the GCS can see.

**Firmware work:**
1. Replace the FNV-1a mission hash with a cryptographic digest (SHA-256 or BLAKE2b) used as the change detector. Check whether a crypto library is already in the tree at the pinned commit; the secure bootloader support uses monocypher. FNV-1a can be forged on purpose and must not be called an integrity check.
2. Optional, stronger version: provision the approved digest of the sensitive parameters and the mission into protected storage over the maintenance link. Check it before arming and report a mismatch as a PreArm *warning* plus an `IDSF`/`IDSE` event. It must not block arming unless the safety case explicitly allows that (blueprint §7.3: detection stays separate from response).
3. Seed the onboard parameter and mission detectors from the approved values, not from first observation.

**Done when (V-019):** a parameter or mission changed before boot is detected against the approved digest; an approved maintenance change is recorded with operator identity; a manifest for another vehicle is rejected.

---

## FW-10 — Firmware root of trust, signed update, anti-rollback, recovery (GAP-04)

The GCS release manifest is signed with an Ed25519 "release" key (`release/manifest.sig.json`). That proves which files were released. It does **not** make the flight controller refuse other firmware: a hash checked by AP_IDS after the image has already booted is not secure boot (blueprint §13).

**Do:**
1. Write `docs/platform_trust_architecture.md`. Cover the ROM bootloader, the ArduPilot bootloader, the application, configuration, key storage, SWD/JTAG, DFU, the update interface and the recovery path.
2. Check the exact MCU part on the Pixhawk 6C (STM32**H743**, not H753). Do not assume H753 crypto or secure-boot features. Record the silicon revision, option bytes (RDP level, write protection) and the debug-port state.
3. Evaluate ArduPilot's signed-firmware bootloader support at the pinned commit (secure bootloader build plus signing tools under `Tools/`; confirm the exact scripts and flags). Record what it provides — signature check before boot — and what it does not, likely including anti-rollback and protection against reflashing over SWD/DFU.
4. If the bootloader can be replaced, software on the same MCU cannot provide a root of trust. Choose one of the three options in blueprint GAP-04: a protected boot chain if the board supports it, an external secure element or supervisor, or a controller with suitable hardware security.
5. Anti-rollback: keep a monotonic security version in protected storage and reject images below the approved minimum.
6. Make updates atomic: a power cut at any point must leave either the old valid image or a recoverable state.
7. Test with an invalid signature, an altered image, an older signed image, a missing manifest, an interrupted update, a corrupt recovery image and key rotation.

**Done when (V-007..V-009):** unauthorised images are rejected before they execute; images below the approved minimum version are rejected; every power-loss point has a tested recovery. The trust model separates hardware-backed controls from software-only ones.

---

## FW-11 — Independent navigation evidence (GAP-09)

**GCS side (done).** The correlator now counts evidence by physical source. Ground, FC and Lua GPS results that all depend on the same GNSS/EKF residual form **one** line of evidence. GPS-only incidents therefore reach CORRELATED, not CONFIRMED, and say so in their limitations. A second GNSS receiver (`GPS2_RAW`) is its own independent group.

**Firmware and configuration work:**
1. Where the airframe allows, fit a second GNSS receiver with its own antenna and receiver chain. Stream `GPS2_RAW` (`SRx_EXT_STAT` or the equivalent at the pinned commit) and log it.
2. Expose receiver-quality data (C/N0, jamming/spoofing indicators where the receiver reports them reliably) through MAVLink or new bindings, and give each a lineage group in `backend/app/ids/lineage.py`.
3. Do not present GNSS/EKF disagreement as proof of spoofing. The onboard reports must use "navigation inconsistency / spoofing candidate" wording, as the GCS does.

---

## FW-12 — Safety invariants, fault-injection build, CI (SAFE-01, SAFE-02)

1. **Static check in CI.** Fail the build if any file under `libraries/AP_IDS/` calls the control APIs (mode set, arm/disarm, failsafe, mission or position-target setters, RC override, motor output). Keep an explicit allowlist of AP_IDS's read-only accessors.
2. **Fault-injection build flag** `AP_IDS_FAULT_INJECTION`, for test builds only and never in release. It forces a detector exception, invalid input, a full queue, an SD write error, a script restart and an IDS restart. Every injected fault must produce an `IDSF` record, and the autopilot must keep flying normally.
3. **SITL autotest steps** for FW-02 (no PreArm internal error), FW-04 (burst observed), FW-06 (PIDS v2 sequence continuity) and FW-03 (DataFlash `IDSE` replay matches the live events).
4. **Lua tests in CI** with `lupa` installed, against the strict binding mocks updated for any new methods.

---

## What the GCS already does, for reference

| Area | Where |
|---|---|
| Evidence lineage / independence | `backend/app/ids/lineage.py`, `correlation.py`; tests `test_lineage.py` |
| Bridge v2, delivery tracking, reboot and dup detection | `firmware/scripts/ids_gcs_bridge.lua`, `backend/app/mavlink/pushpak.py::EventDeliveryTracker`; `test_event_delivery.py` |
| DataFlash IDSE/IDSH/IDSF/IDSW and PIDS v2 STATUSTEXT / SYNC boot= drop= | `pushpak_fc.py::_dataflash`, `sources/files.py`; `test_firmware_contract.py` |
| Signing keyring, per-link policy, four facts | `backend/app/security/keys.py`, `ids/mavlink.py`; Settings → Security |
| Signed cases, custody, audit checkpoints | `backend/app/security/evidence.py`, `forensic/snapshot.py`; `test_trust_controls.py` |
| Approved baseline | `backend/app/security/baseline.py`, `ids/baseline.py` |
| Server-side authorization tests | `backend/tests/test_authorization.py` |
| ML baseline profiles | `backend/app/ids/ml_profiles.py`, `ids/ml.py`; `test_ml_baseline.py` |
| Evaluation harness | `scripts/evaluate_detectors.py`, `docs/validation/dataset_card_template.md` |
| Release manifest + SBOM | `scripts/make_release_manifest.py`, `release/` |
| Canonical observation contract | `backend/app/models/observation.py` |
