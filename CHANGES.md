# SPIDERS.Mk1 — SITL autotest fixes, script binding fixes (2026-11-11)

Found by running the ArduPilot autotests and the scripts on 4.7.1 SITL instead of only the Lua mocks.

| Area | Change | Tests |
|---|---|---|
| Lua scripts | `gcs:sysid_mygcs_last_seen_time_ms()` → `gcs:last_seen()` in five scripts (the C++ name; Lua sees the `bindings.desc` rename). Every script that used it stopped on the firmware. | `test_lua_scripts.py` mock corrected; 4.7.1 SITL: no `Lua:` errors |
| Lua scripts | `parameter_confirm.lua` watches both pre-4.7 and 4.7 parameter names again; six of fifteen were missing on 4.7.1 | new `test_parameter_change_while_armed_47_names`; SITL: `[PIDS] PAR THREAT LV2` |
| ROMFS package | `ROMFS_custom_fixed.zip` rebuilt from `firmware/scripts`; the ArduPilot tree's `ROMFS_custom/` (still the 14 Oct copies) replaced with it | `romfs_drift`: MATCH |
| ArduPilot tree | `Tools/ardupilotwaf/boards.py`: SITL builds skip `ROMFS_custom/scripts/`. With them embedded, nine upstream scripting autotests ran out of Lua heap and failed "Prearm bit never went true" | FlyEachFrame, LUAConfigProfile, LuaParamLockdown, ScriptCopterPosOffsets, ScriptMountAllModes, ScriptMountDriver, ScriptMountPOI, ScriptingFlipMode, ScriptingFlyVelocity pass; FlyEachFrame also passes with the engine compiled out |
| ArduPilot tree | `libraries/AP_IDS/AP_IDS.h`: `AP_IDS_ENABLED` defaults to `APM_BUILD_COPTER_OR_HELI` where the vehicle is known. `tool/Replay` and other vehicles compiled the `ids` binding but never link AP_IDS | `./waf build --target tool/Replay` links |
| Native adapter | `firmware/native/AP_IDS/AP_IDS_GNSSIntegrity.cpp` uses `get_first_usable_gyro/accel()` (4.7.1 has no `get_primary_*`); README updated | engine host tests: 153 checks, 0 failures |
| Snapshot | `firmware/GNSSIntegrity_snapshot/` regenerated; base + patch + tarball reproduces the tree exactly | — |
| Release | `release/` manifest regenerated and re-signed (same key) | `make_release_manifest.py --verify`: VALID |

Still open (see `firmware/FIRMWARE_WORK_REQUIRED.md`): no Pixhawk image built from the fixed tree (DISC-005 open for build_v3); `IDS_GI_*` parameters not registered; GNSS engine evidence not yet fed to the GPS detector; idle `FC_EVENT` noise from a native detector; `AP_IDS_ENABLED 0` does not compile; the Replay autotest panics in this WSL environment, also on clean upstream.

---

# SPIDERS.Mk1 — GNSS integrity physics engine (2026-11-10, FW-13)

Implements *SPIDERS_Mk1_GNSS_Physics_Engine_Research_Integration.md*: an IMU-propagated, GNSS-independent integrity monitor for the native AP_IDS GPS path. See `firmware/native/README.md`.

| Area | Change | Tests |
|---|---|---|
| Native engine | `firmware/native/AP_IDS/GNSSIntegrity/`: portable C++11, fixed memory, no heap. It has five horizons (2/5/15/30/60 s), each with its own seed, frozen bias and covariance, and a shared GNSS-free integrator with fix-time history. It provides a gated non-GNSS heading, a rate-limited bias estimator with change-point detection, and position/velocity/heading-free/baro/ground tests. The joint persistence decision includes a trust gate, confirmed re-arm, a latched ALARM, sensitivity-aware WARNING clearing and horizon extension during suspicion. It cross-compiles for Cortex-M7 under `-Werror -Wdouble-promotion -fsingle-precision-constant`. | `firmware/native/tests` (25 tests, 149 checks) via `test_native_gnss_integrity.py` |
| Adapter | `firmware/native/AP_IDS/AP_IDS_GNSSIntegrity.{h,cpp}`: ArduPilot capture, seed policy, `IDS_GI_*` parameters, `IDSG`/`IDSR` logging. Was a template; since 2026-11-11 it builds and logs in 4.7.1 SITL (see the entry above). | — |
| Wire contract | New DataFlash `IDSG` (summary) and `IDSR` (per horizon), plus PIDS evidence bits 4096 `INS_PREDICTION` and 8192 `PHYS_CONSTRAINT` | `test_firmware_contract.py` (header ⇄ parser, no Lua bit collision) |
| GCS | `PushpakFCDetector` decodes IDSG/IDSR. WARNING maps to ANOMALOUS and ALARM to SUSPECTED, never CONFIRMED; DEGRADED is a health observation. It dedupes by `(Boot, Seq)`. | `test_firmware_contract.py` |
| Lineage | Physics method lineage is `(GNSS, IMU)` (+`BARO`); FC GPS events carrying `INS_PREDICTION` gain `IMU`. The result merges with GPS_INTEGRITY and IMU_CONSISTENCY into one evidence line and is not counted as independent corroboration. | `test_firmware_contract.py` |
| UI | IDS page → FC GNSS INTEGRITY panel: state, flags and per-horizon residuals, D² values, sigmas and reasons | `npm run typecheck` |
| Discovery | `discover_firmware.py` reports `ap_ids.gnss_integrity_objects` | — |

Firmware work is FW-13 in `firmware/FIRMWARE_WORK_REQUIRED.md`. Nothing has run on Pixhawk hardware yet.

---

# SPIDERS.Mk1 — gap-analysis GCS change set (2026-11-09)

Closes the GCS side of *SPIDERS_Mk1_Gap_Analysis_and_Implementation_Blueprint.md*. Firmware work is listed in `firmware/FIRMWARE_WORK_REQUIRED.md`.

| Gap | Change | Tests |
|---|---|---|
| GAP-09 / DET-02 | Evidence lineage (`ids/lineage.py`). Results sharing a sensor/data path form one line; repeats weigh × `ids.corroboration_weight`; CONFIRMED needs ≥ 2 independent lines. **Behaviour change:** GPS-only incidents now stop at CORRELATED. | `test_lineage.py` |
| GAP-07 | Bridge protocol v2 (version, STATEMAP, periodic SYNC, re-announce on GCS contact); GCS tracks reboots, missed/duplicate events. ROMFS package rebuilt. | `test_event_delivery.py` |
| GAP-08 | MAVLink signing keyring (generate/activate/rotate/revoke/export, secrets never in API), per-link `mavlink.signing_policy`, four separate trust facts. | `test_trust_controls.py`, `test_authorization.py` |
| GAP-11 | Signed approved mission/parameter baseline + `BASELINE` detector (`BASELINE_MISMATCH`, arming check). | `test_trust_controls.py` |
| GAP-12 | Ed25519-signed cases (`case.sig.json`), custody events as signed revisions, signed audit checkpoints with optional mirror. | `test_trust_controls.py` |
| GAP-13 | Route-policy and negative role tests for every mutating API route; denied attempts audited (rate-limited); WebSocket auth test. | `test_authorization.py` |
| GAP-16 | ML baseline modes: approved signed profile / gated untrusted session / collect; OOD suppression; provenance on every alert. | `test_ml_baseline.py` |
| GAP-02 | `scripts/evaluate_detectors.py` + `app/evaluation.py`: per-class/per-detector/per-run metrics, Wilson and Poisson intervals, locked-partition guard; dataset card template. | `test_evaluation.py` |
| GAP-14 | `scripts/make_release_manifest.py`: signed manifest, CycloneDX SBOM, ROMFS drift check, `--verify`. | `test_release.py` |
| GAP-15 | `models/observation.py` canonical `SecurityObservation` (ArduPilot/MAVLink adapter only). | `test_observation.py` |
| Firmware contract | GCS parses DataFlash `IDSE/IDSH/IDSF/IDSW` (not `PID*`: ArduPilot already logs `PIDS`), PIDS v2 STATUSTEXT and SYNC `boot=`/`drop=` ahead of the firmware. | `test_firmware_contract.py` |
| Firmware facts | `discover_firmware.py` now finds detector wiring from every call site in the ELF, verifies the state enum from `AP_IDS.h` (`--ap-ids-source`) and flags ROMFS script drift (DISC-005). `configs/capabilities.json` regenerated from build_v3 (APJ `223c26f8…`): DISC-001–004 resolved, DISC-005 open. README and docs corrected. | — |

UI: Settings → Security (keys, audit checkpoints, approved baseline); case view shows signature status and chain of custody; incident explanations show independent evidence lines; IDS page shows FC event delivery.

New config keys (`configs/default.yaml`): `ids.corroboration_weight`, `mavlink.signing_policy`, `security.keystore_dir`, `security.sign_evidence`, `audit.checkpoint_every`, `audit.checkpoint_mirror_dir`, `baseline.manifest_dir`.

---

# SPIDERS.Mk1 — SILKTRACE advanced change set

This is a cumulative patch against the original `SPIDERS.Mk1-main` repository archive. It contains only added or modified paths. Extract/merge it into the existing repository root; do not replace the repository.

## Added

- `backend/app/silktrace/` — evidence intake, generic and known-format inspection, DJI FlightRecord adapter, isolated parser worker, replay normalization, anomaly analysis, and vehicle knowledge catalog.
- `backend/app/silktrace/knowledge_base/catalog.json` — versioned firmware/log-format reference index.
- `backend/tests/test_silktrace.py` and `backend/tests/test_silktrace_advanced.py` — evidence, integrity, schema, replay, anomaly, profile, isolated-worker and optional Blackbox decoder tests.
- `frontend/src/pages/Silktrace.tsx` — SILKTRACE workspace with two tabs: **Native cases** (`#/silktrace`, `#/silktrace/<CASE-ID>`) and **Universal forensics** (`#/silktrace/universal`). It replaces the former separate Forensics page; old `#/forensics/...` links redirect.
- `frontend/src/pages/SilktraceCases.tsx` — native SPIDERS capture cases (formerly `Forensics.tsx`; still served by `/api/forensics/...`).
- `frontend/src/pages/SilktraceUniversal.tsx` — universal drone-log evidence intake and inspection.
- `frontend/src/pages/SilktraceReplay.tsx` — 2D GPS map replay, 3D position/altitude projection, attitude projection, scrubber, playback speeds, profile selection, analysis and isolated-inspection controls.
- `frontend/src/pages/SilktraceKnowledge.tsx` — firmware reference index and custom vehicle profile builder.
- `docs/silktrace/README.md` and `docs/silktrace/ADVANCED_CAPABILITIES.md` — API, installation, parser limitations, security and validation notes.

## Modified

- `backend/app/main.py` — REST routes for evidence, replay, isolated inspection, vehicle profiles and behavioural screening.
- `backend/requirements.txt` — adds `pydjirecord==1.3.0`; `pyulog` remains optional and the existing `pymavlink` dependency is used for DataFlash.
- `frontend/src/App.tsx` — single SILKTRACE navigation entry (Forensics merged in) and `#/forensics` redirect.
- `frontend/src/pages/Dashboard.tsx`, `frontend/src/pages/Incidents.tsx` — case links point to SILKTRACE.
- `README.md` — SILKTRACE extension overview.

## Install

From the repository root, merge/extract this ZIP, then run:

```bash
python -m pip install -r backend/requirements.txt
```

For stronger Linux parser isolation, install Bubblewrap (`bwrap`) using the OS package manager. If it is absent, SILKTRACE explicitly reports the weaker resource-limited subprocess fallback. For Betaflight frame decoding, install the upstream `blackbox_decode` executable and put it on the backend PATH; it is not bundled.

Start using the repository's existing launcher (`scripts/start.sh` or `scripts/start.ps1`) and open **SILKTRACE**.

## Validation performed in the build environment

- Python compile check: passed.
- Focused SILKTRACE tests: **12 passed**.
- Changed React/TSX files: TypeScript transpile/syntax check passed.
- Full backend test collection: blocked because `pymavlink` was not installed in this execution environment (`ModuleNotFoundError`); install `backend/requirements.txt` and rerun the full suite.
- Frontend production build: **not verified**. `npm ci` timed out repeatedly while fetching dependencies; the available `node_modules` was incomplete (`vite/client` missing). Run `npm ci && npm run build` in an environment with npm registry access.

## Important implementation boundaries

- Replay uses recorded GPS/attitude samples. It does not synthesize missing coordinates, interpolate missing samples, or claim physics-based reconstruction. The 3D aircraft mesh is illustrative and uses a selected custom profile's actuator count/positions when provided.
- DJI FlightRecord TXT v1–12 can be decoded when `pydjirecord` is installed. DJI v13–14 frame data requires per-flight DJI API keychains; this patch does not fetch/store API keys or bypass encryption. DJI aircraft DAT is only structurally triaged unless a compatible dedicated decoder is separately installed.
- The isolated parser worker uses process limits and timeout. Bubblewrap adds read-only filesystem/network/capability isolation on Linux. Without Bubblewrap, the fallback is not a complete OS sandbox.
- Behavioural ML is unsupervised per-recording screening (MAD + optional IsolationForest), not a validated general-purpose fault or intrusion classifier.
