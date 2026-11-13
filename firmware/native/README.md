# GNSSIntegrity: IMU-propagated GNSS integrity engine (FW-13)

This directory implements the integration design in *SPIDERS_Mk1_GNSS_Physics_Engine_Research_Integration.md*. The engine compares each GNSS fix with an inertial prediction that **GNSS cannot correct while a horizon is active** (2, 5, 15, 30 and 60 s). It runs inside the existing native `AP_IDS` GPS detector path as additional evidence. It is not a second IDS and not a ninth detector.

It is **detect-only**. It never changes mode, arming, navigation, EKF or GNSS inputs, actuator outputs, MAVLink handling or failsafes.

## 1. What is here, and what is verified

| Path | What it is | Status |
|---|---|---|
| `AP_IDS/GNSSIntegrity/` | Portable numerical core: no ArduPilot includes, fixed memory, no heap | Host-tested (25 tests, 149 checks). Cross-compiles with `arm-none-eabi-g++ 10.2 -mcpu=cortex-m7 -mfpu=fpv5-d16 -Werror -Wdouble-promotion -fsingle-precision-constant` to about 15 KB of code. No `malloc`/`new`/`printf` references. |
| `AP_IDS/AP_IDS_GNSSIntegrity.{h,cpp}` | ArduPilot adapter: sensor capture, seed policy, parameters, `IDSG`/`IDSR` logging | Compiles and runs in ArduCopter 4.7.1 (`dbe79216`) SITL; the full AP_IDS tree is in `../GNSSIntegrity_snapshot/`. That tree uses a flat include layout and builds the engine in (`AP_IDS_GNSSINT_ENABLED 1`, `EN` default 1) for development; this copy keeps the opt-in defaults. Behavioural `VERIFY` items below are still open. |
| `tests/test_gnss_integrity.cpp` | Unit tests plus a kinematic simulator (IMU, GNSS with latency and spoofing, baro, magnetometer) | `tests/run_tests.sh`, or `pytest backend/tests/test_native_gnss_integrity.py` with `CXX` set |

Nothing here has run on a Pixhawk. SITL, HIL and bench validation are still open (§7).

```bash
CXX=g++ firmware/native/tests/run_tests.sh /tmp
```

On Windows, use MSYS2's ucrt64 g++ (for example `CXX=C:/msys64/ucrt64/bin/g++.exe`).

## 2. Architecture

```text
AP_InertialSensor::update()  ──►  capture_imu_sample()      FAST: read published increment, enqueue (64-slot SPSC)
AP_GPS::update() (50 Hz)     ──►  update_observations()     drain + propagate, baro, mag heading, each NEW fix once
AP_IDS::update() (5 Hz)      ──►  GPS detector + update_logging()   evidence bits / IDSG+IDSR at 1 Hz + transitions
```

| File | Responsibility |
|---|---|
| `InertialSampleBuffer` | Bounded SPSC queue. Duplicate timestamps are rejected, gaps and overflow are counted and marked. |
| `InertialPropagator` | One shared, GNSS-free strapdown integrator (double sums), plus a 0.8 s history for fix-time alignment |
| `HeadingManager` | Gyro-propagated yaw. Absolute yaw comes only from a non-GNSS heading (magnetometer); innovations are gated. |
| `HorizonManager` | Five horizon records. Each has its own seed, frozen bias, snapshot and covariance. |
| `BiasEstimator` | Rate-limited accel-bias Kalman filter with NIS change-point detection. It also fits a NED-fixed offset hypothesis. |
| `NoiseModel` | Inertial process noise scaled by vibration. GNSS noise uses a model floor; receiver accuracy can raise it only up to a cap. |
| `TimeAligner` | Fix-time alignment. Lag is applied once. Out-of-order, stale and future fixes are rejected. |
| `ResidualTests` / `BarometerCheck` | Position, velocity, heading-free speed-change, baro altitude-change and stationary-ground tests |
| `GNSSIntegrity` | Orchestration, the trust gate, joint persistence decision and re-arm policy |

**Why one shared integrator still gives each horizon an independent prediction.** The integrator accumulates `V = ∫a_n dt`, `P = ∫V dt` and the rotation integrals `M1 = ∫R dt`, `M2 = ∫M1 dt`. A horizon armed at `t0` with seed `(p0, v0)` and frozen body bias `b` predicts:

```text
v(t) = v0 + [V(t) − V0] − [M1(t) − M1_0]·b
p(t) = p0 + v0·T + [P(t) − P0 − V0·T] − [M2(t) − M2_0 − M1_0·T]·b
```

The prediction depends only on the seed and on IMU, attitude and heading data. The test `GNSS after arm cannot change prediction` checks this bit-for-bit: two runs with identical IMU data but different GNSS give identical predictions.

## 3. Design decisions (where this differs from, or sharpens, the guide)

1. **Trust policy.** The external seed is `PREFLIGHT_STATIONARY`. It requires disarmed, vehicle-landed, IMU still for 5 s, a 3D fix with ≥ 8 satellites and HDOP ≤ 2, and an absolute non-GNSS heading. `v0 = 0` comes from the stationary state, not from GNSS. The seed **position** is the GNSS fix, so an attack already present at seeding cannot be detected; this is the trust-anchor limitation. `EXTERNAL_REFERENCE` and `OPERATOR` are also accepted. `VALIDATED_GNSS_PERIOD` is engine-internal and cannot be asserted from outside. **Under suspicion (WARNING or ALARM), only `EXTERNAL_REFERENCE` or `OPERATOR` may reseed.** A landed, stationary `PREFLIGHT_STATIONARY` seed is refused, because its GNSS fix is the quantity that may be spoofed. Before this rule, a spoofed receiver could clear an ALARM by reseeding on the ground: a held 28 m offset in SITL reseeded at 44 s while still applied.
2. **Re-arming from GNSS.** An expired or event-invalidated horizon is re-armed only while the trust gate is open: no suspicion, and at least 25 consecutive clean fixes. It is re-armed from a fix that was itself followed by 2 clean fixes. In simulation, the first spoofed fix can pass every test, so re-arming from it would hand the spoofer a reference.
3. **ALARM latches** until an independent reseed. **WARNING clears** only through a horizon at least about as sensitive as the one that raised it (`clear_sensitivity_ratio`), and only once no statistic is above the p = 0.01 hysteresis level. Without this rule, long, loose horizons "vouched" for a spoofed receiver after the short ones expired. This was a real failure seen in simulation, not a hypothetical.
4. **Horizons are extended during suspicion.** While suspicion is active no fresh reference can be armed, so pre-onset horizons keep running past their nominal duration until their uncertainty exceeds the limits. They are flagged `EXTENDED`. Expiring them would only throw away the remaining GNSS-independent evidence.
5. **Correlated horizons.** The decision uses the joint maximum across horizons plus persistence (3 fixes for WARNING, 5 at alarm level for ALARM). Five horizon alarms are never counted as five witnesses.
6. **Baro and stationary-ground tests** can raise WARNING on their own, never ALARM.
7. **DEGRADED, HEADING_UNOBSERVABLE and NO_TRUSTED_SEED** are reported as reduced coverage, never as spoofing.
8. **Parameter names** are `IDS_GI_*` rather than `IDS_GNSSINT_*`. Names such as `IDS_GNSSINT_LAT_MS` exceed ArduPilot's 16-character limit.
9. **DataFlash** is split into `IDSG` (summary) and `IDSR` (one row per horizon), because one FMT record allows at most 16 fields and 64 bytes of labels.

## 4. Patch steps for the ArduPilot fork

Do this in the tree that actually built the release (FW-00). Back it up first:

```bash
git switch -c feature/gnss-integrity-physics
git diff --binary > ../ardupilot-before-gnss-integrity.patch
```

1. **Copy** `AP_IDS/GNSSIntegrity/` to `libraries/AP_IDS/GNSSIntegrity/`, and the adapter to `libraries/AP_IDS/`. If the AP_IDS `wscript` or library registration lists sources explicitly, add every new `.cpp`; do not assume recursive globbing. Build with `AP_IDS_GNSSINT_ENABLED=1` only in the development configuration.
2. **Own it once.** Add `AP_IDS_GNSSIntegrity gnss_integrity;` to `AP_IDS`, add it to `AP_IDS::var_info` as `AP_SUBGROUPINFO(gnss_integrity, "GI_", <idx>, AP_IDS, AP_IDS_GNSSIntegrity)`, and call `gnss_integrity.init()` from `AP_IDS::init()`.
3. **Fast hook** (`ArduCopter/Copter.cpp`). Put it immediately after `FAST_TASK_CLASS(AP_InertialSensor, &copter.ins, update)`:
   ```cpp
   FAST_TASK(capture_ids_imu_sample),
   // void Copter::capture_ids_imu_sample() { ap_ids.gnss_integrity.capture_imu_sample(); }
   ```
   Measure the worst case (`capture_max_us()`) and confirm the loop rate is unchanged.
4. **Observation task.** Put it right after `SCHED_TASK(update_GPS, 50, …)`, with a priority between its neighbours, and measure the budget on the Pixhawk 6C:
   ```cpp
   SCHED_TASK(update_ids_gnss_observation, 50, 150, <prio>),
   // void Copter::update_ids_gnss_observation() {
   //     ap_ids.gnss_integrity.set_landed(true, ap.land_complete);
   //     ap_ids.gnss_integrity.update_observations();
   // }
   ```
5. **GPS detector wiring** (in the existing `AP_IDS::update()` / `GPSDetector`):
   ```cpp
   gps_detector.add_evidence(gnss_integrity.evidence_bits());          // 4096 INS_PREDICTION, 8192 PHYS_CONSTRAINT
   gps_detector.add_suspicion(gnss_integrity.wants_suspected(), gnss_integrity.confidence());
   gnss_integrity.update_logging(boot_id);                             // FW-06 boot id, 0 until implemented
   ```
   Use whatever the local GPS detector really exposes; the names above are placeholders. Its existing persistence policy decides the PIDS state. **Never** map ALARM straight to CONFIRMED.
6. **Safety check (FW-12).** Extend the CI allowlist so that `GNSSIntegrity/` and the adapter use read-only accessors only.

### Verify before building (each `VERIFY` in the adapter)

- `AP_InertialSensor`: the primary-instance accessor is `get_first_usable_gyro()` / `get_first_usable_accel()` in 4.7.1 (there is no `get_primary_*`; resolved). Still to check: `get_delta_angle` / `get_delta_velocity` signatures and their fallback path; `get_last_update_usec()` semantics; `get_accel_clip_count`; `get_vibration_levels` units.
- **Delta-velocity convention.** Run a stationary-level bench test per IMU backend. `IDS_GI_DV_SF=1` means specific force with gravity included; a mismatch raises `GRAVITY_FAULT`. Check whether coning and sculling compensation is already applied, so it is not applied twice.
- `AP_AHRS`: `get_roll_rad()`, `get_pitch_rad()` and `healthy()`. The AHRS yaw is never used.
- `AP_GPS`: whether `last_fix_time_ms()` already reflects the backend lag. Keep `IDS_GI_LAT_MS=0` unless it is proven not to, so the latency correction is never applied twice. Also check the `location().alt` frame.
- `Compass::calculate_heading()` uses only the roll/pitch row. With `COMPASS_AUTODEC` the declination follows GNSS position; prefer a fixed `COMPASS_DEC`.
- `AP_Logger::Write` argument promotion for the `IDSG` / `IDSR` formats.

## 5. Parameters (`IDS_GI_*`)

**Not exposed yet.** `AP_IDS_GNSSIntegrity::var_info` is not linked into Copter's parameter table, so the 4.7.1 SITL build has no `IDS_*` parameters (checked against its full 1370-entry parameter list). The engine runs on the compiled-in defaults below and none of them can be changed from a GCS until the group is registered.

| Name | Default | Meaning |
|---|---|---|
| `EN` | 0 | Enable (reboot required). Off during development. |
| `MASK` | 31 | Horizons 2/5/15/30/60 s |
| `LAT_MS` | 0 | Extra latency compensation, applied once and only if proven necessary |
| `POS_MAX` / `VEL_MAX` | 50 m / 5 m/s | Uncertainty above which a test is not supported |
| `GROUND` | 1 | Stationary-ground GNSS speed check, which requires a valid landed state |
| `MOVING` | 0 | Moving-platform launches: ground check off |
| `LOG` | 1 | 0 none; 1 IDSG+IDSR at 1 Hz plus transitions; 2 every fix (development only) |
| `DV_SF` | 1 | Delta-velocity convention; must be proven per backend |

The engine's other numbers are in `Config` in `GNSSIntegrityTypes.h`: noise model, the 0.5 m/s² bias **prior**, chi-square levels and persistence. They are initial values to validate on target logs, not specifications. Calibrate thresholds for the family-wise false-alarm rate on held-out flights.

## 6. Simulation results (host, synthetic; not hardware evidence)

The simulator uses a level vehicle, IMU noise of 0.02 m/s/√s plus bias, GNSS noise of 0.5 m and 0.05 m/s with 100 ms latency, and magnetometer heading noise of 0.03 rad. It shows that the logic behaves as designed. It says nothing about Pixhawk performance.

| Scenario | Result |
|---|---|
| 30 clean 5-minute flights with turns (2.5 h) | 0 WARNING, 0 ALARM |
| 3 m/s velocity drag-off after 60 s of flight | ALARM about 1.1 s after onset; latched; the spoofed receiver never re-seeds |
| 2 m/s drag-off | WARNING about 0.7 s after onset (below the default ALARM level) |
| 25 m position step | ALARM about 1.1 s after onset |
| GNSS altitude-only 30 m offset | WARNING via baro |
| Accel bias (0.12, −0.08, 0.05) m/s² | Learned to within 0.005 m/s² per axis after 240 s |
| IMU gap, overflow, invalid attitude, gravity misconfiguration | DEGRADED or GRAVITY_FAULT; no false alarm |

**Limits seen in simulation.** Slow pull-offs (around 0.5 m/s) stay inside the conservative tilt and bias error model and are not detected. Neither is any attack present at seeding. The magnitude-only test cannot see direction-only manipulation; the vector tests can, but only when the heading is valid.

## 7. Merge gates (from guide §22; all open on hardware)

| Gate | How |
|---|---|
| Baseline | Reproducible build of the pinned tree; `discover_firmware.py` reports `ap_ids.gnss_integrity_objects` and IDSG/IDSR in `dataflash.ids_log_messages` |
| Sampling | Instrumented replay shows no missed or duplicate INS increment (`counters().imu_duplicates/gaps/overflows`, `buffer_high_water`) |
| Independence | Host test passes; repeat in SITL with GNSS injection |
| Feature disabled | Existing detector/event behaviour byte-identical with `IDS_GI_EN=0` |
| Timing | `capture_max_us`, observe path and logging p50/p99/max on Pixhawk 6C; no loop-rate regression (FW-01) |
| Logs/GCS | Import the `.bin`: the IDS page's FC GNSS INTEGRITY panel and timeline match the live PIDS events; `(Boot, Seq)` dedupe |
| HIL/bench | Fault injection (gap, clip, gravity convention, baro transient, compass disturbance), then a controlled detect-only flight after safety review |
