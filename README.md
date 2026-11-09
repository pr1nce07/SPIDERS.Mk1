# SPIDERS.Mk1
**Security Packet Intrusion Detection Evaluation and Response System**, the ground control, IDS and forensics platform for the PUSHPAK UAV IDS.

A ground control station and IDS for Pixhawk 6C running ArduPilot with the PUSHPAK IDS firmware. It combines a live GCS view, distributed intrusion detection, incident correlation, forensic evidence cases, a visual IDS rule builder and flight replay. It was built from `PUSHPAK_GCS_IDS_BUILDER_MASTER_PROMPT.md`.

**The GCS is read-only.** It only receives MAVLink. No transport or API can send commands to a vehicle. Detection does four things: it detects, records, alerts and preserves evidence.

## Run

### Windows (PowerShell)

One-time setup (Python 3.11+ and Node.js required):

```powershell
py -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
Push-Location frontend
npm install
Pop-Location
```

Build the frontend and start the app at http://127.0.0.1:8600:

```powershell
.\scripts\start.ps1
```

For frontend development with hot reload, run the backend and Vite in separate terminals:

```powershell
# Terminal 1
Push-Location backend
& ..\.venv\Scripts\python.exe run.py

# Terminal 2
Push-Location frontend
npm run dev  # open the URL printed by Vite
# Terminal 2 (if disc is partitioned)
npm.cmd run dev # open the URL printed by Vite
```

### macOS / Linux

```bash
# One-time setup
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt
npm --prefix frontend install

# Build the UI, then start the app at http://127.0.0.1:8600
bash scripts/start.sh
```

For Vite development with hot reload, run the backend and `npm --prefix frontend run dev` in separate terminals. The dev server proxies `/api` and `/ws` to port 8600.

```bash
# tests
cd backend && PYTHONPATH=. ../.venv/bin/python -m pytest -q     # 20 tests

# re-run source-of-truth discovery against the supplied artifacts
.venv/bin/python scripts/discover_firmware.py --build-zip ../shareable_progress/build.zip --romfs-zip ../shareable_progress/ROMFS_custom.zip
```

To connect, use **Connection** in the top bar. Connection strings look like `udp:127.0.0.1:14550`, `tcp:127.0.0.1:5760`, `/dev/ttyUSB0:115200` or `COM3`. Simulation and Replay are also available there. Simulation runs 14 synthetic scenarios. These are real MAVLink frames generated in-process, and they are clearly labelled SIMULATION.

## Source-of-truth findings (`configs/capabilities.json`)
Everything below was read from the supplied `build.zip` and ROMFS files, including a disassembly of the ELF.

| Item | Value |
|---|---|
| Firmware | ArduCopter V4.7.1, git `dbe79216`, Pixhawk6C, APJ board 56 |
| AP_IDS | Native library compiled in. `AP_IDS::update()` runs only the GPS, IMU and Mission detectors |
| Lua `ids` binding | Only `report_confirmed()` and `event_sequence()` exist |
| Custom MAVLink / DataFlash IDS messages | None. The stock `ardupilotmega` dialect is used |

The four discrepancies below are recorded and shown under Settings → Firmware discovery:

* **DISC-001**: The Lua scripts call methods that the binding doesn't have, such as `ids:gps_confidence()`. On this build the scripts are therefore expected to fail with a Lua runtime error. The `PIDS|…` and `PUSHPAK IDS: …` STATUSTEXT messages will not appear. The GCS parses these formats when they do appear, and otherwise shows FC/LUA as N/A. Lua runtime errors are reported as Lua-layer health.
* **DISC-002**: `AP_IDSGCS::report_confirmed` is a stub that just returns false.
* **DISC-003**: Only 3 of the 8 detector families are driven by `AP_IDS::update()`.
* **DISC-004**: The mapping of PIDS state integers to CLEAR/SUSPECTED/CONFIRMED is taken from the documentation. It could not be verified in the binary.

There is one more finding. The gps_confirm.lua report is 81 characters, which is longer than a single 50-character STATUSTEXT. It therefore arrives chunked, and the GCS reassembles it using `id`/`chunk_seq`.

## Fixed Lua scripts
`firmware/scripts/` (and `firmware/ROMFS_custom_fixed.zip`) is a rewrite of the PUSHPAK Lua scripts. They use only the bindings present in this firmware build. See `firmware/README.md`. They are verified under Lua 5.4 against strict binding mocks by `backend/tests/test_lua_scripts.py`. The GCS parses their `PIDS|1|LUA|…`, `BRIDGE` and `FC_EVENT` output.

## Architecture
```
Source (UDP/TCP/Serial | .tlog | DataFlash | JSONL/CSV | case | simulation)
  → Decoder (raw bytes always preserved; BAD_DATA keeps bytes, error, recovered SYSID/COMPID)
  → TelemetryEvent → raw .tlog capture + SQLite (batched) + rolling buffer
  → VehicleState (AVAILABLE / STALE / UNAVAILABLE / INVALID, never a fake 0)
  → 17 ground detectors (each isolated in its own fault boundary) + published IDS-Builder rules
  → Correlator (explainable contributors; CONFIRMED needs ≥2 independent sources or ≥3 detectors)
  → Incidents → automatic forensic case (30 s before + incident + 60 s after, SHA-256 sealed)
  → Event bus → WebSockets /ws/{telemetry,ids,incidents,events,health,builder} → React GUI
```
Live, replay and offline import all run through the same `Pipeline` class (`backend/app/core/pipeline.py`).

**Detectors:**
* HEARTBEAT, MAVLINK_SEQUENCE, SOURCE_IDENTITY, MAVLINK_RATE, MAVLINK_SIGNING
* GPS_INTEGRITY: rules, MAD robust z-score, EWMA, CUSUM, jump detection, GPS↔EKF residuals, EKF innovations, quality mismatch, persistence
* COMMAND, PARAMETER, MISSION (SHA-256 fingerprint), RC_LINK, IMU_CONSISTENCY, OFFBOARD
* BATTERY, FLIGHT_MODE, SENSOR_HEALTH
* PUSHPAK_FC (PIDS, Lua confirmations, Lua errors)
* ML_BASELINE (Isolation Forest). This is supplementary only and never opens an incident on its own.

**Custom Ruleset:**
* Has 50 node types across five categories: input, transform, logic, correlation and output.
* Rules are validated against the MAVLink registry. Validation catches unknown messages and fields, wrong types, bad operators, NaN or negative values, cycles and oversized graphs.
* You can test rules against synthetic scenarios, recorded captures, cases or imported logs, and check expected-trigger tests.
* It also has a live shadow debugger, a rule trace ("OPEN RULE TRACE"), immutable versions with SHA-256, publish/disable/clone, and undo/redo.
* Four built-in rules ship with it, including the §14 GPS/EKF example. All their expectation tests pass.

**Case directory:** `manifest.json`, `incident.json`, `timeline.jsonl`, `mavlink_raw.bin`, `mavlink_decoded.jsonl`, `telemetry.jsonl`, `ids_events.jsonl`, `gps_track.csv`, `attitude.csv`, `battery.csv`, `commands.jsonl`, `parameters.jsonl`, `rules/`, `screenshots/`, `hashes.sha256` and `README.txt`.
* `mavlink_raw.bin` uses tlog framing. It is not a PCAP.
* `hashes.sha256` is compatible with `sha256sum -c`.
* VERIFY CASE returns VALID, MODIFIED, MISSING or UNVERIFIABLE.
* Screenshots can be added only to a case that is still VALID. Each addition is recorded as a manifest revision and in the audit log.

**Other:**
* Audit log: append-only and hash-chained, with a verify endpoint.
* Local mode: loopback only.
* Remote mode: bearer tokens stored as SHA-256 hashes, roles (operator < investigator < engineer < admin), and TLS is required.

## Verified in this build
* 39 backend tests pass (including 19 Lua-script tests). They cover:
  * known-good and known-anomaly flights
  * detector-exception isolation
  * malformed bytes being preserved
  * tlog resync after corruption
  * PUSHPAK formats and chunked text
  * rejection of invalid or circular rules
  * rule expectations
  * all four hash-verification outcomes
* End to end against the running server:
  * a simulation produces correlated incidents and auto-cases, and those cases verify as VALID
  * an imported tlog's SHA-256 matches `shasum`
  * replay with seek works
  * the audit chain verifies as VALID
  * config diff works
  * the frontend type-checks, builds, and renders the dashboard, incidents and builder
* The NORMAL_FLIGHT scenario produces 0 alerts.

## Known limitations
* **Not tested against real hardware.** No real Pixhawk, and no real .tlog or DataFlash file, was available. The UDP/TCP/serial transports and the DataFlash mapper are implemented but have not been exercised against real data.
* **Latency shows N/A.** Measuring it needs TIMESYNC, which requires transmitting.
* **Signing can't be validated without the key.** Without `signing_key_file`, signed frames show as SIGNED (unverified).
* **No reverse playback.** Detector state depends on order, so seeking backwards re-analyses from the start of the recording instead.
* **Detectors are synchronous.** The `process()` interface is synchronous (called in order) rather than `async`, which keeps the offline and live paths identical.
* **Screenshots need an open GUI.** They are captured by a connected GUI client (html2canvas), not by the backend.
* **Tailwind is not used.** The frontend uses its own CSS design system instead.
* **Thresholds are not tuned against real flights.** Detector thresholds in `configs/default.yaml` are initial values and should be tuned against real SITL and flight traces.

## SILKTRACE — universal drone evidence intake

The SILKTRACE module adds evidence-first intake for known and unknown drone blackbox formats. It stores immutable-by-policy originals, records SHA-256 hashes, performs progressive format inspection, and exposes a dedicated investigator workspace. It is an incremental extension: see [`docs/silktrace/README.md`](docs/silktrace/README.md) for supported formats, API routes, limitations and tests. Unknown-format acceptance is supported; universal semantic decoding is not claimed.

### SILKTRACE advanced analysis

SILKTRACE now includes GPS track replay, attitude-based 3D perspective replay, synchronized sample controls, DJI FlightRecord parsing (via `pydjirecord`), resource-limited isolated parser execution, firmware/log-format knowledge references, custom vehicle profiles, and robust statistical/IsolationForest anomaly screening. See [`docs/silktrace/ADVANCED_CAPABILITIES.md`](docs/silktrace/ADVANCED_CAPABILITIES.md) for limitations and deployment hardening. DJI v13–14 frame decryption requires per-flight DJI keychains; SILKTRACE does not fetch or store keys implicitly.
