# SPIDERS.Mk1 — Architecture & Features

**S**ecurity **P**acket **I**ntrusion **D**etection **E**valuation and **R**esponse **S**ystem, Mark 1.
A ground control station (GCS), intrusion detection system (IDS) and digital forensics workbench for a **Pixhawk 6C running ArduCopter 4.7.1 (git `dbe79216`)** with the PUSHPAK on-board IDS.

> **Safety rule:** SPIDERS.Mk1 is **read-only**. It only *receives* MAVLink and never sends commands to the vehicle. When it detects an attack, its response is to **detect, record, alert, correlate and preserve evidence**. It never takes over the aircraft.

---

## 1. System overview

```
                      PIXHAWK 6C — ArduCopter 4.7.1 + PUSHPAK IDS
            ┌──────────────────────────────────────────────────────────┐
            │  Native AP_IDS (C++)  ──►  Lua confirmation scripts        │
            │  (first-stage)             (second-stage, SD card)         │
            └───────────────┬──────────────────────────────────────────┘
                            │ MAVLink v1/v2 (telemetry, STATUSTEXT)
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        SPIDERS.Mk1 BACKEND (Python)                      │
│                                                                          │
│  Sources ─► Decoder ─► Normalizer ─► Ground IDS ─► Correlation ─► Cases  │
│  (live/sim/   (raw kept)  (vehicle     (18 detectors  (incidents)  (SHA-256│
│   file)                     state)      + rules)                  sealed) │
│      │           │              │            │             │          │   │
│      └───────────┴── Raw .tlog recorder · SQLite · Rolling buffers ──┘   │
│                                  │                                       │
│                         Event bus ─► WebSocket hub + REST API            │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   │  REST + 6 WebSocket channels
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      SPIDERS.Mk1 FRONTEND (React)                        │
│  Dashboard · Flight · IDS · Custom Ruleset · Alerts · Incidents ·        │
│  Forensics · Replay · Packets · Logs · Health · Settings                 │
└─────────────────────────────────────────────────────────────────────────┘
```

The design has three detection tiers that deliberately stay separate:

| Tier | Where | Role |
|---|---|---|
| 1. Native AP_IDS | Flight controller (C++) | Fast first-stage detection |
| 2. Lua scripts | Flight controller (SD card) | Independent confirmation, reported as STATUSTEXT |
| 3. Ground IDS | SPIDERS.Mk1 | Deep analysis, cross-source correlation, forensics |

---

## 2. Technology stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11+, FastAPI, asyncio, pymavlink, SQLAlchemy Core + SQLite (PostgreSQL-ready), NumPy/SciPy, scikit-learn (optional), orjson, PyYAML, psutil |
| Frontend | React 19 + TypeScript, Vite, React Flow (`@xyflow/react`), ECharts, Leaflet (OpenStreetMap), TanStack Virtual, html2canvas |
| On-board | ArduPilot Lua 5.4 scripting (PUSHPAK scripts) |
| Testing | pytest (165 tests: 164 pass, 1 needs the original ROMFS package), Lua 5.4 via `lupa` with firmware-accurate mocks |

---

## 3. Data flow — one pipeline for everything

Live links, simulations, replays and imported log files all run through **the same `Pipeline` class**, so results are reproducible.

```
SourceItem (bytes or record)
   │
   ▼
Decoder ── keeps exact wire bytes; undecodable data → BAD_DATA event (bytes + error + recovered SYSID/COMPID)
   │
   ▼
TelemetryEvent  (idx, time, monotonic time, source, link, sysid, compid, msg id/name, seq, fields, raw, signing info)
   │
   ├─► Raw recorder (.tlog)        ├─► SQLite (batched)        ├─► Rolling buffer (5 min)
   ▼
VehicleState (each field: value, source, timestamp, AVAILABLE / STALE / UNAVAILABLE / INVALID)
   │
   ▼
Ground detectors (17) + published Custom Ruleset rules
   │
   ▼
Correlation engine ─► Incidents ─► Automatic forensic case (SHA-256)
   │
   ▼
Event bus ─► WebSocket channels ─► GUI
```

**Time model:** every event keeps UTC wall time *and* monotonic time. Persistence and rate maths use monotonic time. Gaps in data are "ticked through", so heartbeat-loss detection works the same live and offline.

---

## 4. Backend modules

```
backend/app/
├── main.py            REST API + WebSocket endpoints, error handling, static UI serving
├── config.py          YAML config (configs/default.yaml + local overrides)
├── lua_runtime.py     Lua 5.4 firmware-sandbox emulation + Lua-in-the-loop bridge
├── core/
│   ├── runtime.py     Session manager: live/sim/replay/import, health, rule tests
│   ├── pipeline.py    The single analysis pipeline (see §3)
│   ├── bus.py         Async event bus with bounded, lossy-for-display queues
│   ├── errors.py      Structured error model (ERR-000123 …)
│   └── audit.py       Hash-chained, append-only audit log
├── mavlink/
│   ├── registry.py    Dialect registry (IDs, fields, types, units, enums, extensions)
│   ├── decoder.py     Raw-preserving decoder, tlog framing/resync
│   ├── normalizer.py  Vehicle state model with field availability
│   └── pushpak.py     PUSHPAK STATUSTEXT parsers + chunked-text reassembly
├── ids/               Detectors, rule engine, correlation, ML (see §6–8)
├── forensic/          Recorder, rolling buffer, snapshots/cases, hashing (see §9)
├── sources/           live.py (UDP/TCP/serial), files.py (tlog/DataFlash/CSV/JSONL), simulation.py
├── storage/db.py      Database schema + batched background writer
├── websocket/hub.py   Per-channel client queues and resync
└── api/               queries.py (read side), security.py (auth/roles)
```

---

## 5. Connection center & data sources

| Source | Details |
|---|---|
| **UDP** | `udp:127.0.0.1:14550` (listen only) |
| **TCP** | `tcp:127.0.0.1:5760` |
| **Serial / USB** | `/dev/ttyUSB0:115200`, `COM3` |
| **Recorded file (Replay)** | Captures, forensic cases, imported logs |
| **Simulation** | 14 synthetic scenarios, clearly labelled SIMULATION |

**Connection states:** DISCONNECTED, CONNECTING, CONNECTED, DEGRADED, RECONNECTING and ERROR. Reconnection uses exponential backoff and never blocks the GUI.

**Displayed:** SYSID and COMPID, MAVLink version, packet rate, heartbeat age, received count, estimated loss, signing state and bad-frame count. Latency shows N/A, because measuring it needs TIMESYNC, and TIMESYNC requires transmitting.

**Offline import** handles `.tlog`, DataFlash `.bin`/`.log`, `.csv`, `.json`/`.jsonl` and exported case `.zip`. Each file is SHA-256 hashed *before* parsing, its format is auto-detected, and the parser is validated on the first records. Imported content is never executed, and zip extraction is protected against path traversal.

---

## 6. Ground IDS — the 18 detectors

Each detector runs inside its **own fault boundary**: if one crashes, ingestion, recording, the other detectors and the GUI keep running. Each detector reports its health (ONLINE, DEGRADED, WAITING_FOR_DATA, ERROR or DISABLED), plus its event count, errors and latency.

| Detector | What it catches | Methods |
|---|---|---|
| **HEARTBEAT** | Heartbeat stale / loss / recovery, intermittent loss | Gap timing, state machine |
| **MAVLINK_SEQUENCE** | Packet loss, duplicate (replay-like) frames, out-of-order frames | Tracked per SYSID+COMPID+link, windowed loss ratio |
| **SOURCE_IDENTITY** | New SYSID/COMPID, untrusted control-plane sender, vehicle masquerade | Baseline learning, provenance. A new source alone is only "NEW SOURCE OBSERVED" |
| **MAVLINK_RATE** | Message bursts, rate drops, traffic-mix change | EWMA baseline, CUSUM, entropy |
| **MAVLINK_SIGNING** | Unsigned / invalid / downgraded signing | Signing flags; validation when a key is active (keyring in Settings → Security; the key is never displayed); per-link `signing_policy` |
| **GPS_INTEGRITY** | Spoofing, slow drift, jumps, quality mismatch | GPS↔EKF residuals, MAD robust z-score, EWMA, CUSUM, EKF variance, persistence |
| **COMMAND** | Injected, burst, repeated or context-inconsistent commands, ACK mismatch | Weighted evidence (source / context / burst / repeat) |
| **PARAMETER** | Sensitive change while armed, untrusted writer, bursts, drift | Original-value baseline, CUSUM |
| **MISSION** | In-flight mission replacement, index jumps | SHA-256 mission fingerprint |
| **RC_LINK** | Gradual / abrupt / intermittent RC loss, rising radio errors | RSSI EWMA + slope, receiver health bit |
| **IMU_CONSISTENCY** | IMU↔IMU divergence, IMU↔AHRS, barometer↔GPS altitude | Pairwise residuals, leave-one-out, CUSUM |
| **OFFBOARD** | Stale / flooded setpoints, target divergence | Stream freshness, kinematics |
| **BATTERY** | Voltage steps without a load change, implausible readings | Step analysis |
| **FLIGHT_MODE** | Mode flapping, uncommanded mode change, disarm in flight | Transition log |
| **SENSOR_HEALTH** | Unhealthy sensors, EKF flags lost | SYS_STATUS bitmasks |
| **PUSHPAK_FC** | Flight-controller (PIDS) and Lua reports, Lua script errors, bridge reboots and missed events | STATUSTEXT adapters, bridge v2 SYNC, DataFlash IDSE/IDSH/IDSF (when the firmware writes them) |
| **BASELINE** | Parameters or mission that differ from the engineer-approved baseline, arming with mismatches | Signed manifest comparison; never re-learned |
| **ML_BASELINE** | Statistical outliers (supplementary only) | Isolation Forest from an approved profile, or an untrusted session baseline that pauses while other detectors alarm. It never opens an incident by itself |

**Analytic states:** OBSERVED, NORMAL, ANOMALOUS, SUSPECTED, CORRELATED, CONFIRMED, RESOLVED and FALSE_POSITIVE. A single anomaly is **never** turned into a confirmed attack on its own.

---

## 7. Correlation engine & incidents

```
Alert(s) ─► same domain or same attacker SYSID within the time window ─► Incident
```

- **Incident creation:**
  - 2 or more detectors correlate, or
  - the flight controller or Lua reports SUSPECTED or CONFIRMED, or
  - a rule's INCIDENT output fires, or
  - a single HIGH-severity detection is SUSPECTED.
- **Analytic state:**
  - SUSPECTED, then CORRELATED once there are 2 or more detectors or independent evidence lines.
  - CONFIRMED needs confidence ≥ 0.75 **and** at least 2 independent evidence lines. Results that depend on the same sensor or data path (for example ground, FC and Lua GPS checks that all use the GPS/EKF residual) form one line; repeats count at × 0.35 (`ids.corroboration_weight`). See `backend/app/ids/lineage.py`.
- **Confidence is explainable:** it's a list of contributors, e.g. "+35 parameter anomaly · GROUND". It's never an opaque score, and **severity is separate from confidence**.
- **Explanation panel** on every alert and incident: WHAT, WHY, WHEN, SOURCE, EVIDENCE, RULE, CONFIDENCE and LIMITATIONS.
- **Workflow:** OPEN, ACKNOWLEDGED, INVESTIGATING, RESOLVED and FALSE_POSITIVE. Evidence is **never deleted**, even when an alert is marked a false positive.

---

## 8. Custom Ruleset (visual rule builder)

Operators build detection logic **without code**. Rules are JSON *data*; there is no code generation or `eval`.

- **Node types (50):**
  - **INPUT:** MAVLink message, telemetry field, GPS/IMU/EKF/Battery/RC/Mission/Command/Parameter presets, flight mode, vehicle state, PUSHPAK FC detector, Lua event, DataFlash event, ground detector state
  - **TRANSFORM:** select field, normalize, difference, absolute value, scale, magnitude, derivative, moving average, EWMA, z-score, robust z-score, rate, frequency, count, delta, persistence, threshold, range check, CUSUM change detection
  - **LOGIC:** AND, OR, NOT, XOR, N-of-M, sequence, within window, before, after, until
  - **CORRELATION:** cross sensor, cross detector, FC + GROUND, multi-source, temporal, evidence-weighted
  - **OUTPUT:** OBSERVATION, ANOMALY, SUSPECTED, INCIDENT, CONFIRMED, FORENSIC SNAPSHOT
- **Validation** rejects:
  - unknown messages or fields (checked against the MAVLink registry)
  - non-numeric fields and type mismatches
  - bad operators, NaN values and negative durations
  - cycles, unconnected inputs and oversized graphs
- **Test** a rule against synthetic scenarios, recorded captures, forensic cases or imported logs. **Simulate expectations** checks the rule's expected trigger / non-trigger tests.
- **Live debug:** attaches a draft rule to the live session in shadow mode (it can't create incidents) and shows node values in real time.
- **Rule trace:** step by step, input → transform → condition → correlation → result, with the actual measured values.
- **Versioning:** every save is an immutable version with a SHA-256. You can publish, disable, clone and view version history, and forensic cases reference the exact rule version used. Undo/redo is supported.
- **Built-in rules (4):** GPS-CONSISTENCY-001, HEARTBEAT-RATE-001, CMD-BURST-001 and MAVSEC-CORR-001.

---

## 9. Forensics

| Feature | Details |
|---|---|
| **Raw recorder** | Every frame of every session is written to `.tlog` (8-byte timestamp + exact wire bytes). If disk space runs low, recording stops and the loss is logged explicitly. |
| **Rolling buffers** | 5 minutes of packets, results, state and timeline; bounded and rotation-counted |
| **Automatic snapshot** | On HIGH/CRITICAL or CONFIRMED incidents, or on manual request: **30 s before + incident + 60 s after** (configurable) |
| **Case directory** | `manifest.json`, `incident.json`, `timeline.jsonl`, `mavlink_raw.bin`, `mavlink_decoded.jsonl`, `telemetry.jsonl`, `ids_events.jsonl`, `gps_track.csv`, `attitude.csv`, `battery.csv`, `commands.jsonl`, `parameters.jsonl`, `rules/`, `screenshots/`, `hashes.sha256`, `case.sig.json` (Ed25519), `README.txt` |
| **Manifest** | Vehicle, firmware and git commit, trigger, capture window, evidence counts, rule versions, config snapshot, and every artifact's size, SHA-256, time and source |
| **VERIFY CASE** | Returns VALID, MODIFIED, MISSING or UNVERIFIABLE per file, plus the signature status (VALID, UNSIGNED, CONTENT_CHANGED, INVALID_SIGNATURE, UNTRUSTED_KEY). `hashes.sha256` is compatible with `sha256sum -c` (cases sealed on Windows before 9 Nov 2026 have `\r\n` lines) |
| **Append-only additions** | Screenshots (html2canvas) and custody events can only be added to a VALID case; each addition is a signed manifest revision |
| **Export** | Case ZIP; re-importable and re-verifiable |
| **Evidence graph** | Clickable graph: incident ↔ detector results ↔ MAVLink messages ↔ rules ↔ Lua/FC ↔ attacker ↔ snapshot |

> Hashes detect modification; on their own they do not establish a legal chain of custody.

---

## 10. On-board Lua scripts (PUSHPAK)

Located in `firmware/scripts/` and verified against the real firmware binary.

| Script | Confirms | Evidence used |
|---|---|---|
| `gps_confirm.lua` | GPS spoofing / drift | `gps:`, `ahrs:get_location/get_velocity_NED/get_variances` |
| `mavlink_confirm.lua` | Link loss / DoS pattern | GCS last-seen time, intermittency |
| `command_confirm.lua` | Command injection (by its effect) | Mode changes, ModeReason, GCS silence |
| `jamming_confirm.lua` | RC/telemetry jamming | `rc:has_valid_input`, telemetry loss |
| `imu_confirm.lua` | IMU divergence / bias | `ins:` accel/gyro, health, consistency |
| `mission_confirm.lua` | Mission tampering | `mission:get_item` fingerprint, nav index |
| `parameter_confirm.lua` | Parameter tampering | `param:get` sensitive watch list |
| `offboard_confirm.lua` | External-control anomaly | GUIDED target vs position |
| `ids_gcs_bridge.lua` | Binding availability and native event counter | `ids:event_sequence()` |
| `modules/ids_common.lua` | Shared helpers, hysteresis state machine | loaded with `require()` |

Each script reports **both** ways:
- a `PIDS|1|LUA|<DET>|<state>|<conf>|<evidence>|…` STATUSTEXT line
- `ids:report_confirmed(...)` into the native IDS

Long texts are chunked; the GCS reassembles them.

**Firmware findings (from build-artifact discovery, `configs/capabilities.json`):**
- **DISC-001–004 are resolved.** They described the 26 Sep 2026 build: a 2-method binding the original scripts didn't match, a stub `AP_IDSGCS::report_confirmed`, only 3 of 8 native detectors driven, and an unverified state map. build_v3 (APJ `223c26f8…`) has a 26-method binding, implements `report_confirmed`, drives all 8 detectors, and pins the state enum with `static_assert`s. The current scripts use only the two methods every build has.
- **DISC-005 is open:** build_v3's ROMFS embeds older copies of 6 of the current scripts. See `firmware/BUILD_AND_LINKING.md`.
- Script fixes that apply to every build: the firmware has no `dofile`, so helpers are loaded with `require()` from `scripts/modules/`; `gyros_consistent()` needs an integer argument.

**Install:** copy `scripts/` (including `modules/`) to `APM/scripts/` on the SD card, then set `SCR_ENABLE=1` and `SCR_DIR_DISABLE=1` (to skip the broken scripts embedded in ROMFS).

---

## 11. Source-of-truth discovery

`scripts/discover_firmware.py` inspects a build zip + a ROMFS package (including disassembling the ELF) and, with `--ap-ids-source`, the AP_IDS headers. It writes **`configs/capabilities.json`** (currently generated from build_v3, APJ `223c26f8…`):

- firmware version, git commit, board, flash size, APJ SHA-256
- compiled AP_IDS objects and Lua binding methods
- which native detectors are driven, from every call site of `<Detector>::update/observe` in the ELF
- whether `AP_IDSGCS::report_confirmed` is a stub
- the PIDS state enum, verified from `static_assert`s in `AP_IDS.h`
- custom MAVLink messages (none), DataFlash IDS messages (none)
- embedded ROMFS scripts vs supplied scripts
- recorded discrepancies

Rule: **actual firmware wins.** Unknown values are shown as **N/A**, never invented.

---

## 12. Frontend (GUI)

**Layout:** top status strip, collapsible sidebar with icons, workspace, bottom status bar (telemetry, recorder, IDS, DB, disk, WebSocket, UTC clock).
**UI modes:** OPERATOR, INVESTIGATOR and ENGINEER, each showing only the pages it needs.
**Themes:** Light, Dark or System (Settings → Appearance).

| Page | Features |
|---|---|
| **Dashboard** | Critical-incident banner, stats (detectors OK / open incidents / new alerts), live map, telemetry strip (ALT, SPD, HDG, CLIMB, BAT, GPS, LINK), IDS health rail per PUSHPAK family (Ground / FC / Lua), critical alerts, recent events |
| **Flight** | Map, artificial horizon, flight state, battery, GPS, link, compact IDS status, altitude and speed charts (GPS vs EKF vs VFR) |
| **IDS** | Detector grid, FC vs Ground comparison table, Lua script health, active anomalies, confidence timeline, correlation graph, threat history, live rule statistics |
| **Custom Ruleset** | Visual rule builder (§8) |
| **Alerts** | SOC-style table, filters (severity, source, status, detector, confidence, session, search), actions (Open, Investigate, Acknowledge, False positive, Resolve, Snapshot), CSV/JSON export |
| **Incidents** | List + investigation view: header, contributors, event timeline, map with time cursor, evidence tabs (results with explanation and trace, telemetry with markers, evidence graph, MAVLink packets, config diff) |
| **Forensics** | Case search (ID, severity, detector, date, SYSID, source), manifest, artifacts with hashes, VERIFY CASE, file viewer, screenshot, ZIP export |
| **Replay** | Play/pause, 0.25×–10×, seek slider, jump to first anomaly / incident / command, synchronised map, telemetry, detectors, events and packets |
| **Packets** | Virtualised packet table (TIME, SYS, COMP, SEQ, ID, MESSAGE, SOURCE, SIGNING), live tail or session query, filters, jump to time, decoded fields, hex dump, header, definition, copy decoded/hex |
| **Logs** | Import (hash, size, format, parser version), sessions, analytics (time-series overlay, correlation matrix, message frequency, source analysis, detector history), flight comparison, config diff, audit log with chain verification, system events |
| **Health** | Subsystem status, resources, detector health, structured errors (engineer detail), fault injection for failure testing |
| **Settings** | Connection center, firmware discovery and discrepancies, runtime settings (audited), MAVLink schema browser, appearance/theme |

**Map:** Leaflet + OpenStreetMap tiles. It shows the live vehicle position and heading from `GLOBAL_POSITION_INT`, the EKF track, home, and clickable alert/incident markers. If tiles can't load (offline), the data layers still render.

---

## 13. API

**REST (selected):**

```
GET  /api/health  /api/capabilities  /api/meta  /api/vehicle  /api/telemetry/{current,history,track}
GET  /api/mavlink/registry  /api/mavlink/messages  /api/mavlink/messages/{session}/{idx}  /api/mavlink/sources
GET  /api/ids  /api/ids/detectors  /api/ids/comparison  /api/ids/events  /api/ids/results/{id}
POST /api/ids/events/{id}/status  /api/ids/detectors/{id}  /api/ids/fault-injection
GET  /api/incidents  /api/incidents/{id}          POST /api/incidents/{id}/status
GET  /api/rules  /api/rules/catalog  /api/rules/{id}  /api/rules/{id}/history
POST /api/rules  /api/rules/validate  /api/rules/test  /api/rules/test-expectations  /api/rules/publish
POST /api/rules/{id}/{enable,disable,clone}  /api/rules/live-test
GET  /api/forensics/cases  /api/forensics/cases/{id}  /api/forensics/cases/{id}/{file,export}
POST /api/forensics/snapshot  /api/forensics/verify  /api/forensics/cases/{id}/screenshot
POST /api/connection   DELETE /api/connection   POST /api/replay/control   GET /api/replay/datasets
POST /api/logs/import  GET /api/logs/imports  GET /api/analytics/{series,frequency,sources,correlation,compare,detector-history}
GET  /api/config/diff  /api/settings  /api/audit  /api/audit/verify  /api/errors  /api/timeline  /api/sessions
```

There is **no endpoint that sends MAVLink to the vehicle.**

**WebSocket channels:** `/ws/telemetry` (10 Hz state), `/ws/ids`, `/ws/incidents`, `/ws/events` (timeline, packets, connection), `/ws/health`, `/ws/builder`. Each client gets a full resync on (re)connect.

---

## 14. Storage (SQLite, PostgreSQL-ready)

**Tables:** flights (sessions), connections, telemetry, mavlink_messages, detector_states, detector_results, ids_events (alerts), incidents, incident_evidence, rules, rule_versions, rule_runs, gps_points, attitude_samples, battery_samples, commands, parameters, forensic_cases, artifacts, artifact_hashes, system_events, audit_log, imports.

- **Batched writer thread:** writes are batched every 0.5 s, so ingest never waits on disk.
- **Database outages:** critical rows go to a bounded emergency queue and the degraded state is shown in the GUI.
- **Retention:** high-rate rows are purged after `retention_days`.

---

## 15. Security & reliability

- **Local by default:** binds to 127.0.0.1 and only loopback clients are served.
- **Remote mode:** needs TLS and bearer tokens (stored as SHA-256 hashes). Roles are operator < investigator < engineer < admin.
- **Input safety:** bounded payloads and queues, safe JSON, path-traversal checks, and no shell execution from user input.
- **Audit log:** hash-chained. It records connections, rule create/modify/publish/disable, case opened/exported, hash verified, false positive marked, incident resolved and settings changed.
- **Fail-safe design:**
  - A decoder failure still keeps the raw bytes.
  - A detector crash is isolated.
  - A database outage uses the emergency queue.
  - A WebSocket drop reconnects and resyncs.
  - Disk full stops the recorder and logs the loss explicitly.
- **Backpressure:** display updates may be dropped under load, but forensic evidence is never dropped silently.

---

## 16. Simulation & validation

**14 synthetic scenarios.** Each generates real MAVLink v2 frames from a vehicle, a GCS (SYSID 255) and an attacker (SYSID 42), with nothing transmitted:
NORMAL_FLIGHT, GPS_DRIFT, GPS_JUMP, GPS_IMU_MISMATCH, MAVLINK_SEQUENCE_GAP, HEARTBEAT_LOSS, UNKNOWN_SOURCE, COMMAND_BURST, PARAMETER_CHANGE, MISSION_CHANGE, RC_DEGRADATION, MULTI_SIGNAL_INCIDENT, PUSHPAK_CONFIRMATION, LUA_BINDING_MISMATCH.

**Lua-in-the-loop:** `LuaFlightBridge` runs the real PUSHPAK Lua scripts on the simulated vehicle state. Their STATUSTEXT is packed in-order by the simulated vehicle, so the GCS receives exactly what a Pixhawk would send.

**Validation (`scripts/run_validation.py`):**
- TC-01 to TC-06, 10 varied runs each: random seed, attack magnitude 0.6–1.4×, injection 35–60 s.
- Results fill the Stage-1 report table (`scripts/fill_report_table.py`).

| Test | Scenario | Ground IDS | Lua |
|---|---|---|---|
| TC-01 | Normal flight | 0 false alerts | 0 false alarms |
| TC-02 | GPS spoofing | 10/10, ≈1.0 s, CONFIRMED | 10/10 CONFIRMED |
| TC-03 | Command injection | 10/10, ≈2.1 s, CONFIRMED | 10/10 SUSPECTED |
| TC-04 | Parameter tampering | 10/10 | 10/10 CONFIRMED |
| TC-05 | RC jamming | 10/10 | 10/10 CONFIRMED |
| TC-06 | Mission tampering | 10/10 | 10/10 CONFIRMED |

*(All results are from simulated data.)*

**Test suite:** 40 pytest tests, covering:
- known-good and known-anomaly flights
- detector-crash isolation
- malformed bytes
- tlog resync
- PUSHPAK parsing
- rule validation and expectations
- hash verification
- the Lua scripts under a strict firmware-sandbox emulation

---

## 17. Configuration (`configs/default.yaml`)

Every threshold lives in configuration or in rule definitions, never in GUI code. The main sections are `mavlink` (connection, trusted GCS SYSIDs, signing), `recording`, `forensics` (pre/post windows, auto-snapshot severities), `ids` (thresholds, correlation window, per-detector settings), `database`, `limits`, `security` and `simulation`. Runtime changes are made through Settings (engineer role) and are audited.

---

## 18. Run

```bash
python3 -m venv .venv && .venv/bin/pip install -r backend/requirements.txt
cd frontend && npm install && npm run build && cd ..
cd backend && ../.venv/bin/python run.py         # → http://127.0.0.1:8600
```

Tests: `cd backend && PYTHONPATH=. ../.venv/bin/python -m pytest -q`

---

## 19. Known limitations

- **Not validated on hardware or with real flight/attack logs.** All results are simulated, and thresholds need tuning on SITL and real flights.
- **ArduPilot only.** PX4 and multi-vehicle fleets aren't supported yet.
- **No RF-layer sensing.** Jamming is inferred from link behaviour only.
- **No firmware or bootloader integrity detection.**
- **Firmware-side gaps** that need firmware work: no native DataFlash IDS records, no passive PARAM_SET or setpoint hooks, an 8-slot RAM-only event ring, and build_v3 embedding older ROMFS scripts (DISC-005). See `firmware/FIRMWARE_WORK_REQUIRED.md`.
- **Lua visibility is limited** by the available bindings: it can't see packet source, RSSI or the command stream.
- **Link latency is N/A,** because measuring it would require transmitting (TIMESYNC).
- **No reverse replay:** seek re-analyses the recording from the start instead.
