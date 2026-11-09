# SILKTRACE advanced capabilities

This extension adds progressive replay, DJI FlightRecord parsing, isolated parser execution, a versioned firmware/log-format knowledge index, investigator-defined vehicle profiles, and anomaly screening. It is a forensic analysis aid; it does not guarantee semantic decoding of every proprietary or encrypted aircraft log.

## 2D/3D replay

`GET /api/silktrace/evidence/{evidence_id}/replay` builds a replay stream from decoded parser samples or the investigator's saved custom-schema result.

- 2D: Leaflet map, recorded GPS polyline, first/last fixes, current-sample marker, sample scrubbing and play speeds (0.25x–8x).
- 3D: perspective projection of an illustrative multirotor frame, driven by recorded roll/pitch/yaw or an explicitly named quaternion. It is an attitude visualization, not an aircraft-specific CAD model or physics simulation.
- Sparse message formats preserve each message's source timestamp/index. The UI carries the latest preceding GPS and attitude sample while scrubbing; it does not interpolate missing telemetry.
- GPS values are only displayed when valid coordinates exist. Quaternion-to-Euler conversion is a derived transformation. Radian conversion is applied only to fields explicitly named `*_rad`.
- Map tiles use OpenStreetMap and therefore require network access unless the deployment supplies an offline tile source. Telemetry replay itself is local.

## Betaflight / INAV Blackbox

The ingestion parser recognizes the Blackbox header. If the upstream `blackbox_decode` executable is installed on the backend PATH, the isolated worker invokes it with CSV output and explicit unit arguments, then stores a bounded decoded sample preview for replay and analysis. The executable is not bundled; this avoids silently importing GPL-3.0 code into SPIDERS. The official Betaflight tool documents `blackbox_decode LOG00001.TXT`, `--stdout`, unit selection and CSV conversion. Build it on Linux from the upstream repository:

```bash
git clone https://github.com/betaflight/blackbox-tools.git
cd blackbox-tools
make obj/blackbox_decode
sudo install -m 0755 obj/blackbox_decode /usr/local/bin/blackbox_decode
```

On Windows, use a compatible upstream release binary and add its directory to PATH. If it is absent, SILKTRACE reports header-only support rather than claiming frame decoding. See the upstream [blackbox-tools](https://github.com/betaflight/blackbox-tools) and [Betaflight Blackbox documentation](https://betaflight.com/docs/wiki/guides/current/Black-Box-logging-and-usage).

## DJI FlightRecord

The optional `pydjirecord==1.3.0` package is integrated for DJI FlightRecord TXT files. It supports log format versions 1–14; v1–12 frame parsing can be performed without per-flight keychains. DJI FlightRecord v13–14 frame records are encrypted and require per-flight keychains obtained from DJI's API. SILKTRACE does not fetch keys implicitly, does not request or store a developer key, and does not bypass encryption. Without keychains it records available header metadata and reports that frame telemetry is unavailable.

DJI aircraft DAT files are not interchangeable with app FlightRecord TXT files. The DAT path remains conservative structural triage unless a validated model-specific decoder is integrated. A converted DJI/Airdata CSV can be imported as ordinary delimited telemetry.

## Parser isolation

`POST /api/silktrace/evidence/{evidence_id}/sandbox-inspect` executes only reviewed built-in parsers in a separate Python process. The worker applies CPU, address-space, output-file and file-descriptor limits, uses a timeout, has no stdin, and emits bounded JSON. It does not load third-party parser plugins or execute content extracted from evidence.

On Linux, install Bubblewrap (`bwrap`) to enable the stronger mode: read-only root filesystem, isolated network namespace, no Linux capabilities, private `/tmp`, and process limits. If Bubblewrap is unavailable, the API explicitly reports the weaker resource-limited subprocess mode; do not describe that fallback as a complete OS sandbox. Production deployments handling hostile evidence should require Bubblewrap or run parser workers in a dedicated container/VM with no network and read-only evidence mounts.

## Vehicle knowledge base

`backend/app/silktrace/knowledge_base/catalog.json` indexes ArduPilot, PX4, Betaflight, INAV, DJI FlightRecord and unknown/custom systems. Entries contain format families, parameter namespaces, source references and limitations. They are not manufacturer-verified airframe performance specifications. The API supports custom investigator profiles with arbitrary actuator counts, sensor lists and geometry fields. Profiles are marked `verified: false` until independently corroborated.

- `GET /api/silktrace/vehicles`
- `POST /api/silktrace/vehicles`

## Behavioural analysis

`POST /api/silktrace/evidence/{evidence_id}/behavior` runs robust median/MAD outlier screening and, when sufficient complete numeric features exist and scikit-learn is installed, IsolationForest. The model is fit to the current recording only. It is not a trained fault classifier, and results are screening candidates—not proof of equipment failure, spoofing, compromise or malicious intent. There is no labelled cross-airframe training corpus in this change set.

## Validation

Focused tests:

```bash
cd backend
PYTHONPATH=. python -m pytest -q tests/test_silktrace.py tests/test_silktrace_advanced.py
```

Frontend production build:

```bash
cd frontend
npm ci
npm run build
```

The frontend build must be run in an environment where the locked npm dependencies can be installed. A network timeout during `npm ci` is not a successful build.
