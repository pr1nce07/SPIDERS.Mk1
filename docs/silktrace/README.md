# SILKTRACE — SPIDERS.Mk1 extension

SILKTRACE is an evidence-first drone-log investigation module integrated into the existing SPIDERS.Mk1 FastAPI backend and React frontend. It reuses the repository's authentication and UI components; it does not replace the MAVLink IDS pipeline.

## Implemented

- L0/L1 acceptance and structural inspection for unknown file extensions.
- SHA-256 hashing, post-copy verification, read-only original evidence guardrail and integrity recheck.
- Isolated parser worker with CPU/address-space/file-size limits and timeout. Bubblewrap adds filesystem/network/capability isolation on Linux when installed. Without Bubblewrap, the API explicitly reports the weaker resource-limited subprocess fallback.
- PX4 ULog topic sample extraction via `pyulog` and ArduPilot DataFlash message extraction via `pymavlink` where dependencies and log versions permit.
- Betaflight Blackbox header inspection; optional upstream `blackbox_decode` invocation from the isolated worker when the executable is installed.
- DJI FlightRecord TXT parsing via `pydjirecord` for supported unencrypted versions. DJI v13–14 frame decryption requires per-flight keychains and is not fetched implicitly. DJI aircraft DAT remains structural triage unless a model-specific decoder is installed separately.
- CSV/JSON/NMEA and custom fixed-width binary schema support.
- 2D GPS map replay, 3D position/altitude projection, 3D attitude projection, synchronized sample scrubbing, play/pause and speed control.
- Versioned firmware/log-format knowledge catalog and investigator-defined vehicle profiles with arbitrary actuator counts.
- Robust median/MAD anomaly screening and optional IsolationForest on sufficiently complete numeric features.

See [`ADVANCED_CAPABILITIES.md`](ADVANCED_CAPABILITIES.md) for detailed parser, replay, DJI, sandbox, ML and deployment boundaries.

## API

- `GET /api/silktrace/capabilities`
- `POST /api/silktrace/evidence` — multipart `file` and optional `notes`
- `GET /api/silktrace/evidence`
- `GET /api/silktrace/evidence/{evidence_id}` — current hash integrity check
- `POST /api/silktrace/evidence/{evidence_id}/schema` — custom fixed-width schema decode
- `GET /api/silktrace/evidence/{evidence_id}/replay?profile_id=...` — replay stream
- `POST /api/silktrace/evidence/{evidence_id}/sandbox-inspect` — isolated parser rerun
- `POST /api/silktrace/evidence/{evidence_id}/behavior` — anomaly screening
- `GET /api/silktrace/vehicles` — built-in references and custom profiles
- `POST /api/silktrace/vehicles` — save investigator-defined profile

Intake and analysis require the existing `investigator` role; read endpoints use `operator` role. Upload size follows `limits.max_upload_mb`.

## Install / run

```bash
python -m pip install -r backend/requirements.txt
```

For stronger Linux parser isolation, install Bubblewrap (`bwrap`) using the OS package manager. For Betaflight frame decoding, install the upstream `blackbox_decode` executable and ensure it is on the backend PATH. Start SPIDERS with the existing `scripts/start.sh` or `scripts/start.ps1` and select **SILKTRACE** in the navigation. The page has two tabs: **Native cases** lists the incident cases SPIDERS captured itself (served by `/api/forensics/...`), and **Universal forensics** is the drone-log evidence workspace described here.

## Test

```bash
cd backend
PYTHONPATH=. python -m pytest -q tests/test_silktrace.py tests/test_silktrace_advanced.py
```

Frontend build:

```bash
cd frontend
npm ci
npm run build
```

A successful production build must be confirmed in an environment where the locked npm dependencies install successfully.
