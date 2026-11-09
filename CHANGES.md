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
| Firmware contract | GCS parses DataFlash `PIDS/PIDH/PIDF/PIDW`, PIDS v2 STATUSTEXT and SYNC `boot=`/`drop=` ahead of the firmware. | `test_firmware_contract.py` |

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
