# Dataset card and corpus manifest (GAP-02)

Fill one dataset card per evaluation corpus. `scripts/evaluate_detectors.py` reads the corpus manifest below and replays every run through the same pipeline the GCS uses live.

## 1. Dataset card

| Field | Value |
|---|---|
| Corpus ID / version | e.g. `pushpak-quadx-2026.11` |
| Owner / contact | |
| Collection period | |
| Vehicles (ID, airframe, board revision) | |
| Autopilot builds (commit, image SHA-256) | Every run must name the exact firmware hash it was recorded on. |
| Sensor configuration | GNSS receiver(s), compass, IMU count, rangefinder, airspeed, optical flow |
| Environments | Site, weather, temperature, GNSS conditions (open sky / urban / multipath) |
| Collection method | Live telemetry (`.tlog`), onboard DataFlash (`.bin`), or both |
| Ground-truth method | How each attack window was established: injection log, test-director timeline, RF facility record |
| Labelling protocol | Who labelled, how disagreements were settled, the label vocabulary |
| Known gaps | Conditions not covered: night, rain, specific manoeuvres, other airframes |
| Legal / safety approval | RF tests only in an approved facility or simulator; never conduct unauthorised interference or spoofing |

## 2. Partitions

Keep the four partitions strictly separate. A flight belongs to exactly one.

| Partition | Use |
|---|---|
| `tune` | Choose thresholds and persistence settings. |
| `validation` | Tune correlation policy; check that tuning generalises. |
| `locked` | **Never** used for tuning. Run once, after the configuration is frozen. The harness refuses it unless `--frozen-config` matches the current configuration fingerprint. |
| `external` | Different vehicle, firmware build, environment or attack implementation. |

Record the fingerprint before running `locked`:

```bash
python scripts/evaluate_detectors.py --fingerprint
```

```bash
python scripts/evaluate_detectors.py corpus.json --partition locked --frozen-config <fingerprint> --out reports/locked
```

## 3. Benign scenarios to include

Takeoff/landing, hover, aggressive acceleration and turns, altitude changes, vibration, GPS multipath, satellite-count changes, receiver reset, estimator reset, RC range degradation, telemetry congestion, legitimate parameter changes, mission uploads while disarmed, GCS reconnection and battery transients.

## 4. Controlled attack/fault scenarios

Malformed frames, unknown sources, stale or replayed signed messages, command bursts, parameter changes, mission changes, stale offboard streams, simulated GNSS anomalies and sensor faults. Use a simulator, an approved RF test facility or an isolated laboratory for anything RF-related.

## 5. Corpus manifest format

```json
{
  "corpus_id": "pushpak-quadx-2026.11",
  "dataset_card": "docs/validation/pushpak-quadx-2026.11.md",
  "runs": [
    {
      "run_id": "F001",
      "file": "flights/F001.tlog",
      "label": "benign",
      "partition": "tune",
      "meta": {"vehicle": "QX-01", "flight_id": "F001", "board": "Pixhawk6C rev B", "firmware": "dbe79216/223c26f8…",
               "environment": "open-field, 18 °C, light wind", "profile": "AUTO survey"}
    },
    {
      "run_id": "F014",
      "file": "flights/F014.tlog",
      "label": "gps_spoof",
      "partition": "validation",
      "attack_windows": [[312.0, 371.5]],
      "expected_detectors": ["GPS_INTEGRITY"],
      "meta": {"vehicle": "QX-01", "flight_id": "F014", "environment": "RF lab, simulator-injected GNSS",
               "ground_truth": "injection controller log, clock-aligned to tlog ±0.1 s"}
    }
  ]
}
```

* `attack_windows` are seconds from the first record of the log. Include the attack's after-effects (for example the position snap-back after a GNSS jump), otherwise those alerts are counted as false alarms.
* `label` is `benign` or an attack class name; attack runs without `attack_windows` are rejected.
* Paths are relative to the manifest file.

## 6. Reporting rules

* Report per attack class, per detector, per run and per platform/environment. The overall F1 in the report is for reference only.
* Quote false alarms **per flight-hour with the 95 % interval and the number of hours**. Never write "zero false positives" without the corpus size and conditions.
* Every report names the corpus version, the configuration fingerprint and the firmware/GCS hashes (see `release/manifest.json`).
