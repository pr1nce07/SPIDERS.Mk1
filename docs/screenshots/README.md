# SPIDERS.Mk1 — screenshots

## attacks/
Each subfolder shows one attack scenario run in simulation and its detection in the GCS:
`1_ids_detection.png` (detector grid + FC-vs-Ground), `2_alerts.png` (alert center),
`3_incident_*.png` (correlated incident with evidence/timeline/map), `4_dashboard.png`.

| Folder | Attack | Primary detectors |
|---|---|---|
| gps_spoofing | GPS/EKF velocity divergence | GPS_INTEGRITY + rule |
| command_injection | Command burst from unknown SYSID 42 | COMMAND, SOURCE_IDENTITY + rule |
| parameter_tampering | Sensitive PARAM_SET while armed | PARAMETER, SOURCE_IDENTITY |
| mission_tampering | Mission replaced in flight | MISSION, SOURCE_IDENTITY |
| rc_jamming | RC/telemetry degradation | RC_LINK (alerts; no auto-incident) |
| mavlink_replay_loss | Sequence gaps + duplicates | MAVLINK_SEQUENCE, MAVLINK_RATE |
| correlated_multistage | Unknown source + commands + params | multi-detector CONFIRMED incident |

## features/
One screenshot per GCS workspace (dashboard, flight, IDS, custom ruleset, alerts,
incidents list + investigation, forensics list + case, replay, packets, logs, health, settings).

## cli/
Terminal output: backend startup, test suite (40 passed), attack validation table,
firmware source-of-truth discovery.

All captures are from simulation (synthetic MAVLink); no hardware was used.
