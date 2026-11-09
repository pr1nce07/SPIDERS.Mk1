"""Automatic / manual forensic snapshots and case directories (spec §35–37, §65).

incident → freeze metadata → copy rolling buffer → capture post-event → collect
related events → collect detector evidence → create manifest → SHA-256 → ready.
Case writing happens on a worker thread so ingestion never blocks on disk.
"""
from __future__ import annotations

import copy
import csv
import io
import json
import shutil
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from ..mavlink.decoder import tlog_record
from ..models.events import iso_from_epoch, utc_now_iso
from .hashing import HASH_FILE, sha256_file, verify_case, write_hash_file

GCS_VERSION = "1.0.0"
PARSER_VERSION = "pymavlink-ardupilotmega/decoder-1.0"
CUSTODY_NOTE = ("SHA-256 hashes allow later detection of modification of these files. Hashes alone do not establish "
                "a legal chain of custody; custody records, access control and handling procedures are also required.")


class CaseCapture:
    def __init__(self, case_id, incident, trigger, t_trigger, pre_s, post_s, session, frozen):
        self.case_id = case_id
        self.incident = copy.deepcopy(incident) if incident else None
        self.trigger = trigger
        self.t_trigger = t_trigger
        self.pre_s = pre_s
        self.post_s = post_s
        self.start = t_trigger - pre_s
        self.end = max(t_trigger, (incident or {}).get("last_seen", t_trigger)) + post_s
        self.session = session
        self.frozen = frozen            # metadata frozen at trigger time
        self.events: list = []
        self.results: list[dict] = []
        self.states: list[dict] = []
        self.timeline: list[dict] = []
        self.created_at = utc_now_iso()
        self.status = "COLLECTING"


class SnapshotManager:
    def __init__(self, case_root: Path, config, errors, on_case: Callable[[dict], None] | None = None, keystore=None):
        self.root = case_root
        self.config = config
        self.errors = errors
        self.on_case = on_case
        self.pre_s = float(config.get("forensics.pre_event_seconds", 30))
        self.post_s = float(config.get("forensics.post_event_seconds", 60))
        self.max_case_bytes = int(config.get("forensics.max_case_mb", 512)) * (1 << 20)
        self.active: dict[str, CaseCapture] = {}
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="case-writer")
        self._lock = threading.Lock()
        self.written = 0
        self.keystore = keystore  # signs sealed cases when set (GAP-12)

    # --------------------------------------------------------------- trigger
    def trigger(self, *, incident: Optional[dict], reason: str, t: float, session: dict, frozen: dict,
                pre_events: list, pre_results: list, pre_states: list, pre_timeline: list,
                pre_s: Optional[float] = None, post_s: Optional[float] = None) -> str:
        if incident:
            base = incident["incident_id"]
            case_id = base
            n = 2
            while (self.root / case_id).exists() or case_id in self.active:
                case_id = f"{base}-S{n}"
                n += 1
        else:
            case_id = f"CASE-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:4].upper()}"
        cap = CaseCapture(case_id, incident, {"reason": reason, **(frozen.get("trigger") or {})}, t,
                          self.pre_s if pre_s is None else pre_s, self.post_s if post_s is None else post_s, session, frozen)
        cap.events = [e for e in pre_events if e.t >= cap.start]
        cap.results = [r for r in pre_results if r.get("t", 0) >= cap.start]
        cap.states = [s for s in pre_states if s.get("t", 0) >= cap.start]
        cap.timeline = [x for x in pre_timeline if x.get("t", 0) >= cap.start]
        with self._lock:
            self.active[case_id] = cap
        self._notify(cap, "COLLECTING")
        return case_id

    def update_incident(self, incident: dict) -> None:
        with self._lock:
            caps = [c for c in self.active.values() if c.incident and c.incident["incident_id"] == incident["incident_id"]]
        for c in caps:
            c.incident = copy.deepcopy(incident)
            c.end = max(c.end, incident["last_seen"] + c.post_s)

    def feed_event(self, ev) -> None:
        for c in list(self.active.values()):
            if ev.t <= c.end:
                c.events.append(ev)

    def feed_result(self, r: dict) -> None:
        for c in list(self.active.values()):
            if r.get("t", 0) <= c.end:
                c.results.append(r)

    def feed_state(self, s: dict) -> None:
        for c in list(self.active.values()):
            c.states.append(s)

    def feed_timeline(self, x: dict) -> None:
        for c in list(self.active.values()):
            c.timeline.append(x)

    def check(self, t: float) -> None:
        with self._lock:
            done = [cid for cid, c in self.active.items() if t > c.end]
            caps = [self.active.pop(cid) for cid in done]
        for c in caps:
            self._submit(c, partial=False)

    def finalize_all(self, partial: bool = True, wait: bool = False) -> None:
        with self._lock:
            caps = list(self.active.values())
            self.active.clear()
        futs = [self._submit(c, partial=partial) for c in caps]
        if wait:
            for f in futs:
                f.result(timeout=120)

    def _submit(self, cap: CaseCapture, partial: bool):
        cap.status = "WRITING"
        return self.pool.submit(self._write_safe, cap, partial)

    def _notify(self, cap: CaseCapture, status: str, extra: dict | None = None) -> None:
        if self.on_case:
            self.on_case({"case_id": cap.case_id, "incident_id": (cap.incident or {}).get("incident_id"), "status": status,
                          "session_id": cap.session.get("session_id"), "created_at": cap.created_at,
                          "window": {"start": iso_from_epoch(cap.start), "end": iso_from_epoch(cap.end)}, **(extra or {})})

    # --------------------------------------------------------------- writing
    def _write_safe(self, cap: CaseCapture, partial: bool) -> None:
        try:
            info = self._write(cap, partial)
            self.written += 1
            self._notify(cap, info["status"], {"path": str(self.root / cap.case_id), "manifest_sha256": info["manifest_sha256"],
                                               "artifacts": info["artifacts"], "manifest": info["manifest"]})
        except Exception as exc:
            self.errors.record("FORENSICS", "CASE_WRITE_FAILED", f"{cap.case_id}: {exc}", recoverable=True, exc=exc)
            self._notify(cap, "ERROR", {"error": str(exc)[:200]})

    def _write(self, cap: CaseCapture, partial: bool) -> dict:
        d = self.root / cap.case_id
        (d / "screenshots").mkdir(parents=True, exist_ok=True)
        (d / "rules").mkdir(exist_ok=True)
        events = sorted({e.idx: e for e in cap.events}.values(), key=lambda e: e.idx)
        if events and events[-1].t < cap.end - 1.0:
            partial = True  # the source ended before the post-event window closed
        artifacts: list[dict] = []
        now = utc_now_iso()

        def add(name: str, data: bytes | str, source: str):
            p = d / name
            p.parent.mkdir(parents=True, exist_ok=True)
            # Write exact bytes: text mode on Windows would turn "\n" into "\r\n", doubling the
            # csv module's "\r\n" and making case files differ between platforms.
            p.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
            artifacts.append({"filename": name, "size": p.stat().st_size, "sha256": sha256_file(p), "created_at": now, "source": source})

        def jl(rows) -> str:
            return "".join(json.dumps(r, default=str) + "\n" for r in rows)

        raw = bytearray()
        bad = 0
        for e in events:
            if e.raw:
                raw += tlog_record(e.t, e.raw)
            if e.parse_error:
                bad += 1
            if len(raw) > self.max_case_bytes:
                partial = True
                break
        add("mavlink_raw.bin", bytes(raw), "raw MAVLink frames, tlog framing (8-byte BE µs timestamp + wire bytes)")
        add("mavlink_decoded.jsonl", jl(e.to_dict(include_raw=True) for e in events), "decoder output incl. raw_hex per frame")
        add("telemetry.jsonl", jl(cap.states), "normalized vehicle state snapshots (1 Hz)")
        add("ids_events.jsonl", jl(sorted(cap.results, key=lambda r: r.get("t", 0))), "detector/rule results with explanations and traces")
        timeline = sorted(cap.timeline + [{"t": r["t"], "ts": r.get("ts"), "type": "IDS_ALERT", "title": r["title"],
                                           "detector": r["detector"], "state": r["state"], "result_id": r["result_id"]}
                                          for r in cap.results if r.get("kind") == "alert"], key=lambda x: x.get("t", 0))
        add("timeline.jsonl", jl(timeline), "session timeline events in the capture window")
        add("incident.json", json.dumps(cap.incident or {"manual_snapshot": True, "reason": cap.trigger.get("reason")}, indent=2, default=str),
            "incident object frozen at finalisation (includes all underlying observations)")
        add("gps_track.csv", self._gps_csv(events), "derived from GPS_RAW_INT / GLOBAL_POSITION_INT frames (packet idx retained)")
        add("attitude.csv", self._csv(events, "ATTITUDE", ["roll", "pitch", "yaw", "rollspeed", "pitchspeed", "yawspeed"]), "derived from ATTITUDE frames")
        add("battery.csv", self._battery_csv(events), "derived from SYS_STATUS / BATTERY_STATUS frames")
        add("commands.jsonl", jl({"idx": e.idx, "ts": e.timestamp_utc, "msg": e.msg_name, "sysid": e.sysid, "compid": e.compid, **e.fields}
                                 for e in events if e.msg_name in ("COMMAND_LONG", "COMMAND_INT", "COMMAND_ACK", "SET_MODE")),
            "command traffic in window")
        originals = cap.frozen.get("parameter_originals", {})
        add("parameters.jsonl", jl({"idx": e.idx, "ts": e.timestamp_utc, "msg": e.msg_name, "sysid": e.sysid,
                                    "param": str(e.fields.get("param_id")), "value": e.fields.get("param_value"),
                                    "original_value": originals.get(str(e.fields.get("param_id")))}
                                   for e in events if e.msg_name in ("PARAM_VALUE", "PARAM_SET")),
            "parameter traffic with original (first-seen) values")
        for rv in cap.frozen.get("rule_definitions", []):
            add(f"rules/{rv['rule_id']}_v{rv['version']}.json", json.dumps(rv, indent=2, default=str), "immutable rule version used")
        add("README.txt", self._readme(cap, partial, len(events), bad), "case description")
        start_ts, end_ts = iso_from_epoch(cap.start), iso_from_epoch(min(cap.end, events[-1].t if events else cap.end))
        inc = cap.incident or {}
        manifest = {
            "case_id": cap.case_id, "created_at": cap.created_at, "finalized_at": utc_now_iso(),
            "status": "PARTIAL" if partial else "COMPLETE", "incident_id": inc.get("incident_id"),
            "session": cap.session,
            "vehicle": cap.frozen.get("vehicle", {}),
            "trigger": {"detector": ",".join(inc.get("detectors", [])) or cap.trigger.get("detector"),
                        "severity": inc.get("severity", cap.trigger.get("severity")),
                        "confidence": inc.get("confidence", cap.trigger.get("confidence")),
                        "state": inc.get("state"), "reason": cap.trigger.get("reason"), "time": iso_from_epoch(cap.t_trigger)},
            "capture_window": {"pre_seconds": cap.pre_s, "post_seconds": cap.post_s, "start": start_ts, "end": end_ts,
                               "incident_duration_s": round(inc.get("last_seen", cap.t_trigger) - inc.get("first_seen", cap.t_trigger), 2)},
            "evidence_counts": {"frames": len(events), "raw_frames": sum(1 for e in events if e.raw), "bad_frames": bad,
                                "results": len(cap.results), "state_samples": len(cap.states)},
            "buffer": cap.frozen.get("buffer", {}),
            "rule_versions": [{"rule_id": r["rule_id"], "version": r["version"], "sha256": r.get("sha256")} for r in cap.frozen.get("rule_definitions", [])],
            "config_snapshot": cap.frozen.get("config", {}),
            "tools": {"gcs_version": GCS_VERSION, "parser_version": PARSER_VERSION, "hash_algorithm": "sha256"},
            "artifacts": artifacts, "revisions": [], "custody_note": CUSTODY_NOTE,
            "acquisition": {"method": "automatic snapshot (incident trigger)" if cap.incident else "manual snapshot",
                            "tool": f"SPIDERS.Mk1 GCS {GCS_VERSION}", "source": cap.session.get("kind"),
                            "clock": "host system clock, UTC; time synchronisation is not verified by SPIDERS",
                            "evidence_signing": "Ed25519 case.sig.json" if self.keystore else "not enabled"},
            "custody": [{"at": utc_now_iso(), "event": "ACQUIRED", "by": "SPIDERS GCS (automatic)" if cap.incident else "SPIDERS GCS",
                         "note": cap.trigger.get("reason")}],
        }
        (d / "manifest.json").write_bytes(json.dumps(manifest, indent=2, default=str).encode("utf-8"))
        write_hash_file(d)
        self._sign(d)
        return {"status": manifest["status"], "manifest_sha256": sha256_file(d / "manifest.json"),
                "artifacts": len(artifacts) + 2, "manifest": manifest}

    @staticmethod
    def _csv(events, msg, cols) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["idx", "timestamp_utc", "sysid"] + cols)
        for e in events:
            if e.msg_name == msg:
                w.writerow([e.idx, e.timestamp_utc, e.sysid] + [e.fields.get(c) for c in cols])
        return buf.getvalue()

    @staticmethod
    def _gps_csv(events) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["idx", "timestamp_utc", "source_msg", "lat_deg", "lon_deg", "alt_m", "speed_ms", "fix_type", "satellites", "hdop"])
        for e in events:
            f = e.fields
            if e.msg_name == "GPS_RAW_INT":
                w.writerow([e.idx, e.timestamp_utc, "GPS_RAW_INT", (f.get("lat") or 0) / 1e7, (f.get("lon") or 0) / 1e7,
                            (f.get("alt") or 0) / 1000, None if f.get("vel") in (None, 65535) else f["vel"] / 100,
                            f.get("fix_type"), f.get("satellites_visible"), None if f.get("eph") in (None, 65535) else f["eph"] / 100])
            elif e.msg_name == "GLOBAL_POSITION_INT":
                w.writerow([e.idx, e.timestamp_utc, "GLOBAL_POSITION_INT(EKF)", (f.get("lat") or 0) / 1e7, (f.get("lon") or 0) / 1e7,
                            (f.get("alt") or 0) / 1000, None, None, None, None])
        return buf.getvalue()

    @staticmethod
    def _battery_csv(events) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["idx", "timestamp_utc", "source_msg", "voltage_v", "current_a", "remaining_pct"])
        for e in events:
            f = e.fields
            if e.msg_name == "SYS_STATUS":
                v, c, r = f.get("voltage_battery"), f.get("current_battery"), f.get("battery_remaining")
                w.writerow([e.idx, e.timestamp_utc, "SYS_STATUS", None if v in (None, 65535) else v / 1000,
                            None if c in (None, -1) else c / 100, None if r in (None, -1) else r])
        return buf.getvalue()

    def _readme(self, cap, partial, n, bad) -> str:
        inc = cap.incident or {}
        return f"""SPIDERS.Mk1 forensic case {cap.case_id}
=====================================================
Incident:        {inc.get('incident_id', 'manual snapshot')}
Title:           {inc.get('title', cap.trigger.get('reason'))}
Analytic state:  {inc.get('state', 'N/A')}   Severity: {inc.get('severity', 'N/A')}   Confidence: {inc.get('confidence', 'N/A')}
Session:         {cap.session.get('session_id')} ({cap.session.get('kind')}, source {cap.session.get('source')})
Capture window:  {iso_from_epoch(cap.start)} → {iso_from_epoch(cap.end)}  ({cap.pre_s:.0f} s pre-event + incident + {cap.post_s:.0f} s post-event)
Status:          {'PARTIAL (capture ended before the post-event window closed)' if partial else 'COMPLETE'}
Frames:          {n} ({bad} undecodable frames preserved with raw bytes)

Files
-----
manifest.json          case metadata, artifact list with SHA-256, rule versions, firmware metadata
incident.json          the incident with every underlying observation (nothing collapsed)
timeline.jsonl         ordered session events in the window
mavlink_raw.bin        raw MAVLink wire frames using .tlog framing (8-byte big-endian µs timestamp + frame).
                       It is NOT a PCAP; rename to .tlog to open in MAVProxy/Mission Planner.
mavlink_decoded.jsonl  one decoded frame per line (fields + raw_hex + idx)
telemetry.jsonl        normalized vehicle state (1 Hz)
ids_events.jsonl       detector/rule results with explanations and rule traces
gps_track.csv, attitude.csv, battery.csv   derived tables (idx column links back to the frame)
commands.jsonl, parameters.jsonl           command and parameter traffic (original values preserved)
rules/                 exact immutable rule versions used
screenshots/           GUI screenshots (added when a GUI client captured one; hashed on addition)
hashes.sha256          sha256sum-compatible list of every file above

Verify: `sha256sum -c hashes.sha256` or VERIFY CASE in the GUI.
{CUSTODY_NOTE}
"""

    # --------------------------------------------------------------- mutation (append-only)
    def add_artifact(self, case_id: str, rel_name: str, data: bytes, source: str) -> dict:
        d = self.root / case_id
        if not (d / "manifest.json").exists():
            raise FileNotFoundError(case_id)
        pre = verify_case(d)
        if pre["status"] != "VALID":
            raise ValueError(f"case integrity is {pre['status']}; refusing to add artifacts to a non-VALID case")
        prev_manifest_sha = sha256_file(d / "manifest.json")
        p = d / rel_name
        if p.exists():
            raise FileExistsError(rel_name)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        m = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
        art = {"filename": rel_name, "size": len(data), "sha256": sha256_file(p), "created_at": utc_now_iso(), "source": source}
        m["artifacts"].append(art)
        m.setdefault("revisions", []).append({"at": art["created_at"], "action": f"added {rel_name}", "previous_manifest_sha256": prev_manifest_sha})
        (d / "manifest.json").write_bytes(json.dumps(m, indent=2, default=str).encode("utf-8"))
        write_hash_file(d)
        self._sign(d)
        return {"artifact": art, "previous_manifest_sha256": prev_manifest_sha, "manifest_sha256": sha256_file(d / "manifest.json")}

    def _sign(self, d: Path) -> None:
        if self.keystore is None:
            return
        from ..security.evidence import sign_case
        sign_case(d, self.keystore.signing_key("evidence"))

    def add_custody_event(self, case_id: str, event: str, actor: str, to: str = "", note: str = "") -> dict:
        """Record a custody transfer/receipt/export as a new manifest revision; evidence files are untouched."""
        if event not in ("TRANSFERRED", "RECEIVED", "EXPORTED", "REVIEWED", "SEALED_COPY_MADE"):
            raise ValueError("unknown custody event")
        d = self.root / case_id
        if not (d / "manifest.json").exists():
            raise FileNotFoundError(case_id)
        pre = verify_case(d)
        if pre["status"] != "VALID":
            raise ValueError(f"case integrity is {pre['status']}; custody cannot be recorded on a non-VALID case")
        prev_manifest_sha = sha256_file(d / "manifest.json")
        m = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
        rec = {"at": utc_now_iso(), "event": event, "by": actor, "to": to[:200], "note": note[:500]}
        m.setdefault("custody", []).append(rec)
        m.setdefault("revisions", []).append({"at": rec["at"], "action": f"custody {event}", "previous_manifest_sha256": prev_manifest_sha})
        (d / "manifest.json").write_bytes(json.dumps(m, indent=2, default=str).encode("utf-8"))
        write_hash_file(d)
        self._sign(d)
        return {"custody": rec, "previous_manifest_sha256": prev_manifest_sha, "manifest_sha256": sha256_file(d / "manifest.json")}

    def export_zip(self, case_id: str) -> Path:
        d = self.root / case_id
        if not d.exists():
            raise FileNotFoundError(case_id)
        out = self.root.parent / "exports"
        out.mkdir(exist_ok=True)
        base = out / f"{case_id}"
        return Path(shutil.make_archive(str(base), "zip", root_dir=self.root, base_dir=case_id))
