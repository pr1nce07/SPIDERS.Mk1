"""Analysis pipeline — one per session. Live MAVLink, simulation, replay and
offline log import all run through this exact code path (spec §42):

  SourceItem → Decoder (raw preserved) → TelemetryEvent → recorder / DB / rolling
  buffer → VehicleState → ground detectors + published rules → correlation →
  incidents → forensic snapshots → bus (GUI)
"""
from __future__ import annotations

import time
import uuid
from collections import Counter, deque
from typing import Any, Callable, Optional

from ..config import severity_rank
from ..forensic.recorder import RawRecorder
from ..forensic.rolling_buffer import PacketIndex, RollingBuffer
from ..ids.base import AnalysisContext
from ..ids.correlation import Correlator
from ..ids.engine import IDSEngine
from ..mavlink.decoder import Decoder, recover_header
from ..mavlink.normalizer import VehicleState
from ..models.events import DetectorResult, TelemetryEvent, iso_from_epoch, state_rank, utc_now_iso
from ..sources.files import SourceItem
from ..storage.db import dumps

TIMELINE_BY_DETECTOR = {"GPS_INTEGRITY": "GPS_EVENT", "IMU_CONSISTENCY": "IMU_EVENT", "COMMAND": "COMMAND",
                        "PARAMETER": "PARAMETER_CHANGE", "MISSION": "MISSION_CHANGE", "RC_LINK": "LINK_DEGRADED",
                        "MAVLINK_SEQUENCE": "LINK_DEGRADED"}


class Pipeline:
    def __init__(self, *, session_id: str, kind: str, source_desc: str, config, registry, errors, capabilities: dict,
                 allocator, db=None, bus=None, snapshots=None, recorder_dir=None, rules: list | None = None,
                 signing_key: Optional[bytes] = None, live_clock: bool = False, persist_messages: bool = True,
                 correlate: bool = True, on_system_event: Optional[Callable] = None):
        self.session_id = session_id
        self.kind = kind
        self.source_desc = source_desc
        self.config = config
        self.registry = registry
        self.errors = errors
        self.capabilities = capabilities
        self.db = db
        self.bus = bus
        self.snapshots = snapshots
        self.live_clock = live_clock
        self.persist_messages = persist_messages
        self.signing_key = signing_key
        self.on_system_event = on_system_event
        self.ctx = AnalysisContext(registry=registry, config=config,
                                   trusted_gcs=set(config.get("mavlink.trusted_gcs_sysids", [255]) or []))
        self.vstate = VehicleState(self.ctx, config)
        self.engine = IDSEngine(config, errors, registry, key_configured=signing_key is not None)
        ml = self.engine.get("ML_BASELINE")
        if ml:
            ml.session_id = session_id
        self.rules = list(rules or [])
        self.shadow_rules: list = []
        self.correlator = Correlator(config, allocator, session_id, self._incident_created, self._incident_updated) if correlate else None
        self.decoders: dict[str, Decoder] = {}
        self.idx = 0
        roll_s = float(config.get("recording.rolling_minutes", 5)) * 60
        max_items = int(config.get("recording.max_rolling_items", 200000))
        self.packets = PacketIndex(roll_s, max_items)
        self.results_buf = RollingBuffer(roll_s, 20000, key=lambda r: r["t"])
        self.states_buf = RollingBuffer(roll_s, 2000, key=lambda s: s["t"])
        self.timeline_buf = RollingBuffer(roll_s, 5000, key=lambda x: x["t"])
        self.timeline: deque = deque(maxlen=20000)
        self.alerts: dict[str, dict] = {}
        self.alert_order: deque = deque(maxlen=5000)
        self.recorder = RawRecorder(recorder_dir, session_id, int(config.get("limits.disk_min_free_mb", 500)), errors,
                                    on_event=self._system_event, enabled=bool(config.get("recording.enabled", True))) if recorder_dir else None
        self.msg_counts: Counter = Counter()
        self.rate_window: deque = deque()
        self.bad_frames = 0
        self.rule_errors = 0
        self.started_wall = time.time()
        self.t_first: Optional[float] = None
        self.t_last: Optional[float] = None
        self.last_tick_mono: Optional[float] = None
        self.tick_period = 1.0 / float(config.get("ids.tick_hz", 1.0))
        self.last_state_t = 0.0
        self.prev_airborne: Optional[bool] = None
        self.first_heartbeat = False
        self.last_mono_ns = 0
        self.fw_banner: Optional[str] = None
        self.detector_state_sample_t = 0.0
        self.closed = False
        self._timeline("SESSION_START", f"Session started ({kind}: {source_desc})", t=time.time() if live_clock else None)

    # ================================================================ ingest
    def decoder_for(self, link: str, source: str) -> Decoder:
        d = self.decoders.get(link)
        if d is None:
            d = self.decoders[link] = Decoder(self.registry, link, source, self.signing_key)
        return d

    def handle_item(self, item: SourceItem) -> int:
        n = 0
        if item.kind == "frame":
            dec = self.decoder_for(item.link, item.source)
            for parsed in dec.feed(item.data):
                self.process_event(dec.to_event(parsed, self._next_idx(), item.t, self._mono_ns(item.t)))
                n += 1
        else:
            d = item.data
            raw = d.get("raw")
            name = d.get("msg_name", "UNKNOWN")
            ev = TelemetryEvent(idx=self._next_idx(), t=item.t, mono_ns=self._mono_ns(item.t), source=item.source,
                                link=item.link, sysid=d.get("sysid", self.ctx.vehicle_sysid if item.source == "DATAFLASH" else None),
                                compid=d.get("compid", 1 if item.source == "DATAFLASH" else None),
                                msg_id=self.registry.msg_id(name), msg_name=name, sequence=d.get("seq"),
                                fields=d.get("fields") or {}, raw=raw if isinstance(raw, (bytes, bytearray)) else None,
                                origin=d.get("origin"), parse_error=(d.get("fields") or {}).get("reason") if name == "BAD_DATA" else None)
            if item.source == "DATAFLASH" and ev.sysid is None:
                ev.sysid, ev.compid = 1, 1
                if self.ctx.vehicle_sysid is None:
                    self.ctx.vehicle_sysid, self.ctx.vehicle_compid = 1, 1
            self.process_event(ev)
            n = 1
        return n

    def _next_idx(self) -> int:
        self.idx += 1
        return self.idx

    def _mono_ns(self, t: float) -> int:
        if self.live_clock:
            v = time.monotonic_ns()
        else:
            v = int(t * 1e9)
        v = max(v, self.last_mono_ns)
        self.last_mono_ns = v
        return v

    # ================================================================ core
    def process_event(self, ev: TelemetryEvent) -> None:
        ctx = self.ctx
        mono = ev.mono_ns / 1e9
        if ctx.session_start_mono is None:
            ctx.session_start_mono = mono
            self.last_tick_mono = mono
        # advance time-based detectors through any data gap before this event
        while self.last_tick_mono is not None and mono - self.last_tick_mono >= self.tick_period:
            self.last_tick_mono += self.tick_period
            gap_t = ev.t - (mono - self.last_tick_mono)
            self._tick(self.last_tick_mono, gap_t)
        ctx.t, ctx.mono = ev.t, mono
        self.t_first = self.t_first if self.t_first is not None else ev.t
        self.t_last = ev.t
        self.msg_counts[ev.msg_name] += 1
        self.rate_window.append(mono)
        while self.rate_window and mono - self.rate_window[0] > 5:
            self.rate_window.popleft()
        if ev.parse_error:
            self.bad_frames += 1
        self.packets.append(ev)
        if self.recorder and ev.raw and ev.source != "DATAFLASH":
            self.recorder.write(ev.t, ev.raw)
        self._persist_event(ev)
        try:
            self.vstate.update(ev)
        except Exception as exc:
            self.errors.record("NORMALIZER", "STATE_UPDATE_FAILED", str(exc), exc=exc, context={"msg": ev.msg_name})
        self._timeline_from_event(ev)
        results = self.engine.process(ev, ctx)
        for rr in self.rules:
            try:
                results.extend(rr.evaluate(ev, ctx, self.vstate))
            except Exception as exc:
                self.rule_errors += 1
                rr.errors += 1
                self.errors.record(f"RULE:{rr.rule_id}", "RULE_EVAL_FAILED", str(exc), exc=exc)
        for rr in self.shadow_rules:
            try:
                for r in rr.evaluate(ev, ctx, self.vstate):
                    if self.bus:
                        self.bus.publish("BUILDER_TRACE", {"rule_id": rr.rule_id, "version": rr.version, "result": r.to_dict()}, "builder")
            except Exception as exc:
                rr.errors += 1
                self.errors.record(f"SHADOW:{rr.rule_id}", "RULE_EVAL_FAILED", str(exc), exc=exc)
        for r in results:
            self.handle_result(r)
        if self.snapshots:
            self.snapshots.feed_event(ev)
        if self.bus:
            self.bus.publish("MAVLINK_DECODED", ev, "pipeline")

    def tick_live(self) -> None:
        """Called periodically by the runtime for live sources so time-based
        detectors (heartbeat loss) run even when no packets arrive."""
        if not self.live_clock or self.ctx.session_start_mono is None:
            return
        mono = time.monotonic()
        while mono - self.last_tick_mono >= self.tick_period:
            self.last_tick_mono += self.tick_period
            self._tick(self.last_tick_mono, time.time() - (mono - self.last_tick_mono))

    def _tick(self, mono: float, t: float) -> None:
        ctx = self.ctx
        ctx.mono, ctx.t = mono, t
        for r in self.engine.tick(ctx):
            self.handle_result(r)
        for rr in self.rules:
            try:
                for r in rr.evaluate(None, ctx, self.vstate):
                    self.handle_result(r)
            except Exception as exc:
                self.rule_errors += 1
                self.errors.record(f"RULE:{rr.rule_id}", "RULE_EVAL_FAILED", str(exc), exc=exc)
        snap = {"t": t, "ts": iso_from_epoch(t), "state": self.vstate.snapshot()}
        self.states_buf.append(snap)
        if self.snapshots:
            self.snapshots.feed_state(snap)
            self.snapshots.check(t)
        if self.db and t - self.last_state_t >= 1.0:
            self.last_state_t = t
            self.db.insert("telemetry", {"session_id": self.session_id, "t": t, "state": dumps(snap["state"])})
            if t - self.detector_state_sample_t >= 5:
                self.detector_state_sample_t = t
                for h in self.engine.health(ctx):
                    self.db.insert("detector_states", {"session_id": self.session_id, "t": t, "detector": h["detector"],
                                                       "health": h["health"], "state": h["state"], "confidence": h["confidence"],
                                                       "data": dumps({"events": h["events"], "errors": h["errors"], "latency_ms": h["latency_ms"]})})
        # takeoff / land timeline
        if ctx.airborne is not None and self.prev_airborne is not None and ctx.airborne != self.prev_airborne:
            self._timeline("TAKEOFF" if ctx.airborne else "LAND", "Takeoff" if ctx.airborne else "Landed", t=t)
        self.prev_airborne = ctx.airborne if ctx.airborne is not None else self.prev_airborne

    # ================================================================ results
    def handle_result(self, r: DetectorResult) -> None:
        rd = r.to_dict()
        rd["session_id"] = self.session_id
        self.results_buf.append(rd)
        if self.db:
            self.db.insert("detector_results", {"result_id": r.result_id, "session_id": self.session_id, "t": r.t, "detector": r.detector,
                                                "state": r.state, "severity": r.severity, "confidence": r.confidence, "source": r.source,
                                                "domain": r.domain, "rule_id": r.rule_id, "rule_version": r.rule_version, "kind": r.kind,
                                                "data": dumps(rd)}, critical=state_rank(r.state) >= 2)
        if self.snapshots:
            self.snapshots.feed_result(rd)
        is_alert = (r.kind == "alert" and (state_rank(r.state) >= 2 or severity_rank(r.severity) >= 1)) or r.kind == "health"
        if is_alert:
            alert = {"alert_id": "ALR-" + r.result_id[2:], "session_id": self.session_id, "t": r.t, "ts": iso_from_epoch(r.t),
                     "result_id": r.result_id, "detector": r.detector, "severity": r.severity, "confidence": r.confidence,
                     "source": r.source, "state": r.state, "status": "NEW", "incident_id": None, "title": r.title,
                     "domain": r.domain, "evidence_count": len(r.packet_refs), "rule_id": r.rule_id, "rule_version": r.rule_version,
                     "sysid": r.sysid}
            self.alerts[alert["alert_id"]] = alert
            self.alert_order.append(alert["alert_id"])
            if len(self.alerts) > 5000:
                self.alerts.pop(next(iter(self.alerts)))
            self._persist_alert(alert, rd)
            if self.bus:
                self.bus.publish("IDS_ALERT", alert, r.detector)
        ttype = self._timeline_type(r)
        if ttype and (is_alert or r.kind in ("observation", "recovery")):
            self._timeline(ttype, r.title, t=r.t, ref={"result_id": r.result_id, "detector": r.detector, "state": r.state,
                                                       "idx": r.packet_refs[0] if r.packet_refs else None})
        if self.correlator:
            inc = self.correlator.ingest(r, self.ctx)
            if inc and is_alert:
                a = self.alerts.get("ALR-" + r.result_id[2:])
                if a and a["incident_id"] is None:
                    a["incident_id"] = inc["incident_id"]
                    self._persist_alert(a, rd)
        if r.actions.get("snapshot"):
            self.snapshot(reason=f"rule {r.rule_id} v{r.rule_version} FORENSIC SNAPSHOT output", incident=None, trigger=rd)
        if self.bus:
            self.bus.publish("DETECTOR_RESULT", rd, r.detector)

    def _timeline_type(self, r: DetectorResult) -> Optional[str]:
        if r.detector == "FLIGHT_MODE":
            return "ARM" if r.title == "Armed" else "DISARM" if r.title.startswith("Disarm") or "DISARM" in r.title else "MODE_CHANGE"
        if r.detector == "HEARTBEAT":
            return "LINK_LOSS" if "loss" in r.title.lower() else "LINK_RECOVERY" if r.kind == "recovery" else "LINK_DEGRADED"
        if r.detector == "RC_LINK" and "complete loss" in r.title:
            return "LINK_LOSS"
        if r.detector == "COMMAND" and r.kind == "observation":
            return "COMMAND"
        if r.detector == "SOURCE_IDENTITY" and r.kind == "observation":
            return None
        return TIMELINE_BY_DETECTOR.get(r.detector, "IDS_ALERT")

    def _persist_alert(self, alert: dict, rd: dict) -> None:
        if self.db:
            row = {k: alert[k] for k in ("alert_id", "session_id", "t", "result_id", "detector", "severity", "confidence", "source",
                                         "state", "status", "incident_id", "title")}
            row["data"] = dumps({"alert": alert, "result": rd})
            self.db.upsert("ids_events", row)

    # ================================================================ incidents
    def _incident_created(self, inc: dict) -> None:
        pub = Correlator.public(inc)
        self._persist_incident(pub, created=True)
        self._timeline("INCIDENT", f"{inc['incident_id']}: {inc['title']} ({inc['state']})", t=inc["first_seen"],
                       ref={"incident_id": inc["incident_id"]})
        if self.bus:
            self.bus.publish("INCIDENT_CREATED", pub, "correlation")
        sev_auto = set(self.config.get("forensics.auto_snapshot_severities", ["HIGH", "CRITICAL"]))
        if inc["severity"] in sev_auto or (inc["state"] == "CONFIRMED" and self.config.get("forensics.auto_snapshot_on_confirmed", True)):
            self.snapshot(reason=f"auto: incident {inc['incident_id']} {inc['severity']}/{inc['state']}", incident=inc)

    def _incident_updated(self, inc: dict) -> None:
        pub = Correlator.public(inc)
        self._persist_incident(pub)
        if self.snapshots:
            self.snapshots.update_incident(pub)
        if self.bus:
            self.bus.publish("INCIDENT_UPDATED", pub, "correlation")
        if inc.get("case_id") is None and ((inc["state"] == "CONFIRMED" and self.config.get("forensics.auto_snapshot_on_confirmed", True))
                                           or inc["severity"] in set(self.config.get("forensics.auto_snapshot_severities", []))):
            self.snapshot(reason=f"auto: incident {inc['incident_id']} escalated to {inc['severity']}/{inc['state']}", incident=inc)

    def _persist_incident(self, inc: dict, created: bool = False) -> None:
        if not self.db:
            return
        self.db.upsert("incidents", {"incident_id": inc["incident_id"], "session_id": self.session_id, "first_seen": inc["first_seen"],
                                     "last_seen": inc["last_seen"], "state": inc["state"], "status": inc["status"],
                                     "severity": inc["severity"], "confidence": inc["confidence"], "domain": inc["domain"],
                                     "title": inc["title"], "data": dumps(inc)})
        if created:
            for o in inc["observations"]:
                self.db.insert("incident_evidence", {"incident_id": inc["incident_id"], "result_id": o["result_id"], "t": o["t"],
                                                     "kind": "context" if o["context"] else "alert", "ref": dumps(o)}, critical=True)

    # ================================================================ forensics
    def frozen_metadata(self, trigger: dict | None = None) -> dict:
        caps = self.capabilities or {}
        veh = caps.get("vehicle", {})
        param = self.engine.get("PARAMETER")
        return {
            "vehicle": {"sysid": self.ctx.vehicle_sysid, "compid": self.ctx.vehicle_compid,
                        "board": veh.get("board"), "firmware": veh.get("firmware"), "git_commit": veh.get("git_commit"),
                        "firmware_banner_observed": self.fw_banner,
                        "note": "board/firmware/git_commit from build-artifact discovery (configs/capabilities.json); "
                                "firmware_banner_observed is what the vehicle reported this session"},
            "config": self.config.redacted().get("ids", {}),
            "rule_definitions": [dict(r.rule, version=r.version) for r in self.rules],
            "parameter_originals": dict(param.original) if param else {},
            "buffer": {"packets": self.packets.buf.stats(), "results": self.results_buf.stats()},
            "trigger": trigger or {},
        }

    def snapshot(self, reason: str, incident: Optional[dict] = None, trigger: Optional[dict] = None,
                 pre_s: Optional[float] = None, post_s: Optional[float] = None) -> Optional[str]:
        if not self.snapshots:
            return None
        t = self.ctx.t
        pre = float(pre_s if pre_s is not None else self.snapshots.pre_s)
        case_id = self.snapshots.trigger(
            incident=Correlator.public(incident) if incident else None, reason=reason, t=t,
            session={"session_id": self.session_id, "kind": self.kind, "source": self.source_desc},
            frozen=self.frozen_metadata(trigger), pre_events=self.packets.window(t - pre),
            pre_results=self.results_buf.window(t - pre), pre_states=self.states_buf.window(t - pre),
            pre_timeline=self.timeline_buf.window(t - pre), pre_s=pre_s, post_s=post_s)
        if incident is not None:
            incident["case_id"] = case_id
            live = self.correlator.incidents.get(incident["incident_id"]) if self.correlator else None
            if live is not None:
                live["case_id"] = case_id
            self._persist_incident(Correlator.public(incident))
        self._timeline("SNAPSHOT", f"Forensic snapshot {case_id} started ({reason})", t=t, ref={"case_id": case_id})
        if self.bus:
            self.bus.publish("FORENSIC_SNAPSHOT", {"case_id": case_id, "reason": reason, "status": "COLLECTING"}, "forensics")
        return case_id

    # ================================================================ persistence helpers
    def _persist_event(self, ev: TelemetryEvent) -> None:
        if not self.db:
            return
        if self.persist_messages:
            self.db.insert("mavlink_messages", {"session_id": self.session_id, "idx": ev.idx, "t": ev.t, "sysid": ev.sysid,
                                                "compid": ev.compid, "msg_id": ev.msg_id, "msg_name": ev.msg_name, "seq": ev.sequence,
                                                "source": ev.source, "link": ev.link, "signed": ev.signed, "sig": ev.signature_status,
                                                "parse_error": ev.parse_error, "fields": dumps(ev.fields),
                                                "raw_hex": ev.raw.hex() if ev.raw else None}, critical=bool(ev.parse_error))
        n, f = ev.msg_name, ev.fields
        sid = self.session_id
        if n in ("COMMAND_LONG", "COMMAND_INT", "COMMAND_ACK", "SET_MODE"):
            cmd = f.get("command")
            self.db.insert("commands", {"session_id": sid, "t": ev.t, "idx": ev.idx, "msg": n, "sysid": ev.sysid, "compid": ev.compid,
                                        "target_system": f.get("target_system"), "target_component": f.get("target_component"),
                                        "command": cmd, "command_name": self.registry.command_name(cmd) if cmd is not None else n,
                                        "params": dumps({k: v for k, v in f.items() if k.startswith("param") or k in ("x", "y", "z", "base_mode", "custom_mode")}),
                                        "ack_result": str(f.get("result")) if n == "COMMAND_ACK" else None, "armed": self.ctx.armed,
                                        "mode": self.ctx.mode}, critical=True)
        elif n in ("PARAM_VALUE", "PARAM_SET"):
            name = str(f.get("param_id") or "").rstrip("\x00")
            param = self.engine.get("PARAMETER")
            old = param.values.get(name) if param else None
            orig = param.original.get(name) if param else None
            kind = "SET_REQUEST" if n == "PARAM_SET" else ("BASELINE" if old is None else ("CHANGE" if old != f.get("param_value") else "REPORT"))
            if kind != "REPORT":
                self.db.insert("parameters", {"session_id": sid, "t": ev.t, "idx": ev.idx, "name": name, "value": f.get("param_value"),
                                              "old_value": old, "original_value": orig if orig is not None else f.get("param_value"),
                                              "sysid": ev.sysid, "compid": ev.compid, "armed": self.ctx.armed, "kind": kind}, critical=True)
        elif n in ("GPS_RAW_INT", "GLOBAL_POSITION_INT") and ev.sysid == self.ctx.vehicle_sysid:
            lat, lon = f.get("lat"), f.get("lon")
            if lat and lon:
                self.db.insert("gps_points", {"session_id": sid, "t": ev.t, "lat": lat / 1e7, "lon": lon / 1e7,
                                              "alt": (f.get("alt") or 0) / 1000.0, "kind": "GPS" if n == "GPS_RAW_INT" else "EKF"})
        elif n == "ATTITUDE" and ev.sysid == self.ctx.vehicle_sysid and ev.idx % 3 == 0:
            import math
            self.db.insert("attitude_samples", {"session_id": sid, "t": ev.t, "roll": math.degrees(f.get("roll") or 0),
                                                "pitch": math.degrees(f.get("pitch") or 0), "yaw": math.degrees(f.get("yaw") or 0)})
        elif n == "SYS_STATUS" and ev.sysid == self.ctx.vehicle_sysid:
            v, c, r = f.get("voltage_battery"), f.get("current_battery"), f.get("battery_remaining")
            self.db.insert("battery_samples", {"session_id": sid, "t": ev.t, "voltage": None if v in (None, 65535) else v / 1000,
                                               "current": None if c in (None, -1) else c / 100, "remaining": None if r in (None, -1) else r})

    def _timeline_from_event(self, ev: TelemetryEvent) -> None:
        if ev.msg_name == "HEARTBEAT" and not self.first_heartbeat and ev.sysid == self.ctx.vehicle_sysid:
            self.first_heartbeat = True
            self._timeline("HEARTBEAT", f"First vehicle heartbeat (SYSID {ev.sysid}, COMPID {ev.compid})", t=ev.t, ref={"idx": ev.idx})
        elif ev.msg_name == "STATUSTEXT" and ev.sysid == self.ctx.vehicle_sysid:
            text = str(ev.fields.get("text") or "")
            if text.startswith("ArduCopter V") or text.startswith("ArduPlane V"):
                self.fw_banner = text
            self._timeline("STATUSTEXT", text[:120], t=ev.t, ref={"idx": ev.idx, "severity": ev.fields.get("severity")})

    def _timeline(self, type_: str, title: str, t: Optional[float] = None, ref: Optional[dict] = None) -> None:
        tt = t if t is not None else (self.ctx.t or time.time())
        e = {"id": uuid.uuid4().hex[:10], "t": tt, "ts": iso_from_epoch(tt), "type": type_, "title": title, "ref": ref or {},
             "session_id": self.session_id}
        self.timeline.append(e)
        self.timeline_buf.append(e)
        if self.snapshots:
            self.snapshots.feed_timeline(e)
        if self.db:
            self.db.insert("system_events", {"session_id": self.session_id, "t": tt, "type": type_, "severity": "INFO",
                                             "message": title[:300], "data": dumps(e)}, critical=True)
        if self.bus:
            self.bus.publish("TIMELINE", e, "pipeline")

    def _system_event(self, type_: str, severity: str, message: str) -> None:
        self._timeline(type_, message)
        if self.on_system_event:
            self.on_system_event(type_, severity, message)

    # ================================================================ views
    def packet_rate(self) -> float:
        if len(self.rate_window) < 2:
            return 0.0
        span = self.rate_window[-1] - self.rate_window[0]
        return round(len(self.rate_window) / span, 1) if span > 0 else 0.0

    def connection_stats(self) -> dict:
        ctx = self.ctx
        hb = self.engine.get("HEARTBEAT")
        seq = self.engine.get("MAVLINK_SEQUENCE")
        sig = self.engine.get("MAVLINK_SIGNING")
        age = None
        if hb and hb.last_hb is not None:
            now = time.monotonic() if self.live_clock else ctx.mono
            age = round(now - hb.last_hb, 2)
        loss = None
        if seq:
            rows = [r for r in seq.summary() if r["sysid"] == ctx.vehicle_sysid]
            tot = sum(r["received"] + r["lost"] for r in rows)
            loss = round(100 * sum(r["lost"] for r in rows) / tot, 2) if tot else None
        return {"sysid": ctx.vehicle_sysid, "compid": ctx.vehicle_compid, "mavlink_version": self.vstate.value("mavlink_version"),
                "wire_version": 2 if any(d.decoded for d in self.decoders.values()) else None, "packet_rate_hz": self.packet_rate(),
                "heartbeat_age_s": age, "received": self.idx, "bad_frames": self.bad_frames, "estimated_loss_pct": loss,
                "signing": sig.state_for((ctx.vehicle_sysid, ctx.vehicle_compid)) if sig and ctx.vehicle_sysid else "SIGNING UNKNOWN",
                "latency_ms": None, "latency_note": "N/A — needs TIMESYNC, which requires transmitting (GCS is read-only)"}

    def summary(self) -> dict:
        return {"session_id": self.session_id, "kind": self.kind, "source": self.source_desc, "packets": self.idx,
                "t_first": self.t_first, "t_last": self.t_last, "alerts": len(self.alerts),
                "incidents": len(self.correlator.incidents) if self.correlator else 0, "bad_frames": self.bad_frames,
                "messages": dict(self.msg_counts.most_common(60))}

    def set_rules(self, runtimes: list) -> None:
        self.rules = runtimes

    def close(self, partial: bool = True) -> None:
        if self.closed:
            return
        self.closed = True
        self._timeline("SESSION_END", "Session ended")
        if self.snapshots:
            self.snapshots.finalize_all(partial=partial)
        if self.recorder:
            self.recorder.close()
