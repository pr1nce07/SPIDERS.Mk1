"""Runtime: owns the active session, sources, replay, imports, rule execution,
health, and the bridge from the event bus to WebSocket channels."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import threading
import time
import uuid
import zipfile
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import psutil
from sqlalchemy import func, select, text

from ..config import PROJECT_ROOT, Config
from ..forensic.hashing import sha256_file, verify_case
from ..forensic.snapshot import PARSER_VERSION, SnapshotManager
from ..ids.correlation import Correlator, IncidentIdAllocator
from ..ids.rule_store import RuleStore
from ..ids.rules import compile_rule, validate_rule
from ..mavlink.registry import DialectRegistry
from ..models.events import iso_from_epoch, utc_now_iso
from ..security.keys import KeyStore
from ..sources.files import SourceItem, detect_format, open_source
from ..sources.live import LiveMavlinkSource, parse_spec
from ..sources.simulation import SCENARIOS, FlightSimulator
from ..storage import db as D
from ..websocket.hub import Hub
from .audit import AuditLog
from .bus import EventBus
from .errors import ErrorRegistry
from .pipeline import Pipeline

VERSION = "1.0.0"


def _sid(kind: str) -> str:
    return f"{kind.upper()}-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:4]}"


class ActiveSession:
    def __init__(self, session_id: str, kind: str, source: str, pipeline: Pipeline):
        self.session_id = session_id
        self.kind = kind            # live | simulation | replay
        self.source = source
        self.pipeline = pipeline
        self.state = "CONNECTING"
        self.state_detail = ""
        self.task: Optional[asyncio.Task] = None
        self.live: Optional[LiveMavlinkSource] = None
        self.replay: Optional["ReplayController"] = None
        self.started = time.time()
        self.scenario: Optional[str] = None


class ReplayController:
    """Plays recorded frames through a fresh pipeline at 0.25×–10×. Seek rebuilds
    detector state by fast re-analysis from the start (detectors are stateful),
    so replay always shows what the engine derives from the recording itself."""

    SPEEDS = (0.25, 0.5, 1.0, 2.0, 5.0, 10.0)

    def __init__(self, rt: "Runtime", ref: str, items: list, speed: float = 1.0):
        self.rt = rt
        self.ref = ref
        self.items = items
        self.speed = speed if speed in self.SPEEDS else 1.0
        self.pos = 0
        self.paused = False
        self.t0 = items[0].t if items else 0.0
        self.t_end = items[-1].t if items else 0.0
        self._wake = asyncio.Event()
        self.finished = False

    def status(self) -> dict:
        cur = self.items[min(self.pos, len(self.items) - 1)].t if self.items else 0.0
        return {"ref": self.ref, "speed": self.speed, "paused": self.paused, "finished": self.finished, "position": self.pos,
                "total": len(self.items), "t_start": self.t0, "t_end": self.t_end, "t_current": cur,
                "offset_s": round(cur - self.t0, 2), "duration_s": round(self.t_end - self.t0, 2),
                "reverse_playback": "not supported: detector state is causal; use seek to move backwards"}

    async def run(self, sess: ActiveSession):
        last_wall = time.monotonic()
        last_t = None
        while self.pos < len(self.items):
            if self.paused:
                self._wake.clear()
                await self._wake.wait()
                last_wall, last_t = time.monotonic(), None
                continue
            it = self.items[self.pos]
            if last_t is not None:
                wait = (it.t - last_t) / self.speed - (time.monotonic() - last_wall)
                if wait > 0:
                    try:
                        await asyncio.wait_for(self._wake.wait(), timeout=min(wait, 0.5))
                        self._wake.clear()
                        continue
                    except asyncio.TimeoutError:
                        if wait > 0.5:
                            continue
            last_wall, last_t = time.monotonic(), it.t
            sess.pipeline.handle_item(it)
            self.pos += 1
            if self.pos % 200 == 0:
                await asyncio.sleep(0)
        self.finished = True
        sess.state = "REPLAY_COMPLETE"

    def control(self, action: str, value: Any = None):
        if action == "pause":
            self.paused = True
        elif action == "play":
            self.paused = False
        elif action == "speed":
            v = float(value)
            if v not in self.SPEEDS:
                raise ValueError(f"speed must be one of {self.SPEEDS}")
            self.speed = v
        self._wake.set()


class Runtime:
    def __init__(self, config: Config):
        self.config = config
        self.root = PROJECT_ROOT
        self.dirs = {k: config.resolve_path(p, p) for k, p in (("captures", config.get("recording.capture_dir", "data/captures")),
                                                               ("cases", config.get("forensics.case_dir", "data/cases")),
                                                               ("imports", "data/imports"), ("audit", "data/audit"),
                                                               ("exports", "data/exports"), ("work", "data/work"),
                                                               ("simulations", "data/simulations"))}
        self.errors = ErrorRegistry()
        self.engine = D.make_engine(config.get("database.url", "sqlite:///data/database/pushpak_gcs.db"), self.root)
        self.db = D.DBWriter(self.engine, self.errors, float(config.get("database.batch_interval_s", 0.5)),
                             int(config.get("database.max_queue", 50000)), int(config.get("database.emergency_queue", 20000)))
        self.audit = AuditLog(self.engine, self.dirs["audit"])
        self.keys = KeyStore(config.resolve_path("security.keystore_dir", "data/keys"))
        self.sign_evidence = bool(config.get("security.sign_evidence", True))
        self.audit.on_record = self._audit_checkpoint
        self.signing_key_id: Optional[str] = None
        self.bus = EventBus(default_maxsize=5000)
        self.hub = Hub(int(config.get("limits.max_ws_queue", 500)))
        self.registry = DialectRegistry(config.get("mavlink.dialect", "ardupilotmega"), config.get("mavlink.dialect_xml"), self.dirs["work"])
        if self.registry.load_error:
            self.errors.record("DIALECT", "LOAD_FAILED", self.registry.load_error, recoverable=True)
        self.capabilities = self._load_capabilities()
        self.signing_key = self._load_signing_key()
        self.allocator = IncidentIdAllocator(self._max_incident_no())
        self._detector_ids = None
        self.rule_store = RuleStore(self.engine, self.registry, self.detector_ids)
        self.active: Optional[ActiveSession] = None
        self.ingest_q: Optional[asyncio.Queue] = None
        self.ingest_dropped = 0
        self.imports: dict[str, dict] = {}
        self.cases_status: dict[str, dict] = {}
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self._tasks: list[asyncio.Task] = []
        self._lock = asyncio.Lock()
        self.shadow: Optional[dict] = None
        self.last_connection: dict = {"state": "DISCONNECTED", "detail": "", "spec": None}
        self.started = time.time()
        self.packet_batch: deque = deque(maxlen=400)
        self.ws_rate_scale = 1.0

    # ---------------------------------------------------------------- setup
    def _load_capabilities(self) -> dict:
        p = self.root / "configs" / "capabilities.json"
        if p.exists():
            try:
                caps = json.loads(p.read_text())
                from ..mavlink import pushpak
                pushpak.PIDS_STATE_MAP_VERIFIED = bool((caps.get("pushpak") or {}).get("state_map_verified"))
                return caps
            except Exception as exc:
                self.errors.record("DISCOVERY", "CAPABILITIES_INVALID", str(exc))
        return {"vehicle": {}, "pushpak": {}, "mavlink": {"version": "2", "custom_dialect": False}, "findings": [],
                "discrepancies": [], "note": "capabilities.json missing — run scripts/discover_firmware.py"}

    def _audit_checkpoint(self, entry: dict) -> None:
        """Every N audit entries, sign the chain head and copy it to the (separately administered) mirror (GAP-12)."""
        every = int(self.config.get("audit.checkpoint_every", 100) or 0)
        if not self.sign_evidence or every <= 0 or entry["seq"] % every:
            return
        try:
            from ..security.evidence import write_checkpoint
            mirror = self.config.get("audit.checkpoint_mirror_dir")
            write_checkpoint(self.audit, self.keys.signing_key("evidence"), self.dirs["audit"], Path(mirror) if mirror else None)
        except Exception as exc:
            self.errors.record("AUDIT", "CHECKPOINT_FAILED", f"{type(exc).__name__}: {exc}", recoverable=True)

    def apply_signing_key(self, kid: Optional[str], key: Optional[bytes]) -> None:
        """Switch the MAVLink validation key, including on the running session's decoders (receive-only)."""
        self.signing_key, self.signing_key_id = key, kid
        sess = self.active
        if sess is not None:
            p = sess.pipeline
            p.signing_key = key
            for d in p.decoders.values():
                d.signing_key_configured = key is not None
                d.mav.signing.secret_key = key
                d.mav.signing.sign_outgoing = False
                d.mav.signing.allow_unsigned_callback = lambda mav, msgid: True
            sig = p.engine.get("MAVLINK_SIGNING")
            if sig is not None:
                sig.key_configured = key is not None

    def _load_signing_key(self) -> Optional[bytes]:
        p = self.config.get("mavlink.signing_key_file")
        if not p:
            # No explicit file: use the active key from the GCS keyring, if any (GAP-08).
            try:
                kid, key = self.keys.active_mavlink_secret()
                self.signing_key_id = kid
                return key
            except Exception as exc:
                self.errors.record("SIGNING", "KEY_LOAD_FAILED", f"active keyring key unusable: {type(exc).__name__}", recoverable=True)
                return None
        try:
            b = Path(p).read_bytes().strip()
            if len(b) == 64:
                b = bytes.fromhex(b.decode())
            if len(b) != 32:
                raise ValueError("signing key must be 32 bytes (or 64 hex chars)")
            return b
        except Exception as exc:
            self.errors.record("SIGNING", "KEY_LOAD_FAILED", f"signing key could not be loaded: {type(exc).__name__}", recoverable=True)
            return None

    def _max_incident_no(self) -> int:
        with self.engine.connect() as c:
            ids = [r[0] for r in c.execute(select(D.incidents.c.incident_id))]
        nums = [int(m.group(1)) for i in ids if (m := re.match(r"INC-\d{4}-(\d+)$", i or ""))]
        return max(nums, default=0)

    def detector_ids(self) -> list[str]:
        if self._detector_ids is None:
            from ..ids.engine import DETECTOR_PLUGINS
            self._detector_ids = list(DETECTOR_PLUGINS)
        return self._detector_ids

    async def start(self) -> None:
        self.loop = asyncio.get_running_loop()
        self.bus.bind_loop(self.loop)
        self.db.start()
        self.rule_store.seed()
        self.ingest_q = asyncio.Queue(maxsize=int(self.config.get("limits.max_ingest_queue", 20000)))
        self.audit.record("SYSTEM_START", "runtime", {"version": VERSION, "read_only": self.config.get("security.read_only", True)}, actor="system", role="system")
        sub = self.bus.subscribe("ws-bridge", maxsize=20000)
        self._tasks += [asyncio.create_task(self._bus_bridge(sub)), asyncio.create_task(self._ingest_consumer()),
                        asyncio.create_task(self._periodic()), asyncio.create_task(self._retention())]

    async def shutdown(self) -> None:
        await self.stop_session(reason="shutdown")
        for t in self._tasks:
            t.cancel()
        self.db.stop()

    # ---------------------------------------------------------------- sessions
    def compiled_rules(self) -> list:
        out = []
        for r in self.rule_store.published():
            try:
                out.append(compile_rule(r, self.registry, self.detector_ids()))
            except Exception as exc:
                self.errors.record(f"RULE:{r.get('rule_id')}", "COMPILE_FAILED", str(exc))
        return out

    def _new_pipeline(self, session_id: str, kind: str, source: str, *, live_clock: bool, persist: bool = True,
                      bus: bool = True, record: bool = True, snapshots: bool = True) -> Pipeline:
        snaps = SnapshotManager(self.dirs["cases"], self.config, self.errors, on_case=self._on_case,
                                keystore=self.keys if self.sign_evidence else None) if snapshots else None
        p = Pipeline(session_id=session_id, kind=kind, source_desc=source, config=self.config, registry=self.registry,
                     errors=self.errors, capabilities=self.capabilities, allocator=self.allocator,
                     db=self.db if persist else None, bus=self.bus if bus else None, snapshots=snaps,
                     recorder_dir=self.dirs["captures"] if record else None, rules=self.compiled_rules(),
                     signing_key=self.signing_key, live_clock=live_clock, on_system_event=self._system_event)
        if persist:
            self.db.upsert("flights", {"session_id": session_id, "kind": kind, "source": source, "started_at": utc_now_iso(),
                                       "ended_at": None, "t_start": None, "t_end": None, "source_hash": None, "packets": 0,
                                       "meta": D.dumps({"capture": f"{session_id}.tlog" if record else None})})
        return p

    async def start_live(self, spec_text: str, actor="operator", role="admin") -> dict:
        spec = parse_spec(spec_text, int(self.config.get("mavlink.baud", 115200)))
        async with self._lock:
            await self._stop_locked("new connection")
            sid = _sid("live")
            p = self._new_pipeline(sid, "live", spec.text, live_clock=True)
            sess = ActiveSession(sid, "live", spec.text, p)
            sess.live = LiveMavlinkSource(spec, self._push_frame, lambda st, d: self._conn_state(sess, st, d),
                                          reconnect=bool(self.config.get("mavlink.auto_reconnect", True)),
                                          rmin=float(self.config.get("mavlink.reconnect_min_s", 1)),
                                          rmax=float(self.config.get("mavlink.reconnect_max_s", 15)))
            self.active = sess
            sess.live.start()
        self.db.insert("connections", {"session_id": sid, "t": time.time(), "spec": spec.text, "state": "CONNECTING", "detail": "operator request"}, critical=True)
        self.audit.record("CONNECTION_OPENED", spec.text, {"session_id": sid}, actor=actor, role=role)
        return {"session_id": sid, "spec": spec.text}

    async def start_simulation(self, scenario: str, speed: float = 1.0, duration_s: float = 900.0, actor="operator", role="admin") -> dict:
        if scenario not in SCENARIOS:
            raise ValueError(f"unknown scenario {scenario}")
        async with self._lock:
            await self._stop_locked("new simulation")
            sid = _sid("sim")
            p = self._new_pipeline(sid, "simulation", f"SIMULATION:{scenario}", live_clock=False)
            sess = ActiveSession(sid, "simulation", f"SIMULATION:{scenario}", p)
            sess.scenario = scenario
            self.active = sess
            sess.state = "CONNECTED"
            sess.task = asyncio.create_task(self._run_sim(sess, scenario, speed, duration_s))
        self._conn_state(sess, "CONNECTED", f"simulation {scenario} (synthetic data, nothing transmitted)")
        self.audit.record("SIMULATION_STARTED", scenario, {"session_id": sid, "speed": speed}, actor=actor, role=role)
        return {"session_id": sid, "scenario": scenario, "label": "SIMULATION — synthetic data"}

    async def _run_sim(self, sess: ActiveSession, scenario: str, speed: float, duration_s: float):
        sim = FlightSimulator(scenario, home=(self.config.get("simulation.home_lat", 12.9716), self.config.get("simulation.home_lon", 77.5946),
                                             self.config.get("simulation.home_alt_m", 920)),
                              duration_s=duration_s, t0=time.time())
        start_wall = time.monotonic()
        t_first = None
        try:
            for fr in sim.frames():
                if t_first is None:
                    t_first = fr.t
                due = (fr.t - t_first) / max(speed, 0.01)
                lag = due - (time.monotonic() - start_wall)
                if lag > 0.005:
                    await asyncio.sleep(lag)
                sess.pipeline.handle_item(SourceItem("frame", fr.t, fr.data, fr.link, "SIMULATION"))
            sess.state = "COMPLETE"
            self._conn_state(sess, "DISCONNECTED", "simulation finished")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.errors.record("SIMULATION", "RUN_FAILED", str(exc), exc=exc)
            self._conn_state(sess, "ERROR", str(exc)[:200])

    def resolve_dataset(self, ref: str) -> tuple[Path, str]:
        """capture:<session> | case:<case_id> | import:<import_id> → (path, format)."""
        kind, _, ident = ref.partition(":")
        if not re.fullmatch(r"[A-Za-z0-9_\-]+", ident or ""):
            raise ValueError("invalid dataset reference")
        if kind == "capture":
            p = self.dirs["captures"] / f"{ident}.tlog"
            return p, "tlog"
        if kind == "case":
            return self.dirs["cases"] / ident / "mavlink_raw.bin", "case_raw"
        if kind == "import":
            imp = self.get_import(ident)
            if not imp:
                raise FileNotFoundError(ref)
            return Path(imp["path"]), imp["format"]
        raise ValueError("dataset must be capture:, case:, import: or scenario:")

    async def start_replay(self, ref: str, speed: float = 1.0, actor="operator", role="admin") -> dict:
        path, fmt = self.resolve_dataset(ref)
        if not path.exists():
            raise FileNotFoundError(str(path.name))
        items = await asyncio.to_thread(lambda: list(open_source(path, fmt)))
        if not items:
            raise ValueError("no records in dataset")
        async with self._lock:
            await self._stop_locked("replay")
            sid = _sid("replay")
            p = self._new_pipeline(sid, "replay", ref, live_clock=False, persist=False, record=False, snapshots=False)
            sess = ActiveSession(sid, "replay", ref, p)
            sess.replay = ReplayController(self, ref, items, speed)
            sess.state = "CONNECTED"
            self.active = sess
            sess.task = asyncio.create_task(sess.replay.run(sess))
        self._conn_state(sess, "CONNECTED", f"replay {ref}")
        self.audit.record("REPLAY_STARTED", ref, {"session_id": sid, "speed": speed}, actor=actor, role=role)
        return {"session_id": sid, "replay": sess.replay.status()}

    async def replay_control(self, action: str, value: Any = None) -> dict:
        sess = self.active
        if not sess or not sess.replay:
            raise RuntimeError("no replay active")
        rc = sess.replay
        if action in ("seek", "jump"):
            target = float(value)
            await self._replay_seek(sess, target)
        else:
            rc.control(action, value)
        return rc.status()

    async def _replay_seek(self, sess: ActiveSession, target_t: float):
        rc = sess.replay
        if sess.task:
            sess.task.cancel()
            try:
                await sess.task
            except (asyncio.CancelledError, Exception):
                pass
        p = self._new_pipeline(sess.session_id, "replay", sess.source, live_clock=False, persist=False, record=False, snapshots=False, bus=False)
        idx = 0
        items = rc.items

        def fast():
            nonlocal idx
            while idx < len(items) and items[idx].t < target_t:
                p.handle_item(items[idx])
                idx += 1
        await asyncio.to_thread(fast)
        p.bus = self.bus
        sess.pipeline = p
        rc.pos = idx
        rc.finished = False
        sess.state = "CONNECTED"
        self.bus.publish("REPLAY_RESYNC", {"session_id": sess.session_id, "t": target_t}, "replay")
        sess.task = asyncio.create_task(rc.run(sess))

    async def stop_session(self, reason: str = "operator", actor="operator", role="admin") -> dict:
        async with self._lock:
            info = await self._stop_locked(reason)
        if info:
            self.audit.record("SESSION_STOPPED", info["session_id"], {"reason": reason}, actor=actor, role=role)
        return info or {}

    async def _stop_locked(self, reason: str) -> Optional[dict]:
        sess = self.active
        if not sess:
            return None
        if sess.live:
            await sess.live.stop()
        if sess.task:
            sess.task.cancel()
            try:
                await sess.task
            except (asyncio.CancelledError, Exception):
                pass
        # drain queued frames for this session before closing
        while self.ingest_q and not self.ingest_q.empty():
            try:
                it = self.ingest_q.get_nowait()
                sess.pipeline.handle_item(it)
            except Exception:
                break
        p = sess.pipeline
        await asyncio.to_thread(p.close, True)
        if p.db:
            self.db.upsert("flights", {"session_id": sess.session_id, "kind": sess.kind, "source": sess.source,
                                       "started_at": iso_from_epoch(sess.started), "ended_at": utc_now_iso(), "t_start": p.t_first,
                                       "t_end": p.t_last, "source_hash": None, "packets": p.idx,
                                       "meta": D.dumps({"capture": f"{sess.session_id}.tlog" if p.recorder else None,
                                                        "recorder": p.recorder.stats() if p.recorder else None,
                                                        "summary": p.summary(), "stop_reason": reason})})
        self._conn_state(sess, "DISCONNECTED", reason)
        self.active = None
        return {"session_id": sess.session_id, "packets": p.idx}

    # ---------------------------------------------------------------- live ingest
    def _push_frame(self, t: float, data: bytes, link: str) -> None:
        try:
            self.ingest_q.put_nowait(SourceItem("frame", t, data, link, "LIVE"))
        except asyncio.QueueFull:
            self.ingest_dropped += 1
            if self.ingest_dropped in (1, 10, 100) or self.ingest_dropped % 1000 == 0:
                self.errors.record("INGEST", "QUEUE_FULL", f"ingest queue full; {self.ingest_dropped} datagrams dropped (loss recorded)")
                self._system_event("INGEST_OVERFLOW", "HIGH", f"{self.ingest_dropped} datagrams dropped at ingest")

    async def _ingest_consumer(self):
        while True:
            it = await self.ingest_q.get()
            sess = self.active
            if sess is None or sess.kind != "live":
                continue
            try:
                sess.pipeline.handle_item(it)
            except Exception as exc:  # never let one frame stop ingestion
                self.errors.record("PIPELINE", "ITEM_FAILED", str(exc), exc=exc)
            if self.ingest_q.qsize() == 0 or sess.pipeline.idx % 500 == 0:
                await asyncio.sleep(0)

    def _conn_state(self, sess: ActiveSession, st: str, detail: str):
        sess.state, sess.state_detail = st, detail
        self.last_connection = {"state": st, "detail": detail, "spec": sess.source, "session_id": sess.session_id, "kind": sess.kind,
                                "t": time.time()}
        self.bus.publish("CONNECTION_STATE", self.last_connection, "connection")
        if sess.kind == "live":
            self.db.insert("connections", {"session_id": sess.session_id, "t": time.time(), "spec": sess.source, "state": st, "detail": detail[:300]}, critical=True)

    def _system_event(self, type_: str, severity: str, message: str):
        self.bus.publish("SYSTEM_EVENT", {"type": type_, "severity": severity, "message": message, "ts": utc_now_iso()}, "system")

    def _on_case(self, info: dict):
        prev = self.cases_status.get(info["case_id"], {})
        self.cases_status[info["case_id"]] = {**prev, **{k: v for k, v in info.items() if k != "manifest"}}
        m = info.get("manifest")
        if info["status"] in ("COMPLETE", "PARTIAL", "ERROR"):
            self.db.upsert("forensic_cases", {"case_id": info["case_id"], "incident_id": info.get("incident_id"),
                                              "session_id": info.get("session_id"), "created_at": info.get("created_at"),
                                              "status": info["status"], "path": info.get("path"),
                                              "manifest_sha256": info.get("manifest_sha256"), "data": D.dumps(m or info)})
            for a in (m or {}).get("artifacts", []):
                self.db.insert("artifacts", {"case_id": info["case_id"], **a}, critical=True)
        self.bus.publish("FORENSIC_SNAPSHOT", {k: v for k, v in info.items() if k != "manifest"}, "forensics")

    # ---------------------------------------------------------------- bus → websocket
    async def _bus_bridge(self, sub):
        type_map = {"IDS_ALERT": ("incidents", "alert"), "INCIDENT_CREATED": ("incidents", "incident"),
                    "INCIDENT_UPDATED": ("incidents", "incident"), "FORENSIC_SNAPSHOT": ("incidents", "case"),
                    "TIMELINE": ("events", "timeline"), "SYSTEM_EVENT": ("events", "system"),
                    "CONNECTION_STATE": ("events", "connection"), "DETECTOR_RESULT": ("ids", "result"),
                    "BUILDER_TRACE": ("builder", "trace"), "REPLAY_RESYNC": ("events", "resync")}
        while True:
            ev = await sub.queue.get()
            try:
                if ev.type == "MAVLINK_DECODED":
                    if self.hub.has("events"):
                        self.packet_batch.append(ev.payload.summary())
                    continue
                m = type_map.get(ev.type)
                if m:
                    if ev.type == "DETECTOR_RESULT" and ev.payload.get("kind") == "observation" and not self.hub.has("ids"):
                        continue
                    self.hub.send(m[0], m[1], ev.payload)
                    if ev.type in ("INCIDENT_CREATED", "INCIDENT_UPDATED", "CONNECTION_STATE"):
                        self.hub.send("ids", m[1], ev.payload)
            except Exception as exc:
                self.errors.record("WEBSOCKET", "BRIDGE_FAILED", str(exc), exc=exc)

    async def _periodic(self):
        hz = float(self.config.get("gui.update_hz", 10))
        k = 0
        while True:
            await asyncio.sleep(1.0 / hz)
            k += 1
            try:
                sess = self.active
                if sess and sess.kind == "live":
                    sess.pipeline.tick_live()
                if self.hub.has("telemetry") and sess and (k % max(1, int(self.ws_rate_scale)) == 0):
                    self.hub.send("telemetry", "state", self.telemetry_snapshot())
                if self.packet_batch and k % max(1, int(hz / 4)) == 0:
                    batch = list(self.packet_batch)
                    self.packet_batch.clear()
                    self.hub.send("events", "packets", batch[-200:])
                if k % max(1, int(hz / 2)) == 0 and self.hub.has("ids"):
                    self.hub.send("ids", "detectors", self.ids_snapshot())
                if k % int(hz) == 0:
                    h = self.health()
                    self.ws_rate_scale = 3.0 if h["resources"]["cpu_pct"] > 90 else 1.0  # degrade visual rate under load
                    self.hub.send("health", "health", h)
                    if self.hub.has("builder") and self.shadow and sess:
                        rt = self.shadow.get("runtime")
                        if rt:
                            self.hub.send("builder", "nodes", {"rule_id": rt.rule_id, "values": rt.node_values(), "evaluations": rt.evaluations,
                                                               "triggers": rt.triggers})
                        if time.time() > self.shadow["until"]:
                            self.stop_shadow()
            except Exception as exc:
                self.errors.record("PERIODIC", "LOOP_ERROR", str(exc), exc=exc)

    async def _retention(self):
        days = float(self.config.get("database.retention_days", 30))
        while True:
            await asyncio.sleep(3600)
            try:
                cutoff = time.time() - days * 86400
                def purge():
                    with self.engine.begin() as c:
                        for t in (D.mavlink_messages, D.telemetry, D.attitude_samples, D.gps_points, D.battery_samples, D.detector_states):
                            c.execute(t.delete().where(t.c.t < cutoff))
                await asyncio.to_thread(purge)
            except Exception as exc:
                self.errors.record("RETENTION", "PURGE_FAILED", str(exc))

    # ---------------------------------------------------------------- snapshots of state
    def telemetry_snapshot(self) -> dict:
        sess = self.active
        if not sess:
            return {"connected": False}
        p = sess.pipeline
        track = p.vstate.track[-1] if p.vstate.track else None
        return {"session_id": sess.session_id, "kind": sess.kind, "t": p.ctx.t, "ts": iso_from_epoch(p.ctx.t),
                "vehicle": p.vstate.snapshot(), "connection": {**p.connection_stats(), "state": sess.state, "detail": sess.state_detail},
                "home": p.vstate.home, "track_point": track, "armed": p.ctx.armed, "mode": p.ctx.mode, "airborne": p.ctx.airborne,
                "replay": sess.replay.status() if sess.replay else None, "scenario": sess.scenario}

    def ids_snapshot(self) -> dict:
        sess = self.active
        if not sess:
            return {"detectors": [], "comparison": self.fc_ground_comparison(None)}
        p = sess.pipeline
        return {"detectors": p.engine.health(p.ctx), "comparison": self.fc_ground_comparison(p),
                "rules": [{"rule_id": r.rule_id, "version": r.version, "evaluations": r.evaluations, "triggers": r.triggers,
                           "errors": r.errors} for r in p.rules]}

    GROUND_FOR_PUSHPAK = {"GPS": ["GPS_INTEGRITY"], "MAVLINK": ["MAVLINK_SEQUENCE", "SOURCE_IDENTITY", "MAVLINK_RATE", "MAVLINK_SIGNING"],
                          "COMMAND": ["COMMAND"], "RC_LINK": ["RC_LINK", "HEARTBEAT"], "IMU": ["IMU_CONSISTENCY"],
                          "MISSION": ["MISSION"], "PARAMETER": ["PARAMETER"], "OFFBOARD": ["OFFBOARD"]}
    DOMAIN_FOR_PUSHPAK = {"GPS": "GPS_INTEGRITY", "MAVLINK": "MAVLINK_SECURITY", "COMMAND": "MAVLINK_SECURITY", "RC_LINK": "LINK",
                          "IMU": "SENSOR", "MISSION": "MISSION", "PARAMETER": "MAVLINK_SECURITY", "OFFBOARD": "MAVLINK_SECURITY"}

    def fc_ground_comparison(self, p: Optional[Pipeline]) -> dict:
        from ..models.events import state_rank
        rows = []
        pk = p.engine.get("PUSHPAK_FC") if p else None
        for det, grounds in self.GROUND_FOR_PUSHPAK.items():
            fc = (pk.fc.get(det) if pk else None)
            lua = (pk.lua.get(det) if pk else None)
            g_states = [(g, p.engine.get(g).state if p and p.engine.get(g) else None) for g in grounds]
            worst = max(g_states, key=lambda x: state_rank(x[1]) if x[1] else -1) if g_states else (None, None)
            corr = None
            if p and p.correlator:
                opened = [i for i in p.correlator.incidents.values() if i["domain"] == self.DOMAIN_FOR_PUSHPAK[det] and i["status"] not in ("RESOLVED", "FALSE_POSITIVE")]
                if opened:
                    corr = max(opened, key=lambda i: i["last_seen"])["state"]
            rows.append({"detector": det,
                         "fc": {"state": fc["state"], "confidence": fc["confidence"], "evidence": fc["evidence"], "t": fc["t"]} if fc else None,
                         "lua": {"class": lua["class"], "confidence": lua["confidence"], "t": lua["t"]} if lua else None,
                         "ground": {"state": "CLEAR" if worst[1] in (None, "NORMAL") else worst[1], "detector": worst[0],
                                    "all": {g: s for g, s in g_states}},
                         "correlated": corr})
        lua_health = pk.lua_health if pk else {}
        return {"rows": rows, "lua_health": lua_health,
                "event_delivery": pk.delivery.status() if pk is not None and hasattr(pk, "delivery") else None,
                "jamming": "JAMMING is not a PIDS detector in the supplied source; jamming_confirm.lua classifies RC_LINK evidence (shown under RC_LINK).",
                "fc_available": bool(pk and pk.fc), "lua_available": bool(pk and pk.lua),
                "firmware_note": next((f"{d['summary']} ({d['id']})" for d in self.capabilities.get("discrepancies", [])), None)}

    # ---------------------------------------------------------------- health
    def health(self) -> dict:
        sess = self.active
        disk = shutil.disk_usage(self.dirs["captures"])
        proc = psutil.Process()
        mem_mb = proc.memory_info().rss / (1 << 20)
        dets = sess.pipeline.engine.health(sess.pipeline.ctx) if sess else []
        det_err = [d["detector"] for d in dets if d["health"] == "ERROR"]
        rec = sess.pipeline.recorder.stats() if sess and sess.pipeline.recorder else None
        dbs = self.db.stats()
        free_mb = disk.free / (1 << 20)
        conn_state = sess.state if sess else "DISCONNECTED"
        stale = None
        if sess:
            cs = sess.pipeline.connection_stats()
            stale = cs["heartbeat_age_s"] is not None and cs["heartbeat_age_s"] > float(self.config.get("mavlink.heartbeat_stale_s", 3))
        issues = []
        if conn_state in ("DISCONNECTED", "ERROR", "RECONNECTING"):
            issues.append({"component": "mavlink", "status": conn_state, "message": "MAVLink disconnected" if conn_state == "DISCONNECTED" else f"MAVLink {conn_state.lower()}"})
        if stale:
            issues.append({"component": "telemetry", "status": "STALE", "message": "Stale telemetry (heartbeat late)"})
        if dbs["status"] != "healthy":
            issues.append({"component": "database", "status": "DEGRADED", "message": f"Database degraded: {dbs['last_error']}"})
        if rec and rec["status"] not in ("RECORDING",):
            issues.append({"component": "recorder", "status": rec["status"], "message": f"Recording {rec['status'].lower()}"})
        if det_err:
            issues.append({"component": "ids", "status": "DEGRADED", "message": f"Detector error: {', '.join(det_err)}"})
        if free_mb < float(self.config.get("limits.disk_min_free_mb", 500)) * 2:
            issues.append({"component": "disk", "status": "LOW", "message": f"Disk nearly full ({free_mb:.0f} MB free)"})
        if mem_mb > float(self.config.get("limits.max_memory_mb", 2048)):
            issues.append({"component": "memory", "status": "HIGH", "message": f"Memory {mem_mb:.0f} MB above limit"})
        score = max(0, 100 - 20 * len([i for i in issues if i["component"] != "mavlink"]) - (10 if conn_state != "CONNECTED" else 0))
        status = "healthy" if not issues else ("degraded" if score >= 50 else "unhealthy")
        return {
            "status": status, "score": score, "issues": issues,
            "mavlink": conn_state.lower(), "recording": bool(rec and rec["status"] == "RECORDING"),
            "database": dbs["status"], "websocket": "healthy", "ids": "degraded" if det_err else "healthy",
            "forensics": "healthy", "session": {"session_id": sess.session_id, "kind": sess.kind, "source": sess.source} if sess else None,
            "connection": self.last_connection, "read_only": bool(self.config.get("security.read_only", True)),
            "subsystems": {
                "ingest": {"queued": self.ingest_q.qsize() if self.ingest_q else 0, "max": self.ingest_q.maxsize if self.ingest_q else 0, "dropped": self.ingest_dropped,
                           "packet_rate_hz": sess.pipeline.packet_rate() if sess else 0, "packets": sess.pipeline.idx if sess else 0,
                           "bad_frames": sess.pipeline.bad_frames if sess else 0},
                "database": dbs, "websocket": self.hub.stats(), "bus": self.bus.stats(), "recorder": rec,
                "rolling_buffer": sess.pipeline.packets.buf.stats() if sess else None,
                "detectors": {"total": len(dets), "errors": det_err, "max_latency_ms": max((d["latency_ms"] for d in dets), default=0)},
                "snapshots": {"active": len(sess.pipeline.snapshots.active) if sess and sess.pipeline.snapshots else 0, "written": sum(1 for c in self.cases_status.values() if c.get("status") in ("COMPLETE", "PARTIAL"))},
                "imports_running": sum(1 for i in self.imports.values() if i.get("status") == "ANALYZING"),
            },
            "resources": {"cpu_pct": psutil.cpu_percent(interval=None), "ram_mb": round(mem_mb, 1),
                          "system_ram_pct": psutil.virtual_memory().percent, "disk_free_mb": round(free_mb, 0),
                          "disk_used_pct": round(100 * disk.used / disk.total, 1)},
            "errors_recent": self.errors.list(10),
            "uptime_s": round(time.time() - self.started, 0), "version": VERSION, "server_time": utc_now_iso(),
        }

    # ---------------------------------------------------------------- imports
    MAX_IMPORT_ITEMS = 5_000_000

    def import_file(self, filename: str, tmp_path: Path, actor="operator", role="admin") -> dict:
        safe = re.sub(r"[^A-Za-z0-9._\-]", "_", Path(filename).name)[:120] or "upload.bin"
        digest = sha256_file(tmp_path)  # hash BEFORE anything else touches it
        size = tmp_path.stat().st_size
        dest_dir = self.dirs["imports"] / digest[:16]
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / safe
        shutil.move(str(tmp_path), dest)
        fmt = detect_format(dest)
        import_id = f"IMP-{digest[:12]}-{uuid.uuid4().hex[:4]}"
        rec = {"import_id": import_id, "filename": safe, "sha256": digest, "size": size, "format": fmt, "path": str(dest),
               "imported_at": utc_now_iso(), "parser_version": PARSER_VERSION, "session_id": None, "status": "VALIDATING",
               "progress": 0, "meta": {}}
        if fmt == "zip":
            try:
                rec = self._import_zip(rec, dest)
            except Exception as exc:
                rec["status"] = "REJECTED"
                rec["meta"]["error"] = str(exc)[:300]
        elif fmt == "unknown":
            rec["status"] = "REJECTED"
            rec["meta"]["error"] = "unrecognised format (supported: .tlog, DataFlash .bin/.log, .jsonl, .json, .csv, case .zip)"
        else:
            try:
                n = 0
                for _ in open_source(dest, fmt):
                    n += 1
                    if n >= 200:
                        break
                if n == 0:
                    raise ValueError("parser produced no records")
                rec["status"] = "QUEUED"
            except Exception as exc:
                rec["status"] = "REJECTED"
                rec["meta"]["error"] = f"parser validation failed: {exc}"[:300]
        self.imports[import_id] = rec
        self._persist_import(rec)
        self.audit.record("LOG_IMPORTED", safe, {"import_id": import_id, "sha256": digest, "size": size, "format": fmt, "status": rec["status"]}, actor=actor, role=role)
        if rec["status"] == "QUEUED":
            threading.Thread(target=self._analyze_import, args=(import_id,), daemon=True, name=f"import-{import_id}").start()
        return rec

    def _import_zip(self, rec: dict, path: Path) -> dict:
        """Safe extraction of an exported case: path traversal / size / count bounded."""
        out = self.dirs["imports"] / rec["sha256"][:16] / "extracted"
        with zipfile.ZipFile(path) as z:
            infos = z.infolist()
            if len(infos) > 500:
                raise ValueError("archive has too many entries")
            if sum(i.file_size for i in infos) > int(self.config.get("limits.max_upload_mb", 1024)) * (1 << 20):
                raise ValueError("archive expands beyond the upload limit")
            for i in infos:
                target = (out / i.filename).resolve()
                if not str(target).startswith(str(out.resolve()) + os.sep) or i.filename.startswith("/") or ".." in Path(i.filename).parts:
                    raise ValueError(f"unsafe path in archive: {i.filename}")
                if i.is_dir():
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with z.open(i) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst, 1 << 20)
        manifests = list(out.rglob("manifest.json"))
        if not manifests:
            raise ValueError("zip does not contain a forensic case (manifest.json)")
        case_dir = manifests[0].parent
        rec["meta"]["verification"] = verify_case(case_dir)
        raw = case_dir / "mavlink_raw.bin"
        if raw.exists() and raw.stat().st_size:
            rec["path"], rec["format"], rec["status"] = str(raw), "case_raw", "QUEUED"
        else:
            rec["status"] = "IMPORTED"
        return rec

    def _analyze_import(self, import_id: str) -> None:
        rec = self.imports[import_id]
        sid = _sid("import")
        rec["session_id"], rec["status"] = sid, "ANALYZING"
        self._persist_import(rec)
        p = self._new_pipeline(sid, "import", f"import:{import_id}:{rec['filename']}", live_clock=False, bus=False, record=False)
        self.db.upsert("flights", {"session_id": sid, "kind": "import", "source": rec["filename"], "started_at": utc_now_iso(),
                                   "ended_at": None, "t_start": None, "t_end": None, "source_hash": rec["sha256"], "packets": 0,
                                   "meta": D.dumps({"import_id": import_id, "format": rec["format"]})})
        size = max(1, rec["size"])
        n = 0
        try:
            for it in open_source(Path(rec["path"]), rec["format"]):
                p.handle_item(it)
                n += 1
                if n % 5000 == 0:
                    rec["progress"] = min(99, int(100 * n / max(n + 1, size / 40)))
                if n >= self.MAX_IMPORT_ITEMS:
                    rec["meta"]["truncated"] = True
                    break
            rec["status"] = "COMPLETE"
        except Exception as exc:
            rec["status"] = "FAILED"
            rec["meta"]["error"] = str(exc)[:300]
            self.errors.record("IMPORT", "ANALYSIS_FAILED", f"{import_id}: {exc}", exc=exc)
        p.close(partial=False)
        if p.snapshots:
            p.snapshots.pool.shutdown(wait=True)
        rec["progress"] = 100
        rec["meta"]["summary"] = p.summary()
        self._persist_import(rec)
        self.db.upsert("flights", {"session_id": sid, "kind": "import", "source": rec["filename"], "started_at": rec["imported_at"],
                                   "ended_at": utc_now_iso(), "t_start": p.t_first, "t_end": p.t_last, "source_hash": rec["sha256"],
                                   "packets": p.idx, "meta": D.dumps({"import_id": import_id, "format": rec["format"], "summary": p.summary()})})
        self.bus.publish("SYSTEM_EVENT", {"type": "IMPORT_COMPLETE", "severity": "INFO", "message": f"{rec['filename']} analysed: {p.idx} records, "
                                          f"{len(p.alerts)} alerts, {len(p.correlator.incidents)} incidents", "import_id": import_id}, "import")

    def _persist_import(self, rec: dict):
        self.db.upsert("imports", {"import_id": rec["import_id"], "filename": rec["filename"], "sha256": rec["sha256"], "size": rec["size"],
                                   "format": rec["format"], "imported_at": rec["imported_at"], "parser_version": rec["parser_version"],
                                   "session_id": rec["session_id"], "status": rec["status"],
                                   "meta": D.dumps({**rec["meta"], "path": rec["path"], "progress": rec.get("progress")})})

    def get_import(self, import_id: str) -> Optional[dict]:
        if import_id in self.imports:
            return self.imports[import_id]
        rows = D.query(self.engine, select(D.imports).where(D.imports.c.import_id == import_id))
        if not rows:
            return None
        r = D.parse_json_cols(rows)[0]
        r["path"] = (r.get("meta") or {}).get("path")
        return r

    # ---------------------------------------------------------------- rule testing
    def dataset_items(self, ref: str, limit: int = 600_000):
        if ref.startswith("scenario:"):
            sc = ref.split(":", 1)[1]
            if sc not in SCENARIOS:
                raise ValueError(f"unknown scenario {sc}")
            for fr in FlightSimulator(sc, duration_s=120).frames():
                yield SourceItem("frame", fr.t, fr.data, fr.link, "SIMULATION")
            return
        path, fmt = self.resolve_dataset(ref)
        if not path.exists():
            raise FileNotFoundError(ref)
        for i, it in enumerate(open_source(path, fmt)):
            if i >= limit:
                break
            yield it

    def test_rule(self, rule: dict, dataset: str, sample_hz: float = 2.0) -> dict:
        from ..ids.rule_store import _definition
        defn = _definition(rule)
        defn.setdefault("version", rule.get("version", 0))
        val = validate_rule(defn, self.registry, self.detector_ids())
        if not val["valid"]:
            return {"valid": False, "validation": val}
        rt = compile_rule(dict(defn, version=rule.get("version", 0)), self.registry, self.detector_ids())
        p = Pipeline(session_id="RULETEST", kind="rule_test", source_desc=dataset, config=self.config, registry=self.registry,
                     errors=self.errors, capabilities=self.capabilities, allocator=IncidentIdAllocator(), rules=[rt], correlate=False)
        triggers, series, last_s = [], {nid: [] for nid in rt.nodes}, None
        orig = p.handle_result
        p.handle_result = lambda r: (triggers.append(r.to_dict()) if r.detector == f"RULE:{rt.rule_id}" else None)  # type: ignore
        t0 = time.time()
        n = 0
        for it in self.dataset_items(dataset):
            p.handle_item(it)
            n += 1
            if p.t_first is not None and (last_s is None or p.ctx.t - last_s >= 1.0 / sample_hz):
                last_s = p.ctx.t
                for nid, st in rt.st.items():
                    v = st.value
                    series[nid].append([round(p.ctx.t - p.t_first, 2), (1 if v else 0) if isinstance(v, bool) else (round(v, 4) if isinstance(v, (int, float)) else None)])
        p.handle_result = orig  # type: ignore
        run = {"run_id": f"RUN-{uuid.uuid4().hex[:10]}", "rule_id": rt.rule_id, "version": rt.version, "dataset": dataset,
               "records": n, "duration_s": round(time.time() - t0, 2), "evaluations": rt.evaluations, "triggered": bool(triggers),
               "triggers": [{"t": x["t"], "offset_s": round(x["t"] - (p.t_first or x["t"]), 2), "state": x["state"], "title": x["title"],
                             "confidence": x["confidence"], "trace": x["trace"], "packet_refs": x["packet_refs"]} for x in triggers[:50]],
               "series": {k: v[-1500:] for k, v in series.items()}, "node_errors": rt.errors, "valid": True, "validation": val}
        expected = [t for t in (rule.get("tests") or []) if t.get("dataset") == dataset]
        if expected:
            want = expected[0].get("expect")
            run["expectation"] = {"expect": want, "passed": (want == "trigger") == bool(triggers)}
        self.db.insert("rule_runs", {"run_id": run["run_id"], "rule_id": rt.rule_id, "version": rt.version, "dataset": dataset,
                                     "started": utc_now_iso(), "result": D.dumps({k: v for k, v in run.items() if k != "series"})}, critical=True)
        return run

    def start_shadow(self, rule: dict, seconds: float = 120) -> dict:
        from ..ids.rule_store import _definition
        if not self.active:
            raise RuntimeError("no active session to attach a live test to")
        rt = compile_rule(dict(_definition(rule), version=rule.get("version", 0)), self.registry, self.detector_ids())
        self.stop_shadow()
        self.active.pipeline.shadow_rules = [rt]
        self.shadow = {"runtime": rt, "until": time.time() + max(5, min(seconds, 1800)), "session_id": self.active.session_id}
        return {"rule_id": rt.rule_id, "until": iso_from_epoch(self.shadow["until"]), "session_id": self.active.session_id}

    def stop_shadow(self):
        if self.active:
            self.active.pipeline.shadow_rules = []
        self.shadow = None

    def reload_rules(self):
        if self.active:
            self.active.pipeline.set_rules(self.compiled_rules())
