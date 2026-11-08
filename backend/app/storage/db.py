"""Database schema (SQLAlchemy Core) and batched background writer.

SQLite (WAL) for the MVP; the same Core schema works on PostgreSQL by changing
`database.url`. High-rate writes are batched by a dedicated writer thread so the
ingest path never waits on disk. On failure batches are held in a bounded
emergency queue and the error is surfaced in health.
"""
from __future__ import annotations

import json
import queue
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Iterable, Optional

import orjson
from sqlalchemy import (JSON, Boolean, Column, Float, Index, Integer, MetaData, String, Table, Text,
                        create_engine, event, select, text)
from sqlalchemy.engine import Engine

metadata = MetaData()

J = JSON().with_variant(Text(), "sqlite")  # JSON stored as text on SQLite (we serialize ourselves)

sessions = Table("flights", metadata,
    Column("session_id", String, primary_key=True), Column("kind", String), Column("source", String),
    Column("started_at", String), Column("ended_at", String), Column("t_start", Float), Column("t_end", Float),
    Column("source_hash", String), Column("packets", Integer, default=0), Column("meta", Text))

connections = Table("connections", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True), Column("session_id", String),
    Column("t", Float), Column("spec", String), Column("state", String), Column("detail", Text))

telemetry = Table("telemetry", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True), Column("session_id", String, index=True),
    Column("t", Float, index=True), Column("state", Text))

mavlink_messages = Table("mavlink_messages", metadata,
    Column("session_id", String, primary_key=True), Column("idx", Integer, primary_key=True),
    Column("t", Float), Column("sysid", Integer), Column("compid", Integer), Column("msg_id", Integer),
    Column("msg_name", String), Column("seq", Integer), Column("source", String), Column("link", String),
    Column("signed", Boolean), Column("sig", String), Column("parse_error", String),
    Column("fields", Text), Column("raw_hex", Text))
Index("ix_msg_t", mavlink_messages.c.session_id, mavlink_messages.c.t)
Index("ix_msg_name", mavlink_messages.c.session_id, mavlink_messages.c.msg_name, mavlink_messages.c.t)
Index("ix_msg_sys", mavlink_messages.c.sysid, mavlink_messages.c.compid)
Index("ix_msg_id", mavlink_messages.c.msg_id)

detector_states = Table("detector_states", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True), Column("session_id", String, index=True),
    Column("t", Float, index=True), Column("detector", String, index=True), Column("health", String),
    Column("state", String), Column("confidence", Float), Column("data", Text))

detector_results = Table("detector_results", metadata,
    Column("result_id", String, primary_key=True), Column("session_id", String, index=True),
    Column("t", Float, index=True), Column("detector", String, index=True), Column("state", String),
    Column("severity", String, index=True), Column("confidence", Float), Column("source", String),
    Column("domain", String), Column("rule_id", String), Column("rule_version", Integer),
    Column("kind", String), Column("data", Text))

ids_events = Table("ids_events", metadata,
    Column("alert_id", String, primary_key=True), Column("session_id", String, index=True),
    Column("t", Float, index=True), Column("result_id", String), Column("detector", String, index=True),
    Column("severity", String, index=True), Column("confidence", Float), Column("source", String),
    Column("state", String), Column("status", String, index=True), Column("incident_id", String, index=True),
    Column("title", String), Column("data", Text))

incidents = Table("incidents", metadata,
    Column("incident_id", String, primary_key=True), Column("session_id", String, index=True),
    Column("first_seen", Float, index=True), Column("last_seen", Float), Column("state", String),
    Column("status", String, index=True), Column("severity", String, index=True), Column("confidence", Float),
    Column("domain", String), Column("title", String), Column("data", Text))

incident_evidence = Table("incident_evidence", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True), Column("incident_id", String, index=True),
    Column("result_id", String), Column("t", Float), Column("kind", String), Column("ref", Text))

rules = Table("rules", metadata,
    Column("rule_id", String, primary_key=True), Column("name", String), Column("status", String),
    Column("current_version", Integer), Column("published_version", Integer), Column("enabled", Boolean),
    Column("modified", String), Column("data", Text))

rule_versions = Table("rule_versions", metadata,
    Column("rule_id", String, primary_key=True), Column("version", Integer, primary_key=True),
    Column("created", String), Column("author", String), Column("status", String), Column("sha256", String),
    Column("data", Text))

rule_runs = Table("rule_runs", metadata,
    Column("run_id", String, primary_key=True), Column("rule_id", String, index=True), Column("version", Integer),
    Column("dataset", String), Column("started", String), Column("result", Text))

gps_points = Table("gps_points", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True), Column("session_id", String, index=True),
    Column("t", Float, index=True), Column("lat", Float), Column("lon", Float), Column("alt", Float),
    Column("kind", String))

attitude_samples = Table("attitude_samples", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True), Column("session_id", String, index=True),
    Column("t", Float, index=True), Column("roll", Float), Column("pitch", Float), Column("yaw", Float))

battery_samples = Table("battery_samples", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True), Column("session_id", String, index=True),
    Column("t", Float, index=True), Column("voltage", Float), Column("current", Float), Column("remaining", Float))

commands = Table("commands", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True), Column("session_id", String, index=True),
    Column("t", Float, index=True), Column("idx", Integer), Column("msg", String), Column("sysid", Integer),
    Column("compid", Integer), Column("target_system", Integer), Column("target_component", Integer),
    Column("command", Integer), Column("command_name", String), Column("params", Text),
    Column("ack_result", String), Column("armed", Boolean), Column("mode", String))

parameters = Table("parameters", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True), Column("session_id", String, index=True),
    Column("t", Float, index=True), Column("idx", Integer), Column("name", String, index=True),
    Column("value", Float), Column("old_value", Float), Column("original_value", Float),
    Column("sysid", Integer), Column("compid", Integer), Column("armed", Boolean), Column("kind", String))

forensic_cases = Table("forensic_cases", metadata,
    Column("case_id", String, primary_key=True), Column("incident_id", String, index=True),
    Column("session_id", String, index=True), Column("created_at", String), Column("status", String),
    Column("path", String), Column("manifest_sha256", String), Column("data", Text))

artifacts = Table("artifacts", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True), Column("case_id", String, index=True),
    Column("filename", String), Column("size", Integer), Column("sha256", String),
    Column("created_at", String), Column("source", String))

artifact_hashes = Table("artifact_hashes", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True), Column("case_id", String, index=True),
    Column("verified_at", String), Column("result", String), Column("data", Text))

system_events = Table("system_events", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True), Column("session_id", String, index=True),
    Column("t", Float, index=True), Column("type", String, index=True), Column("severity", String),
    Column("message", String), Column("data", Text))

audit_log = Table("audit_log", metadata,
    Column("seq", Integer, primary_key=True), Column("ts", String), Column("actor", String),
    Column("role", String), Column("action", String), Column("target", String), Column("detail", Text),
    Column("prev_hash", String), Column("hash", String))

imports = Table("imports", metadata,
    Column("import_id", String, primary_key=True), Column("filename", String), Column("sha256", String),
    Column("size", Integer), Column("format", String), Column("imported_at", String),
    Column("parser_version", String), Column("session_id", String), Column("status", String),
    Column("meta", Text))

TABLES = {t.name: t for t in metadata.sorted_tables}
UPSERT_KEYS = {
    "flights": ["session_id"], "incidents": ["incident_id"], "ids_events": ["alert_id"],
    "rules": ["rule_id"], "forensic_cases": ["case_id"], "imports": ["import_id"],
}


def dumps(obj: Any) -> str:
    return orjson.dumps(obj, default=str, option=orjson.OPT_NON_STR_KEYS | orjson.OPT_SERIALIZE_NUMPY).decode()


def loads(s: Optional[str]) -> Any:
    if s is None or s == "":
        return None
    return orjson.loads(s)


def make_engine(url: str, root: Path) -> Engine:
    if url.startswith("sqlite:///") and not url.startswith("sqlite:////"):
        rel = url[len("sqlite:///"):]
        p = Path(rel)
        if not p.is_absolute():
            p = root / p
        p.parent.mkdir(parents=True, exist_ok=True)
        url = f"sqlite:///{p}"
    eng = create_engine(url, future=True, connect_args={"check_same_thread": False, "timeout": 30} if url.startswith("sqlite") else {})
    if url.startswith("sqlite"):
        @event.listens_for(eng, "connect")
        def _pragmas(dbapi_conn, _):
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.close()
    metadata.create_all(eng)
    return eng


class DBWriter:
    """Background batched writer with bounded queue + emergency queue."""

    def __init__(self, engine: Engine, errors, batch_interval: float = 0.5, max_queue: int = 50000,
                 emergency_max: int = 20000):
        self.engine = engine
        self.errors = errors
        self.batch_interval = batch_interval
        self.q: queue.Queue = queue.Queue(maxsize=max_queue)
        self.emergency: deque = deque(maxlen=emergency_max)
        self.dropped = 0
        self.emergency_dropped = 0
        self.written = 0
        self.failures = 0
        self.status = "healthy"
        self.last_error: Optional[str] = None
        self.last_flush_ms = 0.0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="db-writer", daemon=True)
        self.is_sqlite = engine.dialect.name == "sqlite"

    def start(self) -> None:
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        self._thread.join(timeout)
        self._flush_once()

    def insert(self, table: str, row: dict, critical: bool = False) -> None:
        self._put(("insert", table, row), critical)

    def upsert(self, table: str, row: dict) -> None:
        self._put(("upsert", table, row), True)

    def _put(self, item, critical: bool) -> None:
        try:
            self.q.put_nowait(item)
        except queue.Full:
            if critical:
                if len(self.emergency) == self.emergency.maxlen:
                    self.emergency_dropped += 1
                self.emergency.append(item)
            else:
                self.dropped += 1

    def qsize(self) -> int:
        return self.q.qsize() + len(self.emergency)

    def _run(self) -> None:
        while not self._stop.is_set():
            time.sleep(self.batch_interval)
            self._flush_once()

    def _drain(self) -> list:
        items = []
        while self.emergency:
            items.append(self.emergency.popleft())
        try:
            while len(items) < 20000:
                items.append(self.q.get_nowait())
        except queue.Empty:
            pass
        return items

    def _flush_once(self) -> None:
        items = self._drain()
        if not items:
            return
        t0 = time.perf_counter()
        inserts: dict[str, list] = {}
        upserts: dict[str, dict] = {}
        for op, table, row in items:
            if op == "insert":
                inserts.setdefault(table, []).append(row)
            else:
                key = tuple(row.get(k) for k in UPSERT_KEYS.get(table, []))
                upserts.setdefault(table, {})[key] = row  # last write wins inside a batch
        try:
            with self.engine.begin() as conn:
                for table, rows in inserts.items():
                    t = TABLES[table]
                    if self.is_sqlite and table == "mavlink_messages":
                        from sqlalchemy.dialects.sqlite import insert as sqlite_insert
                        conn.execute(sqlite_insert(t).prefix_with("OR IGNORE"), rows)
                    else:
                        conn.execute(t.insert(), rows)
                for table, rowmap in upserts.items():
                    self._upsert(conn, TABLES[table], list(rowmap.values()), UPSERT_KEYS[table])
            self.written += len(items)
            if self.status != "healthy":
                self.status = "healthy"
            self.last_flush_ms = (time.perf_counter() - t0) * 1000
        except Exception as exc:  # DB outage: keep evidence rows in bounded emergency queue
            self.failures += 1
            self.status = "degraded"
            self.last_error = str(exc)[:300]
            self.errors.record("DATABASE", "WRITE_FAILED", self.last_error, recoverable=True, exc=exc)
            for it in items:
                if it[1] in ("mavlink_messages", "telemetry", "attitude_samples", "gps_points", "battery_samples"):
                    continue  # high-rate rows are reproducible from the raw capture; keep critical ones
                if len(self.emergency) == self.emergency.maxlen:
                    self.emergency_dropped += 1
                self.emergency.append(it)

    def _upsert(self, conn, table: Table, rows: list[dict], keys: list[str]) -> None:
        if self.is_sqlite:
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert
            for r in rows:
                stmt = sqlite_insert(table).values(**r)
                stmt = stmt.on_conflict_do_update(index_elements=keys, set_={k: v for k, v in r.items() if k not in keys})
                conn.execute(stmt)
        else:
            from sqlalchemy.dialects.postgresql import insert as pg_insert
            for r in rows:
                stmt = pg_insert(table).values(**r)
                stmt = stmt.on_conflict_do_update(index_elements=keys, set_={k: v for k, v in r.items() if k not in keys})
                conn.execute(stmt)

    def stats(self) -> dict:
        return {"status": self.status, "queued": self.q.qsize(), "emergency_queued": len(self.emergency),
                "dropped_noncritical": self.dropped, "emergency_dropped": self.emergency_dropped,
                "written": self.written, "failures": self.failures, "last_error": self.last_error,
                "last_flush_ms": round(self.last_flush_ms, 2)}


def query(engine: Engine, stmt) -> list[dict]:
    with engine.connect() as conn:
        return [dict(r._mapping) for r in conn.execute(stmt)]


def parse_json_cols(rows: Iterable[dict], cols=("data", "fields", "meta", "detail", "params", "state", "ref", "result")) -> list[dict]:
    out = []
    for r in rows:
        r = dict(r)
        for c in cols:
            if c in r and isinstance(r[c], str):
                try:
                    r[c] = loads(r[c])
                except Exception:
                    pass
        out.append(r)
    return out
