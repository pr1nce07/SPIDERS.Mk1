"""Append-only, hash-chained operator audit log (spec §79).

Each entry commits to the previous entry's hash, so silently rewriting or
deleting history is detectable by `verify()`. Entries are written synchronously
(low rate) to the database and mirrored to data/audit/audit.jsonl.
"""
from __future__ import annotations

import hashlib
import threading
from pathlib import Path

from sqlalchemy import func, select

from ..models.events import utc_now_iso
from ..storage.db import audit_log, dumps, loads

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, engine, audit_dir: Path):
        self.engine = engine
        self.path = audit_dir / "audit.jsonl"
        self._lock = threading.Lock()
        with engine.connect() as conn:
            row = conn.execute(select(audit_log.c.seq, audit_log.c.hash).order_by(audit_log.c.seq.desc()).limit(1)).first()
        self._seq = row.seq if row else 0
        self._prev = row.hash if row else GENESIS

    @staticmethod
    def _digest(entry: dict) -> str:
        body = {k: entry[k] for k in ("seq", "ts", "actor", "role", "action", "target", "detail", "prev_hash")}
        return hashlib.sha256(dumps(body).encode()).hexdigest()

    def record(self, action: str, target: str = "", detail: dict | None = None,
               actor: str = "local-operator", role: str = "admin") -> dict:
        with self._lock:
            with self.engine.connect() as conn:  # another process may have appended
                row = conn.execute(select(audit_log.c.seq, audit_log.c.hash).order_by(audit_log.c.seq.desc()).limit(1)).first()
            if row and row.seq > self._seq:
                self._seq, self._prev = row.seq, row.hash
            entry = {"seq": self._seq + 1, "ts": utc_now_iso(), "actor": actor, "role": role,
                     "action": action, "target": target, "detail": dumps(detail or {}), "prev_hash": self._prev}
            entry["hash"] = self._digest(entry)
            with self.engine.begin() as conn:
                conn.execute(audit_log.insert().values(**entry))
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(dumps(entry) + "\n")
            self._seq = entry["seq"]
            self._prev = entry["hash"]
        out = dict(entry)
        out["detail"] = detail or {}
        return out

    def list(self, limit: int = 500) -> list[dict]:
        with self.engine.connect() as conn:
            rows = conn.execute(select(audit_log).order_by(audit_log.c.seq.desc()).limit(limit)).all()
        out = []
        for r in rows:
            d = dict(r._mapping)
            d["detail"] = loads(d["detail"]) or {}
            out.append(d)
        return out

    def verify(self) -> dict:
        prev = GENESIS
        broken = []
        count = 0
        with self.engine.connect() as conn:
            for r in conn.execute(select(audit_log).order_by(audit_log.c.seq)):
                d = dict(r._mapping)
                count += 1
                if d["prev_hash"] != prev or self._digest(d) != d["hash"]:
                    broken.append(d["seq"])
                prev = d["hash"]
        return {"entries": count, "valid": not broken, "broken_at": broken[:20],
                "head": prev, "status": "VALID" if not broken else "MODIFIED"}
