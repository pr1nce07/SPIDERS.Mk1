"""Versioned rule storage. Every saved version is immutable (definition + SHA-256);
forensic cases reference (rule_id, version) so old cases never see a mutated rule."""
from __future__ import annotations

import copy
import hashlib
import re
from typing import Optional

from sqlalchemy import select, update

from ..models.events import utc_now_iso
from ..storage.db import dumps, loads, rule_versions, rules
from .builtin_rules import BUILTIN_RULES
from .rules import validate_rule

DEFAULTS = {"description": "", "enabled": True, "severity": "MEDIUM", "persistence_s": 0, "cooldown_s": 10,
            "evidence_window_s": 30, "correlation_window_s": 10, "min_evidence": 0, "domain": "RULE",
            "confidence": {"method": "weighted_evidence", "threshold": 0.0}, "tests": []}


def _definition(rule: dict) -> dict:
    d = copy.deepcopy(DEFAULTS)
    d.update({k: v for k, v in rule.items() if k not in ("version", "status", "created", "modified", "author", "sha256", "published_version", "validation")})
    return d


def _sha(defn: dict) -> str:
    return hashlib.sha256(dumps(defn).encode()).hexdigest()


class RuleStore:
    def __init__(self, engine, registry, detector_ids_fn):
        self.engine = engine
        self.registry = registry
        self.detector_ids_fn = detector_ids_fn

    def validate(self, rule: dict) -> dict:
        return validate_rule(_definition(rule), self.registry, self.detector_ids_fn())

    def seed(self) -> None:
        for r in BUILTIN_RULES:
            if self.get(r["rule_id"]) is None:
                v = self.save_draft(r, author="system")
                self.publish(r["rule_id"], v["version"], author="system")

    def list(self) -> list[dict]:
        with self.engine.connect() as c:
            rows = c.execute(select(rules).order_by(rules.c.rule_id)).all()
        out = []
        for r in rows:
            d = dict(r._mapping)
            data = loads(d.pop("data")) or {}
            data.update({"status": d["status"], "version": d["current_version"], "published_version": d["published_version"],
                         "enabled": bool(d["enabled"]), "modified": d["modified"]})
            out.append(data)
        return out

    def get(self, rule_id: str, version: Optional[int] = None) -> Optional[dict]:
        with self.engine.connect() as c:
            head = c.execute(select(rules).where(rules.c.rule_id == rule_id)).first()
            if head is None:
                return None
            v = version or head.current_version
            row = c.execute(select(rule_versions).where(rule_versions.c.rule_id == rule_id, rule_versions.c.version == v)).first()
        if row is None:
            return None
        d = loads(row.data)
        d.update({"version": row.version, "status": row.status, "created": row.created, "author": row.author, "sha256": row.sha256,
                  "published_version": head.published_version, "enabled": bool(head.enabled), "modified": head.modified})
        return d

    def history(self, rule_id: str) -> list[dict]:
        with self.engine.connect() as c:
            rows = c.execute(select(rule_versions).where(rule_versions.c.rule_id == rule_id).order_by(rule_versions.c.version.desc())).all()
        return [{"version": r.version, "created": r.created, "author": r.author, "status": r.status, "sha256": r.sha256,
                 "name": (loads(r.data) or {}).get("name")} for r in rows]

    def save_draft(self, rule: dict, author: str = "operator") -> dict:
        defn = _definition(rule)
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", str(defn.get("rule_id", ""))):
            raise ValueError("rule_id must be 1–64 chars [A-Za-z0-9-_]")
        val = validate_rule(defn, self.registry, self.detector_ids_fn())
        now = utc_now_iso()
        with self.engine.begin() as c:
            head = c.execute(select(rules).where(rules.c.rule_id == defn["rule_id"])).first()
            last = c.execute(select(rule_versions.c.version).where(rule_versions.c.rule_id == defn["rule_id"])
                             .order_by(rule_versions.c.version.desc()).limit(1)).scalar()
            version = (last or 0) + 1
            defn_hash = _sha(defn)
            c.execute(rule_versions.insert().values(rule_id=defn["rule_id"], version=version, created=now, author=author,
                                                    status="DRAFT", sha256=defn_hash, data=dumps(defn)))
            vals = dict(name=defn.get("name"), current_version=version, modified=now, data=dumps(defn),
                        status="DRAFT" if head is None or head.published_version is None else "PUBLISHED_WITH_DRAFT")
            if head is None:
                c.execute(rules.insert().values(rule_id=defn["rule_id"], published_version=None, enabled=bool(defn.get("enabled", True)), **vals))
            else:
                c.execute(update(rules).where(rules.c.rule_id == defn["rule_id"]).values(**vals))
        return {"rule_id": defn["rule_id"], "version": version, "sha256": defn_hash, "validation": val}

    def publish(self, rule_id: str, version: Optional[int] = None, author: str = "operator") -> dict:
        r = self.get(rule_id, version)
        if r is None:
            raise KeyError(rule_id)
        val = validate_rule(_definition(r), self.registry, self.detector_ids_fn())
        if not val["valid"]:
            return {"published": False, "validation": val}
        now = utc_now_iso()
        with self.engine.begin() as c:
            c.execute(update(rule_versions).where(rule_versions.c.rule_id == rule_id, rule_versions.c.status == "PUBLISHED")
                      .values(status="SUPERSEDED"))
            c.execute(update(rule_versions).where(rule_versions.c.rule_id == rule_id, rule_versions.c.version == r["version"])
                      .values(status="PUBLISHED"))
            c.execute(update(rules).where(rules.c.rule_id == rule_id).values(published_version=r["version"], status="PUBLISHED",
                                                                             enabled=True, modified=now))
        return {"published": True, "rule_id": rule_id, "version": r["version"], "validation": val}

    def set_enabled(self, rule_id: str, enabled: bool) -> bool:
        with self.engine.begin() as c:
            res = c.execute(update(rules).where(rules.c.rule_id == rule_id).values(enabled=enabled, modified=utc_now_iso(),
                                                                                  status="PUBLISHED" if enabled else "DISABLED"))
        return res.rowcount > 0

    def clone(self, rule_id: str, new_id: str, author: str = "operator") -> dict:
        r = self.get(rule_id)
        if r is None:
            raise KeyError(rule_id)
        if self.get(new_id) is not None:
            raise ValueError(f"{new_id} already exists")
        d = _definition(r)
        d["rule_id"] = new_id
        d["name"] = f"{d.get('name')} (copy)"
        return self.save_draft(d, author=author)

    def published(self) -> list[dict]:
        out = []
        with self.engine.connect() as c:
            heads = c.execute(select(rules).where(rules.c.enabled == True, rules.c.published_version.is_not(None))).all()  # noqa: E712
        for h in heads:
            r = self.get(h.rule_id, h.published_version)
            if r:
                out.append(r)
        return out
