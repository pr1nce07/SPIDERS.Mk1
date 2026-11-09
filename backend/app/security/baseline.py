"""Approved mission / parameter baselines (GAP-11).

The runtime detectors learn "normal" from whatever they first see, so a value
that was already malicious at startup becomes the reference. An approved
baseline fixes that: an engineer approves a signed manifest of the expected
parameter values and mission, and the BASELINE detector compares what the
vehicle reports against it. Detectors can never edit the manifest; only the
approval workflow (with operator identity, reason and previous digest) can.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .keys import KeyStore, sign_json, verify_json

SCHEMA = 1


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_mission(items: list) -> list[list]:
    """Mission items as (seq, command, frame, x, y, z, p1..p4) with stable rounding."""
    out = []
    for it in items:
        it = list(it)
        out.append([int(it[0]), int(it[1]), int(it[2]), int(it[3] or 0), int(it[4] or 0)] +
                   [round(float(v or 0), 3) for v in it[5:10]])
    return sorted(out, key=lambda r: r[0])


def mission_digest(items: list) -> str:
    return hashlib.sha256(json.dumps(canonical_mission(items), separators=(",", ":")).encode()).hexdigest()


def body_digest(body: dict) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def make_body(*, vehicle: dict, parameters: dict, mission_items: Optional[list], approved_by: str, reason: str,
              previous_digest: Optional[str], profile_version: str, tolerance_rel: float = 1e-4,
              tolerance_abs: float = 1e-6) -> dict:
    if not reason.strip():
        raise ValueError("an approval reason is required")
    if not parameters and mission_items is None:
        raise ValueError("a baseline needs parameters, a mission, or both")
    params = {}
    for k, v in parameters.items():
        name = str(k).strip()
        if not name or len(name) > 16:
            raise ValueError(f"invalid MAVLink parameter name: {k!r}")
        params[name] = float(v)
    mission = None
    if mission_items is not None:
        mission = {"count": len(mission_items), "digest": mission_digest(mission_items), "items": canonical_mission(mission_items)}
    return {"schema": SCHEMA, "profile_version": str(profile_version)[:40], "created_at": _now(),
            "vehicle": {k: vehicle.get(k) for k in ("sysid", "board", "firmware") if vehicle.get(k) is not None},
            "parameters": dict(sorted(params.items())), "mission": mission,
            "tolerance": {"relative": tolerance_rel, "absolute": tolerance_abs},
            "approval": {"approved_by": approved_by, "reason": reason[:500], "previous_digest": previous_digest}}


def verify_doc(doc: dict, trusted: dict, vehicle: Optional[dict] = None) -> dict:
    """VALID | INVALID | UNTRUSTED_KEY | WRONG_VEHICLE | MALFORMED."""
    try:
        body, sig = doc["body"], doc["signature"]
    except (KeyError, TypeError):
        return {"status": "MALFORMED"}
    v = verify_json(body, sig, trusted)
    out = {"key_id": sig.get("key_id"), "digest": body_digest(body), "profile_version": body.get("profile_version")}
    if v != "VALID":
        return {"status": "INVALID" if v == "INVALID" else "UNTRUSTED_KEY", **out}
    if body.get("schema") != SCHEMA:
        return {"status": "MALFORMED", **out}
    for k, expected in (body.get("vehicle") or {}).items():
        actual = (vehicle or {}).get(k)
        if actual is not None and actual != expected:
            return {"status": "WRONG_VEHICLE", "field": k, "manifest": expected, "observed": actual, **out}
    return {"status": "VALID", **out}


class BaselineStore:
    """data/baselines/active.json plus an append-only history of approvals."""

    def __init__(self, root: Path, keys: KeyStore):
        self.root = Path(root)
        self.hist = self.root / "history"
        self.hist.mkdir(parents=True, exist_ok=True)
        self.keys = keys

    @classmethod
    def from_config(cls, config) -> "BaselineStore":
        keys = KeyStore(config.resolve_path("security.keystore_dir", "data/keys"))
        return cls(config.resolve_path("baseline.manifest_dir", "data/baselines"), keys)

    def active(self) -> Optional[dict]:
        p = self.root / "active.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

    def status(self, vehicle: Optional[dict] = None) -> dict:
        doc = self.active()
        if doc is None:
            return {"status": "NO_APPROVED_BASELINE"}
        res = verify_doc(doc, self.keys.trusted_public_keys("approval"), vehicle)
        b = doc.get("body", {})
        return {**res, "approval": b.get("approval"), "created_at": b.get("created_at"), "vehicle": b.get("vehicle"),
                "parameter_count": len(b.get("parameters") or {}), "mission_count": (b.get("mission") or {}).get("count")}

    def approve(self, *, vehicle: dict, parameters: dict, mission_items: Optional[list], approved_by: str, reason: str,
                profile_version: str) -> dict:
        prev = self.active()
        prev_digest = body_digest(prev["body"]) if prev else None
        body = make_body(vehicle=vehicle, parameters=parameters, mission_items=mission_items, approved_by=approved_by,
                         reason=reason, previous_digest=prev_digest, profile_version=profile_version)
        doc = {"body": body, "signature": sign_json(self.keys.signing_key("approval"), body)}
        data = json.dumps(doc, indent=2, ensure_ascii=False).encode("utf-8")
        digest = body_digest(body)
        (self.hist / f"{datetime.now(timezone.utc):%Y%m%dT%H%M%S}-{digest[:12]}.json").write_bytes(data)
        (self.root / "active.json").write_bytes(data)
        return {"digest": digest, "previous_digest": prev_digest, "doc": doc}
