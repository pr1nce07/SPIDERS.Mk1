"""Versioned, signed ML baseline profiles (GAP-16).

A profile is the training corpus for the ML_BASELINE detector, built from
labelled, verified benign flights of one airframe/configuration. It stores the
feature rows themselves (JSON, never a pickled model) and the model is refit
deterministically when loaded, so loading a profile cannot execute code.
Profiles are signed with the GCS "approval" key; an unsigned or tampered
profile is refused.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..security.keys import KeyStore, sign_json, verify_json

PROFILE_SCHEMA = 1


def rows_digest(rows: list) -> str:
    return hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()


def build_profile(rows: list[list[Optional[float]]], features: list[str], feature_version: str, *, profile_id: str,
                  airframe: str, corpus_version: str, flights: list[dict], approved_by: str, keys: KeyStore) -> dict:
    """flights: one entry per source flight, e.g. {"file": "...", "sha256": "...", "label": "benign", "notes": "..."}."""
    if not rows:
        raise ValueError("no feature rows")
    if any(f.get("label") != "benign" for f in flights):
        raise ValueError("profiles may only be built from flights labelled benign")
    body = {"schema": PROFILE_SCHEMA, "profile_id": profile_id, "airframe": airframe, "corpus_version": corpus_version,
            "feature_version": feature_version, "features": features, "rows": rows, "rows_sha256": rows_digest(rows),
            "flights": flights, "created_at": datetime.now(timezone.utc).isoformat(), "approved_by": approved_by}
    return {"body": body, "signature": sign_json(keys.signing_key("approval"), body)}


def save_profile(doc: dict, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json.dumps(doc, ensure_ascii=False).encode("utf-8"))
    return path


def load_profile(path: Path, trusted: dict) -> tuple[dict, str]:
    """Returns (body, status). status: VALID | MISSING | MALFORMED | INVALID | UNTRUSTED_KEY | DIGEST_MISMATCH."""
    if not path.exists():
        return {}, "MISSING"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        body, sig = doc["body"], doc["signature"]
    except Exception:
        return {}, "MALFORMED"
    v = verify_json(body, sig, trusted)
    if v != "VALID":
        return {}, "INVALID" if v == "INVALID" else v
    if rows_digest(body.get("rows", [])) != body.get("rows_sha256"):
        return {}, "DIGEST_MISMATCH"
    return body, "VALID"
