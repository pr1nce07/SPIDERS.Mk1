"""Signed case manifests and signed audit checkpoints (GAP-12).

Hashes alone only detect edits by someone who cannot also rewrite the hash list.
These Ed25519 signatures bind a case's file hashes (and the audit chain head) to
a GCS key whose public half can be held by a third party. A signature proves
integrity relative to that key; it is not legal chain of custody on its own.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..forensic.hashing import HASH_FILE, SIGNATURE_FILE, read_hash_file, sha256_file
from .keys import Ed25519PrivateKey, sign_json, verify_json

CHECKPOINTS = "checkpoints.jsonl"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ------------------------------------------------------------------ cases
def sign_case(case_dir: Path, key: Ed25519PrivateKey, signer: str = "SPIDERS GCS") -> dict:
    listed = read_hash_file(case_dir) or {}
    manifest = case_dir / "manifest.json"
    m = json.loads(manifest.read_text(encoding="utf-8")) if manifest.exists() else {}
    body = {"schema": 1, "case_id": case_dir.name, "signed_at": _now(), "signed_by": signer,
            "revision": len(m.get("revisions", [])), "hashes": listed,
            "hashes_file_sha256": sha256_file(case_dir / HASH_FILE) if (case_dir / HASH_FILE).exists() else None,
            "statement": "Ed25519 signature over this case's SHA-256 file list. Detects modification relative to the "
                         "signing key; it does not by itself establish legal chain of custody."}
    doc = {"body": body, "signature": sign_json(key, body)}
    (case_dir / SIGNATURE_FILE).write_bytes(json.dumps(doc, indent=2, ensure_ascii=False).encode("utf-8"))
    return doc


def verify_case_signature(case_dir: Path, trusted: dict) -> dict:
    """UNSIGNED | INVALID_SIGNATURE | UNTRUSTED_KEY | CONTENT_CHANGED | VALID."""
    p = case_dir / SIGNATURE_FILE
    if not p.exists():
        return {"status": "UNSIGNED", "note": "case was sealed before evidence signing was enabled, or the signature file is missing"}
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
        body, sig = doc["body"], doc["signature"]
    except Exception:
        return {"status": "INVALID_SIGNATURE", "note": "signature file unreadable"}
    v = verify_json(body, sig, trusted)
    out = {"key_id": sig.get("key_id"), "signed_at": body.get("signed_at"), "revision": body.get("revision")}
    if v != "VALID":
        return {"status": "INVALID_SIGNATURE" if v == "INVALID" else "UNTRUSTED_KEY", **out}
    changed = []
    for rel, expected in body.get("hashes", {}).items():
        f = case_dir / rel
        if ".." in Path(rel).parts or not f.is_file() or sha256_file(f) != expected:
            changed.append(rel)
    current = read_hash_file(case_dir) or {}
    added = sorted(set(current) - set(body.get("hashes", {})))
    if changed or added:
        return {"status": "CONTENT_CHANGED", "changed_or_missing": changed, "added_after_signing": added, **out}
    return {"status": "VALID", **out}


# ------------------------------------------------------------------ audit checkpoints
def write_checkpoint(audit, key: Ed25519PrivateKey, audit_dir: Path, mirror_dir: Optional[Path] = None,
                     actor: str = "SPIDERS GCS") -> dict:
    chain = audit.verify()
    body = {"schema": 1, "ts": _now(), "entries": chain["entries"], "head_hash": chain["head"],
            "chain_status": chain["status"], "signed_by": actor}
    line = json.dumps({"body": body, "signature": sign_json(key, body)}, ensure_ascii=False) + "\n"
    targets = [audit_dir / CHECKPOINTS] + ([Path(mirror_dir) / CHECKPOINTS] if mirror_dir else [])
    written = []
    for t in targets:
        t.parent.mkdir(parents=True, exist_ok=True)
        with open(t, "ab") as fh:
            fh.write(line.encode("utf-8"))
        written.append(str(t))
    return {**body, "key_id": json.loads(line)["signature"]["key_id"], "written_to": written}


def verify_checkpoints(audit, trusted: dict, path: Path) -> dict:
    """Each signed checkpoint must verify AND match the live chain hash at that entry."""
    if not path.exists():
        return {"status": "NO_CHECKPOINTS", "checkpoints": 0, "problems": []}
    problems, n = [], 0
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        n += 1
        try:
            doc = json.loads(line)
            body, sig = doc["body"], doc["signature"]
        except Exception:
            problems.append({"line": i, "problem": "unreadable"})
            continue
        v = verify_json(body, sig, trusted)
        if v != "VALID":
            problems.append({"line": i, "problem": v})
            continue
        live = audit.hash_at(body["entries"]) if body["entries"] else None
        if body["entries"] and live != body["head_hash"]:
            problems.append({"line": i, "problem": "AUDIT_CHAIN_REWRITTEN" if live else "AUDIT_ENTRIES_MISSING",
                             "entries": body["entries"], "signed_head": body["head_hash"], "live_hash": live})
    return {"status": "VALID" if not problems else "PROBLEMS", "checkpoints": n, "problems": problems[:50], "file": str(path)}
