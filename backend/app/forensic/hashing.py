"""SHA-256 hashing and case verification (spec §38, §68).

Hashes detect modification; they do not on their own establish a legal chain of
custody (that also needs custody records, access control and procedure).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

CHUNK = 1 << 20
HASH_FILE = "hashes.sha256"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def write_hash_file(case_dir: Path) -> dict[str, str]:
    entries = {}
    for p in sorted(case_dir.rglob("*")):
        if p.is_file() and p.name != HASH_FILE:
            entries[p.relative_to(case_dir).as_posix()] = sha256_file(p)
    with open(case_dir / HASH_FILE, "w", encoding="utf-8") as fh:
        for rel, h in entries.items():
            fh.write(f"{h}  {rel}\n")
    return entries


def read_hash_file(case_dir: Path) -> dict[str, str] | None:
    p = case_dir / HASH_FILE
    if not p.exists():
        return None
    out = {}
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            h, rel = line.split("  ", 1)
            if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
                return None
            out[rel.strip()] = h
    except Exception:
        return None
    return out


def verify_case(case_dir: Path) -> dict:
    listed = read_hash_file(case_dir)
    if not case_dir.exists():
        return {"status": "MISSING", "artifacts": [], "message": "case directory not found"}
    if listed is None:
        return {"status": "UNVERIFIABLE", "artifacts": [], "message": "hashes.sha256 missing or unparsable"}
    results = []
    for rel, expected in listed.items():
        p = case_dir / rel
        if ".." in Path(rel).parts:
            results.append({"file": rel, "status": "UNVERIFIABLE", "expected": expected, "actual": None})
            continue
        if not p.exists():
            results.append({"file": rel, "status": "MISSING", "expected": expected, "actual": None})
            continue
        actual = sha256_file(p)
        results.append({"file": rel, "status": "VALID" if actual == expected else "MODIFIED", "expected": expected, "actual": actual})
    on_disk = {p.relative_to(case_dir).as_posix() for p in case_dir.rglob("*") if p.is_file() and p.name != HASH_FILE}
    for rel in sorted(on_disk - set(listed)):
        results.append({"file": rel, "status": "MODIFIED", "expected": None, "actual": sha256_file(case_dir / rel),
                        "note": "file not listed in hashes.sha256 (added after sealing)"})
    # manifest cross-check
    mf = case_dir / "manifest.json"
    manifest_ok = None
    if mf.exists():
        try:
            m = json.loads(mf.read_text())
            mismatch = [a["filename"] for a in m.get("artifacts", []) if listed.get(a["filename"]) not in (None, a.get("sha256"))]
            manifest_ok = not mismatch
            if mismatch:
                results.append({"file": "manifest.json", "status": "MODIFIED", "note": f"manifest hashes disagree for {mismatch}"})
        except Exception:
            manifest_ok = False
    statuses = {r["status"] for r in results}
    overall = "MODIFIED" if "MODIFIED" in statuses else "MISSING" if "MISSING" in statuses else \
        "UNVERIFIABLE" if "UNVERIFIABLE" in statuses else "VALID"
    return {"status": overall, "artifacts": results, "files_checked": len(results), "manifest_consistent": manifest_ok,
            "note": "SHA-256 detects modification; it does not by itself establish legal chain of custody."}
