#!/usr/bin/env python3
"""Generate (or verify) the signed release manifest + SBOM (GAP-14, Sprint 0).

    python scripts/make_release_manifest.py --version 1.1.0 --apj arducopter.apj --elf arducopter.elf \
        --source-archive ardupilot-dbe79216-patched.tar.gz --patch "AP_IDS: add PIDS DataFlash records"
    python scripts/make_release_manifest.py --verify

Writes release/manifest.json, manifest.sig.json, release_ed25519.pub.pem, sbom.cdx.json and hashes.sha256.
Dependency vulnerability scanning is not run here (it needs network access): run
`pip-audit -r backend/requirements.txt` and `npm audit --prefix frontend` and attach the output.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.config import Config  # noqa: E402
from app.release import build_manifest, rebuild_romfs_zip, verify_release, write_release  # noqa: E402
from app.security.keys import KeyStore  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", default="unversioned")
    ap.add_argument("--apj", type=Path)
    ap.add_argument("--elf", type=Path)
    ap.add_argument("--source-archive", type=Path)
    ap.add_argument("--patch", action="append", default=[], help="describe each local ArduPilot patch (repeatable)")
    ap.add_argument("--out", type=Path, default=ROOT / "release")
    ap.add_argument("--rebuild-romfs", action="store_true", help="repackage firmware/scripts into firmware/ROMFS_custom_fixed.zip first")
    ap.add_argument("--verify", action="store_true", help="verify an existing release/ against the current files")
    a = ap.parse_args()
    keys = KeyStore(Config.load().resolve_path("security.keystore_dir", "data/keys"))
    if a.verify:
        res = verify_release(ROOT, a.out, keys)
        print(json.dumps(res, indent=2))
        return 0 if res["status"] == "VALID" else 1
    if a.rebuild_romfs:
        print(f"rebuilt {rebuild_romfs_zip(ROOT)}", file=sys.stderr)
    m = build_manifest(ROOT, a.version, a.apj, a.elf, a.source_archive, a.patch)
    sig = write_release(ROOT, a.out, m, keys)
    print(f"wrote {a.out}/manifest.json (signed by release key {sig['key_id']}); release_ready={m['release_ready']}", file=sys.stderr)
    for f in m["findings"]:
        print(f"  [{f['severity']}] {f['id']}: {f['text']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
