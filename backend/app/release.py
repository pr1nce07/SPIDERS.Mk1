"""Release manifest, SBOM and provenance checks (GAP-14, Sprint 0).

Generated from the files actually present, never copied from an old report:

* SHA-256 of every GCS source file, the built frontend, configs, Lua scripts,
  the ROMFS package and (when supplied) the firmware APJ/ELF;
* firmware identity from configs/capabilities.json, the scripts embedded in the
  ROMFS zip compared byte-for-byte with firmware/scripts (drift = finding);
* a CycloneDX 1.5 SBOM from the installed Python packages and package-lock.json;
* a detached Ed25519 signature with the GCS "release" key.

Findings are listed, not hidden: a release without firmware images or with
script drift still produces a manifest, marked `release_ready: false`.
"""
from __future__ import annotations

import hashlib
import json
import platform
import re
import subprocess
import zipfile
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from typing import Optional

from .security.keys import KeyStore, sign_json, verify_json

GCS_GLOBS = ["backend/app/**/*.py", "backend/app/**/*.json", "backend/requirements.txt", "backend/run.py",
             "frontend/dist/**/*", "frontend/package.json", "frontend/package-lock.json", "configs/*.yaml", "configs/*.json",
             "firmware/scripts/**/*.lua", "firmware/ROMFS_custom_fixed.zip", "scripts/*.py", "scripts/*.sh", "scripts/*.ps1"]
EXCLUDE = re.compile(r"(__pycache__|\.pyc$|configs/local\.yaml$)")


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_files(root: Path) -> dict[str, str]:
    out = {}
    for g in GCS_GLOBS:
        for p in sorted(root.glob(g)):
            rel = p.relative_to(root).as_posix()
            if p.is_file() and not EXCLUDE.search(rel):
                out[rel] = sha256(p)
    return dict(sorted(out.items()))


def romfs_drift(root: Path) -> dict:
    """Compare the scripts packaged in ROMFS_custom_fixed.zip with firmware/scripts."""
    z = root / "firmware" / "ROMFS_custom_fixed.zip"
    scripts = root / "firmware" / "scripts"
    if not z.exists():
        return {"status": "NO_ROMFS_PACKAGE"}
    packaged = {}
    with zipfile.ZipFile(z) as zf:
        for i in zf.infolist():
            if i.filename.endswith(".lua"):
                rel = i.filename.split("scripts/", 1)[-1]
                packaged[rel] = hashlib.sha256(zf.read(i)).hexdigest()
    source = {p.relative_to(scripts).as_posix(): sha256(p) for p in scripts.rglob("*.lua")}
    differ = sorted(k for k in set(packaged) & set(source) if packaged[k] != source[k])
    only_pkg = sorted(set(packaged) - set(source))
    only_src = sorted(set(source) - set(packaged))
    return {"status": "MATCH" if not (differ or only_pkg or only_src) else "DRIFT", "different": differ,
            "only_in_package": only_pkg, "only_in_source": only_src, "packaged": packaged}


def rebuild_romfs_zip(root: Path) -> Path:
    """Repackage firmware/scripts as ROMFS_custom/scripts/** (deterministic order and timestamps)."""
    z = root / "firmware" / "ROMFS_custom_fixed.zip"
    scripts = root / "firmware" / "scripts"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        for d in ("ROMFS_custom/", "ROMFS_custom/scripts/", "ROMFS_custom/scripts/modules/"):
            zf.writestr(zipfile.ZipInfo(d, (2026, 1, 1, 0, 0, 0)), b"")
        for p in sorted(scripts.rglob("*.lua")):
            info = zipfile.ZipInfo(f"ROMFS_custom/scripts/{p.relative_to(scripts).as_posix()}", (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, p.read_bytes())
    return z


def _git(root: Path) -> Optional[dict]:
    try:
        rev = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=10)
        if rev.returncode != 0:
            return None
        dirty = subprocess.run(["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True, timeout=10).stdout.strip()
        return {"commit": rev.stdout.strip(), "dirty": bool(dirty)}
    except (OSError, subprocess.SubprocessError):
        return None


def sbom(root: Path) -> dict:
    """CycloneDX 1.5 JSON: Python packages actually installed for requirements.txt, plus npm lockfile packages."""
    comps = []
    req = root / "backend" / "requirements.txt"
    for line in req.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Za-z0-9_.\-]+)", line.strip())
        if not m or line.strip().startswith("#"):
            continue
        name = m.group(1)
        try:
            ver = metadata.version(name)
            lic = (metadata.metadata(name).get("License-Expression") or metadata.metadata(name).get("License") or "")[:120]
        except metadata.PackageNotFoundError:
            ver, lic = None, ""
        comps.append({"type": "library", "name": name, "version": ver or "NOT_INSTALLED",
                      "purl": f"pkg:pypi/{name.lower()}@{ver}" if ver else f"pkg:pypi/{name.lower()}",
                      "licenses": [{"license": {"name": lic}}] if lic else [], "properties": [{"name": "requirement", "value": line.strip()}]})
    lock = root / "frontend" / "package-lock.json"
    if lock.exists():
        pk = json.loads(lock.read_text(encoding="utf-8")).get("packages", {})
        for path, info in sorted(pk.items()):
            if not path or not info.get("version"):
                continue
            name = path.split("node_modules/")[-1]
            comps.append({"type": "library", "name": name, "version": info["version"], "purl": f"pkg:npm/{name}@{info['version']}",
                          "hashes": [{"alg": "SHA-512", "content": info["integrity"].split("-", 1)[1]}] if str(info.get("integrity", "")).startswith("sha512-") else [],
                          "scope": "optional" if info.get("dev") else "required"})
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(), "component": {"type": "application", "name": "SPIDERS.Mk1 GCS"},
                         "tools": [{"name": "spiders-release", "version": "1"}]},
            "components": comps}


def build_manifest(root: Path, version: str, apj: Optional[Path] = None, elf: Optional[Path] = None,
                   source_archive: Optional[Path] = None, patches: Optional[list[str]] = None) -> dict:
    caps = {}
    cp = root / "configs" / "capabilities.json"
    if cp.exists():
        caps = json.loads(cp.read_text(encoding="utf-8"))
    files = collect_files(root)
    drift = romfs_drift(root)
    fw = {"identity_from_capabilities": caps.get("vehicle"), "capabilities_generated_at": caps.get("generated_at"),
          "local_patches": patches or [], "images": {}}
    for label, p in (("apj", apj), ("elf", elf), ("source_archive", source_archive)):
        if p:
            fw["images"][label] = {"file": Path(p).name, "sha256": sha256(Path(p)), "bytes": Path(p).stat().st_size}
    findings = []
    if "apj" not in fw["images"] or "elf" not in fw["images"]:
        findings.append({"id": "REL-FW-IMAGES", "severity": "BLOCKER",
                         "text": "Firmware APJ/ELF not supplied: this manifest cannot identify the tested firmware binary."})
    if "source_archive" not in fw["images"]:
        findings.append({"id": "REL-FW-SOURCE", "severity": "BLOCKER",
                         "text": "ArduPilot source archive/commit with local patches not supplied (AP_IDS source is not in this repository)."})
    if drift["status"] == "DRIFT":
        findings.append({"id": "REL-ROMFS-DRIFT", "severity": "BLOCKER",
                         "text": f"ROMFS package scripts differ from firmware/scripts: {drift['different'] + drift['only_in_package'] + drift['only_in_source']}. "
                                 "Rebuild the package (--rebuild-romfs) and the firmware image that embeds it."})
    for d in caps.get("discrepancies", []) or []:
        findings.append({"id": f"CAP-{d.get('id', 'DISC')}", "severity": "INFO", "text": str(d.get("summary") or d)[:300]})
    findings.append({"id": "REL-DOC-BASELINE", "severity": "WARNING",
                     "text": "firmware/BUILD_AND_LINKING.md and configs/capabilities.json describe the 2-method `ids` binding build; "
                             "the external technical reference describes build_v3 (26 methods). Treat this manifest's hashes as authoritative."})
    git = _git(root)
    if git is None:
        findings.append({"id": "REL-NO-VCS", "severity": "WARNING",
                         "text": "Project is not a git checkout: source cannot be tied to a reviewed commit. Put it under version control."})
    elif git["dirty"]:
        findings.append({"id": "REL-DIRTY", "severity": "BLOCKER", "text": "Working tree has uncommitted changes."})
    blockers = [f for f in findings if f["severity"] == "BLOCKER"]
    return {"schema": 1, "release_version": version, "generated_at": datetime.now(timezone.utc).isoformat(),
            "generator": {"python": platform.python_version(), "platform": platform.platform()},
            "source_control": git, "firmware": fw, "romfs_scripts": {k: v for k, v in drift.items() if k != "packaged"},
            "gcs_files": files, "gcs_tree_sha256": hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest(),
            "findings": findings, "release_ready": not blockers,
            "statement": "Test reports must cite gcs_tree_sha256 and the firmware image SHA-256 values above."}


def write_release(root: Path, out: Path, manifest: dict, keys: KeyStore) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    (out / "manifest.json").write_bytes(json.dumps(manifest, indent=2).encode("utf-8"))
    sig = sign_json(keys.signing_key("release"), manifest)
    (out / "manifest.sig.json").write_bytes(json.dumps(sig, indent=2).encode("utf-8"))
    (out / "release_ed25519.pub.pem").write_text(keys.public_key_pem("release"), encoding="utf-8")
    (out / "sbom.cdx.json").write_bytes(json.dumps(sbom(root), indent=2).encode("utf-8"))
    lines = [f"{h}  {rel}\n" for rel, h in manifest["gcs_files"].items()]
    lines += [f"{v['sha256']}  firmware:{v['file']}\n" for v in manifest["firmware"]["images"].values()]
    (out / "hashes.sha256").write_bytes("".join(lines).encode("utf-8"))
    return sig


def verify_release(root: Path, out: Path, keys: KeyStore) -> dict:
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    sig = json.loads((out / "manifest.sig.json").read_text(encoding="utf-8"))
    status = verify_json(manifest, sig, keys.trusted_public_keys("release"))
    current = collect_files(root)
    changed = sorted(k for k in manifest["gcs_files"] if current.get(k) != manifest["gcs_files"][k])
    added = sorted(set(current) - set(manifest["gcs_files"]))
    return {"signature": status, "changed_or_missing": changed, "added": added,
            "status": "VALID" if status == "VALID" and not changed and not added else "MISMATCH"}
