"""GAP-14 / V-022: release manifest is generated from real files, signed, and detects drift."""
import json
import shutil
from pathlib import Path

from app.release import build_manifest, rebuild_romfs_zip, romfs_drift, sbom, verify_release, write_release
from app.security.keys import KeyStore

ROOT = Path(__file__).resolve().parents[2]


def _mini_repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    for d in ("firmware", "configs"):
        shutil.copytree(ROOT / d, r / d)
    (r / "backend" / "app").mkdir(parents=True)
    (r / "backend" / "app" / "x.py").write_text("print(1)\n")
    shutil.copy(ROOT / "backend" / "requirements.txt", r / "backend" / "requirements.txt")
    (r / "frontend").mkdir()
    shutil.copy(ROOT / "frontend" / "package-lock.json", r / "frontend" / "package-lock.json")
    return r


def test_manifest_flags_missing_firmware_and_romfs_drift_then_signs_and_verifies(tmp_path):
    r = _mini_repo(tmp_path)
    (r / "firmware" / "scripts" / "ids_gcs_bridge.lua").write_text("-- changed\nreturn function() end, 1000\n")
    m = build_manifest(r, "test")
    ids = {f["id"] for f in m["findings"]}
    assert {"REL-FW-IMAGES", "REL-ROMFS-DRIFT"} <= ids and m["release_ready"] is False
    assert "ids_gcs_bridge.lua" in m["romfs_scripts"]["different"]

    rebuild_romfs_zip(r)
    assert romfs_drift(r)["status"] == "MATCH"

    apj = tmp_path / "arducopter.apj"
    apj.write_bytes(b"fake image")
    m = build_manifest(r, "test", apj=apj, elf=apj)
    assert m["firmware"]["images"]["apj"]["bytes"] == 10
    keys = KeyStore(tmp_path / "keys")
    out = tmp_path / "release"
    write_release(r, out, m, keys)
    assert verify_release(r, out, keys)["status"] == "VALID"
    (r / "backend" / "app" / "x.py").write_text("print(2)\n")          # unreviewed change after release
    res = verify_release(r, out, keys)
    assert res["status"] == "MISMATCH" and res["changed_or_missing"] == ["backend/app/x.py"]
    forged = json.loads((out / "manifest.json").read_text())
    forged["release_ready"] = True
    (out / "manifest.json").write_text(json.dumps(forged))
    assert verify_release(r, out, keys)["signature"] == "INVALID"


def test_sbom_lists_python_and_npm_components():
    doc = sbom(ROOT)
    names = {c["name"] for c in doc["components"]}
    assert doc["bomFormat"] == "CycloneDX" and {"fastapi", "cryptography", "pymavlink"} <= names
    assert any(c["purl"].startswith("pkg:npm/") for c in doc["components"])
