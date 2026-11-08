#!/usr/bin/env python3
"""Source-of-truth discovery (spec §7): build configs/capabilities.json from the
actual supplied artifacts. Every capability is backed by an `evidence` string;
nothing is set true without proof.

Usage:
  python scripts/discover_firmware.py --build-zip <build.zip> --romfs-zip <ROMFS_custom.zip> \
      [--objdump arm-none-eabi-objdump] [--out configs/capabilities.json]
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def strings(data: bytes, min_len: int = 4) -> list[str]:
    return [m.decode("ascii", "ignore") for m in re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)]


def safe_read(z: zipfile.ZipFile, name: str) -> bytes | None:
    try:
        return z.read(name)
    except KeyError:
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-zip", required=True)
    ap.add_argument("--romfs-zip", required=True)
    ap.add_argument("--objdump", default=shutil.which("arm-none-eabi-objdump"))
    ap.add_argument("--out", default=str(ROOT / "configs" / "capabilities.json"))
    a = ap.parse_args()

    findings: list[dict] = []
    discrepancies: list[dict] = []

    def fact(key, value, evidence):
        findings.append({"key": key, "value": value, "evidence": evidence})
        return value

    bz = zipfile.ZipFile(a.build_zip)
    names = bz.namelist()
    ver_h = (safe_read(bz, "build/Pixhawk6C/ap_version.h") or b"").decode(errors="ignore")
    git = re.search(r'GIT_VERSION "([0-9a-f]+)"', ver_h)
    git_ext = re.search(r'GIT_VERSION_EXTENDED "([0-9a-f]+)"', ver_h)
    chib = re.search(r'CHIBIOS_GIT_VERSION "([0-9a-f]+)"', ver_h)
    cache = (safe_read(bz, "build/c4che/Pixhawk6C_cache.py") or b"").decode(errors="ignore")
    board = re.search(r"^BOARD = '([^']+)'", cache, re.M)
    board_id = re.search(r"^APJ_BOARD_ID = '([^']+)'", cache, re.M)
    flash = re.search(r"^BOARD_FLASH_SIZE = (\d+)", cache, re.M)

    elf = safe_read(bz, "build/Pixhawk6C/bin/arducopter") or b""
    apj = safe_read(bz, "build/Pixhawk6C/bin/arducopter.apj")
    fw_bin = safe_read(bz, "build/Pixhawk6C/bin/arducopter.bin") or b""
    elf_strings = set(strings(elf, 3))
    fw_version = next((s for s in strings(fw_bin) if re.match(r"^ArduCopter V\d+\.\d+\.\d+ \(", s)), None)

    fact("firmware.version", fw_version, "string literal in build/Pixhawk6C/bin/arducopter.bin")
    fact("firmware.git_commit", git.group(1) if git else None, "build/Pixhawk6C/ap_version.h GIT_VERSION")
    fact("firmware.git_commit_extended", git_ext.group(1) if git_ext else None, "ap_version.h GIT_VERSION_EXTENDED")
    fact("firmware.chibios_commit", chib.group(1) if chib else None, "ap_version.h CHIBIOS_GIT_VERSION")
    fact("board.target", board.group(1) if board else None, "build/c4che/Pixhawk6C_cache.py BOARD")
    fact("board.apj_board_id", board_id.group(1) if board_id else None, "Pixhawk6C_cache.py APJ_BOARD_ID")
    fact("board.flash_kb", int(flash.group(1)) if flash else None, "Pixhawk6C_cache.py BOARD_FLASH_SIZE")

    ap_ids_objs = sorted(Path(n).name for n in names if "/libraries/AP_IDS/" in n and n.endswith(".o"))
    fact("ap_ids.compiled_objects", ap_ids_objs, "object files under build/Pixhawk6C/libraries/AP_IDS/")

    # Lua binding methods for the `ids` singleton: generated binding functions AP_IDS_<method>
    bind = sorted({m.group(1) for s in elf_strings for m in [re.match(r"_ZL\d+AP_IDS_([a-z_]+)P9lua_State", s)] if m and m.group(1) not in ("index",)})
    fact("ap_ids.lua_binding_methods", bind, "ELF symbols _ZL..AP_IDS_<method>P9lua_State (generated scripting bindings)")

    # Disassembly-level facts (optional, needs objdump)
    dis_facts = {}
    if a.objdump and elf:
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(elf)
            elf_path = tf.name
        try:
            out = subprocess.run([a.objdump, "-d", "-C", "--no-show-raw-insn", elf_path], capture_output=True, text=True, timeout=600).stdout
            fn = re.search(r"<AP_IDSGCS::report_confirmed[^>]*>:\n((?:.*\n){1,6})", out)
            if fn:
                body = fn.group(1)
                dis_facts["AP_IDSGCS.report_confirmed_stub"] = ("movs\tr0, #0" in body and "bx\tlr" in body)
            upd = re.search(r"<AP_IDS::update\(\)>:\n((?:.+\n)+)", out)
            if upd:
                called = sorted(set(re.findall(r"<(\w+Detector)::update", upd.group(1))))
                dis_facts["AP_IDS.update_invokes"] = called
            linked = sorted(set(re.findall(r"<(\w+Detector)::\w+\(", out)))
            dis_facts["linked_detector_classes"] = linked
        finally:
            Path(elf_path).unlink(missing_ok=True)
        fact("ap_ids.update_invokes_detectors", dis_facts.get("AP_IDS.update_invokes"), "objdump of AP_IDS::update(): direct calls")
        fact("ap_ids.linked_detector_classes", dis_facts.get("linked_detector_classes"), "objdump: detector methods present in final ELF")
        fact("ap_ids.gcs_report_is_stub", dis_facts.get("AP_IDSGCS.report_confirmed_stub"), "objdump: AP_IDSGCS::report_confirmed = `movs r0,#0; bx lr`")

    # Custom MAVLink message? search generated headers for anything IDS/PUSHPAK
    hdrs = [n for n in names if "/include/mavlink/v2.0/ardupilotmega/mavlink_msg_" in n]
    custom = [Path(n).name for n in hdrs if re.search(r"ids|pushpak", Path(n).name, re.I)]
    fact("mavlink.custom_messages", custom, f"scanned {len(hdrs)} generated ardupilotmega message headers")
    df_ids = sorted(s for s in elf_strings if re.fullmatch(r"IDS[A-Z0-9]{0,1}", s))
    fact("dataflash.ids_log_messages", df_ids, "ELF string table (LogStructure names). Note: 'PIDS' is ArduPilot's PID-steering log, unrelated")

    romfs_h = (safe_read(bz, "build/Pixhawk6C/ap_romfs_embedded.h") or b"").decode(errors="ignore")
    embedded = {m.group(1): int(m.group(2)) for m in re.finditer(r'\{ "(scripts/[^"]+)", sizeof\(ap_romfs_\d+\), (\d+),', romfs_h)}
    fact("romfs.embedded_scripts", embedded, "build/Pixhawk6C/ap_romfs_embedded.h")

    rz = zipfile.ZipFile(a.romfs_zip)
    scripts = {}
    method_calls: dict[str, set] = {}
    for n in rz.namelist():
        if n.endswith(".lua"):
            b = rz.read(n)
            scripts[Path(n).name] = {"size": len(b), "sha256": sha256(b),
                                     "embedded_size_match": embedded.get(f"scripts/{Path(n).name}") == len(b)}
            for m in re.finditer(rb"ids:([a-z_]+)\(", b):
                method_calls.setdefault(m.group(1).decode(), set()).add(Path(n).name)
    fact("lua.scripts", scripts, "ROMFS_custom.zip (sizes compared against ap_romfs_embedded.h)")
    missing = {m: sorted(v) for m, v in method_calls.items() if m not in bind}
    fact("lua.ids_methods_called", sorted(method_calls), "regex ids:<method>( over the Lua sources")
    fact("lua.ids_methods_missing_from_binding", missing, "called in Lua but not present in compiled binding")
    if missing:
        discrepancies.append({
            "id": "DISC-001",
            "summary": "Lua scripts call AP_IDS accessor methods that the compiled `ids` binding does not provide",
            "detail": f"binding exposes {bind}; scripts call {sorted(missing)}",
            "impact": "ids_gcs_bridge.lua and *_confirm.lua are expected to stop with a Lua runtime error on this build; "
                      "PIDS|... and 'PUSHPAK IDS: ...' STATUSTEXT will not be emitted. The GCS parses them when present "
                      "and surfaces Lua runtime errors as Lua-layer health.",
            "resolution": "Regenerate bindings from AP_IDS_bindings.desc.append including the accessor methods, or change scripts to available API.",
        })
    if dis_facts.get("AP_IDSGCS.report_confirmed_stub"):
        discrepancies.append({
            "id": "DISC-002", "summary": "AP_IDSGCS::report_confirmed is a stub returning false",
            "detail": "native confirmation reporting to the GCS is a no-op in this build",
            "impact": "no native FC IDS telemetry reaches the GCS", "resolution": "implement AP_IDSGCS transport",
        })
    if dis_facts.get("AP_IDS.update_invokes") is not None and len(dis_facts["AP_IDS.update_invokes"]) < 8:
        discrepancies.append({
            "id": "DISC-003", "summary": "AP_IDS::update() only drives a subset of detectors",
            "detail": f"invokes {dis_facts['AP_IDS.update_invokes']}; DETECTION_METHODS.md lists 8 detector families",
            "impact": "FC-side states for the remaining detectors will not change on this build",
            "resolution": "connect remaining native adapters (see VALIDATION.md 'Not yet end-to-end validated')",
        })
    discrepancies.append({
        "id": "DISC-004", "summary": "PIDS state integer mapping unverified",
        "detail": "CLEAR/SUSPECTED/CONFIRMED order is from DETECTION_METHODS.md; enum values not recoverable from stripped binary",
        "impact": "GCS labels PIDS states 0/1/2 as CLEAR/SUSPECTED/CONFIRMED with an 'unverified mapping' flag",
        "resolution": "confirm AP_IDS::State enum in AP_IDS.h",
    })

    caps = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {"build_zip_sha256": sha256(Path(a.build_zip).read_bytes()),
                   "romfs_zip_sha256": sha256(Path(a.romfs_zip).read_bytes()),
                   "apj_present": apj is not None},
        "vehicle": {"board": board.group(1) if board else None, "firmware": fw_version,
                    "git_commit": git.group(1) if git else None},
        "mavlink": {"version": "2", "dialect": "ardupilotmega", "custom_dialect": bool(custom)},
        "pushpak": {
            "ap_ids_native": bool(ap_ids_objs),
            "lua_scripts_present": bool(scripts),
            "lua_bridge_script_present": "ids_gcs_bridge.lua" in scripts,
            "lua_bridge_functional": not missing,
            "fc_telemetry_to_gcs": bool(not missing) or (dis_facts.get("AP_IDSGCS.report_confirmed_stub") is False),
            "native_detectors_active": dis_facts.get("AP_IDS.update_invokes"),
            "structured_custom_message": False,
            "statustext_formats_from_source": ["PIDS|1|FC|<DET>|<state>|<conf>|<evidence>|<metric>|<instance>",
                                               "PUSHPAK IDS: <CLASS> conf=<c> evidence=0x<hex>",
                                               "PUSHPAK IDS: GPS CONFIRMED conf=.. pos=..m vel=..m/s robust=.. cusum=.."],
            "jamming_detector": "LUA_CLASS_ONLY (jamming_confirm.lua classifies RC_LINK evidence; no JAMMING PIDS detector)",
        },
        "logging": {"dataflash": True, "tlog": True, "dataflash_ids_messages": df_ids,
                    "remote_log_streaming": "UNVERIFIED (depends on LOG_BACKEND_TYPE at runtime)"},
        "findings": findings,
        "discrepancies": discrepancies,
    }
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(caps, indent=2))
    print(json.dumps({"out": a.out, "discrepancies": [d["id"] for d in discrepancies]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
