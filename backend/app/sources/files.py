"""Offline TelemetrySource implementations (spec §42/§43/§67).

Each source yields SourceItem objects; the pipeline turns them into the same
normalized TelemetryEvent stream as live data. Imported files are untrusted:
nothing is executed, parsing is bounded and all failures are preserved.
"""
from __future__ import annotations

import csv
import io
import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional

from ..mavlink.decoder import MAGIC_V1, MAGIC_V2, iter_tlog

MAX_LINE = 1 << 20


@dataclass
class SourceItem:
    kind: str                 # "frame" | "event"
    t: float
    data: Any                 # bytes for frames; dict for events
    link: str = "file"
    source: str = "TLOG"


# -------------------------------------------------------------------- detection
def detect_format(path: Path) -> str:
    with open(path, "rb") as fh:
        head = fh.read(4096)
    name = path.name.lower()
    if head[:2] == b"\xa3\x95":
        return "dataflash_bin"
    if head.startswith(b"FMT,") or b"\nFMT," in head[:2048]:
        return "dataflash_log"
    if len(head) >= 9 and head[8] in (MAGIC_V1, MAGIC_V2):
        ts = int.from_bytes(head[:8], "big")
        if 946684800_000000 <= ts <= 4102444800_000000:
            return "tlog"
    if head[:2] == b"PK":
        return "zip"
    stripped = head.lstrip()
    if stripped[:1] == b"{":
        return "jsonl"
    if stripped[:1] == b"[":
        return "json"
    if name.endswith(".csv") or b"," in head.split(b"\n")[0]:
        return "csv"
    return "unknown"


# -------------------------------------------------------------------- tlog / case
def iter_tlog_file(path: Path, source: str = "TLOG") -> Iterator[SourceItem]:
    data = path.read_bytes()
    bad: list[tuple[int, bytes]] = []
    last_t = [None]

    def on_skip(pos, chunk):
        bad.append((pos, chunk))

    for t, frame in iter_tlog(data, on_skip=on_skip):
        while bad:  # preserve skipped bytes as evidence at the point they occurred
            _pos, chunk = bad.pop(0)
            yield SourceItem("frame", last_t[0] or t, chunk[:4096], link=path.name, source=source)
        last_t[0] = t
        yield SourceItem("frame", t, frame, link=path.name, source=source)
    for _pos, chunk in bad:
        yield SourceItem("frame", last_t[0] or 0.0, chunk[:4096], link=path.name, source=source)


# -------------------------------------------------------------------- DataFlash
DF_GPS_STATUS = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6}


def iter_dataflash(path: Path) -> Iterator[SourceItem]:
    """Map DataFlash records to MAVLink-equivalent field sets where semantics are
    1:1 (documented unit conversion); other records keep their DataFlash name
    (msg_name 'DF_<TYPE>'). The original record type is kept in `origin`."""
    from pymavlink import DFReader
    reader = DFReader.DFReader_binary(str(path), zero_time_base=False) if detect_format(path) == "dataflash_bin" \
        else DFReader.DFReader_text(str(path), zero_time_base=False)
    xkf_vel: Optional[tuple] = None
    armed = None
    while True:
        try:
            m = reader.recv_msg()
        except Exception as exc:  # corrupted record: preserve and continue
            yield SourceItem("event", 0.0, {"msg_name": "BAD_DATA", "fields": {"reason": f"DataFlash parse error: {exc}"}, "origin": "DF"}, source="DATAFLASH")
            continue
        if m is None:
            break
        typ = m.get_type()
        t = getattr(m, "_timestamp", None) or 0.0
        d = m.to_dict()
        d.pop("mavpackettype", None)
        raw = None
        try:
            raw = bytes(m.get_msgbuf())
        except Exception:
            pass
        mapped = None
        if typ == "GPS" and d.get("I", 0) in (0, None):
            mapped = ("GPS_RAW_INT", {"fix_type": DF_GPS_STATUS.get(d.get("Status"), d.get("Status")),
                                      "lat": int(d.get("Lat", 0) * 1e7), "lon": int(d.get("Lng", 0) * 1e7),
                                      "alt": int(d.get("Alt", 0) * 1000), "eph": int(d.get("HDop", 99.99) * 100),
                                      "vel": int(d.get("Spd", 0) * 100), "cog": int(d.get("GCrs", 0) * 100),
                                      "satellites_visible": d.get("NSats")})
        elif typ == "GPS" and d.get("I") == 1:
            mapped = ("GPS2_RAW", {"fix_type": d.get("Status"), "lat": int(d.get("Lat", 0) * 1e7), "lon": int(d.get("Lng", 0) * 1e7)})
        elif typ == "XKF1" and d.get("C", 0) == 0:
            xkf_vel = (d.get("VN"), d.get("VE"), d.get("VD"))
        elif typ == "POS":
            vn, ve, vd = xkf_vel or (None, None, None)
            mapped = ("GLOBAL_POSITION_INT", {"lat": int(d.get("Lat", 0) * 1e7), "lon": int(d.get("Lng", 0) * 1e7),
                                              "alt": int(d.get("Alt", 0) * 1000), "relative_alt": int((d.get("RelHomeAlt") or 0) * 1000),
                                              "vx": None if vn is None else int(vn * 100), "vy": None if ve is None else int(ve * 100),
                                              "vz": None if vd is None else int(vd * 100), "hdg": None})
        elif typ == "ATT":
            mapped = ("ATTITUDE", {"roll": math.radians(d.get("Roll", 0)), "pitch": math.radians(d.get("Pitch", 0)),
                                   "yaw": math.radians(d.get("Yaw", 0)), "rollspeed": None, "pitchspeed": None, "yawspeed": None})
        elif typ == "IMU":
            inst = d.get("I", 0)
            name = {0: "RAW_IMU", 1: "SCALED_IMU2", 2: "SCALED_IMU3"}.get(inst)
            if name:
                g = 9.80665
                mapped = (name, {"xacc": int(d.get("AccX", 0) / g * 1000), "yacc": int(d.get("AccY", 0) / g * 1000),
                                 "zacc": int(d.get("AccZ", 0) / g * 1000), "xgyro": int(d.get("GyrX", 0) * 1000),
                                 "ygyro": int(d.get("GyrY", 0) * 1000), "zgyro": int(d.get("GyrZ", 0) * 1000)})
        elif typ == "BAT" and d.get("Inst", 0) in (0, None):
            mapped = ("SYS_STATUS", {"voltage_battery": int(d.get("Volt", 0) * 1000), "current_battery": int(d.get("Curr", 0) * 100),
                                     "battery_remaining": d.get("RemPct", -1)})
        elif typ == "MSG":
            mapped = ("STATUSTEXT", {"text": d.get("Message", ""), "severity": None})
        elif typ == "PARM":
            mapped = ("PARAM_VALUE", {"param_id": d.get("Name"), "param_value": d.get("Value")})
        elif typ == "MODE":
            from pymavlink import mavutil
            mapped = ("DF_MODE", {"mode": mavutil.mode_mapping_acm.get(d.get("ModeNum"), str(d.get("Mode"))), "mode_num": d.get("ModeNum")})
        elif typ == "EV":
            ev_id = d.get("Id")
            if ev_id in (10, 11):
                armed = ev_id == 10
            mapped = ("DF_EV", {"event_id": ev_id, "armed": armed if ev_id in (10, 11) else None})
        elif typ == "IDSW":
            # Onboard PARAM_SET receive hook (firmware FW-04): sender identity as seen by the autopilot.
            name = d.get("Name")
            name = name.decode(errors="ignore") if isinstance(name, (bytes, bytearray)) else name
            mapped = ("PARAM_SET", {"param_id": str(name or "").rstrip("\x00"), "param_value": d.get("Val"), "param_type": d.get("Typ"),
                                    "onboard_result": {0: "REQUESTED", 1: "APPLIED", 2: "REJECTED"}.get(d.get("Res"), d.get("Res")),
                                    "signature": {0: "NONE", 1: "VALID", 2: "INVALID"}.get(d.get("Sig"), d.get("Sig")),
                                    "channel": d.get("Chan")})
            yield SourceItem("event", t, {"msg_name": mapped[0], "fields": mapped[1], "origin": typ, "df_fields": d, "raw": raw,
                                          "sysid": d.get("Sys"), "compid": d.get("Comp")}, source="DATAFLASH")
            continue
        elif typ == "RCIN":
            mapped = ("RC_CHANNELS_RAW_DF", {k: v for k, v in d.items() if k.startswith("C")})
        if mapped:
            yield SourceItem("event", t, {"msg_name": mapped[0], "fields": mapped[1], "origin": typ, "df_fields": d, "raw": raw}, source="DATAFLASH")
        else:
            yield SourceItem("event", t, {"msg_name": f"DF_{typ}", "fields": d, "origin": typ, "raw": raw}, source="DATAFLASH")


# -------------------------------------------------------------------- JSONL / JSON / CSV
def _event_from_obj(o: dict, source: str) -> SourceItem:
    if not isinstance(o, dict):
        raise ValueError("record is not an object")
    t = float(o.get("t") or o.get("timestamp") or 0.0)
    if o.get("raw_hex"):
        return SourceItem("frame", t, bytes.fromhex(o["raw_hex"]), link=str(o.get("link") or "jsonl"), source=source)
    return SourceItem("event", t, {"msg_name": str(o.get("msg_name") or o.get("msg") or "UNKNOWN"), "fields": dict(o.get("fields") or {}),
                                   "sysid": o.get("sysid"), "compid": o.get("compid"), "seq": o.get("seq")},
                      link=str(o.get("link") or "jsonl"), source=source)


def iter_jsonl(path: Path) -> Iterator[SourceItem]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            if len(line) > MAX_LINE:
                yield SourceItem("event", 0.0, {"msg_name": "BAD_DATA", "fields": {"reason": f"line {n} exceeds {MAX_LINE} bytes"}}, source="JSONL")
                continue
            line = line.strip()
            if not line:
                continue
            try:
                yield _event_from_obj(json.loads(line), "JSONL")
            except Exception as exc:
                yield SourceItem("event", 0.0, {"msg_name": "BAD_DATA", "fields": {"reason": f"line {n}: {exc}", "text": line[:500]}}, source="JSONL")


def iter_json(path: Path) -> Iterator[SourceItem]:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    for o in data if isinstance(data, list) else data.get("messages", []):
        try:
            yield _event_from_obj(o, "JSONL")
        except Exception as exc:
            yield SourceItem("event", 0.0, {"msg_name": "BAD_DATA", "fields": {"reason": str(exc)}}, source="JSONL")


def iter_csv(path: Path) -> Iterator[SourceItem]:
    """Format: timestamp,msg_name,sysid,compid,<field columns…> (or raw_hex)."""
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        rd = csv.DictReader(fh)
        cols = rd.fieldnames or []
        if "msg_name" not in cols and "raw_hex" not in cols:
            raise ValueError("CSV must have msg_name (or raw_hex) column; see docs for the import format")
        for n, row in enumerate(rd, 2):
            try:
                t = float(row.get("timestamp") or row.get("t") or 0)
                if row.get("raw_hex"):
                    yield SourceItem("frame", t, bytes.fromhex(row["raw_hex"]), link="csv", source="CSV")
                    continue
                fields = {}
                for k, v in row.items():
                    if k in ("timestamp", "t", "msg_name", "sysid", "compid", "seq") or v in (None, ""):
                        continue
                    try:
                        fields[k] = int(v) if v.lstrip("-").isdigit() else float(v)
                    except ValueError:
                        fields[k] = v
                yield SourceItem("event", t, {"msg_name": row["msg_name"], "fields": fields,
                                              "sysid": int(row["sysid"]) if row.get("sysid") else None,
                                              "compid": int(row["compid"]) if row.get("compid") else None}, link="csv", source="CSV")
            except Exception as exc:
                yield SourceItem("event", 0.0, {"msg_name": "BAD_DATA", "fields": {"reason": f"row {n}: {exc}"}}, source="CSV")


def open_source(path: Path, fmt: Optional[str] = None) -> Iterator[SourceItem]:
    fmt = fmt or detect_format(path)
    if fmt in ("tlog",):
        return iter_tlog_file(path)
    if fmt == "case_raw":
        return iter_tlog_file(path, source="CASE")
    if fmt in ("dataflash_bin", "dataflash_log"):
        return iter_dataflash(path)
    if fmt == "jsonl":
        return iter_jsonl(path)
    if fmt == "json":
        return iter_json(path)
    if fmt == "csv":
        return iter_csv(path)
    raise ValueError(f"unsupported or unrecognised format '{fmt}'")
