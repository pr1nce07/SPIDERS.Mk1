"""Raw-preserving MAVLink decoder.

Wraps pymavlink's parser but guarantees (spec §86) that every byte sequence that
arrives is represented by a TelemetryEvent: decodable frames keep their exact
wire bytes, and undecodable data becomes a `BAD_DATA` event that still carries
the raw bytes, the parse error, and SYSID/COMPID when they can be recovered from
the header.
"""
from __future__ import annotations

import math
import struct
from typing import Callable, Iterator, Optional

from ..models.events import TelemetryEvent

MAGIC_V1 = 0xFE
MAGIC_V2 = 0xFD


def frame_length(buf: bytes | bytearray, pos: int = 0) -> Optional[int]:
    """Total length of the frame starting at pos, or None if not determinable."""
    if len(buf) - pos < 3:
        return None
    magic = buf[pos]
    if magic == MAGIC_V2:
        if len(buf) - pos < 3:
            return None
        plen = buf[pos + 1]
        incompat = buf[pos + 2]
        return 12 + plen + (13 if incompat & 0x01 else 0)
    if magic == MAGIC_V1:
        return 8 + buf[pos + 1]
    return None


def recover_header(raw: bytes) -> tuple[Optional[int], Optional[int], Optional[int], Optional[int]]:
    """(sysid, compid, seq, msgid) from a possibly-corrupt frame, if the header survives."""
    try:
        if raw and raw[0] == MAGIC_V2 and len(raw) >= 10:
            return raw[5], raw[6], raw[4], raw[7] | (raw[8] << 8) | (raw[9] << 16)
        if raw and raw[0] == MAGIC_V1 and len(raw) >= 6:
            return raw[3], raw[4], raw[2], raw[5]
    except Exception:
        pass
    return None, None, None, None


def _clean(v):
    if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
        return None
    if isinstance(v, (bytes, bytearray)):
        return v.hex()
    if isinstance(v, list):
        return [_clean(x) for x in v]
    return v


def msg_fields(msg) -> dict:
    d = {}
    for name in msg.get_fieldnames():
        try:
            d[name] = _clean(getattr(msg, name))
        except Exception:
            d[name] = None
    return d


class Decoder:
    """One decoder per link (keeps its own pymavlink parser state)."""

    def __init__(self, registry, link: str, source: str, signing_key: Optional[bytes] = None):
        self.registry = registry
        self.link = link
        self.source = source
        self.mav = registry.module.MAVLink(None, srcSystem=255, srcComponent=190)
        self.mav.robust_parsing = True
        self.signing_key_configured = signing_key is not None
        if signing_key:
            # Validation only — we never sign outgoing (read-only GCS).
            self.mav.signing.secret_key = signing_key
            self.mav.signing.sign_outgoing = False
            self.mav.signing.allow_unsigned_callback = lambda mav, msgid: True
        self.decoded = 0
        self.bad = 0

    def feed(self, data: bytes) -> list:
        try:
            msgs = self.mav.parse_buffer(data) or []
        except Exception as exc:  # parser must never take ingestion down
            return [("error", bytes(data), str(exc))]
        return [("msg", m, None) for m in msgs]

    def to_event(self, item, idx: int, t: float, mono_ns: int) -> TelemetryEvent:
        kind, obj, err = item
        if kind == "error":
            sysid, compid, seq, mid = recover_header(obj)
            self.bad += 1
            return TelemetryEvent(idx=idx, t=t, mono_ns=mono_ns, source=self.source, link=self.link,
                                  sysid=sysid, compid=compid, msg_id=mid, msg_name="BAD_DATA", sequence=seq,
                                  fields={"reason": err}, raw=obj, parse_error=err)
        msg = obj
        name = msg.get_type()
        if name == "BAD_DATA":
            raw = bytes(getattr(msg, "data", b"") or b"")
            reason = getattr(msg, "reason", "bad data")
            sysid, compid, seq, mid = recover_header(raw)
            self.bad += 1
            sig = "INVALID" if "signature" in str(reason).lower() else None
            return TelemetryEvent(idx=idx, t=t, mono_ns=mono_ns, source=self.source, link=self.link,
                                  sysid=sysid, compid=compid, msg_id=mid, msg_name="BAD_DATA", sequence=seq,
                                  fields={"reason": str(reason)}, raw=raw, parse_error=str(reason),
                                  signature_status=sig)
        raw = bytes(msg.get_msgbuf())
        hdr = msg.get_header()
        signed = bool(getattr(msg, "_signed", False))
        sig_status = None
        if signed:
            sig_status = "VALID" if self.signing_key_configured else "UNVERIFIED"
        self.decoded += 1
        fields = msg_fields(msg)
        boot_ms = fields.get("time_boot_ms") if isinstance(fields.get("time_boot_ms"), int) else None
        return TelemetryEvent(idx=idx, t=t, mono_ns=mono_ns, source=self.source, link=self.link,
                              sysid=hdr.srcSystem, compid=hdr.srcComponent, msg_id=msg.get_msgId(),
                              msg_name=name, sequence=hdr.seq, fields=fields, raw=raw,
                              mavlink_version=2 if raw[:1] == b"\xfd" else 1, signed=signed,
                              signature_status=sig_status, link_id=getattr(msg, "_link_id", None),
                              boot_ms=boot_ms)

    def signing_counters(self) -> dict:
        s = self.mav.signing
        return {"key_configured": self.signing_key_configured, "good": getattr(s, "goodsig_count", 0),
                "bad": getattr(s, "badsig_count", 0), "unsigned": getattr(s, "unsigned_count", 0),
                "rejected": getattr(s, "reject_count", 0)}


# ---------------------------------------------------------------- tlog framing
TLOG_TS = struct.Struct(">Q")


def iter_tlog(data: bytes, on_skip: Callable[[int, bytes], None] | None = None) -> Iterator[tuple[float, bytes]]:
    """Yield (epoch_seconds, frame_bytes) from .tlog content (8-byte BE µs + frame).

    Resynchronises after corruption; skipped byte ranges are reported through
    on_skip so they can be preserved as BAD_DATA evidence.
    """
    pos = 0
    n = len(data)
    last_ts = None
    while pos + 9 <= n:
        ts_us = TLOG_TS.unpack_from(data, pos)[0]
        flen = frame_length(data, pos + 8)
        plausible = 946684800_000000 <= ts_us <= 4102444800_000000  # 2000..2100
        if plausible and flen is not None and pos + 8 + flen <= n:
            if last_ts is None or abs(ts_us / 1e6 - last_ts) < 86400 * 30:
                frame = data[pos + 8: pos + 8 + flen]
                last_ts = ts_us / 1e6
                yield last_ts, bytes(frame)
                pos += 8 + flen
                continue
        # resync: find next position that looks like ts + magic
        start = pos
        pos += 1
        while pos + 9 <= n:
            if data[pos + 8] in (MAGIC_V1, MAGIC_V2):
                ts2 = TLOG_TS.unpack_from(data, pos)[0]
                if 946684800_000000 <= ts2 <= 4102444800_000000:
                    break
            pos += 1
        if on_skip:
            on_skip(start, bytes(data[start:pos]))
    if pos < n and on_skip:
        on_skip(pos, bytes(data[pos:]))


def tlog_record(t: float, frame: bytes) -> bytes:
    return TLOG_TS.pack(int(t * 1e6)) + frame
