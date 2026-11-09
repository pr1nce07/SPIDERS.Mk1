from __future__ import annotations
import csv, io, json, math, re, struct
from pathlib import Path
from typing import Any
from .models import ParseResult

TEXT_LIMIT = 4 * 1024 * 1024

def _generic(data: bytes) -> ParseResult:
    n = len(data)
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in data[:min(n, 1_000_000)])
    entropy = 0.0
    if data:
        import math as _m
        counts = [0] * 256
        for b in data[:min(n, 1_000_000)]: counts[b] += 1
        total = sum(counts)
        entropy = -sum((c/total)*_m.log2(c/total) for c in counts if c)
    res = ParseResult(metadata={"size_bytes": n, "entropy_bits_per_byte": round(entropy, 4),
        "printable_ratio_sample": round(printable/max(1,min(n,1_000_000)), 4), "prefix_hex": data[:64].hex(),
        "probable_compression_or_encryption": bool(n > 64 and entropy > 7.65)})
    res.warnings.append("No validated semantic parser matched this evidence. Original bytes were preserved.")
    res.limitations.append("Channel names, units, timestamps and vehicle identity are unknown until a schema or parser is supplied.")
    # Candidate little-endian float series are deliberately unlabeled and only emitted when plausibility is high.
    for width, fmt in ((4, "f"), (8, "d")):
        count = min(n // width, 4096)
        if count < 8: continue
        for offset in range(min(width, 4)):
            vals=[]
            for i in range(count):
                try: v=struct.unpack_from("<"+fmt, data, offset+i*width)[0]
                except struct.error: break
                vals.append(v)
            finite=[v for v in vals if math.isfinite(v)]
            if len(finite) >= max(8, int(count*.9)):
                lo, hi=min(finite), max(finite)
                if hi-lo > 1e-12 and abs(hi) < 1e12:
                    res.channels.append({"name":f"candidate_f{width*8}_le_offset_{offset}","type":f"float{width*8}","offset":offset,"count":len(finite),"min":lo,"max":hi,"semantic":"unassigned hypothesis"})
                    if len(res.channels) >= 8: break
        if len(res.channels) >= 8: break
    return res

def inspect_file(path: Path, original_name: str) -> ParseResult:
    total_size = path.stat().st_size
    with path.open("rb") as fh:
        data = fh.read(min(total_size, 8 * 1024 * 1024))
    lower = original_name.lower()
    # DJI artifacts: only CSV/JSON exports are semantically decoded here;
    # proprietary DAT files receive conservative structural triage.
    if lower.endswith((".dat", ".txt")) or "dji" in lower or data[:3] == b"DJI":
        try:
            from .dji import inspect_dji
            dji = inspect_dji(path, original_name)
            if dji.get("semantic_decode") or "DJI" in dji.get("family", ""):
                return ParseResult(format_id="dji.artifact", format_name=dji["family"],
                    support_level="L3" if dji.get("semantic_decode") else "L2", decoder=dji["decoder"],
                    confidence=.85 if dji.get("semantic_decode") else .55, records=dji.get("records",0),
                    channels=dji.get("channels",[]), samples=dji.get("samples",[]), metadata=dji.get("metadata",{}),
                    warnings=dji.get("warnings",[]), limitations=dji.get("limitations",[]))
        except Exception:
            pass
    # Signature-first identification; filename is only a weak hint.
    if data.startswith(b"ULog"): return _parse_ulog(path, data)
    if data.startswith(b" MAV") or data[:2] == b"\xa3\x95" or (len(data)>3 and data[0] in (0xA3,0xA4) and b"FMT" in data[:128]):
        return _parse_dataflash(path, data)
    if data.startswith(b"H Product:") or data.startswith(b"H Firmware type:") or b"H Field I name:" in data[:8192]:
        r=_generic(data); r.metadata["size_bytes"] = total_size; r.format_id="betaflight.blackbox"; r.format_name="Betaflight Blackbox"; r.support_level="L2"; r.decoder="blackbox-header-inspector"; r.confidence=.9
        r.metadata["header_preview"]=data[:8192].decode("utf-8","replace")[:4000]
        r.warnings.append("Blackbox header recognized; full frame decoding requires a compatible blackbox-tools decoder.")
        r.limitations.append("Frame predictor decoding has not been performed by this build.")
        return r
    if data[:1] in (b"\xfe",b"\xfd"):
        r=_generic(data); r.metadata["size_bytes"] = total_size; r.format_id="mavlink.capture"; r.format_name="MAVLink raw stream"; r.support_level="L2"; r.decoder="mavlink-signature-inspector"; r.confidence=.75
        r.metadata["mavlink_v1_magic_count"]=data.count(b"\xfe"); r.metadata["mavlink_v2_magic_count"]=data.count(b"\xfd")
        r.warnings.append("Raw MAVLink stream identified; use the existing SPIDERS telemetry importer for validated tlog decoding.")
        return r
    if data.startswith(b"SQLite format 3\x00"):
        r=_generic(data); r.metadata["size_bytes"] = total_size; r.format_id="sqlite.database"; r.format_name="SQLite database"; r.support_level="L2"; r.decoder="sqlite-signature-inspector"; r.confidence=.99
        return r
    if data.startswith(b"PK\x03\x04"):
        r=_generic(data); r.metadata["size_bytes"] = total_size; r.format_id="zip.archive"; r.format_name="ZIP archive"; r.support_level="L1"; r.decoder="archive-signature-inspector"; r.confidence=.99
        r.limitations.append("Archive contents are not automatically extracted in this evidence-only workflow.")
        return r
    if data[:4] == b"\xd4\xc3\xb2\xa1" or data[:4] == b"\xa1\xb2\xc3\xd4":
        r=_generic(data); r.metadata["size_bytes"] = total_size; r.format_id="pcap.capture"; r.format_name="PCAP capture"; r.support_level="L1"; r.decoder="pcap-signature-inspector"; r.confidence=.99
        return r
    if total_size <= TEXT_LIMIT and (data[:1] == b"{" or data[:1] == b"["):
        try:
            obj=json.loads(data.decode("utf-8"))
            r=ParseResult(format_id="json",format_name="JSON telemetry/artifact",support_level="L3",decoder="json",confidence=.99,metadata={"root_type":type(obj).__name__})
            if isinstance(obj,list):
                r.records=len(obj)
                if obj and isinstance(obj[0],dict):
                    keys=list(obj[0].keys()); r.channels=[{"name":k,"semantic":"source field"} for k in keys]
                    r.samples=obj[:2000]
            elif isinstance(obj,dict):
                r.channels=[{"name":k,"semantic":"source field"} for k in obj.keys()]
                r.samples=[obj]
            return r
        except Exception: pass
    # CSV/TSV with consistent header and rows.
    if b"\n" in data[:TEXT_LIMIT] and (b"," in data[:4096] or b"\t" in data[:4096]):
        try:
            text=data[:TEXT_LIMIT].decode("utf-8-sig")
            dialect=csv.Sniffer().sniff(text[:8192], delimiters=",\t;")
            rows=list(csv.DictReader(io.StringIO(text), dialect=dialect))
            if rows and len(rows[0]) >= 2:
                keys=list(rows[0].keys())
                r=ParseResult(format_id="delimited.telemetry",format_name="Delimited telemetry",support_level="L3",decoder="csv",confidence=.9,records=len(rows),channels=[{"name":k,"semantic":"source column"} for k in keys],samples=rows[:2000],metadata={"columns":keys,"delimiter":repr(dialect.delimiter)})
                if len(rows)>2000: r.warnings.append("Preview limited to first 2,000 rows; source evidence remains complete.")
                return r
        except Exception: pass
    if b"$G" in data[:4096] or b"$GP" in data[:4096] or b"$GN" in data[:4096]:
        r=_generic(data); r.metadata["size_bytes"] = total_size; r.format_id="nmea.gnss"; r.format_name="NMEA GNSS stream"; r.support_level="L2"; r.decoder="nmea-inspector"; r.confidence=.7
        r.metadata["nmea_sentence_count"]=len(re.findall(rb"\$[A-Z]{2,3}[A-Z0-9]{2,3},",data))
        return r
    result = _generic(data)
    result.metadata["size_bytes"] = total_size
    if total_size > len(data): result.warnings.append("Structural inspection sampled the first 8 MiB to bound memory use; full evidence was preserved and hashed.")
    return result

def _scalar(value):
    try:
        if hasattr(value, "item"): value=value.item()
        if isinstance(value, (int,float,str,bool)) or value is None: return value
        if hasattr(value, "tolist"): value=value.tolist()
        if isinstance(value, (list,tuple)):
            return [ _scalar(v) for v in value[:16] ]
    except Exception: pass
    return None

def _parse_ulog(path: Path, data: bytes) -> ParseResult:
    try:
        from pyulog import ULog
        u=ULog(str(path)); channels=[]; records=0; rows=[]
        # Build an event stream from actual topic samples. Topic timestamps are
        # preserved; different topics are not silently interpolated or merged.
        for d in u.data_list:
            if len(rows)>=10000: break
            fields=list(d.data.keys()); timestamps=d.data.get("timestamp")
            count=len(timestamps) if timestamps is not None else max((len(v) for v in d.data.values() if hasattr(v,"__len__")),default=0)
            records=max(records,count)
            for field,values in d.data.items(): channels.append({"name":f"{d.name}.{field}","topic":d.name,"semantic":"ULog field"})
            stride=max(1,math.ceil(count/10000))
            for i in range(0,count,stride):
                if len(rows)>=10000: break
                row={"topic":d.name,"sample_index":i}
                if timestamps is not None and i<len(timestamps): row["timestamp_us"]=_scalar(timestamps[i])
                for field,values in d.data.items():
                    if field=="timestamp" or not hasattr(values,"__len__") or i>=len(values): continue
                    value=_scalar(values[i])
                    if isinstance(value,list):
                        for j,part in enumerate(value): row[f"{d.name}.{field}[{j}]"]=part
                    else: row[f"{d.name}.{field}"]=value
                rows.append(row)
        rows.sort(key=lambda r: (r.get("timestamp_us") is None, r.get("timestamp_us") or 0))
        return ParseResult(format_id="px4.ulog",format_name="PX4 ULog",support_level="L3",decoder="pyulog",confidence=.99,records=records,channels=channels[:2000],samples=rows[:10000],metadata={"start_timestamp":u.start_timestamp,"msg_info":u.msg_info_dict,"topic_count":len(u.data_list)},warnings=["Topic samples are retained as timestamped events. No cross-topic interpolation or clock alignment has been applied."])
    except ImportError:
        return ParseResult(format_id="px4.ulog",format_name="PX4 ULog",support_level="L2",decoder="ulog-signature-inspector",confidence=.99,metadata={"size_bytes":len(data)},warnings=["ULog signature recognized, but pyulog is not installed. Install pyulog to decode topics."],limitations=["Semantic topic decoding unavailable in current environment."])
    except Exception as e:
        r=_generic(data); r.metadata["size_bytes"] = path.stat().st_size; r.format_id="px4.ulog"; r.format_name="PX4 ULog"; r.decoder="pyulog"; r.confidence=.99; r.warnings.append(f"ULog parser failed safely: {type(e).__name__}: {e}"); return r

def _parse_dataflash(path: Path, data: bytes) -> ParseResult:
    try:
        from pymavlink import DFReader
        reader=DFReader.DFReader_binary(str(path), zero_time_base=True)
        counts={}; names=set(); samples=[]
        while True:
            msg=reader.recv_msg()
            if msg is None: break
            name=msg.get_type(); counts[name]=counts.get(name,0)+1
            values=msg.to_dict(); names.update(f"{name}.{k}" for k in values if k!="mavpackettype")
            if len(samples)<10000:
                row={"topic":name,"record_index":sum(counts.values())-1}
                for key,value in values.items():
                    if key=="mavpackettype": continue
                    if isinstance(value,(int,float,str,bool)) or value is None: row[f"{name}.{key}"]=value
                # Preserve the reader's message timestamp if exposed by pymavlink.
                ts=getattr(msg,"_timestamp",None)
                if ts is not None: row["timestamp"]=ts
                samples.append(row)
        return ParseResult(format_id="ardupilot.dataflash",format_name="ArduPilot DataFlash",support_level="L3",decoder="pymavlink-DFReader",confidence=.98,records=sum(counts.values()),channels=[{"name":n,"semantic":"DataFlash field"} for n in sorted(names)],samples=samples,metadata={"message_counts":counts},warnings=["DataFlash messages are preserved as timestamped/ordered events; channels from different message types are not interpolated."] + (["Sample preview capped at 10,000 messages."] if sum(counts.values())>len(samples) else []))
    except Exception as e:
        r=_generic(data); r.metadata["size_bytes"] = path.stat().st_size; r.format_id="ardupilot.dataflash"; r.format_name="ArduPilot DataFlash"; r.decoder="dataflash-signature-inspector"; r.confidence=.8; r.warnings.append(f"DataFlash semantic decode unavailable: {type(e).__name__}: {e}"); return r
