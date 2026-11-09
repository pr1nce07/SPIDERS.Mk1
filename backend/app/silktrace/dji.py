from __future__ import annotations
import csv, io
from pathlib import Path
from typing import Any

MAX_DJI_BYTES = 128 * 1024 * 1024

def _obj_dict(obj: Any) -> dict[str, Any]:
    if obj is None: return {}
    if hasattr(obj, "__dict__"): return {k:v for k,v in vars(obj).items() if not k.startswith("_")}
    try:
        import dataclasses
        if dataclasses.is_dataclass(obj): return dataclasses.asdict(obj)
    except Exception: pass
    return {}

def _num(v):
    if isinstance(v,(int,float,str)) and not isinstance(v,bool):
        try:
            n=float(v)
            if n==n and abs(n)!=float('inf'): return n
        except (ValueError,TypeError): pass
    return v if isinstance(v,(bool,type(None))) else None

def _parse_pydjirecord(path:Path)->dict[str,Any]|None:
    try:
        from pydjirecord import DJILog
    except ImportError: return None
    with path.open("rb") as fh: prefix=fh.read(12)
    # DJI FlightRecord v1-v14 stores the format version in byte 10 of its prefix.
    # Avoid feeding Betaflight's unrelated .TXT logs to this decoder.
    if len(prefix)<11 or not 1 <= prefix[10] <= 14: return None
    if path.stat().st_size > MAX_DJI_BYTES:
        return {'family':'DJI FlightRecord candidate','decoder':'pydjirecord-not-run','semantic_decode':False,'records':0,'channels':[],'samples':[],
                'warnings':['File exceeds the 128 MiB in-memory parser limit.'],'limitations':['Use a validated streaming decoder or split/export the evidence; original remains preserved.']}
    log=DJILog.from_bytes(path.read_bytes())
    details=_obj_dict(log.details)
    metadata={'log_version':getattr(log,'version',None),'details':details}
    result={'family':'DJI FlightRecord TXT','decoder':'pydjirecord 1.3.x','semantic_decode':False,'records':0,'channels':[],'samples':[],'warnings':[],'limitations':[],'metadata':metadata}
    frames=[]
    try:
        if int(getattr(log,'version',0)) >= 13:
            # No implicit network calls or key retrieval from the parser sandbox.
            result['warnings'].append('DJI log version 13+ frame data is encrypted. Header metadata is available, but frame decoding requires per-flight DJI API keychains.')
            result['limitations'].append('No API key was requested or fetched. Supply a separately authorized, securely provisioned keychain workflow to decode frame telemetry.')
        else:
            frames=list(log.frames(None))
    except Exception as exc:
        result['warnings'].append(f'DJI frame decoding stopped safely: {type(exc).__name__}: {str(exc)[:240]}')
    samples=[]; channel_names=set()
    for i,frame in enumerate(frames[:10000]):
        row={'sample_index':i}
        for group in ('osd','gimbal','battery','rc','home','camera'):
            vals=_obj_dict(getattr(frame,group,None))
            for key,value in vals.items():
                flat=f'{group}.{key}'; row[flat]=_num(value); channel_names.add(flat)
        # Preserve frame time when exposed by the library.
        for tkey in ('timestamp','time','fly_time','time_ms'):
            value=getattr(frame,tkey,None)
            if value is not None: row['timestamp']=_num(value); break
        samples.append(row)
    result.update(semantic_decode=bool(samples),records=len(frames),samples=samples,channels=[{'name':n,'semantic':'decoded DJI frame field'} for n in sorted(channel_names)])
    if len(frames)>len(samples): result['warnings'].append('Frame preview capped at 10,000 samples; original evidence remains complete.')
    if not samples and int(getattr(log,'version',0))<13: result['limitations'].append('No frame records were returned by the parser for this file.')
    return result

def inspect_dji(path:Path, filename:str)->dict[str,Any]:
    """DJI FlightRecord parser plus conservative DJI DAT triage."""
    name=filename.lower()
    if name.endswith('.txt') or 'dji' in name:
        parsed=_parse_pydjirecord(path)
        if parsed is not None: return parsed
    with path.open('rb') as fh: data=fh.read(8*1024*1024)
    result={'family':'DJI artifact candidate','decoder':'dji-triage','semantic_decode':False,'records':0,'channels':[],'samples':[],'warnings':[],'limitations':[],'metadata':{'size_bytes':path.stat().st_size,'prefix_hex':data[:64].hex()}}
    if name.endswith('.json'):
        try:
            import json
            obj=json.loads(data.decode('utf-8')); rows=obj if isinstance(obj,list) else [obj]
            if rows and isinstance(rows[0],dict): result.update(family='DJI JSON artifact (filename-based candidate)',semantic_decode=True,records=len(rows),channels=[{'name':k,'semantic':'source field'} for k in rows[0]],samples=rows[:2000])
            return result
        except Exception: pass
    if len(data)>0 and (b'Time' in data[:4096] or b'latitude' in data[:4096].lower() or b'longitude' in data[:4096].lower()):
        try:
            text=data.decode('utf-8-sig',errors='strict'); dialect=csv.Sniffer().sniff(text[:8192],delimiters=',\t;'); rows=list(csv.DictReader(io.StringIO(text),dialect=dialect))
            if rows:
                result.update(family='DJI delimited flight record candidate',semantic_decode=True,records=len(rows),channels=[{'name':k,'semantic':'source column'} for k in rows[0]],samples=rows[:2000],metadata={**result['metadata'],'columns':list(rows[0]),'delimiter':dialect.delimiter})
                return result
        except Exception: pass
    if 'dji' in name or data.startswith(b'DJI') or b'DJI' in data[:64]:
        result['family']='DJI DAT binary artifact candidate'
        result['metadata'].update(ascii_preview=''.join(chr(b) if 32<=b<127 else '.' for b in data[:256]))
        result['warnings'].append('DJI DAT variants are device/firmware dependent; only structural triage was performed.')
        result['limitations'].append('Do not confuse DJI aircraft DAT files with DJI app FlightRecord TXT files. This DAT path does not claim to decrypt proprietary aircraft logs.')
    else:
        result['family']='Unidentified binary artifact (DJI not confirmed)' if name.endswith('.dat') else 'Possible DJI-associated artifact (unconfirmed)'
        result['warnings'].append('No reliable DJI signature or documented record structure was established.')
    return result
