"""Isolated worker entrypoint. Only built-in, reviewed decoders are importable here."""
from __future__ import annotations
import csv, io, json, os, shutil, subprocess, sys, tempfile
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE.parent))
try:
    import resource
    resource.setrlimit(resource.RLIMIT_CPU,(12,12))
    resource.setrlimit(resource.RLIMIT_AS,(768*1024*1024,768*1024*1024))
    resource.setrlimit(resource.RLIMIT_FSIZE,(16*1024*1024,16*1024*1024))
    resource.setrlimit(resource.RLIMIT_NOFILE,(32,32))
except Exception: pass

def main():
    path=Path(sys.argv[1]).resolve(); name=sys.argv[2]
    if not path.is_file(): raise SystemExit(2)
    from app.silktrace.detect import inspect_file
    parsed=inspect_file(path,name)
    # Betaflight/INAV Blackbox predictor decoding is delegated to the upstream
    # blackbox_decode binary when explicitly installed. It runs inside this
    # already resource-limited worker (and Bubblewrap namespace when available).
    if parsed.format_id == "betaflight.blackbox":
        decoder=shutil.which("blackbox_decode")
        if decoder:
            cmd=[decoder,"--stdout","--merge-gps","--unit-frame-time","s","--unit-height","m","--unit-rotation","deg/s","--unit-acceleration","m/s2","--unit-gps-speed","mps","--unit-vbat","V",str(path)]
            try:
                with tempfile.TemporaryFile(mode="w+b") as output:
                    proc=subprocess.run(cmd,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.PIPE,timeout=10,check=False)
                    output.seek(0); decoded=output.read(16*1024*1024+1)
                if proc.returncode==0 and len(decoded)<=16*1024*1024:
                    text=decoded.decode("utf-8-sig",errors="replace")
                    dialect=csv.Sniffer().sniff(text[:8192],delimiters=",\t;")
                    rows=list(csv.DictReader(io.StringIO(text),dialect=dialect))
                    if rows:
                        parsed.samples=rows[:10000]
                        parsed.channels=[{"name":k,"semantic":"blackbox_decode output field; units selected by decoder arguments"} for k in rows[0].keys()]
                        parsed.records=len(rows); parsed.support_level="L3"; parsed.decoder="Betaflight blackbox_decode"
                        parsed.metadata["decoded_with"]="blackbox_decode"; parsed.metadata["decoder_stderr"]=proc.stderr.decode("utf-8","replace")[:2000]
                        if len(rows)>10000: parsed.warnings.append("Blackbox sample preview capped at 10,000 rows.")
                    else: parsed.warnings.append("blackbox_decode returned no CSV rows; header inspection retained.")
                else: parsed.warnings.append(f"blackbox_decode unavailable or failed (exit {proc.returncode}); header inspection retained.")
            except Exception as exc: parsed.warnings.append(f"blackbox_decode failed safely: {type(exc).__name__}: {str(exc)[:240]}")
        else: parsed.limitations.append("Install the upstream blackbox_decode executable to decode predictor-compressed frames; this evidence currently has header-only inspection.")
    print(json.dumps(parsed.to_dict(),ensure_ascii=False,allow_nan=False))
if __name__=='__main__':main()
