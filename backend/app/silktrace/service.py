from __future__ import annotations
import hashlib, json, os, re, shutil, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from .models import ParseResult
from .sandbox import inspect_isolated

class SILKTRACE:
    """Append-only evidence intake with hash-verified originals and derived inspections."""
    def __init__(self, root: Path, max_bytes: int = 1024*1024*1024):
        self.root=Path(root); self.evidence=self.root/"evidence"; self.cases=self.root/"cases"
        self.evidence.mkdir(parents=True,exist_ok=True); self.cases.mkdir(parents=True,exist_ok=True)
        self.max_bytes=max_bytes

    @staticmethod
    def _sha(path: Path) -> str:
        h=hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda:f.read(1024*1024),b""): h.update(chunk)
        return h.hexdigest()

    def ingest(self, filename: str, source: Path, investigator: str, notes: str="") -> dict[str,Any]:
        size=source.stat().st_size
        if size>self.max_bytes: raise ValueError(f"evidence exceeds configured limit ({self.max_bytes} bytes)")
        digest=self._sha(source); eid="EV-"+uuid.uuid4().hex[:12].upper()
        safe=re.sub(r"[^A-Za-z0-9._-]","_",Path(filename).name)[:180] or "evidence.bin"
        folder=self.evidence/eid; folder.mkdir(mode=0o700)
        original=folder/safe
        # Copy, then verify copy before recording metadata.
        shutil.copyfile(source,original)
        copied=self._sha(original)
        if copied != digest:
            shutil.rmtree(folder,ignore_errors=True); raise RuntimeError("evidence copy hash mismatch")
        parser_isolation = "resource-limited subprocess"
        try:
            parsed_data=inspect_isolated(original,filename,timeout=30)
            parser_isolation=parsed_data.pop("_isolation",parser_isolation)
            parsed=ParseResult(**parsed_data)
        except Exception as exc:
            # Evidence acceptance must survive parser crashes/timeouts. Do not
            # retry a failed hostile-file parser in the API process.
            with original.open("rb") as fh: prefix=fh.read(64)
            parsed=ParseResult(format_id="unknown.binary",format_name="Unknown binary",support_level="L1",
                decoder="isolated-parser-unavailable",confidence=0.0,metadata={"size_bytes":size,"prefix_hex":prefix.hex()},
                warnings=[f"Evidence was preserved, but isolated inspection failed: {type(exc).__name__}: {str(exc)[:240]}"],
                limitations=["Re-run inspection after repairing the parser worker environment. Original evidence remains available and hash-verified."])
            parser_isolation="failed-closed; no in-process parser fallback"
        now=datetime.now(timezone.utc).isoformat()
        record={"evidence_id":eid,"original_filename":filename,"stored_filename":safe,"size_bytes":size,"sha256":digest,
            "sha256_verified_after_copy":True,"acquired_at":now,"investigator":investigator,"notes":notes,
            "support_level":parsed.support_level,"format_id":parsed.format_id,"format_name":parsed.format_name,
            "parser":parsed.decoder,"parser_isolation":parser_isolation,"inspection":parsed.to_dict(),"source_path":safe}
        manifest=folder/"evidence.json"
        manifest.write_text(json.dumps(record,indent=2,ensure_ascii=False),encoding="utf-8")
        # Make source read-only as a guardrail; directories remain writable for derived manifests.
        try: original.chmod(0o440)
        except OSError: pass
        return record

    def list(self) -> list[dict[str,Any]]:
        rows=[]
        for p in sorted(self.evidence.glob("*/evidence.json"),key=lambda x:x.stat().st_mtime,reverse=True):
            try: rows.append(json.loads(p.read_text(encoding="utf-8")))
            except Exception: continue
        return rows

    def get(self,evidence_id: str) -> dict[str,Any] | None:
        if not re.fullmatch(r"EV-[A-F0-9]{12}",evidence_id): return None
        p=self.evidence/evidence_id/"evidence.json"
        if not p.is_file(): return None
        rec=json.loads(p.read_text(encoding="utf-8")); original=self.evidence/evidence_id/rec["stored_filename"]
        actual=self._sha(original) if original.is_file() else None
        return {**rec,"integrity":{"expected_sha256":rec["sha256"],"actual_sha256":actual,"status":"VALID" if actual==rec["sha256"] else "MISSING" if actual is None else "MODIFIED"}}

    def apply_schema(self, evidence_id: str, schema: dict[str, Any], investigator: str) -> dict[str, Any]:
        """Decode a custom fixed-width record layout without changing original evidence."""
        import struct
        rec=self.get(evidence_id)
        if not rec: raise KeyError(evidence_id)
        record_size=int(schema.get("record_size",0)); header_size=int(schema.get("header_size",0))
        endian=schema.get("endianness","little")
        if not 1 <= record_size <= 65536 or not 0 <= header_size <= 16*1024*1024:
            raise ValueError("record_size must be 1..65536 and header_size 0..16777216")
        if endian not in ("little","big"): raise ValueError("endianness must be little or big")
        fields=schema.get("fields")
        if not isinstance(fields,list) or not fields or len(fields)>256: raise ValueError("fields must contain 1..256 field definitions")
        types={"u8":("B",1),"i8":("b",1),"u16":("H",2),"i16":("h",2),"u32":("I",4),"i32":("i",4),"u64":("Q",8),"i64":("q",8),"f32":("f",4),"f64":("d",8)}
        normalized=[]
        for f in fields:
            name=str(f.get("name","")).strip(); typ=str(f.get("type","")); off=int(f.get("offset",-1))
            if not name or len(name)>96 or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*",name): raise ValueError("field name must be a valid identifier (max 96 chars)")
            if typ not in types: raise ValueError(f"unsupported field type: {typ}")
            code,width=types[typ]
            if off<0 or off+width>record_size: raise ValueError(f"field {name} extends beyond record_size")
            normalized.append({**f,"name":name,"type":typ,"offset":off,"_code":code,"_width":width})
        original=self.evidence/evidence_id/rec["stored_filename"]
        size=original.stat().st_size; count=max(0,(size-header_size)//record_size); count=min(count,20000)
        samples=[]; endian_prefix="<" if endian=="little" else ">"
        with original.open("rb") as fh:
            for idx in range(count):
                base=header_size+idx*record_size; fh.seek(base); raw=fh.read(record_size)
                if len(raw)!=record_size: break
                row={"_record_index":idx,"_byte_offset":base}
                for f in normalized:
                    value=struct.unpack_from(endian_prefix+f["_code"],raw,f["offset"])[0]
                    scale=float(f.get("scale",1.0)); bias=float(f.get("bias",0.0)); value=value*scale+bias
                    if isinstance(value,float) and not __import__("math").isfinite(value): value=None
                    row[f["name"]]=value
                samples.append(row)
        safe_schema={k:v for k,v in schema.items()}
        for f in normalized: f.pop("_code",None); f.pop("_width",None)
        result={"evidence_id":evidence_id,"source_sha256":rec["sha256"],"schema_version":1,"applied_at":datetime.now(timezone.utc).isoformat(),
            "investigator":investigator,"schema":safe_schema,"record_count_decoded":len(samples),"channels":[{"name":f["name"],"type":f["type"],"unit":f.get("unit"),"semantic":f.get("semantic","investigator-defined mapping")} for f in normalized],
            "samples":samples,"truncated_preview":count==20000,"provenance":"schema-driven decode; original bytes and SHA-256 retained"}
        derived=self.evidence/evidence_id/"derived"; derived.mkdir(exist_ok=True)
        (derived/"custom-schema-v1.json").write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding="utf-8")
        return result
