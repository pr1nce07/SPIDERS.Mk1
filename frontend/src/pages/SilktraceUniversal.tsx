import { useEffect, useMemo, useState } from "react";
import { api } from "../services/api";
import SilktraceReplay from "./SilktraceReplay";
import SilktraceKnowledge from "./SilktraceKnowledge";
import { Badge, Empty, JsonView, KV, PageTitle, Panel, State } from "../components/ui";

type Evidence = { evidence_id:string; original_filename:string; size_bytes:number; sha256:string; acquired_at:string; support_level:string; format_id:string; format_name:string; inspection?:any; integrity?:any; notes?:string; sha256_verified_after_copy?:boolean };
const fmt=(n:number)=>n<1024?`${n} B`:n<1048576?`${(n/1024).toFixed(1)} KB`:`${(n/1048576).toFixed(2)} MB`;

export default function SilktraceUniversal(){
  const [items,setItems]=useState<Evidence[]>([]); const [selected,setSelected]=useState<Evidence|null>(null);
  const [file,setFile]=useState<File|null>(null); const [notes,setNotes]=useState(""); const [busy,setBusy]=useState(false); const [error,setError]=useState(""); const [schemaText,setSchemaText]=useState(JSON.stringify({record_size:16,header_size:0,endianness:"little",fields:[{name:"time_ms",offset:0,type:"u32",unit:"ms",semantic:"timestamp"},{name:"candidate_value",offset:4,type:"f32",unit:"unknown"}]},null,2)); const [customDecode,setCustomDecode]=useState<any>(null);
  const refresh=()=>api.get<Evidence[]>("/api/silktrace/evidence").then(setItems).catch(e=>setError(e.message));
  useEffect(()=>{refresh();},[]);
  const upload=async()=>{if(!file)return;setBusy(true);setError("");try{const f=new FormData();f.append("file",file);f.append("notes",notes);const r=await api.upload<Evidence>("/api/silktrace/evidence",f);setSelected(r);setFile(null);setNotes("");await refresh();}catch(e:any){setError(e.message||"Evidence intake failed");}finally{setBusy(false);}};
  const detail=useMemo(()=>selected?.inspection||null,[selected]);
  return <div className="col">
    <div className="grid g2">
      <Panel title="Acquire blackbox / drone evidence">
        <div className="col">
          <input className="in" type="file" onChange={e=>setFile(e.target.files?.[0]||null)} />
          <textarea className="in" rows={3} placeholder="Acquisition notes, source device, context (optional)" value={notes} onChange={e=>setNotes(e.target.value)} />
          <div className="row wrap"><button className="btn primary" disabled={!file||busy} onClick={upload}>{busy?"PRESERVING…":"PRESERVE & INSPECT"}</button>{file&&<span className="small dim">{file.name} · {fmt(file.size)}</span>}</div>
          <p className="small dim">Unknown formats are accepted and hashed. A recognized file signature does not guarantee semantic decoding. Original evidence is stored separately from derived inspection results.</p>
          {error&&<div className="notice crit">{error}</div>}
        </div>
      </Panel>
      <Panel title="Compatibility model">
        <div className="col small">
          {[["L0","Evidence acceptance","Hash, preserve and register"],["L1","Structural inspection","Signatures, size, entropy, headers"],["L2","Generic extraction","Recognizable structure and candidate fields"],["L3","Semantic decoding","Known parsers or structured formats"],["L4–L6","Vehicle analysis → findings","Profile, replay and forensic conclusions — staged expansion"]].map(x=><div className="row" key={x[0]}><Badge v={x[0]} tone="info"/><div><strong>{x[1]}</strong><div className="dim">{x[2]}</div></div></div>)}
        </div>
      </Panel>
    </div>
    <SilktraceKnowledge/>
    <Panel title={`Evidence register (${items.length})`} flush right={<button className="btn sm" onClick={refresh}>Refresh</button>}>
      {!items.length?<Empty title="NO SILKTRACE EVIDENCE" text="Import a blackbox recording, telemetry file, controller artifact or unknown binary file. Evidence acceptance does not depend on drone identification."/>:
      <table className="tbl"><thead><tr><th>Evidence ID / File</th><th>Detected format</th><th>Level</th><th>Size</th><th>SHA-256</th></tr></thead><tbody>{items.map(x=><tr key={x.evidence_id} className="click" onClick={()=>api.get<Evidence>(`/api/silktrace/evidence/${x.evidence_id}`).then(setSelected).catch(e=>setError(e.message))}><td><strong className="mono">{x.evidence_id}</strong><div className="small dim">{x.original_filename}</div></td><td>{x.format_name}<div className="small dim">{x.format_id}</div></td><td><State s={x.support_level}/></td><td className="mono">{fmt(x.size_bytes)}</td><td className="mono small">{x.sha256.slice(0,18)}…</td></tr>)}</tbody></table>}
    </Panel>
    {selected&&<>
      <PageTitle title={`${selected.evidence_id} · Inspection`} sub={selected.original_filename} right={<button className="btn sm" onClick={()=>setSelected(null)}>Close</button>}/>
      <div className="grid g2">
        <Panel title="Evidence integrity"><KV rows={[["Format",selected.format_name],["Support",selected.support_level],["Size",fmt(selected.size_bytes)],["SHA-256",selected.sha256],["Acquired",selected.acquired_at],["Copy verification",selected.sha256_verified_after_copy?"VALID":"NOT VERIFIED"],["Integrity recheck",selected.integrity?.status||"Not rechecked"]]}/></Panel>
        <Panel title="Parser assessment"><KV rows={[["Decoder",detail?.decoder],["Confidence",detail?.confidence],["Records",detail?.records],["Channels",detail?.channels?.length??0],["Warnings",detail?.warnings?.length??0],["Limitations",detail?.limitations?.length??0]]}/></Panel>
      </div>
      {detail?.channels?.length>0&&<Panel title="Extracted / candidate channels" flush><table className="tbl"><thead><tr><th>Field</th><th>Type</th><th>Meaning</th><th>Count / range</th></tr></thead><tbody>{detail.channels.map((c:any,i:number)=><tr key={i}><td className="mono">{c.name}</td><td>{c.type||"—"}</td><td>{c.semantic||"—"}</td><td className="mono small">{c.count??"—"} {c.min!==undefined?`· ${c.min} … ${c.max}`:""}</td></tr>)}</tbody></table></Panel>}
      {detail?.warnings?.length>0&&<Panel title="Warnings"><ul>{detail.warnings.map((w:string,i:number)=><li key={i}>{w}</li>)}</ul></Panel>}
      {detail?.limitations?.length>0&&<Panel title="Limitations"><ul>{detail.limitations.map((w:string,i:number)=><li key={i}>{w}</li>)}</ul></Panel>}
      <Panel title="Custom binary schema mapping" right={<button className="btn sm primary" onClick={async()=>{try{setError("");const result=await api.post(`/api/silktrace/evidence/${selected.evidence_id}/schema`,JSON.parse(schemaText));setCustomDecode(result);}catch(e:any){setError(e.message||"Schema mapping failed");}}}>APPLY MAPPING</button>}>
        <p className="small dim">Define a fixed-width record layout. Offsets are relative to each record. Supported types: u8/i8/u16/i16/u32/i32/u64/i64/f32/f64. Values are investigator-mapped, not automatically identified.</p>
        <textarea className="in code" rows={10} value={schemaText} onChange={e=>setSchemaText(e.target.value)} spellCheck={false}/>
        {error&&<div className="notice crit">{error}</div>}
      </Panel>
      {customDecode&&<Panel title={`Custom decode · ${customDecode.record_count_decoded} records`}><KV rows={[["Source hash",customDecode.source_sha256],["Schema version",customDecode.schema_version],["Provenance",customDecode.provenance]]}/><pre className="code" style={{maxHeight:360,overflow:"auto"}}>{JSON.stringify(customDecode.samples?.slice(0,30),null,2)}</pre></Panel>}
      <SilktraceReplay evidenceId={selected.evidence_id}/>
      <Panel title="Inspection metadata"><JsonView data={detail?.metadata||{}}/></Panel>
      {detail?.samples?.length>0&&<Panel title={`Decoded preview (${detail.samples.length} rows)`}><pre className="code" style={{maxHeight:360,overflow:"auto"}}>{JSON.stringify(detail.samples.slice(0,30),null,2)}</pre></Panel>}
    </>}
  </div>;
}
