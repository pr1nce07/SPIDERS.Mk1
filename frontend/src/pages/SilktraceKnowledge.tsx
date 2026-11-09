import { useEffect, useState } from "react";
import { api } from "../services/api";
import { Badge, Panel } from "../components/ui";
export default function SilktraceKnowledge(){
 const [data,setData]=useState<any>(null),[name,setName]=useState(""),[type,setType]=useState("unknown"),[actuators,setActuators]=useState("4"),[error,setError]=useState("");
 const refresh=()=>api.get("/api/silktrace/vehicles").then(setData).catch(e=>setError(e.message));useEffect(()=>{refresh();},[]);
 const save=async()=>{try{setError("");const n=Number(actuators);if(!Number.isInteger(n)||n<0||n>64)throw new Error("Actuator count must be 0–64");await api.post("/api/silktrace/vehicles",{name,vehicle_type:type,actuators:Array.from({length:n},(_,i)=>({channel:i+1,label:`Actuator ${i+1}`})),sensors:[],geometry:{}});setName("");refresh();}catch(e:any){setError(e.message||"Profile save failed");}};
 return <Panel title="Vehicle & firmware knowledge base" right={<Badge v="REFERENCE + CUSTOM" tone="info"/>}>
  <p className="small dim">Built-in entries index format and parameter references. They are not authoritative aircraft performance specifications. Custom profiles are investigator-supplied and remain unverified until supported by evidence.</p>
  <div className="grid g2">{(data?.profiles||[]).map((p:any)=><div className="panel" key={p.id}><strong>{p.name}</strong><div className="small dim">{p.kind} · {p.status}</div><div className="small">Formats: {p.formats.join(", ")}</div><div className="small">Parameter namespaces: {p.parameter_prefixes.join(", ")||"Custom"}</div>{p.references.map((u:string)=><div className="small" key={u}><a href={u} target="_blank" rel="noreferrer">{u}</a></div>)}</div>)}</div>
  <div className="grid g3" style={{marginTop:12}}><input className="in" placeholder="Custom aircraft profile name" value={name} onChange={e=>setName(e.target.value)}/><select className="in" value={type} onChange={e=>setType(e.target.value)}><option value="unknown">Unknown</option><option value="multirotor">Multirotor</option><option value="fixed-wing">Fixed wing</option><option value="vtol">VTOL / hybrid</option><option value="helicopter">Helicopter</option><option value="custom">Other custom</option></select><input className="in" type="number" min="0" max="64" value={actuators} onChange={e=>setActuators(e.target.value)} placeholder="Actuator count"/></div>
  <button className="btn primary" style={{marginTop:8}} disabled={!name.trim()} onClick={save}>SAVE CUSTOM VEHICLE PROFILE</button>
  {error&&<div className="notice crit">{error}</div>}
  {!!data?.custom_profiles?.length&&<div style={{marginTop:12}}><strong>Investigator profiles ({data.custom_profiles.length})</strong><pre className="code" style={{maxHeight:220,overflow:"auto"}}>{JSON.stringify(data.custom_profiles,null,2)}</pre></div>}
 </Panel>;
}
