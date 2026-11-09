import { useEffect, useRef, useState } from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { api } from "../services/api";
import { Badge, Panel } from "../components/ui";

type Point={index:number;time:number|null;lat:number|null;lon:number|null;alt:number|null;roll_deg:number|null;pitch_deg:number|null;yaw_deg:number|null;raw?:any};
type Replay={points:Point[];has_geospatial:boolean;has_attitude:boolean;warnings:string[];sample_count:number;provenance:string;vehicle_profile?:any};
export default function SilktraceReplay({evidenceId}:{evidenceId:string}){
 const [data,setData]=useState<Replay|null>(null),[idx,setIdx]=useState(0),[busy,setBusy]=useState(false),[error,setError]=useState(""),[behavior,setBehavior]=useState<any>(null),[sandbox,setSandbox]=useState<any>(null),[playing,setPlaying]=useState(false),[speed,setSpeed]=useState(1),[profiles,setProfiles]=useState<any[]>([]),[profileId,setProfileId]=useState("");
 const mapHost=useRef<HTMLDivElement|null>(null),mapRef=useRef<L.Map|null>(null),markerRef=useRef<L.CircleMarker|null>(null),craftCanvas=useRef<HTMLCanvasElement|null>(null),trajectoryCanvas=useRef<HTMLCanvasElement|null>(null);
 const points=data?.points||[]; const current=points[Math.min(idx,Math.max(0,points.length-1))];
 const gpsPoint=points.slice(0,idx+1).reverse().find(p=>p.lat!==null&&p.lon!==null);
 const attitudePoint=points.slice(0,idx+1).reverse().find(p=>p.roll_deg!==null||p.pitch_deg!==null||p.yaw_deg!==null);
 useEffect(()=>{api.get<any>("/api/silktrace/vehicles").then(r=>setProfiles([...(r.profiles||[]),...(r.custom_profiles||[])] )).catch(e=>setError(e.message));},[]);
 useEffect(()=>{setData(null);setIdx(0);setPlaying(false);setBehavior(null);setSandbox(null);setError("");const q=profileId?`?profile_id=${encodeURIComponent(profileId)}`:"";api.get<Replay>(`/api/silktrace/evidence/${evidenceId}/replay${q}`).then(setData).catch(e=>setError(e.message));},[evidenceId,profileId]);
 useEffect(()=>{if(!playing||!points.length)return;const timer=window.setInterval(()=>setIdx(i=>i>=points.length-1?0:i+1),Math.max(40,1000/speed));return ()=>window.clearInterval(timer);},[playing,speed,points.length]);
 useEffect(()=>{
  if(!mapHost.current||!data?.has_geospatial||!points.length)return;
  const coords=points.filter(p=>p.lat!==null&&p.lon!==null).map(p=>[p.lat as number,p.lon as number] as L.LatLngExpression);
  if(!coords.length)return;
  const map=L.map(mapHost.current,{zoomControl:true,attributionControl:true,preferCanvas:true}).setView(coords[0],15);
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",{maxZoom:19,attribution:'© OpenStreetMap contributors'}).addTo(map);
  const line=L.polyline(coords,{color:'#9b8cff',weight:3,opacity:.9}).addTo(map);
  L.circleMarker(coords[0] as L.LatLngExpression,{radius:5,color:'#22c55e'}).addTo(map).bindTooltip('First recorded fix');
  L.circleMarker(coords[coords.length-1] as L.LatLngExpression,{radius:5,color:'#f97316'}).addTo(map).bindTooltip('Last recorded fix');
  markerRef.current=L.circleMarker(coords[0] as L.LatLngExpression,{radius:7,color:'#fbbf24',fillOpacity:1}).addTo(map);
  map.fitBounds(line.getBounds(),{padding:[24,24]});mapRef.current=map;
  return ()=>{map.remove();mapRef.current=null;markerRef.current=null;};
 },[data?.has_geospatial,evidenceId]);
 useEffect(()=>{if(!mapRef.current||!markerRef.current||!gpsPoint)return;markerRef.current.setLatLng([gpsPoint.lat as number,gpsPoint.lon as number]);},[idx,data]);
 useEffect(()=>{
  const canvas=trajectoryCanvas.current;if(!canvas||!data?.has_geospatial)return;
  const ctx=canvas.getContext('2d');if(!ctx)return;const w=canvas.width,h=canvas.height;ctx.clearRect(0,0,w,h);ctx.fillStyle='#0b1220';ctx.fillRect(0,0,w,h);
  const valid=points.filter(p=>p.lat!==null&&p.lon!==null);if(!valid.length)return;
  const lat0=valid[0].lat as number,lon0=valid[0].lon as number,cos=Math.cos(lat0*Math.PI/180);
  const raw=valid.map(p=>({p,x:((p.lon as number)-lon0)*111320*cos,y:((p.lat as number)-lat0)*111320,z:p.alt??0}));
  const spanX=Math.max(1,...raw.map(v=>Math.abs(v.x))),spanY=Math.max(1,...raw.map(v=>Math.abs(v.y))),spanZ=Math.max(1,...raw.map(v=>Math.abs(v.z-(valid[0].alt??0))));
  const project=(x:number,y:number,z:number)=>{x=x/spanX*1.7;y=y/spanY*1.7;z=(z-(valid[0].alt??0))/spanZ*1.2;const az=-Math.PI/4,el=Math.PI/6;const u=x*Math.cos(az)-y*Math.sin(az),v=(x*Math.sin(az)+y*Math.cos(az))*Math.sin(el)-z*Math.cos(el),depth=3.8+(x*Math.sin(az)+y*Math.cos(az))*Math.cos(el);return [w/2+u*145/depth,h/2-v*145/depth];};
  ctx.strokeStyle='#334155';ctx.lineWidth=1;for(let i=-2;i<=2;i++){const a=project(i*spanX/2, -spanY,0),b=project(i*spanX/2,spanY,0);ctx.beginPath();ctx.moveTo(a[0],a[1]);ctx.lineTo(b[0],b[1]);ctx.stroke();}
  ctx.beginPath();raw.forEach((v,i)=>{const q=project(v.x,v.y,v.z);i?ctx.lineTo(q[0],q[1]):ctx.moveTo(q[0],q[1]);});ctx.strokeStyle='#a78bfa';ctx.lineWidth=3;ctx.stroke();
  const active=raw.find(v=>v.p.index===gpsPoint?.index)||raw[0];const pos=project(active.x,active.y,active.z);ctx.fillStyle='#fbbf24';ctx.beginPath();ctx.arc(pos[0],pos[1],7,0,Math.PI*2);ctx.fill();
  ctx.fillStyle='#cbd5e1';ctx.font='11px sans-serif';ctx.fillText('3D recorded trajectory · local ENU-like projection',12,18);
 },[idx,data]);
 useEffect(()=>{
  const canvas=craftCanvas.current;if(!canvas||!data?.has_attitude||!attitudePoint)return;
  const ctx=canvas.getContext('2d');if(!ctx)return;const w=canvas.width,h=canvas.height;ctx.clearRect(0,0,w,h);ctx.fillStyle='#0b1220';ctx.fillRect(0,0,w,h);
  const roll=(attitudePoint.roll_deg||0)*Math.PI/180,pitch=(attitudePoint.pitch_deg||0)*Math.PI/180,yaw=(attitudePoint.yaw_deg||0)*Math.PI/180;
  const project=(v:number[])=>{let [x,y,z]=v;let a=x*Math.cos(yaw)-y*Math.sin(yaw),b=x*Math.sin(yaw)+y*Math.cos(yaw);let c=b*Math.cos(roll)-z*Math.sin(roll),d=b*Math.sin(roll)+z*Math.cos(roll);let e=a*Math.cos(pitch)+d*Math.sin(pitch),f=-a*Math.sin(pitch)+d*Math.cos(pitch);let depth=260+f*0.65;return [w/2+e*1050/depth,h/2-c*1050/depth];};
  ctx.strokeStyle='#334155';ctx.lineWidth=1;for(let i=-3;i<=3;i++){const a=project([-3,i,-.8]),b=project([3,i,-.8]);ctx.beginPath();ctx.moveTo(...a as [number,number]);ctx.lineTo(...b as [number,number]);ctx.stroke();}
  const vehicle=data?.vehicle_profile||{};const vehicleType=String(vehicle.vehicle_type||vehicle.kind||'unknown').toLowerCase();
  if(vehicleType.includes('fixed')){const wingA=project([-2.2,0,0]),wingB=project([2.2,0,0]),tailA=project([-0.8,-1.2,0]),tailB=project([0.8,-1.2,0]),nose=project([0,1.5,0]),tail=project([0,-1.4,0]);ctx.strokeStyle='#a78bfa';ctx.lineWidth=9;[[wingA,wingB],[tailA,tailB],[nose,tail]].forEach(([a,b])=>{ctx.beginPath();ctx.moveTo(a[0],a[1]);ctx.lineTo(b[0],b[1]);ctx.stroke();});}
  else {const actuators=Array.isArray(vehicle.actuators)?vehicle.actuators:[];const count=Math.max(1,Math.min(64,actuators.length||4));const positions=Array.isArray(vehicle.geometry?.actuator_positions)?vehicle.geometry.actuator_positions:null;const motors=positions?.length?positions.slice(0,64).map((p:any)=>[Number(p.x)||0,Number(p.y)||0,Number(p.z)||0]):Array.from({length:count},(_,i)=>{const a=2*Math.PI*i/count;return [Math.cos(a)*1.5,Math.sin(a)*1.5,0];});
   motors.forEach((m:number[],i:number)=>{const a=project([0,0,0]),b=project(m);ctx.strokeStyle=i%2?'#c4b5fd':'#8b7cff';ctx.lineWidth=8;ctx.beginPath();ctx.moveTo(a[0],a[1]);ctx.lineTo(b[0],b[1]);ctx.stroke();ctx.beginPath();ctx.arc(b[0],b[1],13,0,Math.PI*2);ctx.strokeStyle='#64748b';ctx.lineWidth=2;ctx.stroke();});}
  const c=project([0,0,0]);ctx.fillStyle='#fbbf24';ctx.beginPath();ctx.arc(c[0],c[1],7,0,Math.PI*2);ctx.fill();
  ctx.fillStyle='#cbd5e1';ctx.font='11px sans-serif';ctx.fillText(`ROLL ${attitudePoint.roll_deg?.toFixed(1)??'—'}°  PITCH ${attitudePoint.pitch_deg?.toFixed(1)??'—'}°  YAW ${attitudePoint.yaw_deg?.toFixed(1)??'—'}°`,12,18);
 },[idx,data]);
 const run=async(kind:"behavior"|"sandbox")=>{setBusy(true);setError("");try{const r=await api.post(`/api/silktrace/evidence/${evidenceId}/${kind}`);kind==="behavior"?setBehavior(r):setSandbox(r);}catch(e:any){setError(e.message||`${kind} failed`);}finally{setBusy(false);}};
 return <div className="col">
  <Panel title="Recorded flight replay · 2D geospatial" right={<Badge v={data?.has_geospatial?"GPS RECORDED":"NO GPS DATA"} tone={data?.has_geospatial?"ok":"warn"}/> }>
   {data?.has_geospatial?<><div ref={mapHost} style={{width:"100%",height:320,borderRadius:8,overflow:"hidden",background:"#0b1220"}}/><p className="small dim">Map marker follows the selected recorded sample. Map tiles are supplied by OpenStreetMap; the telemetry path itself is derived only from recorded coordinates.</p></>:<div className="notice">No valid latitude/longitude pairs were decoded. Geographic replay is disabled rather than inventing a route.</div>}
  </Panel>
  <Panel title="3D flight path · position and altitude" right={<Badge v={data?.has_geospatial?"RECORDED GPS":"UNAVAILABLE"} tone={data?.has_geospatial?"ok":"warn"}/> }>
   {data?.has_geospatial?<canvas ref={trajectoryCanvas} width={640} height={360} style={{width:"100%",height:300,background:"#0b1220",borderRadius:8}} aria-label="Three-dimensional reconstructed flight path"/>:<div className="notice">A 3D trajectory requires recorded GPS coordinates. No path is synthesized from attitude-only data.</div>}
   <p className="small dim">Local perspective projection of recorded latitude/longitude and altitude. Missing altitude is shown at the zero reference plane; no missing GPS samples are interpolated.</p>
  </Panel>
  <Panel title="Attitude replay · 3D orientation" right={<Badge v={data?.has_attitude?"ATTITUDE RECORDED":"NO ATTITUDE DATA"} tone={data?.has_attitude?"ok":"warn"}/> }><div className="row wrap small" style={{marginBottom:10}}><span className="dim">AIRFRAME PROFILE</span><select className="in" value={profileId} onChange={e=>setProfileId(e.target.value)} style={{maxWidth:320}}><option value="">Generic placeholder</option>{profiles.map((p:any)=><option key={p.id} value={p.id}>{p.name}</option>)}</select><span className="dim">{data?.vehicle_profile?.verified===false?"Investigator-defined / unverified":"Geometry may be illustrative"}</span></div>
   {data?.has_attitude&&current?<div style={{display:"grid",gridTemplateColumns:"minmax(180px,1fr) minmax(180px,1fr)",gap:16,alignItems:"center"}}>
    <canvas ref={craftCanvas} width={640} height={440} style={{width:"100%",height:220,background:"#0b1220",borderRadius:8}} aria-label="3D perspective vehicle attitude view"/>
    <div className="col small"><div><span className="dim">ROLL</span><h2>{attitudePoint?.roll_deg?.toFixed(2)??"—"}°</h2></div><div><span className="dim">PITCH</span><h2>{attitudePoint?.pitch_deg?.toFixed(2)??"—"}°</h2></div><div><span className="dim">YAW</span><h2>{attitudePoint?.yaw_deg?.toFixed(2)??"—"}°</h2></div><div className="dim">Perspective 3D projection uses the selected profile’s actuator count/positions when provided. Missing geometry falls back to an illustrative layout; this is not a physics simulation.</div></div>
   </div>:<div className="notice">No roll/pitch/yaw channels were decoded. 3D orientation replay is unavailable for this evidence.</div>}
  </Panel>
  {points.length>0&&<Panel title="Synchronized replay timeline" right={<span className="small dim">{idx+1} / {points.length}</span>}>
   <input aria-label="Replay position" type="range" min={0} max={Math.max(0,points.length-1)} value={idx} onChange={e=>setIdx(Number(e.target.value))} style={{width:"100%"}}/>
   <div className="row wrap small"><button className="btn sm primary" onClick={()=>setPlaying(v=>!v)}>{playing?"PAUSE":"PLAY"}</button><button className="btn sm" onClick={()=>{setPlaying(false);setIdx(0);}}>RESET</button><button className="btn sm" onClick={()=>setIdx(Math.max(0,idx-1))}>PREVIOUS SAMPLE</button><button className="btn sm" onClick={()=>setIdx(Math.min(points.length-1,idx+1))}>NEXT SAMPLE</button><label className="small dim">SPEED <select className="in" value={speed} onChange={e=>setSpeed(Number(e.target.value))} style={{display:"inline-block",width:86,padding:4}}>{[0.25,0.5,1,2,4,8].map(v=><option key={v} value={v}>{v}×</option>)}</select></label><span className="dim">Sample #{current?.index} · {current?.time??"time unavailable"}</span></div>
   <div className="grid g3 small" style={{marginTop:10}}><div>LAT <strong>{current?.lat??"—"}</strong></div><div>LON <strong>{current?.lon??"—"}</strong></div><div>ALT <strong>{current?.alt??"—"}</strong></div></div>
  </Panel>}
  {(data?.warnings ?? []).length > 0 && (
  <Panel title="Replay limitations">
    <ul>
      {(data?.warnings ?? []).map((w, i) => (
        <li key={i}>{w}</li>
      ))}
    </ul>
  </Panel>
)}
  <div className="grid g2">
   <Panel title="Behavioural anomaly screening"><p className="small dim">Runs robust MAD outlier screening and optional IsolationForest. Results are leads for review, not proof of fault or intrusion.</p><button className="btn primary" disabled={busy} onClick={()=>run("behavior")}>RUN ANALYSIS</button>{behavior&&<><div className="row wrap small"><Badge v={`${behavior.alerts?.length||0} candidate alerts`} tone="warn"/><Badge v={behavior.ml?.status||"ML not run"} tone="info"/></div><pre className="code" style={{maxHeight:260,overflow:"auto"}}>{JSON.stringify({method:behavior.method,features:behavior.features,alerts:behavior.alerts?.slice(0,30),ml:behavior.ml,limitations:behavior.limitations},null,2)}</pre></>}</Panel>
   <Panel title="Isolated parser execution"><p className="small dim">Re-runs reviewed built-in inspection in a separate Python process with CPU, memory, file-size and timeout limits. Arbitrary third-party plugins are not executed.</p><button className="btn" disabled={busy} onClick={()=>run("sandbox")}>RUN ISOLATED INSPECTION</button>{sandbox&&<pre className="code" style={{maxHeight:260,overflow:"auto"}}>{JSON.stringify(sandbox,null,2)}</pre>}</Panel>
  </div>
  {error&&<div className="notice crit">{error}</div>}
 </div>;
}
