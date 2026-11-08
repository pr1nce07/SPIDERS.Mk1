// Packet inspector (spec §40): virtualised table, live tail or historical query, raw + decoded detail.
import { useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { api, qs } from "../services/api";
import { getState, setState, toast, useLive } from "../services/store";
import { useRoute } from "../lib/nav";
import { PacketView } from "../components/Drawers";
import { Badge, Empty, PageTitle, Panel, Seg } from "../components/ui";
import { time } from "../lib/format";
import type { Packet } from "../types";

export default function Packets() {
  const route = useRoute();
  const live = useLive((s) => s.packets);
  const paused = useLive((s) => s.packetsPaused);
  const sid = useLive((s) => s.sessionId);
  const [mode, setMode] = useState<"live" | "query">(route.query.get("session") ? "query" : "live");
  const [session, setSession] = useState(route.query.get("session") || "");
  const [q, setQ] = useState("");
  const [msg, setMsg] = useState("");
  const [sysid, setSysid] = useState("");
  const [errorsOnly, setErrorsOnly] = useState(false);
  const [rows, setRows] = useState<Packet[]>([]);
  const [sel, setSel] = useState<Packet | null>(null);
  const [tFrom, setTFrom] = useState("");
  const [sessions, setSessions] = useState<any[]>([]);
  useEffect(() => { api.get("/api/sessions").then(setSessions).catch(() => {}); }, []);
  const run = async () => {
    const s = session || sid;
    if (!s) return;
    const t = tFrom ? Date.parse(tFrom.endsWith("Z") ? tFrom : tFrom + "Z") / 1000 : undefined;
    const r = await api.get(`/api/mavlink/messages${qs({ session_id: s, msg, sysid, q, errors_only: errorsOnly || undefined, t_from: t, limit: 5000 })}`).catch((e) => { toast(e.message, "error"); return { messages: [] }; });
    setRows(r.messages);
  };
  useEffect(() => { if (mode === "query") run(); }, [mode, session]);
  useEffect(() => {
    const idx = route.query.get("idx");
    const s = route.query.get("session");
    if (idx && s) api.get(`/api/mavlink/messages/${s}/${idx}`).then(setSel).catch(() => {});
  }, [route.query.toString()]);
  const data = useMemo(() => {
    const base = mode === "live" ? live.slice().reverse() : rows;
    return base.filter((p) => (!msg || p.msg.includes(msg.toUpperCase())) && (!sysid || String(p.sysid) === sysid) && (!q || JSON.stringify(p).toLowerCase().includes(q.toLowerCase())) && (!errorsOnly || p.err));
  }, [mode, live, rows, msg, sysid, q, errorsOnly]);
  const parent = useRef<HTMLDivElement>(null);
  const v = useVirtualizer({ count: data.length, getScrollElement: () => parent.current, estimateSize: () => 27, overscan: 20 });
  const pick = (p: Packet) => api.get(`/api/mavlink/messages/${mode === "live" ? sid : session || sid}/${p.idx}`).then(setSel).catch((e) => toast(e.message, "error"));
  const cols = "90px 50px 50px 50px 60px minmax(160px,1fr) 110px 110px";
  return (
    <div className="col">
      <PageTitle title="Packet inspector" sub={`${data.length} frames`} right={<Seg value={mode} onChange={setMode} options={[{ v: "live", l: "Live tail" }, { v: "query", l: "Session query" }]} />} />
      <Panel><div className="row wrap">
        {mode === "query" && <select className="in" value={session} onChange={(e) => setSession(e.target.value)}><option value="">current session</option>{sessions.map((s) => <option key={s.session_id} value={s.session_id}>{s.session_id}</option>)}</select>}
        <input className="in" placeholder="Search fields/text" value={q} onChange={(e) => setQ(e.target.value)} />
        <input className="in" placeholder="Message" value={msg} onChange={(e) => setMsg(e.target.value)} style={{ width: 160 }} />
        <input className="in" placeholder="SYSID" value={sysid} onChange={(e) => setSysid(e.target.value)} style={{ width: 80 }} />
        <label className="row small"><input type="checkbox" checked={errorsOnly} onChange={(e) => setErrorsOnly(e.target.checked)} />parse errors only</label>
        {mode === "query" && <><input className="in" placeholder="Jump to UTC 2026-09-26T13:30:00" value={tFrom} onChange={(e) => setTFrom(e.target.value)} /><button className="btn" onClick={run}>Query</button></>}
        {mode === "live" && <button className="btn" onClick={() => setState({ packetsPaused: !getState().packetsPaused })}>{paused ? "Resume" : "Pause"}</button>}
      </div></Panel>
      <div className="grid" style={{ gridTemplateColumns: sel ? "minmax(0,1fr) 460px" : "1fr" }}>
        <Panel flush>
          <div className="tbl" style={{ display: "grid", gridTemplateColumns: cols, fontSize: 10.5, color: "var(--muted)", fontWeight: 700, padding: "7px 10px", borderBottom: "1px solid var(--line)" }}>
            <span>TIME</span><span>SYS</span><span>COMP</span><span>SEQ</span><span>ID</span><span>MESSAGE</span><span>SOURCE</span><span>SIGNING</span>
          </div>
          {data.length === 0 ? <Empty title="NO PACKETS" text="Connect a source or pick a session." /> : (
            <div ref={parent} style={{ height: "calc(100vh - 290px)", overflow: "auto" }}>
              <div style={{ height: v.getTotalSize(), position: "relative" }}>
                {v.getVirtualItems().map((it) => {
                  const p = data[it.index];
                  return (
                    <div key={it.key} onClick={() => pick(p)} className="mono"
                      style={{ position: "absolute", top: 0, left: 0, right: 0, transform: `translateY(${it.start}px)`, height: 27, display: "grid", gridTemplateColumns: cols, alignItems: "center", padding: "0 10px", borderBottom: "1px solid var(--line)", cursor: "pointer", fontSize: 11.5, background: sel?.idx === p.idx ? "rgba(85,194,255,0.08)" : p.err ? "var(--crit-bg)" : undefined }}>
                      <span>{time(p.t, true)}</span><span>{p.sysid ?? "?"}</span><span>{p.compid ?? "?"}</span><span>{p.seq ?? "?"}</span><span>{p.msg_id ?? "?"}</span>
                      <span style={{ fontFamily: "var(--sans)" }}>{p.msg}{p.err ? <span className="t-crit"> ⚠ {p.err}</span> : null}</span><span className="dim">{p.source}</span>
                      <span>{p.signed ? <Badge v={p.sig || "SIGNED"} tone="info" /> : <span className="muted">unsigned</span>}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </Panel>
        {sel && <Panel title={`#${sel.idx} ${sel.msg}`} right={<button className="btn sm" onClick={() => setSel(null)}>✕</button>}><PacketView p={sel} /></Panel>}
      </div>
    </div>
  );
}
