// Logs & analytics (spec §44, §67–71, §79): import, sessions, overlays, correlation,
// frequency, source analysis, flight comparison, config diff, audit log.
import { useMemo, useState } from "react";
import { api, qs } from "../services/api";
import { toast, useLive } from "../services/store";
import { go } from "../lib/nav";
import Chart, { Heatmap } from "../charts/Chart";
import { Badge, Empty, ErrorNote, PageTitle, Panel, State, Tabs, useAsync } from "../components/ui";
import { ConfigDiff } from "./Incidents";
import { bytes, dateTime } from "../lib/format";

const FIELDS = ["gps_speed", "ekf_speed", "groundspeed", "altitude_rel", "battery_v", "ekf_vel_var", "satellites", "hdop", "rc_rssi"];

export default function Logs() {
  const [tab, setTab] = useState("import");
  return (
    <div className="col">
      <PageTitle title="Logs & analytics" />
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "import", label: "Import" }, { id: "sessions", label: "Sessions" }, { id: "analytics", label: "Analytics" }, { id: "compare", label: "Flight comparison" }, { id: "diff", label: "Config diff" }, { id: "audit", label: "Audit log" }, { id: "system", label: "System events" }]} />
      {tab === "import" && <Import />}
      {tab === "sessions" && <Sessions />}
      {tab === "analytics" && <Analytics />}
      {tab === "compare" && <Compare />}
      {tab === "diff" && <DiffTab />}
      {tab === "audit" && <Audit />}
      {tab === "system" && <SystemEvents />}
    </div>
  );
}

function Import() {
  const { data, reload } = useAsync<any[]>(() => api.get("/api/logs/imports"), [], 2000);
  const [busy, setBusy] = useState(false);
  const upload = async (f: File) => {
    setBusy(true);
    const fd = new FormData();
    fd.append("file", f);
    try {
      const r = await api.upload("/api/logs/import", fd);
      toast(`${r.filename}: ${r.status} (${r.format})`, r.status === "REJECTED" ? "error" : "ok");
      reload();
    } catch (e: any) { toast(e.message, "error"); } finally { setBusy(false); }
  };
  return (
    <div className="col">
      <Panel title="Import evidence source">
        <div className="row wrap">
          <input type="file" accept=".tlog,.bin,.log,.csv,.json,.jsonl,.zip" disabled={busy} onChange={(e) => e.target.files?.[0] && upload(e.target.files[0])} />
          <span className="small muted">.tlog · DataFlash .bin/.log · .csv · .json/.jsonl · exported case .zip — hashed (SHA-256) before parsing; never executed; archives extracted with path-traversal checks.</span>
        </div>
      </Panel>
      <Panel flush>{!data?.length ? <Empty title="NO IMPORTS" /> : (
        <table className="tbl"><thead><tr><th>File</th><th>Source hash (SHA-256)</th><th className="right">Size</th><th>Format</th><th>Import time</th><th>Parser</th><th>Status</th><th>Result</th></tr></thead><tbody>
          {data.map((i) => (
            <tr key={i.import_id}>
              <td>{i.filename}<div className="muted small mono">{i.import_id}</div></td><td className="mono small" title={i.sha256}>{i.sha256.slice(0, 24)}…</td>
              <td className="right mono small">{bytes(i.size)}</td><td>{i.format}</td><td className="mono small">{dateTime(i.imported_at)}</td><td className="small">{i.parser_version}</td>
              <td><State s={i.status} /> {i.status === "ANALYZING" && <span className="mono small">{i.progress}%</span>}{i.meta?.error && <div className="err-text">{i.meta.error}</div>}</td>
              <td className="small">{i.meta?.summary ? <>{i.meta.summary.packets} records · {i.meta.summary.alerts} alerts · <a onClick={() => go(`incidents?session=${i.session_id}`)}>{i.meta.summary.incidents} incidents</a></> : null}
                {i.meta?.verification && <div>case verify: <State s={i.meta.verification.status} /></div>}</td>
            </tr>
          ))}
        </tbody></table>)}
      </Panel>
    </div>
  );
}

function Sessions() {
  const { data } = useAsync<any[]>(() => api.get("/api/sessions"), [], 5000);
  return (
    <Panel flush>{!data?.length ? <Empty title="NO SESSIONS" /> : (
      <table className="tbl"><thead><tr><th>Session</th><th>Kind</th><th>Source</th><th>Started</th><th>Ended</th><th className="right">Packets</th><th>Source hash</th></tr></thead><tbody>
        {data.map((s) => <tr key={s.session_id}><td className="mono small">{s.session_id} {s.active && <Badge v="ACTIVE" tone="ok" />}</td><td>{s.kind}</td><td className="small">{s.source}</td><td className="mono small">{s.started_at?.substring(0, 19)}</td><td className="mono small">{s.ended_at?.substring(0, 19) || "—"}</td><td className="right mono">{s.packets}</td><td className="mono small">{s.source_hash?.slice(0, 16) || "—"}</td></tr>)}
      </tbody></table>)}
    </Panel>
  );
}

function useSessionPicker() {
  const cur = useLive((s) => s.sessionId);
  const { data } = useAsync<any[]>(() => api.get("/api/sessions"), []);
  const [sid, setSid] = useState("");
  const s = sid || cur || data?.[0]?.session_id || "";
  const el = <select className="in" value={s} onChange={(e) => setSid(e.target.value)}>{(data || []).map((x) => <option key={x.session_id} value={x.session_id}>{x.session_id} ({x.kind})</option>)}</select>;
  return { sid: s, el, sessions: data || [] };
}

function Analytics() {
  const { sid, el } = useSessionPicker();
  const [fields, setFields] = useState(["gps_speed", "ekf_speed", "groundspeed"]);
  const series = useAsync<any>(() => sid ? api.get(`/api/analytics/series${qs({ session_id: sid, fields: fields.join(",") })}`) : Promise.resolve(null), [sid, fields.join()]);
  const corr = useAsync<any>(() => sid ? api.get(`/api/analytics/correlation${qs({ session_id: sid })}`) : Promise.resolve(null), [sid]);
  const freq = useAsync<any>(() => sid ? api.get(`/api/analytics/frequency${qs({ session_id: sid })}`) : Promise.resolve(null), [sid]);
  const srcs = useAsync<any[]>(() => sid ? api.get(`/api/analytics/sources${qs({ session_id: sid })}`) : Promise.resolve([]), [sid]);
  const hist = useAsync<any>(() => sid ? api.get(`/api/analytics/detector-history${qs({ session_id: sid })}`) : Promise.resolve(null), [sid]);
  const ser = useMemo(() => Object.entries(series.data?.series || {}).map(([k, v]: any) => ({ name: `${k}`, points: v.points, axis: (["ekf_vel_var", "hdop", "satellites"].includes(k) ? 1 : 0) as 0 | 1 })), [series.data]);
  return (
    <div className="col">
      <div className="row wrap">{el}{FIELDS.map((f) => <label key={f} className="row small"><input type="checkbox" checked={fields.includes(f)} onChange={(e) => setFields(e.target.checked ? [...fields, f] : fields.filter((x) => x !== f))} />{f}</label>)}</div>
      <Panel title="Time-series overlay (e.g. GPS vs EKF vs ground speed)"><Chart series={ser} height={280} exportName={`${sid}-overlay`} /><div className="small muted">{Object.entries(series.data?.series || {}).map(([k, v]: any) => `${k} ← ${v.provenance}`).join(" · ")}</div></Panel>
      <div className="grid g2">
        <Panel title="Correlation matrix">{corr.data?.fields?.length ? <Heatmap labels={corr.data.fields} matrix={corr.data.matrix} /> : <Empty title="NOT ENOUGH DATA" />}</Panel>
        <Panel title="Detector score history"><Chart height={300} series={Object.entries(hist.data || {}).slice(0, 8).map(([k, v]: any) => ({ name: k, points: v.filter((x: any) => x[1] != null).map((x: any) => [x[0], x[1]]), step: true }))} /></Panel>
      </div>
      <div className="grid g2">
        <Panel title="Message frequency (per second)"><Chart height={260} series={Object.entries(freq.data?.series || {}).slice(0, 8).map(([k, v]: any) => ({ name: k, points: v }))} /></Panel>
        <Panel title="Source analysis" flush><table className="tbl"><thead><tr><th>SYSID</th><th>COMPID</th><th>Role</th><th className="right">Count</th><th>Links</th></tr></thead><tbody>
          {(srcs.data || []).map((s: any) => <tr key={`${s.sysid}-${s.compid}`}><td className="mono">{s.sysid}</td><td className="mono">{s.compid}</td><td><State s={s.role || "N/A"} /></td><td className="right mono">{s.count}</td><td className="small">{(s.links || []).join(", ")}</td></tr>)}
        </tbody></table></Panel>
      </div>
    </div>
  );
}

function Compare() {
  const { sessions } = useSessionPicker();
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const r = useAsync<any>(() => a && b ? api.get(`/api/analytics/compare${qs({ a, b })}`) : Promise.resolve(null), [a, b]);
  const sel = (v: string, set: (x: string) => void) => <select className="in" value={v} onChange={(e) => set(e.target.value)}><option value="">— session —</option>{sessions.map((s) => <option key={s.session_id} value={s.session_id}>{s.session_id} ({s.kind})</option>)}</select>;
  const fields = r.data ? Object.keys(r.data.sessions[a] || {}).filter((k) => !k.startsWith("_")) : [];
  return (
    <div className="col">
      <div className="row">A {sel(a, setA)} B {sel(b, setB)}<span className="small muted">aligned on relative time</span></div>
      <ErrorNote error={r.error} />
      {r.data && <>
        <table className="tbl"><thead><tr><th>Metric</th><th>A</th><th>B</th></tr></thead><tbody>
          {Object.keys(r.data.sessions[a]._stats).map((k) => <tr key={k}><td>{k}</td><td className="mono">{r.data.sessions[a]._stats[k]}</td><td className="mono">{r.data.sessions[b]._stats[k]}</td></tr>)}
        </tbody></table>
        <div className="grid g2">{fields.map((f) => <Panel key={f} title={f}><Chart height={200} series={[{ name: "A", points: r.data.sessions[a][f].points }, { name: "B", points: r.data.sessions[b][f].points }]} /></Panel>)}</div>
      </>}
    </div>
  );
}

function DiffTab() {
  const [b, setB] = useState("previous");
  return <div className="col"><div className="row">Compare current with <input className="in" value={b} onChange={(e) => setB(e.target.value)} /><span className="small muted">previous · incident:INC-…</span></div><Panel><ConfigDiff a="current" b={b} /></Panel></div>;
}

function Audit() {
  const { data } = useAsync<any[]>(() => api.get("/api/audit"), [], 5000);
  const v = useAsync<any>(() => api.get("/api/audit/verify"), [], 5000);
  return (
    <div className="col">
      <div className="row"><strong>Hash-chained audit log</strong>{v.data && <State s={v.data.status} />}<span className="small muted">{v.data?.entries} entries · head {v.data?.head?.slice(0, 16)}…</span></div>
      <Panel flush><table className="tbl"><thead><tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th><th>Hash</th></tr></thead><tbody>
        {(data || []).map((e) => <tr key={e.seq}><td className="mono">{e.seq}</td><td className="mono small">{e.ts?.substring(0, 19)}</td><td className="small">{e.actor} ({e.role})</td><td><Badge v={e.action} outline /></td><td className="mono small">{e.target}</td><td className="mono small" style={{ maxWidth: 380, overflow: "hidden", textOverflow: "ellipsis" }}>{JSON.stringify(e.detail)}</td><td className="mono small">{e.hash.slice(0, 10)}…</td></tr>)}
      </tbody></table></Panel>
    </div>
  );
}

function SystemEvents() {
  const { data } = useAsync<any[]>(() => api.get("/api/system/events?limit=500"), [], 5000);
  return <Panel flush><table className="tbl"><tbody>{(data || []).map((e) => <tr key={e.id}><td className="mono small">{dateTime(e.t)}</td><td><Badge v={e.type} outline /></td><td>{e.message}</td><td className="mono small muted">{e.session_id}</td></tr>)}</tbody></table></Panel>;
}
