// SOC alert center (spec §32). Marking false positive never deletes evidence.
import { useState } from "react";
import { api, downloadText, qs, toCSV } from "../services/api";
import { toast } from "../services/store";
import { go, openDrawer } from "../lib/nav";
import { Confidence, Empty, ErrorNote, PageTitle, Panel, State, useAsync } from "../components/ui";
import { dateTime } from "../lib/format";
import type { Alert } from "../types";

export default function Alerts() {
  const [f, setF] = useState<Record<string, string>>({ severity: "", detector: "", source: "", status: "", q: "", min_conf: "", session_id: "" });
  const { data, error, reload } = useAsync<Alert[]>(() => api.get(`/api/ids/events${qs({ ...f, limit: 1000 })}`), [JSON.stringify(f)], 3000);
  const { data: sessions } = useAsync<any[]>(() => api.get("/api/sessions"), []);
  const set = (k: string, v: string) => setF((x) => ({ ...x, [k]: v }));
  const act = async (a: Alert, status: string) => {
    try {
      await api.post(`/api/ids/events/${a.alert_id}/status`, { status, note: "" });
      toast(`${a.alert_id} → ${status} (evidence preserved)`, "ok");
      reload();
    } catch (e: any) { toast(e.message, "error"); }
  };
  const snap = async (a: Alert) => {
    try {
      const r = await api.post("/api/forensics/snapshot", { incident_id: a.incident_id || undefined, reason: `alert ${a.alert_id}` });
      toast(`Snapshot ${r.case_id} collecting`, "ok");
    } catch (e: any) { toast(e.message, "error"); }
  };
  const rows = data || [];
  return (
    <div className="col">
      <PageTitle title="Alert Center" sub={`${rows.length} alerts`} right={<>
        <button className="btn sm" onClick={() => downloadText("alerts.csv", toCSV(rows as any), "text/csv")}>Export CSV</button>
        <button className="btn sm" onClick={() => downloadText("alerts.json", JSON.stringify(rows, null, 2), "application/json")}>Export JSON</button></>} />
      <Panel>
        <div className="row wrap">
          <input className="in" placeholder="Search…" value={f.q} onChange={(e) => set("q", e.target.value)} />
          <select className="in" value={f.severity} onChange={(e) => set("severity", e.target.value)}><option value="">All severities</option>{["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((s) => <option key={s}>{s}</option>)}</select>
          <select className="in" value={f.source} onChange={(e) => set("source", e.target.value)}><option value="">All sources</option>{["GROUND", "FC", "LUA"].map((s) => <option key={s}>{s}</option>)}</select>
          <select className="in" value={f.status} onChange={(e) => set("status", e.target.value)}><option value="">All statuses</option>{["NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"].map((s) => <option key={s}>{s}</option>)}</select>
          <input className="in" placeholder="Detector" value={f.detector} onChange={(e) => set("detector", e.target.value.toUpperCase())} style={{ width: 150 }} />
          <input className="in" placeholder="Min conf 0–1" value={f.min_conf} onChange={(e) => set("min_conf", e.target.value)} style={{ width: 110 }} />
          <select className="in" value={f.session_id} onChange={(e) => set("session_id", e.target.value)}><option value="">All flights/sessions</option>{(sessions || []).map((s) => <option key={s.session_id} value={s.session_id}>{s.session_id}</option>)}</select>
        </div>
      </Panel>
      <ErrorNote error={error} />
      <Panel flush>
        {rows.length === 0 ? <Empty title="NO ALERTS" text="No alerts match the current filters." /> : (
          <div className="scroll" style={{ maxHeight: "calc(100vh - 260px)" }}>
            <table className="tbl">
              <thead><tr><th>Time</th><th>Severity</th><th>Incident</th><th>Detector</th><th>Source</th><th>Confidence</th><th>Evidence</th><th>Status</th><th>Actions</th></tr></thead>
              <tbody>
                {rows.map((a) => (
                  <tr key={a.alert_id}>
                    <td className="mono small nowrap">{dateTime(a.t)}</td>
                    <td><State s={a.severity} /></td>
                    <td>{a.incident_id ? <a onClick={() => go(`incidents/${a.incident_id}`)}>{a.incident_id}</a> : <span className="muted">—</span>}</td>
                    <td><a onClick={() => openDrawer({ kind: "result", id: a.result_id })}>{a.title}</a><div className="muted small">{a.detector} · <State s={a.state} /></div></td>
                    <td>{a.source}</td><td><Confidence v={a.confidence} /></td><td className="mono">{a.evidence_count}</td><td><State s={a.status} /></td>
                    <td className="nowrap">
                      <button className="btn sm" onClick={() => openDrawer({ kind: "result", id: a.result_id })}>Open</button>{" "}
                      {a.incident_id && <button className="btn sm" onClick={() => go(`incidents/${a.incident_id}`)}>Investigate</button>}{" "}
                      <button className="btn sm" onClick={() => act(a, "ACKNOWLEDGED")}>Ack</button>{" "}
                      <button className="btn sm" onClick={() => act(a, "FALSE_POSITIVE")}>FP</button>{" "}
                      <button className="btn sm" onClick={() => act(a, "RESOLVED")}>Resolve</button>{" "}
                      <button className="btn sm" onClick={() => snap(a)}>Snapshot</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
