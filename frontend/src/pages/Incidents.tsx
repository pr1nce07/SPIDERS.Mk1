// Incidents list + split investigation layout (spec §33, §39): alert → event → packet → values → rule → evidence → snapshot.
import { useTheme } from "../lib/theme";
import { useMemo, useState } from "react";
import { ReactFlow, Background, type Edge, type Node } from "@xyflow/react";
import { api, qs } from "../services/api";
import { toast } from "../services/store";
import { go, openDrawer, useRoute } from "../lib/nav";
import MapView from "../map/MapView";
import Chart from "../charts/Chart";
import { Badge, Confidence, Contributors, Empty, ErrorNote, ExplanationView, KV, PageTitle, Panel, State, Tabs, Timeline, TraceView, useAsync } from "../components/ui";
import { captureScreenshot } from "../components/Drawers";
import { dateTime, time } from "../lib/format";
import type { Incident } from "../types";

export default function Incidents() {
  const r = useRoute();
  return r.id ? <IncidentDetail id={r.id} /> : <IncidentList />;
}

function IncidentList() {
  const [status, setStatus] = useState("");
  const [q, setQ] = useState("");
  const { data, error } = useAsync<Incident[]>(() => api.get(`/api/incidents${qs({ status, q })}`), [status, q], 3000);
  return (
    <div className="col">
      <PageTitle title="Incidents" sub="correlated evidence; severity ≠ confidence" right={<>
        <input className="in" placeholder="Search" value={q} onChange={(e) => setQ(e.target.value)} />
        <select className="in" value={status} onChange={(e) => setStatus(e.target.value)}><option value="">All</option>{["OPEN", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"].map((s) => <option key={s}>{s}</option>)}</select></>} />
      <ErrorNote error={error} />
      <Panel flush>
        {!data?.length ? <Empty title="NO INCIDENTS" text="No incidents have been recorded." /> : (
          <table className="tbl"><thead><tr><th>First seen</th><th>Incident</th><th>Severity</th><th>State</th><th>Confidence</th><th>Detectors</th><th>Sources</th><th>Case</th><th>Status</th></tr></thead><tbody>
            {data.map((i) => (
              <tr key={i.incident_id} className="click" onClick={() => go(`incidents/${i.incident_id}`)}>
                <td className="mono small">{dateTime(i.first_seen)}</td><td><strong>{i.incident_id}</strong><div className="small">{i.title}</div></td>
                <td><State s={i.severity} /></td><td><State s={i.state} /></td><td><Confidence v={i.confidence} /></td>
                <td className="small">{i.detectors.join(", ")}</td><td className="small">{i.sources.join(", ")}</td><td className="mono small">{i.case_id || "—"}</td><td><State s={i.status} /></td>
              </tr>
            ))}
          </tbody></table>
        )}
      </Panel>
    </div>
  );
}

function EvidenceGraph({ graph }: { graph: any }) {
  const theme = useTheme();
  const { nodes, edges } = useMemo(() => {
    const kinds = ["actor", "message", "pushpak", "rule", "detector", "incident", "snapshot"];
    const col: Record<string, number> = { actor: 0, message: 0, pushpak: 0, rule: 1, detector: 1, incident: 2, snapshot: 3 };
    const counts: Record<number, number> = {};
    const color: Record<string, string> = { incident: "var(--crit)", detector: "var(--high)", message: "var(--info)", rule: "#c49bff", pushpak: "var(--warn)", snapshot: "var(--ok)", actor: "var(--crit)" };
    const nodes: Node[] = graph.nodes.sort((a: any, b: any) => kinds.indexOf(a.kind) - kinds.indexOf(b.kind)).map((n: any) => {
      const c = col[n.kind] ?? 1;
      counts[c] = (counts[c] || 0) + 1;
      return { id: n.id, position: { x: c * 280, y: (counts[c] - 1) * 70 }, data: { label: n.label, ref: n.ref, kind: n.kind },
        style: { background: "var(--panel-2)", color: "var(--text)", border: `1px solid ${color[n.kind]}`, fontSize: 10.5, width: 230, whiteSpace: "pre-line" } };
    });
    const edges: Edge[] = graph.edges.map((e: any, i: number) => ({ id: `e${i}`, source: e.source, target: e.target, style: { stroke: "var(--line-2)" } }));
    return { nodes, edges };
  }, [graph]);
  const click = (n: Node) => {
    const d: any = n.data;
    if (d.kind === "detector") openDrawer({ kind: "result", id: d.ref.result_id });
    else if (d.kind === "message") openDrawer({ kind: "packet", session: d.ref.session_id, idx: d.ref.idx });
    else if (d.kind === "rule") go(`builder/${d.ref.rule_id}`);
    else if (d.kind === "snapshot") go(`silktrace/${d.ref.case_id}`);
  };
  return <div style={{ height: 460 }}><ReactFlow nodes={nodes} edges={edges} fitView minZoom={0.15} onNodeClick={(_, n) => click(n)} colorMode={theme} proOptions={{ hideAttribution: true }}><Background gap={24} color="var(--line)" /></ReactFlow></div>;
}

function IncidentDetail({ id }: { id: string }) {
  const { data, error, reload } = useAsync<any>(() => api.get(`/api/incidents/${encodeURIComponent(id)}`), [id]);
  const [tab, setTab] = useState("evidence");
  const [cursor, setCursor] = useState<number | null>(null);
  const [selRes, setSelRes] = useState<any>(null);
  const series = useAsync<any>(() => data ? api.get(`/api/analytics/series${qs({ session_id: data.incident.session_id, fields: "gps_speed,ekf_speed,ekf_vel_var,altitude_rel,rc_rssi" })}`) : Promise.resolve(null), [data?.incident?.session_id]);
  if (error) return <ErrorNote error={error} />;
  if (!data) return <Empty title="LOADING" />;
  const inc: Incident = data.incident;
  const setStatus = async (s: string) => {
    try { await api.post(`/api/incidents/${id}/status`, { status: s, note: "" }); toast(`${id} → ${s} (evidence preserved)`, "ok"); reload(); } catch (e: any) { toast(e.message, "error"); }
  };
  const snapshot = async () => {
    try { const r = await api.post("/api/forensics/snapshot", { incident_id: id, reason: "investigator request" }); toast(`Snapshot ${r.case_id} collecting`, "ok"); } catch (e: any) { toast(e.message, "error"); }
  };
  const w0 = inc.first_seen - 60, w1 = inc.last_seen + 60;
  const chSeries = Object.entries(series.data?.series || {}).map(([k, v]: any) => ({ name: k, points: v.points.filter((p: any) => p[0] >= w0 && p[0] <= w1), axis: (k === "ekf_vel_var" ? 1 : 0) as 0 | 1 }));
  const marks = inc.observations.filter((o) => !o.context).map((o) => ({ t: o.t, label: o.detector, tone: "high" as const, onClick: () => openDrawer({ kind: "result", id: o.result_id }) }));
  return (
    <div className="col">
      <PageTitle title={inc.incident_id} sub={inc.title} right={<>
        <State s={inc.severity} /><State s={inc.state} /><State s={inc.status} />
        <select className="in" value="" onChange={(e) => e.target.value && setStatus(e.target.value)}><option value="">Set status…</option>{["ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE", "OPEN"].map((s) => <option key={s}>{s}</option>)}</select>
        <button className="btn sm" onClick={snapshot}>Create snapshot</button>
        {inc.case_id && <button className="btn sm" onClick={() => captureScreenshot(inc.case_id!)}>Capture screenshot</button>}
        {inc.case_id && <button className="btn sm primary" onClick={() => go(`silktrace/${inc.case_id}`)}>Case {inc.case_id}</button>}</>} />
      <Panel><div className="grid g3">
        <KV rows={[["First seen", dateTime(inc.first_seen)], ["Last seen", dateTime(inc.last_seen)], ["Session", <span className="mono small">{inc.session_id}</span>], ["Domain", inc.domain], ["Created because", inc.creation_reason]]} />
        <div><div className="small muted mb">CONFIDENCE {Math.round(inc.confidence * 100)}% (separate from severity)</div><Contributors items={inc.contributors} /></div>
        <KV rows={[["Detectors", inc.detectors.join(", ")], ["Sources", inc.sources.join(", ")], ["Actors (SYSID)", inc.actors.join(", ") || "—"], ["Rule versions", inc.rule_versions.map((r) => `${r.rule_id} v${r.version}`).join(", ") || "—"], ["Limitations", inc.limitations.join(" ")]]} />
      </div></Panel>
      <div className="grid" style={{ gridTemplateColumns: "360px minmax(0,1fr)" }}>
        <Panel title="Event timeline" bodyStyle={{ maxHeight: 420, overflow: "auto" }}>
          <Timeline events={data.timeline} onPick={(e) => { setCursor(e.t); if (e.ref?.result_id) openDrawer({ kind: "result", id: e.ref.result_id }); else if (e.ref?.idx) openDrawer({ kind: "packet", session: inc.session_id, idx: e.ref.idx }); }} />
        </Panel>
        <div style={{ height: 460 }}><MapView track={data.track} cursor={cursor ?? inc.first_seen} follow={false} markers={[]} /></div>
      </div>
      <Panel>
        <Tabs value={tab} onChange={setTab} tabs={[{ id: "evidence", label: `Evidence (${data.results.length})` }, { id: "telemetry", label: "Telemetry" }, { id: "explain", label: "Explanation" }, { id: "graph", label: "Evidence graph" }, { id: "packets", label: `MAVLink (${inc.evidence.length})` }, { id: "diff", label: "Config diff" }]} />
        {tab === "evidence" && (
          <div className="grid g2">
            <table className="tbl"><tbody>
              {data.results.map((r: any) => (
                <tr key={r.result_id} className={`click ${selRes?.result_id === r.result_id ? "sel" : ""}`} onClick={() => setSelRes(r)}>
                  <td className="mono small">{time(r.t, true)}</td><td><State s={r.state} /></td><td>{r.title}<div className="muted small">{r.detector} · {r.source}</div></td><td><Confidence v={r.confidence} /></td>
                </tr>
              ))}
            </tbody></table>
            <div>{selRes ? <div className="col"><ExplanationView e={selRes.explanation} />{selRes.trace && <TraceView rows={selRes.trace} />}
              <div className="row wrap">{selRes.packet_refs.slice(0, 12).map((i: number) => <a key={i} className="mono small" onClick={() => openDrawer({ kind: "packet", session: inc.session_id, idx: i })}>#{i}</a>)}</div></div>
              : <span className="muted">Select a result to see WHAT/WHY/WHEN/SOURCE/EVIDENCE/RULE/CONFIDENCE/LIMITATIONS.</span>}</div>
          </div>
        )}
        {tab === "telemetry" && <Chart series={chSeries} marks={marks} height={300} yNames={["m/s | m", "variance"]} cursor={cursor} onClickTime={setCursor} exportName={`${id}-telemetry`} />}
        {tab === "explain" && <ExplanationView e={inc.explanation} />}
        {tab === "graph" && <EvidenceGraph graph={data.graph} />}
        {tab === "packets" && <div className="row wrap">{inc.evidence.slice(0, 300).map((i) => <a key={i} className="mono small" onClick={() => openDrawer({ kind: "packet", session: inc.session_id, idx: i })}>#{i}</a>)}</div>}
        {tab === "diff" && <ConfigDiff a="current" b={`incident:${id}`} />}
      </Panel>
    </div>
  );
}

export function ConfigDiff({ a, b }: { a: string; b: string }) {
  const { data, error } = useAsync<any>(() => api.get(`/api/config/diff${qs({ a, b })}`), [a, b]);
  const [only, setOnly] = useState(true);
  if (error) return <ErrorNote error={error} />;
  if (!data) return <span className="muted">Loading…</span>;
  return (
    <div className="col">
      <div className="row"><Badge v={`A: ${data.a}`} outline /><Badge v={`B: ${data.b}`} outline /><label className="row small"><input type="checkbox" checked={only} onChange={(e) => setOnly(e.target.checked)} />changed only</label></div>
      {Object.entries(data.sections).map(([k, s]: any) => (
        <div key={k}>
          <strong className="small">{k.toUpperCase()}</strong> {s.available ? <span className="small muted">{s.changed} changed</span> : <span className="small muted">{s.note}</span>}
          {s.available && (
            <table className="tbl"><tbody>
              {s.rows.filter((r: any) => !only || r.changed).slice(0, 200).map((r: any) => (
                <tr key={r.key} className={r.changed ? "sel" : ""}><td className="mono small">{r.key}</td><td className="mono small">{JSON.stringify(r.a)}</td><td className="mono small">{JSON.stringify(r.b)}</td><td>{r.changed ? <Badge v="CHANGED" tone="warn" /> : null}</td></tr>
              ))}
            </tbody></table>
          )}
        </div>
      ))}
    </div>
  );
}
