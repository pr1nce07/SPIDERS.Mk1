// Detector + system health (spec §48, §49, §99, §102).
import { useState } from "react";
import { api } from "../services/api";
import { toast, useLive } from "../services/store";
import { useMode } from "../lib/nav";
import { Empty, JsonView, KV, PageTitle, Panel, State, useAsync } from "../components/ui";

export default function HealthPage() {
  const h = useLive((s) => s.health);
  const ids = useLive((s) => s.ids);
  const mode = useMode();
  const [fault, setFault] = useState("GPS_INTEGRITY");
  const errs = useAsync<any[]>(() => api.get(`/api/errors?detail=${mode === "ENGINEER"}`), [mode], 4000);
  if (!h) return <Empty title="WAITING FOR HEALTH" />;
  const inject = async (on: boolean) => {
    try { const r = await api.post("/api/ids/fault-injection", { detector: fault, enabled: on }); toast(`Fault injection: ${r.fault_injection.join(", ") || "none"}`, "warn"); } catch (e: any) { toast(e.message, "error"); }
  };
  return (
    <div className="col">
      <PageTitle title="Health" right={<><State s={h.status.toUpperCase()} /><span className="mono">score {h.score}</span></>} />
      {h.issues.length > 0 && <div className="notice warn">{h.issues.map((i, k) => <div key={k}><strong>{i.component}</strong> {i.status}: {i.message}</div>)}</div>}
      <div className="grid g4">
        {(["mavlink", "database", "websocket", "ids", "forensics"] as const).map((k) => <Panel key={k} title={k}><State s={String(h[k]).toUpperCase()} /></Panel>)}
        <Panel title="recording"><State s={h.recording ? "RECORDING" : "STOPPED"} /></Panel>
        <Panel title="resources"><KV rows={[["CPU", `${h.resources.cpu_pct}%`], ["RAM", `${h.resources.ram_mb} MB`], ["Disk free", `${(h.resources.disk_free_mb / 1024).toFixed(1)} GB`]]} /></Panel>
        <Panel title="uptime"><span className="mono">{Math.round(h.uptime_s)} s · v{h.version}</span></Panel>
      </div>
      <Panel title="Detector health" flush>
        <table className="tbl"><thead><tr><th>Name</th><th>Version</th><th>State</th><th>Last update</th><th className="right">Events</th><th className="right">Errors</th><th className="right">Latency</th><th>Data sources</th></tr></thead><tbody>
          {(ids?.detectors || []).map((d) => <tr key={d.detector}><td>{d.name}</td><td className="mono small">{d.version}</td><td><State s={d.health} /></td><td className="mono small">{d.last_update?.substring(11, 19) ?? "N/A"}</td><td className="right mono">{d.events}</td><td className="right mono" title={d.last_error || ""}>{d.errors}</td><td className="right mono">{d.latency_ms.toFixed(3)} ms</td><td className="small muted">{d.data_sources.join(", ") || "all"}</td></tr>)}
        </tbody></table>
      </Panel>
      <div className="grid g2">
        <Panel title="Subsystems"><JsonView data={h.subsystems} maxHeight={420} /></Panel>
        <Panel title={`Errors ${mode === "ENGINEER" ? "(engineer detail)" : ""}`} bodyStyle={{ maxHeight: 440, overflow: "auto" }}>
          {(errs.data || []).length === 0 ? <span className="muted">No errors.</span> : (errs.data || []).map((e) => (
            <div key={e.error_id} className="mb"><div className="row"><span className="mono small">{e.error_id}</span><State s={e.recoverable ? "DEGRADED" : "ERROR"} /><strong className="small">{e.component}</strong><span className="small">{e.type}</span></div>
              <div className="small dim">{e.message}</div>{e.detail && <pre className="code" style={{ maxHeight: 120 }}>{e.detail}</pre>}</div>))}
        </Panel>
      </div>
      {mode === "ENGINEER" && (
        <Panel title="Failure testing (detector exception must not stop the system)">
          <div className="row"><select className="in" value={fault} onChange={(e) => setFault(e.target.value)}>{(ids?.detectors || []).map((d) => <option key={d.detector}>{d.detector}</option>)}</select>
            <button className="btn danger" onClick={() => inject(true)}>Inject fault</button><button className="btn" onClick={() => inject(false)}>Clear</button></div>
        </Panel>
      )}
    </div>
  );
}
