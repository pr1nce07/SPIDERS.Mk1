// Forensics workspace (spec §62–63): case search → incident → timeline → evidence → packet → trace → snapshot → hash verification.
import { useState } from "react";
import { api, qs } from "../services/api";
import { toast } from "../services/store";
import { go, useRoute } from "../lib/nav";
import { Badge, Empty, ErrorNote, JsonView, KV, PageTitle, Panel, State, useAsync } from "../components/ui";
import { captureScreenshot } from "../components/Drawers";
import { bytes, dateTime } from "../lib/format";
import type { CaseSummary } from "../types";

export default function Forensics() {
  const r = useRoute();
  return r.id ? <CaseDetail id={r.id} /> : <CaseList />;
}

function CaseList() {
  const [f, setF] = useState({ q: "", severity: "", detector: "", date: "", sysid: "", source: "" });
  const { data, error } = useAsync<CaseSummary[]>(() => api.get(`/api/forensics/cases${qs(f)}`), [JSON.stringify(f)], 4000);
  const set = (k: string, v: string) => setF((x) => ({ ...x, [k]: v }));
  return (
    <div className="col">
      <PageTitle title="Forensic cases" sub="SHA-256 sealed evidence packages" />
      <Panel><div className="row wrap">
        <input className="in" placeholder="Case / incident / message / text" value={f.q} onChange={(e) => set("q", e.target.value)} />
        <select className="in" value={f.severity} onChange={(e) => set("severity", e.target.value)}><option value="">Any severity</option>{["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => <option key={s}>{s}</option>)}</select>
        <input className="in" placeholder="Detector" value={f.detector} onChange={(e) => set("detector", e.target.value)} />
        <input className="in" placeholder="Date YYYY-MM-DD" value={f.date} onChange={(e) => set("date", e.target.value)} />
        <input className="in" placeholder="Vehicle SYSID" value={f.sysid} onChange={(e) => set("sysid", e.target.value)} style={{ width: 120 }} />
        <input className="in" placeholder="Source / flight" value={f.source} onChange={(e) => set("source", e.target.value)} />
      </div></Panel>
      <ErrorNote error={error} />
      <Panel flush>{!data?.length ? <Empty title="NO CASES" text="Cases are created automatically for HIGH/CRITICAL or CONFIRMED incidents, or manually." /> : (
        <table className="tbl"><thead><tr><th>Case</th><th>Status</th><th>Incident</th><th>Trigger</th><th>Window</th><th>Frames</th><th>Artifacts</th></tr></thead><tbody>
          {data.map((c) => (
            <tr key={c.case_id} className="click" onClick={() => go(`forensics/${c.case_id}`)}>
              <td className="mono">{c.case_id}</td><td><State s={c.status} /></td><td className="mono small">{c.incident_id || "manual"}</td>
              <td className="small">{c.trigger?.severity && <State s={c.trigger.severity} />} {c.trigger?.detector}<div className="muted small">{c.trigger?.reason}</div></td>
              <td className="mono small">{c.capture_window?.start?.substring(11, 19)} → {c.capture_window?.end?.substring(11, 19)}</td>
              <td className="mono">{c.evidence_counts?.frames ?? "—"}</td><td className="mono">{c.artifact_count ?? "—"}</td>
            </tr>
          ))}
        </tbody></table>)}
      </Panel>
    </div>
  );
}

function CaseDetail({ id }: { id: string }) {
  const { data, error, reload } = useAsync<any>(() => api.get(`/api/forensics/cases/${encodeURIComponent(id)}`), [id]);
  const [verify, setVerify] = useState<any>(null);
  const [file, setFile] = useState<{ path: string; text: string } | null>(null);
  if (error) return <ErrorNote error={error} />;
  if (!data) return <Empty title="LOADING" />;
  if (data.collecting) return <Empty title={`CASE ${id} ${data.status}`} text="Capturing the post-event window; the case is sealed with SHA-256 when complete." action={<button className="btn" onClick={reload}>Refresh</button>} />;
  const m = data.manifest;
  const doVerify = async () => {
    const r = await api.post("/api/forensics/verify", { case_id: id });
    setVerify(r);
    toast(`VERIFY CASE: ${r.status}`, r.status === "VALID" ? "ok" : "error");
    reload();
  };
  const open = async (p: string) => {
    if (p.endsWith(".bin") || p.endsWith(".png")) { window.open(`/api/forensics/cases/${id}/file?path=${encodeURIComponent(p)}&download=true`); return; }
    const t = await fetch(`/api/forensics/cases/${id}/file?path=${encodeURIComponent(p)}`).then((r) => r.text());
    setFile({ path: p, text: t.slice(0, 200000) });
  };
  const statusOf = (f: string) => verify?.artifacts?.find((a: any) => a.file === f)?.status;
  return (
    <div className="col">
      <PageTitle title={`Case ${id}`} sub={m?.status} right={<>
        <button className="btn primary" onClick={doVerify}>VERIFY CASE</button>
        {verify && <State s={verify.status} />}
        <button className="btn" onClick={() => captureScreenshot(id).then(reload)}>Add screenshot</button>
        <a className="btn" href={`/api/forensics/cases/${id}/export`}>Export ZIP</a>
        {m?.incident_id && <button className="btn" onClick={() => go(`incidents/${m.incident_id}`)}>Incident →</button>}</>} />
      {verify && <div className={`notice ${verify.status === "VALID" ? "" : "crit"}`}>{verify.status} — {verify.files_checked} files checked · manifest consistent: {String(verify.manifest_consistent)}. {verify.note}</div>}
      <div className="grid g2">
        <Panel title="Manifest"><KV rows={[["Created", m?.created_at], ["Finalized", m?.finalized_at], ["Incident", m?.incident_id || "manual"], ["Trigger", `${m?.trigger?.detector} · ${m?.trigger?.severity} · conf ${m?.trigger?.confidence ?? "N/A"}`], ["Reason", m?.trigger?.reason],
          ["Window", `${m?.capture_window?.start} → ${m?.capture_window?.end} (pre ${m?.capture_window?.pre_seconds}s / post ${m?.capture_window?.post_seconds}s)`],
          ["Vehicle", `SYSID ${m?.vehicle?.sysid ?? "N/A"} · ${m?.vehicle?.board ?? "N/A"} · ${m?.vehicle?.firmware ?? "N/A"} · git ${m?.vehicle?.git_commit ?? "N/A"}`],
          ["Session", `${m?.session?.session_id} (${m?.session?.kind})`], ["Evidence", JSON.stringify(m?.evidence_counts)], ["Rule versions", (m?.rule_versions || []).map((r: any) => `${r.rule_id} v${r.version}`).join(", ")],
          ["Revisions", (m?.revisions || []).map((r: any) => `${r.at}: ${r.action}`).join("; ") || "none"]]} />
          <div className="small muted mt">{m?.custody_note}</div></Panel>
        <Panel title={`Artifacts (${data.files.length})`} flush>
          <table className="tbl"><thead><tr><th>File</th><th className="right">Size</th><th>SHA-256</th><th>Verify</th></tr></thead><tbody>
            {data.files.map((f: any) => {
              const art = m?.artifacts?.find((a: any) => a.filename === f.path);
              return <tr key={f.path} className="click" onClick={() => open(f.path)}><td className="mono small">{f.path}</td><td className="right mono small">{bytes(f.size)}</td>
                <td className="mono small">{art ? `${art.sha256.slice(0, 14)}…` : <span className="muted">—</span>}</td><td>{statusOf(f.path) ? <State s={statusOf(f.path)} /> : null}</td></tr>;
            })}
          </tbody></table>
        </Panel>
      </div>
      {file && <Panel title={file.path} right={<button className="btn sm" onClick={() => setFile(null)}>Close</button>}><pre className="code" style={{ maxHeight: 500 }}>{file.text}</pre></Panel>}
      {data.verifications?.length > 0 && <Panel title="Verification history" flush><table className="tbl"><tbody>{data.verifications.map((v: any) => <tr key={v.id}><td className="mono small">{dateTime(v.verified_at)}</td><td><State s={v.result} /></td></tr>)}</tbody></table></Panel>}
      {data.incident && <Panel title="incident.json (frozen)"><JsonView data={data.incident} /></Panel>}
      <Badge v="Hashes detect modification; they do not by themselves establish legal chain of custody." outline />
    </div>
  );
}
