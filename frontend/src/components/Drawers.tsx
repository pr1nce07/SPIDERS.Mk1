// Global evidence drawers: detector result (WHAT/WHY/…/trace) → exact packet.
import { useEffect, useState } from "react";
import { api } from "../services/api";
import { getState, toast, useLive } from "../services/store";
import { go, openDrawer, useDrawer } from "../lib/nav";
import type { DetectorResult, Packet } from "../types";
import { Badge, Confidence, Copy, Drawer, ErrorNote, ExplanationView, JsonView, KV, State, Tabs, TraceView } from "./ui";
import { dateTime, fmtVal, hexDump, time } from "../lib/format";
import ConnectionCenter from "./ConnectionCenter";

export default function Drawers() {
  const d = useDrawer();
  const close = () => openDrawer(null);
  if (!d) return null;
  if (d.kind === "result") return <ResultDrawer id={d.id} data={d.data} onClose={close} />;
  if (d.kind === "packet") return <PacketDrawer session={d.session} idx={d.idx} onClose={close} />;
  if (d.kind === "detector") return <DetectorGroupDrawer group={d.group} onClose={close} />;
  if (d.kind === "connect") return <Drawer open onClose={close} title="Connection Center"><ConnectionCenter onDone={close} /></Drawer>;
  return null;
}

function ResultDrawer({ id, data, onClose }: { id: string; data?: any; onClose: () => void }) {
  const [r, setR] = useState<DetectorResult | null>(data || null);
  const [err, setErr] = useState<any>();
  const [tab, setTab] = useState("explain");
  useEffect(() => {
    api.get<DetectorResult>(`/api/ids/results/${encodeURIComponent(id)}`).then(setR).catch((e) => !data && setErr(e));
  }, [id]);
  const session = r?.session_id || getState().sessionId || "";
  return (
    <Drawer open onClose={onClose} title={r ? r.title : "Detector result"} right={r && <State s={r.state} />}>
      <ErrorNote error={err} />
      {r && (
        <div className="col">
          <KV rows={[
            ["Detector", <span>{r.detector} <span className="muted">{r.detector_version}</span></span>],
            ["Source", <Badge v={r.source} outline />], ["Severity", <State s={r.severity} />],
            ["Confidence", <Confidence v={r.confidence} />], ["When", dateTime(r.t)],
            ["Method", r.method], ["Score / threshold", r.score !== null ? `${fmtVal(r.score)} / ${fmtVal(r.threshold)}` : null],
            ["Rule", r.rule_id ? <a onClick={() => { onClose(); go(`builder/${r.rule_id}`); }}>{r.rule_id} v{r.rule_version}</a> : null],
          ]} />
          <Tabs value={tab} onChange={setTab} tabs={[{ id: "explain", label: "Explanation" }, { id: "inputs", label: "Measured values" },
            { id: "trace", label: "Rule trace" }, { id: "packets", label: `Packets (${r.packet_refs.length})` }, { id: "raw", label: "JSON" }]} />
          {tab === "explain" && <ExplanationView e={r.explanation} />}
          {tab === "inputs" && (
            <table className="tbl"><tbody>
              {Object.entries(r.inputs || {}).map(([k, v]) => <tr key={k}><td className="dim">{k}</td><td className="mono">{fmtVal(v)}</td></tr>)}
              {Object.entries(r.parameters || {}).map(([k, v]) => <tr key={"p" + k}><td className="muted">param · {k}</td><td className="mono">{fmtVal(v)}</td></tr>)}
            </tbody></table>
          )}
          {tab === "trace" && <TraceView rows={r.trace} />}
          {tab === "packets" && (
            <div className="col gap-s">
              {r.packet_refs.length === 0 && <span className="muted">No packet references.</span>}
              {r.packet_refs.map((idx) => (
                <a key={idx} className="mono" onClick={() => openDrawer({ kind: "packet", session, idx })}>packet #{idx} →</a>
              ))}
            </div>
          )}
          {tab === "raw" && <JsonView data={r} />}
        </div>
      )}
    </Drawer>
  );
}

export function PacketView({ p }: { p: Packet }) {
  const [tab, setTab] = useState("decoded");
  return (
    <div className="col">
      <KV rows={[
        ["Message", <span>{p.msg} <span className="muted">(ID {p.msg_id ?? "N/A"})</span></span>], ["Receive time", `${dateTime(p.t)} (${time(p.t, true)})`],
        ["SYSID / COMPID", `${p.sysid ?? "N/A"} / ${p.compid ?? "N/A"}`], ["Sequence", p.seq], ["Link / source", `${p.link} · ${p.source}`],
        ["MAVLink version", p.ver ? `v${p.ver}` : null], ["Signing", p.signed ? `SIGNED (${p.sig || "UNVERIFIED"})` : "UNSIGNED"],
        ["Length", `${p.len} bytes`], ["Parse error", p.err ? <span className="t-crit">{p.err}</span> : "none"],
      ]} />
      <div className="row">
        <Copy text={JSON.stringify(p.fields || {}, null, 2)} label="Copy decoded" />
        <Copy text={p.raw_hex || ""} label="Copy raw hex" />
      </div>
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "decoded", label: "Decoded fields" }, { id: "hex", label: "Raw bytes" }, { id: "header", label: "Header" }, { id: "def", label: "Definition" }]} />
      {tab === "decoded" && (
        <table className="tbl"><tbody>
          {Object.entries(p.fields || {}).map(([k, v]) => {
            const f = p.definition?.fields?.find((x: any) => x.name === k);
            return <tr key={k}><td className="dim">{k}{f?.extension ? <span className="muted small"> ext</span> : null}</td><td className="mono">{fmtVal(v)}</td><td className="muted small">{f?.units || ""} {f?.enum ? `(${f.enum})` : ""}</td></tr>;
          })}
        </tbody></table>
      )}
      {tab === "hex" && <pre className="code">{hexDump(p.raw_hex) || "raw bytes unavailable for this source (e.g. DataFlash mapped record)"}</pre>}
      {tab === "header" && <JsonView data={p.header || {}} />}
      {tab === "def" && <JsonView data={p.definition || { note: "not in dialect" }} />}
    </div>
  );
}

function PacketDrawer({ session, idx, onClose }: { session: string; idx: number; onClose: () => void }) {
  const [p, setP] = useState<Packet | null>(null);
  const [err, setErr] = useState<any>();
  useEffect(() => {
    api.get<Packet>(`/api/mavlink/messages/${encodeURIComponent(session)}/${idx}`).then(setP).catch(setErr);
  }, [session, idx]);
  return (
    <Drawer open onClose={onClose} title={`Packet #${idx}`} right={<button className="btn sm" onClick={() => { onClose(); go(`packets?session=${session}&idx=${idx}`); }}>Open in inspector</button>}>
      <ErrorNote error={err} />
      {p && <PacketView p={p} />}
    </Drawer>
  );
}

const GROUP_DETECTORS: Record<string, string[]> = {
  GPS: ["GPS_INTEGRITY"], MAVLINK: ["MAVLINK_SEQUENCE", "SOURCE_IDENTITY", "MAVLINK_RATE", "MAVLINK_SIGNING", "HEARTBEAT"],
  COMMAND: ["COMMAND", "FLIGHT_MODE"], RC_LINK: ["RC_LINK", "HEARTBEAT"], IMU: ["IMU_CONSISTENCY", "SENSOR_HEALTH"],
  MISSION: ["MISSION"], PARAMETER: ["PARAMETER"], OFFBOARD: ["OFFBOARD"],
};

function DetectorGroupDrawer({ group, onClose }: { group: string; onClose: () => void }) {
  const ids = useLive((s) => s.ids);
  const alerts = useLive((s) => s.alerts);
  const dets = GROUP_DETECTORS[group] || [group];
  const row = ids?.comparison.rows.find((r) => r.detector === group);
  const related = alerts.filter((a) => dets.includes(a.detector) || (a.detector === "PUSHPAK_FC" && a.title.includes(group))).slice(0, 30);
  return (
    <Drawer open onClose={onClose} title={`${group} — evidence`}>
      <div className="col">
        {row && (
          <table className="tbl"><thead><tr><th>FC IDS</th><th>LUA</th><th>GROUND</th><th>CORRELATED</th></tr></thead><tbody><tr>
            <td>{row.fc ? <><State s={row.fc.state} /> <span className="mono small">{Math.round(row.fc.confidence * 100)}%</span></> : <span className="muted" title="No PIDS telemetry received">N/A</span>}</td>
            <td>{row.lua ? <span className="small">{row.lua.class} {Math.round(row.lua.confidence * 100)}%</span> : <span className="muted">N/A</span>}</td>
            <td><State s={row.ground.state} /></td><td>{row.correlated ? <State s={row.correlated} /> : <span className="muted">—</span>}</td>
          </tr></tbody></table>
        )}
        {ids?.detectors.filter((d) => dets.includes(d.detector)).map((d) => (
          <div key={d.detector} className="panel"><div className="pb">
            <div className="row sp"><strong>{d.name}</strong><span className="row gap-s"><State s={d.health} /><State s={d.state} /></span></div>
            <div className="small dim mt">{d.description}</div>
            <div className="small muted">Methods: {d.methods.join(" · ")}</div>
            {d.metrics && Object.keys(d.metrics).length > 0 && <pre className="code mt" style={{ maxHeight: 160 }}>{JSON.stringify(d.metrics, null, 1)}</pre>}
          </div></div>
        ))}
        <strong className="small muted">RECENT ALERTS</strong>
        {related.length === 0 && <span className="muted">No alerts for this detector family in the current session.</span>}
        {related.map((a) => (
          <div key={a.alert_id} className="row" style={{ cursor: "pointer" }} onClick={() => openDrawer({ kind: "result", id: a.result_id })}>
            <span className="mono small muted">{time(a.t)}</span><State s={a.state} /><span className="grow">{a.title}</span><Confidence v={a.confidence} />
          </div>
        ))}
      </div>
    </Drawer>
  );
}

export async function captureScreenshot(caseId: string) {
  try {
    const { default: html2canvas } = await import("html2canvas");
    const canvas = await html2canvas(document.body, { backgroundColor: getComputedStyle(document.body).backgroundColor, scale: 1, logging: false, useCORS: true });
    const blob: Blob = await new Promise((res) => canvas.toBlob((b) => res(b as Blob), "image/png"));
    const fd = new FormData();
    fd.append("file", blob, `incident-${caseId}.png`);
    const r = await api.upload(`/api/forensics/cases/${encodeURIComponent(caseId)}/screenshot`, fd);
    toast(`Screenshot added to ${caseId} (sha256 ${r.artifact.sha256.slice(0, 12)}…)`, "ok");
    return r;
  } catch (e: any) {
    toast(`Screenshot failed: ${e?.message || e}`, "error");
  }
}
