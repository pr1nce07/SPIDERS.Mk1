// Connection Center (spec §6): Serial/USB, UDP, TCP, recorded file (replay), simulation.
// Connect/disconnect never blocks the GUI; state arrives over /ws/events.
import { useEffect, useState } from "react";
import { api } from "../services/api";
import { toast, useLive } from "../services/store";
import { Badge, KV, Seg, State } from "./ui";
import { ago, num } from "../lib/format";

type Kind = "udp" | "tcp" | "serial" | "file" | "sim";

export default function ConnectionCenter({ onDone }: { onDone?: () => void }) {
  const [kind, setKind] = useState<Kind>("sim");
  const [host, setHost] = useState("127.0.0.1");
  const [port, setPort] = useState("14550");
  const [device, setDevice] = useState("/dev/ttyUSB0");
  const [baud, setBaud] = useState("115200");
  const [scenario, setScenario] = useState("NORMAL_FLIGHT");
  const [dataset, setDataset] = useState("");
  const [speed, setSpeed] = useState(1);
  const [scenarios, setScenarios] = useState<{ id: string; description: string }[]>([]);
  const [datasets, setDatasets] = useState<{ ref: string; label: string; kind: string }[]>([]);
  const [busy, setBusy] = useState(false);
  const conn = useLive((s) => s.telemetry.connection);
  const cstate = useLive((s) => s.connection);

  useEffect(() => {
    api.get("/api/simulation/scenarios").then(setScenarios).catch(() => {});
    api.get("/api/replay/datasets").then((d) => { setDatasets(d); if (d[0]) setDataset(d[0].ref); }).catch(() => {});
    api.get("/api/connection").then((c) => {
      const m = /^(udp|tcp):([\w.\-]+):(\d+)$/.exec(c.default_spec || "");
      if (m) { setHost(m[2]); setPort(m[3]); }
    }).catch(() => {});
  }, []);

  const connect = async () => {
    setBusy(true);
    try {
      let body: any;
      if (kind === "udp") body = { type: "live", spec: `udp:${host}:${port}` };
      else if (kind === "tcp") body = { type: "live", spec: `tcp:${host}:${port}` };
      else if (kind === "serial") body = { type: "live", spec: `${device}:${baud}` };
      else if (kind === "sim") body = { type: "simulation", scenario, speed };
      else body = { type: "replay", dataset, speed };
      const r = await api.post("/api/connection", body);
      toast(`Session ${r.session_id} started`, "ok");
      onDone?.();
    } catch (e: any) {
      toast(e.message, "error");
    } finally {
      setBusy(false);
    }
  };
  const disconnect = async () => {
    await api.del("/api/connection").catch((e) => toast(e.message, "error"));
  };

  return (
    <div className="col gap-l">
      <div className="panel"><div className="pb">
        <div className="row sp mb">
          <strong>Current link</strong>
          <State s={cstate?.state || "DISCONNECTED"} />
        </div>
        <div className="small dim mb">{cstate?.detail || "No active session"}</div>
        <KV rows={[
          ["SYSID / COMPID", conn ? `${conn.sysid ?? "N/A"} / ${conn.compid ?? "N/A"}` : null],
          ["MAVLink version", conn?.mavlink_version ? `v${conn.wire_version ?? 2} (HEARTBEAT mavlink_version ${conn.mavlink_version})` : null],
          ["Packet rate", conn ? num(conn.packet_rate_hz, 1, "Hz") : null], ["Heartbeat age", conn ? ago(conn.heartbeat_age_s) : null],
          ["Received", conn?.received], ["Bad frames (kept raw)", conn?.bad_frames],
          ["Estimated loss", conn?.estimated_loss_pct != null ? `${conn.estimated_loss_pct}%` : null],
          ["Signing", conn?.signing ? <span>{conn.signing} <span className="muted small">(authentication, not encryption)</span></span> : null],
          ["Latency", conn ? <span className="muted small">{conn.latency_note}</span> : null],
        ]} />
        {cstate?.state && cstate.state !== "DISCONNECTED" && <button className="btn danger mt" onClick={disconnect}>Disconnect</button>}
      </div></div>

      <div className="col">
        <Seg<Kind> value={kind} onChange={setKind} options={[{ v: "udp", l: "UDP" }, { v: "tcp", l: "TCP" }, { v: "serial", l: "Serial / USB" }, { v: "file", l: "Recorded file" }, { v: "sim", l: "Simulation" }]} />
        {(kind === "udp" || kind === "tcp") && (
          <div className="row">
            <label className="fld grow">{kind === "udp" ? "Listen address" : "Host"}<input className="in" value={host} onChange={(e) => setHost(e.target.value)} /></label>
            <label className="fld" style={{ width: 110 }}>Port<input className="in" value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, ""))} /></label>
          </div>
        )}
        {kind === "serial" && (
          <div className="row">
            <label className="fld grow">Device<input className="in" value={device} onChange={(e) => setDevice(e.target.value)} placeholder="/dev/ttyUSB0 or COM3" /></label>
            <label className="fld" style={{ width: 130 }}>Baud<select className="in" value={baud} onChange={(e) => setBaud(e.target.value)}>{["57600", "115200", "230400", "460800", "921600"].map((b) => <option key={b}>{b}</option>)}</select></label>
          </div>
        )}
        {kind === "sim" && (
          <>
            <div className="notice warn small">SIMULATION — synthetic MAVLink generated in-process. Nothing is transmitted to any vehicle.</div>
            <label className="fld">Scenario<select className="in" value={scenario} onChange={(e) => setScenario(e.target.value)}>{scenarios.map((s) => <option key={s.id} value={s.id}>{s.id}</option>)}</select></label>
            <div className="small dim">{scenarios.find((s) => s.id === scenario)?.description}</div>
          </>
        )}
        {kind === "file" && (
          <label className="fld">Recorded dataset (captures, forensic cases, imports)
            <select className="in" value={dataset} onChange={(e) => setDataset(e.target.value)}>
              {datasets.length === 0 && <option value="">No recordings yet</option>}
              {datasets.map((d) => <option key={d.ref} value={d.ref}>[{d.kind}] {d.label}</option>)}
            </select>
          </label>
        )}
        {(kind === "sim" || kind === "file") && (
          <label className="fld">Speed<Seg<number> value={speed} onChange={setSpeed} options={[0.25, 0.5, 1, 2, 5, 10].map((v) => ({ v, l: `${v}×` }))} /></label>
        )}
        <div className="row">
          <button className="btn primary" disabled={busy || (kind === "file" && !dataset)} onClick={connect}>{busy ? "Connecting…" : kind === "sim" ? "Start simulation" : kind === "file" ? "Start replay" : "Connect"}</button>
          <span className="small muted">Read-only: the GCS only receives MAVLink; it never sends commands.</span>
        </div>
        <div className="small muted">Examples: <Badge v="udp:127.0.0.1:14550" outline /> <Badge v="tcp:127.0.0.1:5760" outline /> <Badge v="/dev/ttyUSB0" outline /> <Badge v="COM3" outline /></div>
      </div>
    </div>
  );
}
