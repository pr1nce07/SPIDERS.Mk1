// Flight replay (spec §41, §66): replays recorded frames through the same engine.
import { useMemo, useState } from "react";
import { api } from "../services/api";
import { toast, useLive } from "../services/store";
import { go, openDrawer } from "../lib/nav";
import MapView from "../map/MapView";
import Chart from "../charts/Chart";
import { Badge, Empty, PageTitle, Panel, Seg, State, Timeline, useAsync } from "../components/ui";
import { TelemetryStrip, useMapMarkers } from "./Dashboard";
import { Comparison } from "./IDS";
import { time } from "../lib/format";

export default function Replay() {
  const tel = useLive((s) => s.telemetry);
  const track = useLive((s) => s.track);
  const timeline = useLive((s) => s.timeline);
  const packets = useLive((s) => s.packets);
  const markers = useMapMarkers();
  const { data: datasets } = useAsync<any[]>(() => api.get("/api/replay/datasets"), []);
  const [ds, setDs] = useState("");
  const [speed, setSpeed] = useState(1);
  const rp = tel.replay;
  const start = async () => {
    try { await api.post("/api/connection", { type: "replay", dataset: ds || datasets?.[0]?.ref, speed }); } catch (e: any) { toast(e.message, "error"); }
  };
  const ctl = (action: string, value?: any) => api.post("/api/replay/control", { action, value }).catch((e) => toast(e.message, "error"));
  const jump = (types: string[]) => {
    const e = timeline.find((x) => types.includes(x.type));
    if (e) ctl("seek", e.t - 5); else toast("No such event yet in the replayed portion", "warn");
  };
  const v = tel.vehicle || {};
  const recent = useMemo(() => packets.slice(-12).reverse(), [packets]);
  return (
    <div className="col">
      <PageTitle title="Replay" sub="recorded telemetry re-analysed — never regenerated" />
      <Panel><div className="row wrap">
        <select className="in" value={ds} onChange={(e) => setDs(e.target.value)}>{(datasets || []).map((d) => <option key={d.ref} value={d.ref}>[{d.kind}] {d.label}</option>)}</select>
        <Seg<number> value={speed} onChange={(s) => { setSpeed(s); rp && ctl("speed", s); }} options={[0.25, 0.5, 1, 2, 5, 10].map((x) => ({ v: x, l: `${x}×` }))} />
        <button className="btn primary" onClick={start} disabled={!datasets?.length}>Load & play</button>
        {rp && <>
          <button className="btn" onClick={() => ctl(rp.paused ? "play" : "pause")}>{rp.paused ? "▶ Play" : "❚❚ Pause"}</button>
          <button className="btn sm" onClick={() => jump(["IDS_ALERT", "GPS_EVENT", "LINK_DEGRADED", "LINK_LOSS", "IMU_EVENT"])}>First anomaly</button>
          <button className="btn sm" onClick={() => jump(["INCIDENT"])}>Incident</button>
          <button className="btn sm" onClick={() => jump(["COMMAND"])}>Command</button>
          <Badge v={rp.finished ? "FINISHED" : rp.paused ? "PAUSED" : "PLAYING"} tone={rp.finished ? "muted" : "info"} />
          <span className="small muted">{rp.reverse_playback}</span></>}
      </div>
      {rp && <div className="row mt">
        <span className="mono small">{rp.offset_s.toFixed(1)}s</span>
        <input type="range" className="grow" min={0} max={rp.duration_s} step={0.5} value={rp.offset_s} onChange={(e) => ctl("seek", rp.t_start + Number(e.target.value))} />
        <span className="mono small">{rp.duration_s.toFixed(0)}s · frame {rp.position}/{rp.total}</span>
      </div>}</Panel>
      {tel.kind !== "replay" ? <Empty title="NO REPLAY ACTIVE" text="Select a capture, forensic case or imported log and press Load & play." /> : (
        <>
          <div className="grid" style={{ gridTemplateColumns: "minmax(0,1fr) 360px" }}>
            <div style={{ height: 380 }}><MapView track={track} vehicle={v.lat?.value != null ? { lat: v.lat.value, lon: v.lon.value, heading: v.heading_deg?.value } : null} home={tel.home} markers={markers} /></div>
            <Panel title="Events" bodyStyle={{ maxHeight: 340, overflow: "auto" }}><Timeline events={timeline} onPick={(e) => e.ref?.result_id ? openDrawer({ kind: "result", id: e.ref.result_id }) : e.ref?.incident_id && go(`incidents/${e.ref.incident_id}`)} /></Panel>
          </div>
          <TelemetryStrip tel={tel} />
          <div className="grid g2">
            <Panel title="Detectors (synchronised)"><Comparison /></Panel>
            <Panel title="Packet stream" flush><table className="tbl"><tbody>{recent.map((p) => <tr key={p.idx} className="click" onClick={() => openDrawer({ kind: "packet", session: tel.session_id!, idx: p.idx })}><td className="mono small">{time(p.t, true)}</td><td className="mono small">{p.sysid}/{p.compid}</td><td>{p.msg}</td><td className="mono small">seq {p.seq}</td></tr>)}</tbody></table></Panel>
          </div>
        </>
      )}
    </div>
  );
}
