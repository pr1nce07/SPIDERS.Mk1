// Operational flight workspace (spec §57): map + attitude + telemetry + mode + battery + link + compact IDS.
import { useEffect, useMemo, useRef, useState } from "react";
import { useLive } from "../services/store";
import MapView from "../map/MapView";
import Attitude from "../components/Attitude";
import Chart, { type Series } from "../charts/Chart";
import { Badge, Empty, KV, PageTitle, Panel, State } from "../components/ui";
import { ago, num } from "../lib/format";
import { useMapMarkers } from "./Dashboard";
import { go, openDrawer } from "../lib/nav";

function useRolling(keys: string[], windowS = 120) {
  const tel = useLive((s) => s.telemetry);
  const buf = useRef<Record<string, [number, number][]>>({});
  const sid = useRef<string | undefined>(undefined);
  const [, force] = useState(0);
  useEffect(() => {
    if (tel.session_id !== sid.current) {
      buf.current = {};
      sid.current = tel.session_id;
    }
    const t = tel.t;
    if (!t) return;
    for (const k of keys) {
      const f = tel.vehicle?.[k];
      if (!f || typeof f.value !== "number" || f.availability !== "AVAILABLE") continue;
      const arr = (buf.current[k] ||= []);
      if (!arr.length || arr[arr.length - 1][0] !== t) arr.push([t, f.value]);
      while (arr.length && t - arr[0][0] > windowS) arr.shift();
    }
    force((x) => (x + 1) % 1000000);
  }, [tel]);
  return buf.current;
}

export default function Flight() {
  const tel = useLive((s) => s.telemetry);
  const track = useLive((s) => s.track);
  const ids = useLive((s) => s.ids);
  const markers = useMapMarkers();
  const roll = useRolling(["relative_alt_m", "groundspeed_ms", "gps_speed_ms", "ekf_speed_ms", "battery_voltage_v", "climb_ms"]);
  const v = tel.vehicle || {};
  const series1: Series[] = useMemo(() => [
    { name: "rel alt (m)", points: roll.relative_alt_m || [] },
    { name: "climb (m/s)", points: roll.climb_ms || [], axis: 1 },
  ], [roll.relative_alt_m?.length, tel.t]);
  const series2: Series[] = useMemo(() => [
    { name: "GPS speed", points: roll.gps_speed_ms || [] },
    { name: "EKF speed", points: roll.ekf_speed_ms || [] },
    { name: "VFR ground speed", points: roll.groundspeed_ms || [] },
  ], [roll.gps_speed_ms?.length, tel.t]);

  if (!tel.session_id) return <><PageTitle title="Flight" /><Empty title="NO VEHICLE CONNECTED" text="Connect a MAVLink source to begin telemetry monitoring." action={<button className="btn primary" onClick={() => openDrawer({ kind: "connect" })}>Open Connection Center</button>} /></>;
  const f = (k: string, d = 1, u = "") => {
    const x = v[k];
    if (!x || x.value == null) return <span className="muted">N/A</span>;
    return <span className={x.availability === "STALE" ? "t-warn" : ""}>{typeof x.value === "number" ? num(x.value, d, u) : String(x.value)}{x.availability === "STALE" ? " (stale)" : ""}</span>;
  };
  const c = tel.connection;
  const attStale = v.roll_deg?.availability === "STALE";
  const idsRows = ids?.comparison.rows || [];
  return (
    <div className="col">
      <PageTitle title="Flight" sub={`${tel.session_id} · ${tel.kind}`} right={<><Badge v={tel.mode || "MODE N/A"} tone="info" /><Badge v={tel.armed == null ? "ARM N/A" : tel.armed ? "ARMED" : "DISARMED"} tone={tel.armed ? "high" : "muted"} /></>} />
      <div className="grid" style={{ gridTemplateColumns: "minmax(0,1fr) 300px", gap: 12 }}>
        <div className="col">
          <div style={{ height: 420 }}>
            <MapView track={track} vehicle={v.lat?.value != null ? { lat: v.lat.value, lon: v.lon.value, heading: v.heading_deg?.value } : null} home={tel.home} markers={markers} />
          </div>
          <div className="grid g2">
            <Panel title="Altitude / climb"><Chart series={series1} height={180} exportName="altitude" /></Panel>
            <Panel title="Speed: GPS vs EKF vs VFR"><Chart series={series2} height={180} exportName="speed" /></Panel>
          </div>
        </div>
        <div className="col">
          <Panel title="Attitude"><div style={{ display: "grid", placeItems: "center" }}><Attitude roll={v.roll_deg?.value ?? null} pitch={v.pitch_deg?.value ?? null} yaw={v.yaw_deg?.value ?? null} stale={attStale} /></div>
            <KV rows={[["Roll", f("roll_deg", 1, "°")], ["Pitch", f("pitch_deg", 1, "°")], ["Yaw", f("yaw_deg", 0, "°")]]} />
          </Panel>
          <Panel title="Flight state">
            <KV rows={[["Mode", f("mode")], ["Armed", f("armed")], ["Airborne", <span>{f("airborne")} <span className="muted small">{v.airborne?.source?.startsWith("derived") ? "(derived)" : ""}</span></span>],
              ["System", f("system_status")], ["Rel. alt", f("relative_alt_m", 1, "m")], ["AMSL alt", f("altitude_m", 1, "m")],
              ["Ground speed", f("groundspeed_ms", 1, "m/s")], ["Airspeed", f("airspeed_ms", 1, "m/s")], ["Climb", f("climb_ms", 1, "m/s")],
              ["Heading", f("heading_deg", 0, "°")], ["Throttle", f("throttle_pct", 0, "%")], ["Mission item", f("mission_seq", 0)]]} />
          </Panel>
          <Panel title="Battery"><KV rows={[["Voltage", f("battery_voltage_v", 2, "V")], ["Current", f("battery_current_a", 1, "A")], ["Remaining", f("battery_remaining_pct", 0, "%")]]} /></Panel>
          <Panel title="GPS"><KV rows={[["Fix", f("gps_fix")], ["Satellites", f("gps_sats", 0)], ["HDOP", f("gps_hdop", 2)], ["GPS speed", f("gps_speed_ms", 1, "m/s")]]} /></Panel>
          <Panel title="Link"><KV rows={[["State", <State s={c?.state} />], ["Rate", c ? num(c.packet_rate_hz, 1, "Hz") : null], ["Heartbeat age", c ? ago(c.heartbeat_age_s) : null],
            ["Loss (est.)", c?.estimated_loss_pct != null ? `${c.estimated_loss_pct}%` : null], ["RC RSSI", f("rc_rssi", 0)], ["Radio RSSI", f("radio_rssi", 0)], ["Signing", c?.signing]]} /></Panel>
          <Panel title="IDS" right={<a className="small" onClick={() => go("ids")}>details →</a>}>
            <div className="row wrap gap-s">
              {idsRows.map((r) => <span key={r.detector} onClick={() => openDrawer({ kind: "detector", group: r.detector })} style={{ cursor: "pointer" }}><State s={r.ground.state === "NORMAL" ? "CLEAR" : r.ground.state} prefix={r.detector} /></span>)}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
