// Operator dashboard: calm, flight-awareness only (spec §10/§11). Raw packets,
// feature vectors, hashes and detector internals live in other workspaces.
import { useMemo } from "react";
import { useLive } from "../services/store";
import { go, openDrawer } from "../lib/nav";
import MapView, { type MapMarker } from "../map/MapView";
import { Badge, Confidence, Empty, Panel, State } from "../components/ui";
import ConnectionCenter from "../components/ConnectionCenter";
import { ago, num, time } from "../lib/format";
import type { FieldValue, Telemetry } from "../types";

const I = (d: string) => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">{d.split("|").map((x, i) => <path key={i} d={x} />)}</svg>;

const FAMILIES: [string, string][] = [["GPS", "GPS"], ["MAVLINK", "MAVLINK"], ["COMMAND", "COMMAND"], ["RC_LINK", "RC"], ["IMU", "IMU"],
  ["MISSION", "MISSION"], ["PARAMETER", "PARAM"], ["OFFBOARD", "OFFBOARD"]];

export function cell(f: FieldValue | undefined, digits = 1): { v: string; cls: string; age?: string } {
  if (!f || f.value === null || f.value === undefined) return { v: "N/A", cls: "na" };
  const v = typeof f.value === "number" ? f.value.toFixed(digits) : String(f.value);
  return { v, cls: f.availability === "STALE" ? "stale" : f.availability === "AVAILABLE" ? "" : "na", age: f.availability === "STALE" ? `stale ${ago(f.age_s)}` : undefined };
}

export function TelemetryStrip({ tel }: { tel: Telemetry }) {
  const v = tel.vehicle || {};
  const c = tel.connection;
  const alt = cell(v.relative_alt_m), spd = cell(v.groundspeed_ms ?? v.ekf_speed_ms), hdg = cell(v.heading_deg, 0), climb = cell(v.climb_ms);
  const batv = cell(v.battery_voltage_v, 2);
  const cells: [string, { v: string; cls: string; age?: string }, string, string][] = [
    ["ALT", alt, "m", alt.age || `rel. home · ${v.relative_alt_m?.source ?? "N/A"}`],
    ["SPD", spd, "m/s", spd.age || "ground speed"],
    ["HDG", hdg, "°", hdg.age || "EKF heading"],
    ["CLIMB", climb, "m/s", climb.age || "vertical speed"],
    ["BAT", batv, "V", v.battery_remaining_pct?.value != null ? `${v.battery_remaining_pct.value}% remaining` : "remaining N/A"],
    ["GPS", cell(v.gps_fix, 0), "", `${v.gps_sats?.value ?? "N/A"} sats · HDOP ${v.gps_hdop?.value ?? "N/A"}`],
    ["LINK", { v: c ? num(c.packet_rate_hz, 0) : "N/A", cls: c ? "" : "na" }, "Hz", c ? `HB ${ago(c.heartbeat_age_s)} · loss ${c.estimated_loss_pct ?? "N/A"}%` : "no link"],
  ];
  return (
    <div className="tstrip">
      {cells.map(([k, cv, unit, sub]) => (
        <div key={k} className={`tcell ${cv.cls}`}>
          <div className="k">{k}</div>
          <div className="v">{cv.v}{cv.v !== "N/A" && unit && <small>{unit}</small>}</div>
          <div className="s">{sub}</div>
        </div>
      ))}
    </div>
  );
}

export function useMapMarkers(): MapMarker[] {
  const alerts = useLive((s) => s.alerts);
  const incidents = useLive((s) => s.incidents);
  const track = useLive((s) => s.track);
  return useMemo(() => {
    if (!track.length) return [];
    const near = (t: number) => {
      let lo = 0, hi = track.length - 1;
      while (lo < hi) {
        const mid = (lo + hi) >> 1;
        if (track[mid][0] < t) lo = mid + 1; else hi = mid;
      }
      return track[lo];
    };
    const out: MapMarker[] = [];
    alerts.filter((a) => ["ANOMALOUS", "SUSPECTED", "CONFIRMED"].includes(a.state)).slice(0, 150).forEach((a) => {
      const p = near(a.t);
      if (p) out.push({ lat: p[1], lon: p[2], kind: "anomaly", label: `${time(a.t)} ${a.detector}: ${a.title}`, onClick: () => openDrawer({ kind: "result", id: a.result_id }) });
    });
    Object.values(incidents).forEach((i) => {
      const p = near(i.first_seen);
      if (p) out.push({ lat: p[1], lon: p[2], kind: "incident", label: `${i.incident_id}: ${i.title}`, onClick: () => go(`incidents/${i.incident_id}`) });
    });
    return out;
  }, [alerts, incidents, track]);
}


export default function Dashboard() {
  const tel = useLive((s) => s.telemetry);
  const track = useLive((s) => s.track);
  const ids = useLive((s) => s.ids);
  const incidents = useLive((s) => s.incidents);
  const alerts = useLive((s) => s.alerts);
  const timeline = useLive((s) => s.timeline);
  const health = useLive((s) => s.health);
  const markers = useMapMarkers();
  const connected = Boolean(tel.session_id || tel.connection);
  const openIncidents = Object.values(incidents).filter((i) => i.status === "OPEN");
  const newAlerts = alerts.filter((a) => a.status === "NEW");
  const dets = ids?.detectors || [];
  const detOk = dets.filter((d) => d.health === "ONLINE" || d.health === "WAITING_FOR_DATA").length;
  const recent = [...alerts].sort((a, b) => b.t - a.t).slice(0, 3);
  const events = [...timeline].slice(-3).reverse();
  const vehicle = tel.vehicle || {};
  const lat = vehicle.lat?.value, lon = vehicle.lon?.value;
  const readiness = [
    ["Telemetry link", connected ? "Connected" : "Not connected", connected],
    ["IDS service", dets.length ? `${detOk}/${dets.length} ready` : "Not reported", dets.length > 0],
    ["Database", health?.database ? "Online" : "Not reported", Boolean(health?.database)],
  ];
  const shortcuts = [
    { id: "ids", title: "Detection center", sub: "Rules, health & anomaly signals", icon: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z|M9 12l2 2 4-4" },
    { id: "packets", title: "Packet explorer", sub: "Inspect MAVLink packet streams", icon: "M4 6h16|M4 12h16|M4 18h10" },
    { id: "forensics", title: "Forensic workspace", sub: "Investigate evidence & cases", icon: "M11 4a7 7 0 1 1 0 14 7 7 0 0 1 0-14z|M20 20l-4-4" },
  ];
  return (
    <div className="overview">
      <section className="overview-stats">
        <button className="overview-stat" onClick={() => openDrawer({ kind: "connect" })}>
          <span className="ov-label">CONNECTION STATUS</span><span className="ov-icon">ϟ</span>
          <strong>{connected ? "Online" : "Offline"}</strong><small>{connected ? "Telemetry source attached" : "No telemetry source attached"}</small><i>↗</i>
        </button>
        <button className="overview-stat" onClick={() => go("alerts")}>
          <span className="ov-label">NEW ALERTS</span><span className="ov-icon">♧</span>
          <strong>{newAlerts.length}<em> events</em></strong><small>{newAlerts.length ? "Review new security alerts" : "No alerts in this workspace"}</small><i>↗</i>
        </button>
        <button className="overview-stat" onClick={() => go("incidents")}>
          <span className="ov-label">OPEN INCIDENTS</span><span className="ov-icon">△</span>
          <strong>{openIncidents.length}<em> cases</em></strong><small>{openIncidents.length ? "Cases require attention" : "No open cases recorded"}</small><i>↗</i>
        </button>
        <button className="overview-stat" onClick={() => go("ids")}>
          <span className="ov-label">DETECTION ENGINE</span><span className="ov-icon">⌁</span>
          <strong>{dets.length ? (detOk ? "Active" : "Degraded") : "Standby"}</strong><small>{dets.length ? `${detOk} of ${dets.length} detectors ready` : "Awaiting service status"}</small><i>↗</i>
        </button>
      </section>

      <section className="overview-main-grid">
        <article className="overview-panel network-panel">
          <header className="overview-panel-head"><div><span className="ov-label">01 / LIVE MONITOR</span><h2>Network observatory</h2></div><span className="ov-pill"><b />{connected ? "LIVE TELEMETRY" : "AWAITING SIGNAL"}</span></header>
          <div className="network-stage">
            {connected ? <MapView track={track} vehicle={lat != null && lon != null ? { lat, lon, heading: vehicle.heading_deg?.value ?? vehicle.yaw_deg?.value } : null} home={tel.home} markers={markers} /> : (
              <div className="radar-grid" aria-label="Waiting for telemetry">
                <span className="radar-label north">N / 000°</span><span className="radar-label east">E / 090°</span><span className="radar-label south">S / 180°</span>
                <div className="radar-rings"><span /><span /><span /><span /></div>
                <div className="radar-mark"><img src="/brand/spider-mask-128.png" alt="SPIDERS.Mk1 vehicle marker" /></div>
                <div className="radar-empty"><b>⌁ &nbsp; No live signal detected</b><small>Connect a source to visualize your mission data.</small></div>
              </div>
            )}
          </div>
          <footer className="overview-panel-foot"><span>● &nbsp; {connected ? "STREAM ACTIVE" : "STREAM INACTIVE"} &nbsp; / &nbsp; {num(tel.connection?.packet_rate_hz ?? 0, 0)} PACKETS / SEC</span><a onClick={() => go("packets")}>Go to packet explorer ↗</a></footer>
        </article>

        <div className="overview-right">
          <article className="overview-panel get-started">
            <header className="overview-panel-head"><span className="ov-label">GET STARTED</span><span className="ov-step">01 / 03</span></header>
            <div className="get-icon"><img src="/brand/spider-mask-128.png" alt="SPIDERS.Mk1" /></div>
            <h2>{connected ? "Telemetry connected." : "Connect your first data source."}</h2>
            <p>{connected ? "Your workspace is receiving telemetry. Explore packets, detector health and recent events." : "Stream MAVLink telemetry, replay a capture, or start an isolated simulation to explore the platform."}</p>
            <button className="get-action" onClick={() => openDrawer({ kind: "connect" })}>{connected ? "Manage connection" : "Configure connection"} <b>↗</b></button>
            <div className="safe-note">♧ &nbsp; Receives data only · never sends commands</div>
          </article>
          <article className="overview-panel readiness-panel">
            <header className="overview-panel-head"><div><span className="ov-label">SYSTEM / 02</span><h2>Readiness checks</h2></div><a onClick={() => go("health")}>→</a></header>
            {readiness.map(([label, value, ok]) => <div className="readiness-row" key={label as string}><span className={ok ? "ready-dot ok" : "ready-dot"} /> <span>{label}</span><b>{value}</b></div>)}
          </article>
        </div>
      </section>

      <section className="overview-bottom-grid">
        <article className="overview-panel recent-panel">
          <header className="overview-panel-head"><div><span className="ov-label">ACTIVITY / 03</span><h2>Recent intelligence</h2></div><a onClick={() => go("alerts")}>View all alerts ↗</a></header>
          {recent.length || events.length ? (
            <div className="recent-list">
              {recent.length ? recent.map((a) => <button className="recent-item" key={a.alert_id} onClick={() => openDrawer({ kind: "result", id: a.result_id })}><span className="recent-symbol">!</span><span><b>{a.title}</b><small>{a.detector} · {a.severity} · {ago(Math.max(0, (Date.now() / 1000) - a.t))}</small></span></button>) : events.map((e) => <button className="recent-item" key={e.id} onClick={() => e.ref?.incident_id ? go(`incidents/${e.ref.incident_id}`) : go("replay")}><span className="recent-symbol">≋</span><span><b>{e.title}</b><small>{e.type.replace(/_/g, " ").toLowerCase()} · {time(e.t)}</small></span></button>)}
            </div>
          ) : <div className="recent-empty"><span className="recent-symbol">≡</span><span><b>It's quiet in here</b><small>New detections and security events will appear when a session is active.</small></span></div>}
        </article>
        <article className="overview-panel quick-panel">
          <header className="overview-panel-head"><div><span className="ov-label">QUICK ACCESS / 04</span><h2>Explore the platform</h2></div></header>
          <div className="quick-grid">
            {shortcuts.map((item) => <button className="quick-card" key={item.id} onClick={() => go(item.id)}><span className="quick-icon">{I(item.icon)}</span><i>↗</i><b>{item.title}</b><small>{item.sub}</small></button>)}
          </div>
        </article>
      </section>
    </div>
  );
}
