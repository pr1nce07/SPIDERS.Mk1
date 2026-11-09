import { useEffect, useState, type JSX } from "react";
import { go, openDrawer, setMode, useMode, useRoute, type Mode } from "./lib/nav";
import { setState, useLive } from "./services/store";
import { api } from "./services/api";
import { Dot, Toasts } from "./components/ui";
import Drawers from "./components/Drawers";
import { num, stateTone } from "./lib/format";
import Dashboard from "./pages/Dashboard";
import Flight from "./pages/Flight";
import IDSPage from "./pages/IDS";
import Builder from "./builder/Builder";
import Alerts from "./pages/Alerts";
import Incidents from "./pages/Incidents";
import Replay from "./pages/Replay";
import Packets from "./pages/Packets";
import Logs from "./pages/Logs";
import HealthPage from "./pages/Health";
import Settings from "./pages/Settings";
import Silktrace from "./pages/Silktrace";
import { setTheme, useTheme } from "./lib/theme";


const I = (d: string) => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">{d.split("|").map((x, i) => <path key={i} d={x} />)}</svg>;
const ICONS: Record<string, JSX.Element> = {
  dashboard: I("M4 4h7v7H4z|M13 4h7v7h-7z|M4 13h7v7H4z|M13 13h7v7h-7z"),
  flight: I("M12 3l3 7h6l-5 4 2 7-6-4-6 4 2-7-5-4h6z"),
  ids: I("M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z|M9 12l2 2 4-4"),
  builder: I("M5 6h4v4H5z|M15 14h4v4h-4z|M9 8h3a2 2 0 0 1 2 2v4a2 2 0 0 0 2 2"),
  alerts: I("M6 16V11a6 6 0 0 1 12 0v5l2 2H4z|M10 20a2 2 0 0 0 4 0"),
  incidents: I("M12 3l9 16H3z|M12 10v4|M12 17h.01"),
  replay: I("M4 12a8 8 0 1 0 3-6.3|M4 4v4h4|M11 9l4 3-4 3z"),
  packets: I("M4 6h16|M4 12h16|M4 18h10"),
  logs: I("M6 3h9l4 4v14H6z|M14 3v5h5|M9 13h6|M9 17h6"),
  health: I("M3 12h4l3-7 4 14 3-7h4"),
  silktrace: I("M4 5h16v14H4z|M8 9h8|M8 13h5|M16 16l2 2 3-4"),
  settings: I("M12 9a3 3 0 1 1 0 6 3 3 0 0 1 0-6z|M19 12a7 7 0 0 0-.1-1.2l2-1.6-2-3.4-2.4 1a7 7 0 0 0-2-1.2L14 3h-4l-.5 2.6a7 7 0 0 0-2 1.2l-2.4-1-2 3.4 2 1.6A7 7 0 0 0 5 12a7 7 0 0 0 .1 1.2l-2 1.6 2 3.4 2.4-1a7 7 0 0 0 2 1.2L10 21h4l.5-2.6a7 7 0 0 0 2-1.2l2.4 1 2-3.4-2-1.6A7 7 0 0 0 19 12z"),
};

const NAV: { id: string; label: string; modes: Mode[] }[] = [
  { id: "dashboard", label: "Dashboard", modes: ["OPERATOR", "INVESTIGATOR", "ENGINEER"] },
  { id: "flight", label: "Flight", modes: ["OPERATOR", "ENGINEER"] },
  { id: "ids", label: "IDS", modes: ["OPERATOR", "INVESTIGATOR", "ENGINEER"] },
  { id: "builder", label: "Custom Ruleset", modes: ["ENGINEER"] },
  { id: "alerts", label: "Alerts", modes: ["OPERATOR", "INVESTIGATOR", "ENGINEER"] },
  { id: "incidents", label: "Incidents", modes: ["INVESTIGATOR", "ENGINEER"] },
  { id: "silktrace", label: "SILKTRACE", modes: ["INVESTIGATOR", "ENGINEER"] },
  { id: "replay", label: "Replay", modes: ["INVESTIGATOR", "ENGINEER"] },
  { id: "packets", label: "Packets", modes: ["INVESTIGATOR", "ENGINEER"] },
  { id: "logs", label: "Logs", modes: ["INVESTIGATOR", "ENGINEER"] },
  { id: "health", label: "Health", modes: ["ENGINEER", "OPERATOR"] },
  { id: "settings", label: "Settings", modes: ["OPERATOR", "INVESTIGATOR", "ENGINEER"] },
];

export function Brand() {
  return (
    <a className="brand" href="#/dashboard" title="Security Packet Intrusion Detection Evaluation and Response System" aria-label="SPIDERS.Mk1 home">
      <span className="brand-logo" aria-hidden="true" />
      <span className="brand-word">SPIDERS.<span className="brand-mk">Mk1</span></span>
    </a>
  );
}

function TopBar({ onMenu }: { onMenu: () => void }) {
  const theme = useTheme();
  const tel = useLive((s) => s.telemetry);
  const health = useLive((s) => s.health);
  const ids = useLive((s) => s.ids);
  const cstate = useLive((s) => s.connection?.state) || health?.connection?.state || "DISCONNECTED";
  const v = tel.vehicle || {};
  const worst = ids?.detectors?.reduce((acc, d) => {
    const order = ["NORMAL", "OBSERVED", "ANOMALOUS", "SUSPECTED", "CONFIRMED"];
    return order.indexOf(d.state) > order.indexOf(acc) ? d.state : acc;
  }, "NORMAL") || "NORMAL";
  const idsErr = ids?.detectors?.some((d) => d.health === "ERROR");
  const bat = v.battery_remaining_pct?.value;
  const chips: [string, string, boolean?][] = [
    [`MAVLINK ${cstate}`, stateTone(cstate), cstate === "CONNECTING" || cstate === "RECONNECTING"],
    [health?.recording ? "RECORDING" : "NOT RECORDING", health?.recording ? "crit" : "muted", health?.recording],
    [idsErr ? "IDS DEGRADED" : worst === "NORMAL" ? "IDS CLEAR" : `IDS ${worst}`, idsErr ? "warn" : stateTone(worst)],
    [`FC ${v.system_status?.value ?? "N/A"}`, v.system_status?.value === "ACTIVE" || v.system_status?.value === "STANDBY" ? "ok" : "muted"],
    [`GPS ${v.gps_fix?.value ?? "N/A"}`, v.gps_fix?.value === "3D" || String(v.gps_fix?.value || "").startsWith("RTK") ? "ok" : v.gps_fix ? "warn" : "muted"],
    [`BAT ${bat != null ? `${bat}%` : "N/A"}`, bat == null ? "muted" : bat > 30 ? "ok" : bat > 15 ? "warn" : "crit"],
    [tel.mode || "MODE N/A", tel.mode ? "info" : "muted"],
    [tel.armed == null ? "ARM N/A" : tel.armed ? "ARMED" : "DISARMED", tel.armed ? "high" : "muted"],
  ];
  return (
    <header className="topbar">
      <button className="btn ghost icon menu-btn" onClick={onMenu} aria-label="Open navigation">{I("M4 7h16|M4 12h16|M4 17h16")}</button>
      <Brand />
      <div className="search">
        <input type="search" enterKeyHint="search" autoCapitalize="none" autoCorrect="off" spellCheck={false} aria-label="Search incident, case or packet" placeholder="Search incident, case or packet" onKeyDown={(e) => {
          const v = (e.target as HTMLInputElement).value.trim();
          if (e.key !== "Enter" || !v) return;
          if (/^INC-/i.test(v)) go(`incidents/${v.toUpperCase()}`);
          else if (/^(CASE-|INC-)/i.test(v)) go(`silktrace/${v}`);
          else go(`packets?q=${encodeURIComponent(v)}`);
        }} />
        {I("M11 4a7 7 0 1 1 0 14 7 7 0 0 1 0-14z|M20 20l-4-4")}
      </div>
      {tel.kind === "simulation" && <span className="chip sim-label" title={tel.scenario ? `SIMULATION · ${tel.scenario}` : "SIMULATION"}>SIM<span className="chip-detail">ULATION{tel.scenario ? ` · ${tel.scenario}` : ""}</span></span>}
      {tel.kind === "replay" && <span className="chip bg-info t-info">REPLAY</span>}
      <div className="strip">
        {chips.map(([label, tone, pulse]) => (
          <span key={label} className={`chip t-${tone}`}><span className={`dot ${pulse ? "pulse" : ""}`} />{label}</span>
        ))}
        {tel.connection?.sysid != null && <span className="chip t-muted">SYSID {tel.connection.sysid}</span>}
      </div>
      <button
        className="btn ghost icon theme-toggle"
        onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
        title={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
        aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
        aria-pressed={theme === "dark"}
      >
        {theme === "dark"
          ? I("M12 3v2|M12 19v2|M3 12h2|M19 12h2|M5.64 5.64l1.42 1.42|M16.94 16.94l1.42 1.42|M5.64 18.36l1.42-1.42|M16.94 7.06l1.42-1.42|M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8")
          : I("M20.5 14.5A8.5 8.5 0 0 1 9.5 3.5 8.5 8.5 0 1 0 20.5 14.5z")}
      </button>
      <button className={`btn sm ${cstate === "DISCONNECTED" ? "primary" : ""}`} onClick={() => openDrawer({ kind: "connect" })}>{cstate === "DISCONNECTED" ? "Connect" : "Connection"}</button>
      <div className="operator"><div className="avatar">OP</div><span className="small dim">local operator</span></div>
    </header>
  );
}

function StatusBar() {
  const h = useLive((s) => s.health);
  const ws = useLive((s) => s.ws);
  const tel = useLive((s) => s.telemetry);
  const [clock, setClock] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  const wsOk = Object.values(ws).every((s) => s === "open");
  const item = (label: string, tone: string, value: string) => (
    <span className="it"><span className={`dot ${tone}`} />{label} <span className="dim">{value}</span></span>
  );
  const age = tel.connection?.heartbeat_age_s;
  return (
    <footer className="statusbar">
      {item("TELEMETRY", !tel.connection ? "muted" : age != null && age > 3 ? "warn" : "ok", tel.connection ? `${num(tel.connection.packet_rate_hz, 0)} Hz · HB ${age != null ? `${age.toFixed(1)} s` : "N/A"}` : "no link")}
      {item("RECORDER", h?.recording ? "ok" : "muted", h?.subsystems?.recorder?.status ?? "idle")}
      {item("IDS", h?.ids === "healthy" ? "ok" : "warn", h?.ids ?? "N/A")}
      {item("DB", h?.database === "healthy" ? "ok" : "crit", `${h?.database ?? "N/A"} · q ${h?.subsystems?.database?.queued ?? 0}`)}
      {item("DISK", (h?.resources?.disk_free_mb ?? 1e9) < 2000 ? "warn" : "ok", h ? `${(h.resources.disk_free_mb / 1024).toFixed(1)} GB free` : "N/A")}
      {item("WS", wsOk ? "ok" : "crit", wsOk ? "connected" : "reconnecting…")}
      {h?.read_only && <span className="it t-ok">READ-ONLY</span>}
      <div className="grow" />
      <span className="mono">{clock.toISOString().substring(11, 19)} UTC</span>
    </footer>
  );
}

export default function App() {
  const route = useRoute();
  const sid = useLive((s) => s.sessionId);
  useEffect(() => {
    if (!sid) return;
    Promise.all([api.get(`/api/incidents?session_id=${sid}`), api.get(`/api/ids/events?session_id=${sid}&limit=500`), api.get(`/api/timeline?session_id=${sid}&limit=500`)])
      .then(([inc, al, tl]) => setState((s) => ({
        incidents: { ...Object.fromEntries(inc.map((i: any) => [i.incident_id, i])), ...s.incidents },
        alerts: s.alerts.length ? s.alerts : al,
        timeline: s.timeline.length ? s.timeline : tl.events,
      }))).catch(() => {});
  }, [sid]);
  const mode = useMode();
  const [collapsed, setCollapsed] = useState(() => {
    try { return localStorage.getItem("pushpak.nav") === "1"; } catch { return false; }
  });
  const openAlerts = useLive((s) => s.alerts.filter((a) => a.status === "NEW" && ["HIGH", "CRITICAL"].includes(a.severity)).length);
  const openInc = useLive((s) => Object.values(s.incidents).filter((i) => i.status === "OPEN").length);
  const items = NAV.filter((n) => n.modes.includes(mode));
  const toggle = () => {
    setCollapsed((c) => {
      try { localStorage.setItem("pushpak.nav", c ? "0" : "1"); } catch { /* ignore */ }
      return !c;
    });
  };
  const page = route.page;
  // Forensics was merged into SILKTRACE; keep old #/forensics/<case> links working.
  useEffect(() => {
    if (page === "forensics") go(route.id ? `silktrace/${encodeURIComponent(route.id)}` : "silktrace");
  }, [page, route.id]);
  // Mobile: the sidebar becomes a sheet; any navigation closes it.
  const [navOpen, setNavOpen] = useState(false);
  useEffect(() => setNavOpen(false), [page, route.id]);
  useEffect(() => {
    if (!navOpen) return;
    const k = (e: KeyboardEvent) => e.key === "Escape" && setNavOpen(false);
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [navOpen]);
  const Page = {
    dashboard: Dashboard, flight: Flight, ids: IDSPage, builder: Builder, alerts: Alerts, incidents: Incidents, forensics: Silktrace,
    replay: Replay, packets: Packets, logs: Logs, health: HealthPage, settings: Settings, silktrace: Silktrace,
  }[page] || Dashboard;

  return (
    <div className="shell">
      <TopBar onMenu={() => setNavOpen(true)} />
      <div className={`body ${collapsed ? "collapsed" : ""}`}>
        <div className={`nav-scrim ${navOpen ? "open" : ""}`} onClick={() => setNavOpen(false)} aria-hidden="true" />
        <nav className={`nav ${navOpen ? "open" : ""}`} aria-label="Primary">
          <div className="nav-topline">
            <span className="nav-heading lbl">COMMAND CONSOLE</span>
            <button className="nav-collapse" onClick={toggle} title={collapsed ? "Expand navigation" : "Collapse navigation"} aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}>
              {I(collapsed ? "M9 6l6 6-6 6" : "M15 6l-6 6 6 6")}
            </button>
          </div>
          <div className="nav-groups">
            {([
              { label: "WORKSPACE", ids: ["dashboard", "flight", "ids", "builder"] },
              { label: "SECURITY INTELLIGENCE", ids: ["alerts", "incidents", "silktrace", "replay"] },
              { label: "DATA EXPLORER", ids: ["packets", "logs"] },
              { label: "SYSTEM", ids: ["health", "settings"] },
            ] as const).map((group) => {
              const groupItems = group.ids.map((id) => NAV.find((n) => n.id === id)!).filter((n) => items.includes(n));
              if (!groupItems.length) return null;
              return <section className="nav-group" key={group.label}>
                <div className="nav-section-label lbl">{group.label}</div>
                {groupItems.map((n) => (
                  <button key={n.id} className={page === n.id ? "active" : ""} aria-current={page === n.id ? "page" : undefined} onClick={() => go(n.id)} title={n.label}>
                    {ICONS[n.id]}
                    <span className="lbl">{n.label}</span>
                    {n.id === "alerts" && openAlerts > 0 && <span className="badge-count">{openAlerts}</span>}
                    {n.id === "incidents" && openInc > 0 && <span className="badge-count">{openInc}</span>}
                  </button>
                ))}
              </section>;
            })}
          </div>
          <div className="nav-footer">
            <div className="mode">
              <span className="mode-label lbl">WORKSPACE ROLE</span>
              {(["OPERATOR", "INVESTIGATOR", "ENGINEER"] as Mode[]).map((m) => (
                <button key={m} className={mode === m ? "active" : ""} aria-pressed={mode === m} onClick={() => setMode(m)} title={m}>
                  <Dot tone={mode === m ? "ok" : "muted"} /> <span className="lbl">{m.charAt(0) + m.slice(1).toLowerCase()}</span>
                </button>
              ))}
            </div>
          </div>
        </nav>
        <main className="workspace" id="workspace">
          <div className="page" key={page}><Page /></div>
        </main>
      </div>
      <StatusBar />
      <Drawers />
      <Toasts />
    </div>
  );
}
