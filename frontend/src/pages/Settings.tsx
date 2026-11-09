// Settings: connection center, source-of-truth capability manifest, runtime settings, MAVLink schema.
import { useState } from "react";
import { api } from "../services/api";
import { toast } from "../services/store";
import ConnectionCenter from "../components/ConnectionCenter";
import SecuritySettings from "../components/SecuritySettings";
import { resolved, setTheme, useThemePref, type ThemePref } from "../lib/theme";
import { Badge, JsonView, PageTitle, Panel, Tabs, useAsync } from "../components/ui";

export default function Settings() {
  const [tab, setTab] = useState("connection");
  return (
    <div className="col">
      <PageTitle title="Settings" />
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "connection", label: "Connection" }, { id: "caps", label: "Firmware discovery" }, { id: "settings", label: "Runtime settings" }, { id: "security", label: "Security" }, { id: "schema", label: "MAVLink schema" }, { id: "ui", label: "Appearance" }]} />
      {tab === "connection" && <Panel><ConnectionCenter /></Panel>}
      {tab === "caps" && <Caps />}
      {tab === "settings" && <RuntimeSettings />}
      {tab === "security" && <SecuritySettings />}
      {tab === "schema" && <Schema />}
      {tab === "ui" && <Display />}
    </div>
  );
}

function Caps() {
  const { data } = useAsync<any>(() => api.get("/api/capabilities"), []);
  if (!data) return null;
  return (
    <div className="col">
      <div className="grid g3">
        <Panel title="Vehicle"><JsonView data={data.vehicle} /></Panel>
        <Panel title="PUSHPAK"><JsonView data={data.pushpak} /></Panel>
        <Panel title="MAVLink / logging"><JsonView data={{ mavlink: data.mavlink, logging: data.logging }} /></Panel>
      </div>
      <Panel title="Discrepancies (actual source wins; recorded, not silently changed)">
        {(data.discrepancies || []).map((d: any) => <div key={d.id} className="notice warn mb"><Badge v={d.id} tone="warn" /> <strong>{d.summary}</strong><div className="small">{d.detail}</div><div className="small">Impact: {d.impact}</div><div className="small muted">Resolution: {d.resolution}</div></div>)}
      </Panel>
      <Panel title="Findings (each with evidence)" flush><table className="tbl"><tbody>{(data.findings || []).map((f: any) => <tr key={f.key}><td className="mono small">{f.key}</td><td className="mono small" style={{ maxWidth: 420, overflow: "hidden", textOverflow: "ellipsis" }}>{JSON.stringify(f.value)}</td><td className="small muted">{f.evidence}</td></tr>)}</tbody></table></Panel>
    </div>
  );
}

function RuntimeSettings() {
  const { data, reload } = useAsync<any>(() => api.get("/api/settings"), []);
  const [text, setText] = useState('{\n  "forensics": {"pre_event_seconds": 30, "post_event_seconds": 60}\n}');
  const save = async () => {
    try { const r = await api.put("/api/settings", JSON.parse(text)); toast(`Updated ${Object.keys(r.updated).join(", ")}`, "ok"); reload(); } catch (e: any) { toast(e.message, "error"); }
  };
  return (
    <div className="grid g2">
      <Panel title="Effective configuration (secrets redacted)"><JsonView data={data} maxHeight={600} /></Panel>
      <Panel title="Change settings (engineer; audited)"><textarea className="in" rows={10} style={{ width: "100%" }} value={text} onChange={(e) => setText(e.target.value)} /><button className="btn primary mt" onClick={save}>Apply</button>
        <div className="small muted mt">Detector thresholds live in configuration and rule definitions, never in the GUI code.</div></Panel>
    </div>
  );
}

function Schema() {
  const { data } = useAsync<any>(() => api.get("/api/mavlink/registry"), []);
  const [q, setQ] = useState("GPS_RAW_INT");
  const msgs = (data?.messages || []).filter((m: any) => m.name.includes(q.toUpperCase()) || String(m.id) === q);
  return (
    <div className="col">
      <div className="row"><input className="in" value={q} onChange={(e) => setQ(e.target.value)} /><span className="small muted">dialect {data?.dialect} · {data?.message_count} messages · custom: {String(data?.custom)}</span></div>
      {msgs.slice(0, 10).map((m: any) => (
        <Panel key={m.id} title={`#${m.id} ${m.name}`} flush><table className="tbl"><tbody>{m.fields.map((f: any) => <tr key={f.name}><td className="mono small">{f.name}</td><td className="mono small">{f.type}{f.array_length ? `[${f.array_length}]` : ""}</td><td className="small">{f.units}</td><td className="small">{f.enum}</td><td>{f.extension && <Badge v="EXT" outline />}</td></tr>)}</tbody></table></Panel>
      ))}
    </div>
  );
}

function Display() {
  const pref = useThemePref();
  const opts: { v: ThemePref; label: string; note: string }[] = [
    { v: "light", label: "Light", note: "White workspace (default)" },
    { v: "dark", label: "Dark", note: "Low-glare for night operations" },
    { v: "system", label: "System", note: `Follow the OS setting (currently ${resolved("system")})` },
  ];
  return (
    <div className="grid g2" style={{ alignItems: "start" }}>
      <Panel title="Appearance">
        <div className="col">
          {opts.map((o) => (
            <label key={o.v} className="row" style={{ cursor: "pointer", padding: "8px 10px", border: "1px solid var(--line)", borderRadius: 3, background: pref === o.v ? "var(--accent-soft)" : "transparent" }}>
              <input type="radio" name="theme" checked={pref === o.v} onChange={() => setTheme(o.v)} />
              <span style={{ fontWeight: 600, width: 70 }}>{o.label}</span>
              <span className="small dim">{o.note}</span>
            </label>
          ))}
          <span className="small muted">Saved in this browser. Maps, charts and rule graphs follow the selected theme.</span>
        </div>
      </Panel>
      <Panel title="Remote access">
        <label className="fld">Bearer token for remote mode (stored in this browser only)
          <input className="in" type="password" onChange={(e) => { try { localStorage.setItem("pushpak.token", e.target.value); } catch { /* storage unavailable */ } }} />
        </label>
      </Panel>
    </div>
  );
}
