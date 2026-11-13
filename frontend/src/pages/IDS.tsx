// IDS workspace (spec §58): detector grid, active anomalies, confidence timeline,
// FC vs Ground comparison (§27), correlation graph, threat history.
import { useTheme } from "../lib/theme";
import { useMemo } from "react";
import { ReactFlow, Background, type Edge, type Node } from "@xyflow/react";
import { useLive } from "../services/store";
import { go, openDrawer } from "../lib/nav";
import Chart, { type Series } from "../charts/Chart";
import { Badge, Confidence, Empty, PageTitle, Panel, State } from "../components/ui";
import { time } from "../lib/format";
import type { GnssIntegrity, Incident } from "../types";

export function Comparison() {
  const ids = useLive((s) => s.ids);
  const c = ids?.comparison;
  if (!c) return <span className="muted">No data.</span>;
  return (
    <div className="col">
      {!c.fc_available && (
        <div className="notice warn small">
          <strong>FC IDS / LUA columns show N/A because no PUSHPAK telemetry has been received.</strong> {c.firmware_note ? `Firmware finding: ${c.firmware_note}.` : ""} Only actual values are displayed.
        </div>
      )}
      <div className="scroll">
        <table className="tbl">
          <thead><tr><th>Detector</th><th>FC IDS</th><th>LUA</th><th>GROUND IDS</th><th>CORRELATED</th></tr></thead>
          <tbody>
            {c.rows.map((r) => (
              <tr key={r.detector} className="click" onClick={() => openDrawer({ kind: "detector", group: r.detector })}>
                <td><strong>{r.detector}</strong></td>
                <td>{r.fc ? <span className="row gap-s"><State s={r.fc.state} /><span className="mono small">{Math.round(r.fc.confidence * 100)}%</span><span className="muted small">{r.fc.evidence?.bits?.join(",")}</span></span> : <span className="muted" title="No PIDS STATUSTEXT received">N/A</span>}</td>
                <td>{r.lua ? <span className="small"><Badge v="YES" tone="high" /> {r.lua.class} · {Math.round(r.lua.confidence * 100)}%</span> : <span className="muted">—</span>}</td>
                <td><span className="row gap-s"><State s={r.ground.state === "NORMAL" ? "CLEAR" : r.ground.state} />{r.ground.detector && r.ground.state !== "CLEAR" && <span className="muted small">{r.ground.detector}</span>}</span></td>
                <td>{r.correlated ? <State s={r.correlated} /> : <span className="muted">—</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="small muted">{c.jamming}</div>
      {c.event_delivery && <EventDelivery d={c.event_delivery} />}
      {c.gnss_integrity && <GnssIntegrityPanel g={c.gnss_integrity} />}
      {Object.keys(c.lua_health || {}).length > 0 && (
        <div>
          <div className="small muted mb">LUA SCRIPT HEALTH (from ArduPilot scripting STATUSTEXT)</div>
          {Object.entries(c.lua_health).map(([s, h]: any) => (
            <div key={s} className="row small"><State s={h.status === "ERROR" ? "ERROR" : h.status} /><span className="mono">{s}</span><span className="muted grow">{h.message}</span></div>
          ))}
        </div>
      )}
    </div>
  );
}

// GAP-07: one-way bridge delivery. Losses are made visible; they cannot be re-requested over MAVLink.
function EventDelivery({ d }: { d: any }) {
  const lost = d.events_missed_total > 0 || d.sequence_discontinuities > 0;
  return (
    <div className={`notice ${lost ? "warn" : ""}`}>
      <div className="row wrap gap-s small">
        <strong>FC EVENT DELIVERY</strong>
        <Badge v={d.protocol_version ? `bridge v${d.protocol_version}` : "bridge not announced"} tone={d.protocol_version ? "info" : "warn"} />
        {d.state_map_matches_assumed === false && <Badge v="state map differs" tone="warn" />}
        <span>boot epoch {d.boot_epoch}{d.reboots_seen ? ` (${d.reboots_seen} reboot${d.reboots_seen > 1 ? "s" : ""} seen)` : ""}</span>
        <span>received {d.events_received_this_boot}</span>
        {d.events_before_connection != null && <span className="muted">before connection {d.events_before_connection}</span>}
        <span className={lost ? "t-warn" : ""}>missed {d.events_missed_total} · seq gaps {d.sequence_discontinuities}</span>
        <span className="muted">duplicates ignored {d.duplicates_ignored}</span>
      </div>
      <div className="small muted">{d.delivery_model}</div>
    </div>
  );
}

// FW-13: onboard GNSSIntegrity engine (GNSS vs an IMU-only prediction), from DataFlash IDSG/IDSR.
const GI_FLAGS_SHOWN = ["HEADING_VALID", "BIAS_VALID", "TRUST_GATE_OPEN", "GRAVITY_FAULT", "IMU_GAP", "IMU_OVERFLOW",
  "ACCEL_CLIPPING", "HIGH_VIBRATION", "FIX_UNALIGNABLE", "BARO_WARN", "GROUND_WARN", "HEADING_DISTURBED",
  "RESEED_REQUIRED", "ALARM_LATCHED", "CLEAR_BLOCKED"];
const num = (v: number | undefined, d = 1) => (v == null ? "—" : v.toFixed(d));

function GnssIntegrityPanel({ g }: { g: GnssIntegrity }) {
  const suspicious = g.state === "WARNING" || g.state === "ALARM";
  return (
    <div className={`notice ${suspicious ? "warn" : ""}`}>
      <div className="row wrap gap-s small">
        <strong>FC GNSS INTEGRITY (IMU-only prediction)</strong>
        <State s={g.state} />
        <span className="mono">conf {Math.round(g.confidence * 100)}%</span>
        <span className="muted">IDSG seq {g.seq} · fix age {g.fix_age_ms} ms · lag applied {g.applied_lag_ms} ms</span>
        <span className="muted">bias |b| {num(g.accel_bias_norm_mps2, 3)} m/s² · Δspeed {num(g.delta_speed_residual_mps, 2)} m/s · baro Δh {num(g.baro_residual_m, 1)} m</span>
      </div>
      <div className="row wrap gap-s small mb">
        {g.flags.filter((f) => GI_FLAGS_SHOWN.includes(f)).map((f) => (
          <Badge key={f} v={f.replace(/_/g, " ")} tone={["HEADING_VALID", "BIAS_VALID", "TRUST_GATE_OPEN"].includes(f) ? "ok" : "warn"} />
        ))}
      </div>
      <div className="scroll">
        <table className="tbl">
          <thead><tr><th>Horizon</th><th>Status</th><th>Elapsed</th><th>|r_p| m (D²)</th><th>|r_v| m/s (D²)</th><th>Δspeed D²</th><th>σp / σv</th><th>Reason</th></tr></thead>
          <tbody>
            {g.horizons.map((h) => (
              <tr key={h.index}>
                <td><strong>{h.duration_s} s</strong></td>
                <td><span className="row gap-s">{h.alarm ? <State s="ALARM" /> : h.warn ? <State s="WARNING" /> : h.valid ? <State s="VALID" /> : h.armed ? <State s="DEGRADED" /> : <span className="muted">{h.expired ? "expired" : "idle"}</span>}{h.extended && <Badge v="extended" tone="warn" />}{h.heading_free_only && <Badge v="heading-free" tone="info" />}</span></td>
                <td className="mono">{num(h.elapsed_s)}</td>
                <td className="mono">{num(h.position_residual_m)} ({num(h.position_test)})</td>
                <td className="mono">{num(h.velocity_residual_mps, 2)} ({num(h.velocity_test)})</td>
                <td className="mono">{num(h.delta_speed_test)}</td>
                <td className="mono">{num(h.position_sigma_m)} / {num(h.velocity_sigma_mps, 2)}</td>
                <td className="muted small">{h.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="small muted">Horizons share IMU and GNSS data: they are not independent witnesses. DEGRADED means the prediction cannot support a test; it is never reported as spoofing.</div>
    </div>
  );
}

function CorrelationGraph({ incidents }: { incidents: Incident[] }) {
  const theme = useTheme();
  const { nodes, edges } = useMemo(() => {
    const nodes: Node[] = [];
    const edges: Edge[] = [];
    const dets = new Map<string, number>();
    incidents.slice(0, 8).forEach((inc, i) => {
      nodes.push({ id: inc.incident_id, position: { x: 380, y: i * 90 }, data: { label: `${inc.incident_id}\n${inc.state} · ${Math.round(inc.confidence * 100)}%` },
        style: { background: "var(--crit-bg)", color: "var(--text)", border: "1px solid var(--crit)", fontSize: 11, width: 180, whiteSpace: "pre-line" } });
      inc.detectors.forEach((d) => {
        if (!dets.has(d)) {
          dets.set(d, dets.size);
          nodes.push({ id: `d:${d}`, position: { x: 20, y: (dets.size - 1) * 58 }, data: { label: d },
            style: { background: "var(--panel-2)", color: "var(--text)", border: "1px solid var(--line-2)", fontSize: 11, width: 200 } });
        }
        edges.push({ id: `${d}-${inc.incident_id}`, source: `d:${d}`, target: inc.incident_id, animated: inc.status === "OPEN", style: { stroke: "var(--accent-2)" } });
      });
    });
    return { nodes, edges };
  }, [incidents]);
  if (!nodes.length) return <Empty title="NO CORRELATIONS" text="Incidents appear here when evidence from multiple detectors/sources correlates." />;
  return (
    <div style={{ height: 300 }}>
      <ReactFlow nodes={nodes} edges={edges} fitView minZoom={0.15} proOptions={{ hideAttribution: true }} nodesDraggable={false}
        onNodeClick={(_, n) => n.id.startsWith("INC-") && go(`incidents/${n.id}`)} colorMode={theme}>
        <Background gap={24} color="var(--line)" />
      </ReactFlow>
    </div>
  );
}

export default function IDSPage() {
  const ids = useLive((s) => s.ids);
  const alerts = useLive((s) => s.alerts);
  const incidentsMap = useLive((s) => s.incidents);
  const results = useLive((s) => s.results);
  const incidents = useMemo(() => Object.values(incidentsMap).sort((a, b) => b.last_seen - a.last_seen), [incidentsMap]);
  const active = alerts.filter((a) => ["ANOMALOUS", "SUSPECTED", "CONFIRMED"].includes(a.state) && a.status !== "RESOLVED" && a.status !== "FALSE_POSITIVE").slice(0, 25);
  const series: Series[] = useMemo(() => {
    const by: Record<string, [number, number][]> = {};
    results.forEach((r) => {
      if (r.kind === "alert" && r.confidence != null) (by[r.detector] ||= []).push([r.t, r.confidence]);
    });
    return Object.entries(by).slice(0, 8).map(([name, points]) => ({ name, points, step: true }));
  }, [results]);
  const marks = useMemo(() => incidents.map((i) => ({ t: i.first_seen, label: i.incident_id, tone: "crit" as const, onClick: () => go(`incidents/${i.incident_id}`) })), [incidents]);

  return (
    <div className="col">
      <PageTitle title="IDS" sub="ground detectors · PUSHPAK FC/Lua · correlation" />
      <Panel title="Detector grid" flush>
        <div className="scroll">
          <table className="tbl">
            <thead><tr><th>Detector</th><th>Health</th><th>State</th><th>Confidence</th><th>Domain</th><th className="right">Events</th><th className="right">Results</th><th className="right">Errors</th><th className="right">Latency</th><th>Last update</th></tr></thead>
            <tbody>
              {(ids?.detectors || []).map((d) => (
                <tr key={d.detector} className="click" onClick={() => openDrawer({ kind: "detector", group: d.detector })}>
                  <td><strong>{d.name}</strong><div className="muted small">{d.detector} v{d.version}</div></td>
                  <td><State s={d.health} /></td><td><State s={d.state === "NORMAL" ? "CLEAR" : d.state} /></td>
                  <td><Confidence v={d.confidence} /></td><td className="small dim">{d.domain}</td>
                  <td className="right mono">{d.events}</td><td className="right mono">{d.results}</td>
                  <td className={`right mono ${d.errors ? "t-crit" : ""}`} title={d.last_error || ""}>{d.errors}</td>
                  <td className="right mono">{d.latency_ms.toFixed(3)} ms</td><td className="mono small">{d.last_update?.substring(11, 19) ?? "N/A"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
      <div className="grid g2">
        <Panel title="FC vs Ground (distributed detection)"><Comparison /></Panel>
        <Panel title="Active anomalies" right={<a className="small" onClick={() => go("alerts")}>Alert center →</a>} flush>
          {active.length === 0 ? <Empty title="NO ACTIVE ANOMALIES" /> : (
            <table className="tbl"><tbody>
              {active.map((a) => (
                <tr key={a.alert_id} className="click" onClick={() => openDrawer({ kind: "result", id: a.result_id })}>
                  <td className="mono small nowrap">{time(a.t)}</td><td><State s={a.state} /></td><td>{a.title}<div className="muted small">{a.detector} · {a.source}</div></td><td><Confidence v={a.confidence} /></td>
                </tr>
              ))}
            </tbody></table>
          )}
        </Panel>
      </div>
      <Panel title="Confidence timeline (detector scores; incident markers clickable)"><Chart series={series} marks={marks} height={220} exportName="confidence" /></Panel>
      <div className="grid g2">
        <Panel title="Correlation graph"><CorrelationGraph incidents={incidents} /></Panel>
        <Panel title="Threat history" flush>
          {incidents.length === 0 ? <Empty title="NO INCIDENTS" text="No incidents have been recorded in this session." /> : (
            <table className="tbl"><tbody>
              {incidents.map((i) => (
                <tr key={i.incident_id} className="click" onClick={() => go(`incidents/${i.incident_id}`)}>
                  <td className="mono small">{time(i.first_seen)}</td><td><State s={i.severity} /></td><td><State s={i.state} /></td>
                  <td>{i.title}<div className="muted small">{i.incident_id} · {i.detectors.join(", ")}</div></td><td><Confidence v={i.confidence} /></td><td><State s={i.status} /></td>
                </tr>
              ))}
            </tbody></table>
          )}
        </Panel>
      </div>
      {ids?.rules && ids.rules.length > 0 && (
        <Panel title="Published rules (live)" flush>
          <table className="tbl"><thead><tr><th>Rule</th><th className="right">Evaluations</th><th className="right">Triggers</th><th className="right">Errors</th></tr></thead><tbody>
            {ids.rules.map((r) => <tr key={r.rule_id} className="click" onClick={() => go(`builder/${r.rule_id}`)}><td>{r.rule_id} <span className="muted">v{r.version}</span></td><td className="right mono">{r.evaluations}</td><td className="right mono">{r.triggers}</td><td className="right mono">{r.errors}</td></tr>)}
          </tbody></table>
        </Panel>
      )}
    </div>
  );
}
