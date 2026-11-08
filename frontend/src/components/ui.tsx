import React, { useEffect, useState } from "react";
import type { Explanation, TimelineEvent, TraceRow } from "../types";
import { fmtVal, stateTone, time } from "../lib/format";
import { useLive } from "../services/store";

export function Badge({ v, tone, outline, title }: { v: React.ReactNode; tone?: string; outline?: boolean; title?: string }) {
  const t = tone ?? stateTone(typeof v === "string" ? v : "");
  return <span className={`badge ${outline ? "outline" : t}`} title={title}>{v}</span>;
}

/** State badge: text + color (never color alone). */
export function State({ s, prefix }: { s: string | null | undefined; prefix?: string }) {
  const label = s ? String(s).replace(/_/g, " ") : "N/A";
  return <Badge v={<>{prefix ? `${prefix} ` : ""}{label}</>} tone={stateTone(s || "")} />;
}

export function Dot({ tone, pulse }: { tone: string; pulse?: boolean }) {
  return <span className={`dot ${tone} ${pulse ? "pulse" : ""}`} style={{ width: 7, height: 7, borderRadius: "50%", display: "inline-block" }} />;
}

export function Panel({ title, right, children, flush, className, style, bodyStyle }: {
  title?: React.ReactNode; right?: React.ReactNode; children?: React.ReactNode; flush?: boolean; className?: string;
  style?: React.CSSProperties; bodyStyle?: React.CSSProperties;
}) {
  return (
    <section className={`panel ${className || ""}`} style={style}>
      {title !== undefined && (
        <div className="ph">
          <h3>{title}</h3>
          <div className="grow" />
          {right}
        </div>
      )}
      <div className={`pb ${flush ? "flush" : ""}`} style={{ flex: 1, ...bodyStyle }}>{children}</div>
    </section>
  );
}

export function PageTitle({ title, sub, right }: { title: string; sub?: React.ReactNode; right?: React.ReactNode }) {
  return (
    <div className="page-title">
      <h2>{title}</h2>
      {sub && <span className="sub">{sub}</span>}
      <div className="grow" />
      {right}
    </div>
  );
}

export function Empty({ title, text, action }: { title: string; text?: string; action?: React.ReactNode }) {
  return (
    <div className="empty">
      <div>
        <div className="empty-mark" aria-hidden="true" />
        <h4>{title}</h4>
        {text && <p>{text}</p>}
        {action}
      </div>
    </div>
  );
}

export function Drawer({ open, onClose, title, children, right }: { open: boolean; onClose: () => void; title: React.ReactNode; children: React.ReactNode; right?: React.ReactNode }) {
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);
  if (!open) return null;
  return (
    <>
      <div className="overlay" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true">
        <div className="dh">
          <strong>{title}</strong>
          <div className="grow" />
          {right}
          <button className="btn sm ghost" onClick={onClose} aria-label="Close">✕</button>
        </div>
        <div className="db">{children}</div>
      </aside>
    </>
  );
}

export function Modal({ open, onClose, title, children }: { open: boolean; onClose: () => void; title: React.ReactNode; children: React.ReactNode }) {
  if (!open) return null;
  return (
    <>
      <div className="overlay" onClick={onClose} />
      <div className="modal" role="dialog" aria-modal="true">
        <div className="dh row" style={{ padding: "12px 16px", borderBottom: "1px solid var(--line)" }}>
          <strong>{title}</strong>
          <div className="grow" />
          <button className="btn sm ghost" onClick={onClose} aria-label="Close">✕</button>
        </div>
        <div className="mb2">{children}</div>
      </div>
    </>
  );
}

export function Tabs({ tabs, value, onChange }: { tabs: { id: string; label: React.ReactNode }[]; value: string; onChange: (v: string) => void }) {
  return (
    <div className="tabs">
      {tabs.map((t) => (
        <button key={t.id} className={t.id === value ? "on" : ""} onClick={() => onChange(t.id)}>{t.label}</button>
      ))}
    </div>
  );
}

export function Seg<T extends string | number>({ options, value, onChange }: { options: { v: T; l: React.ReactNode }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className="seg">
      {options.map((o) => (
        <button key={String(o.v)} className={o.v === value ? "on" : ""} onClick={() => onChange(o.v)}>{o.l}</button>
      ))}
    </div>
  );
}

export function KV({ rows }: { rows: [React.ReactNode, React.ReactNode][] }) {
  return (
    <dl className="kv">
      {rows.map(([k, v], i) => (
        <React.Fragment key={i}>
          <dt>{k}</dt>
          <dd>{v === null || v === undefined || v === "" ? <span className="muted">N/A</span> : v}</dd>
        </React.Fragment>
      ))}
    </dl>
  );
}

export function Toasts() {
  const toasts = useLive((s) => s.toasts);
  return (
    <div className="toasts">
      {toasts.map((t) => <div key={t.id} className={`toast ${t.kind}`}>{t.text}</div>)}
    </div>
  );
}

export function Confidence({ v, basis }: { v: number | null | undefined; basis?: string }) {
  if (v === null || v === undefined) return <span className="muted" title="Source did not provide a confidence value">N/A</span>;
  const tone = v >= 0.75 ? "crit" : v >= 0.45 ? "high" : v >= 0.2 ? "warn" : "info";
  return (
    <span className="row gap-s" title={basis}>
      <span className="mono">{Math.round(v * 100)}%</span>
      <span className="meter" style={{ width: 46 }}><i style={{ width: `${v * 100}%`, background: `var(--${tone})` }} /></span>
    </span>
  );
}

export function ExplanationView({ e }: { e: Explanation | null | undefined }) {
  if (!e) return <span className="muted">No explanation available.</span>;
  const rows: [string, React.ReactNode][] = [
    ["WHAT", e.what], ["WHY", e.why], ["WHEN", <span className="mono">{e.when}</span>], ["SOURCE", e.source],
    ["EVIDENCE", e.evidence?.length ? <ul>{e.evidence.map((x, i) => <li key={i} className="mono small">{x}</li>)}</ul> : <span className="muted">N/A</span>],
    ["RULE", <span className="mono small">{e.rule}</span>],
    ["CONFIDENCE", <div className="col gap-s"><span>{e.confidence}</span>{e.contributors?.length ? <Contributors items={e.contributors} /> : null}</div>],
    ["LIMITATIONS", e.limitations?.length ? <ul>{e.limitations.map((x, i) => <li key={i}>{x}</li>)}</ul> : <span className="muted">none recorded</span>],
  ];
  if (e.state_policy) rows.push(["POLICY", <span className="small dim">{e.state_policy}</span>]);
  return (
    <div className="expl">
      {rows.map(([k, v]) => (
        <React.Fragment key={k}>
          <div className="k">{k}</div>
          <div>{v}</div>
        </React.Fragment>
      ))}
    </div>
  );
}

export function Contributors({ items }: { items: { label: string; value: number; basis?: string; source?: string }[] }) {
  const max = Math.max(0.01, ...items.map((c) => c.value));
  return (
    <div className="col gap-s">
      {items.map((c, i) => (
        <div key={i} className="contrib" title={c.basis}>
          <span className="mono" style={{ width: 38, textAlign: "right" }}>+{Math.round(c.value * 100)}</span>
          <span className="bar" style={{ width: `${(c.value / max) * 90}px` }} />
          <span className="grow">{c.label}{c.source ? <span className="muted small"> · {c.source}</span> : null}</span>
        </div>
      ))}
    </div>
  );
}

export function TraceView({ rows }: { rows: TraceRow[] | null | undefined }) {
  if (!rows?.length) return <span className="muted">No rule trace (ground detector results carry inputs and method instead).</span>;
  return (
    <div className="trace">
      {rows.map((r) => (
        <div key={r.node_id} className={`tr ${r.category === "RESULT" ? "result" : ""}`}>
          <span className={`cat cat-${r.category}`}>{r.category}</span>
          <span>
            <span>{r.label}</span>
            {Object.keys(r.inputs || {}).length > 0 && <span className="muted small"> ← {Object.entries(r.inputs).map(([k, v]) => `${k}=${fmtVal(v)}`).join(", ")}</span>}
            {r.detail && <div className="muted small">{r.detail}</div>}
          </span>
          <strong>{typeof r.value === "string" ? r.value : fmtVal(r.value)}</strong>
        </div>
      ))}
    </div>
  );
}

const TL_TONE: Record<string, string> = {
  INCIDENT: "crit", IDS_ALERT: "high", GPS_EVENT: "high", IMU_EVENT: "warn", LINK_LOSS: "crit", LINK_DEGRADED: "warn",
  SNAPSHOT: "info", ARM: "ok", DISARM: "ok", TAKEOFF: "ok", LAND: "ok", MODE_CHANGE: "info", COMMAND: "info",
  PARAMETER_CHANGE: "warn", MISSION_CHANGE: "warn", SESSION_START: "ok", SESSION_END: "ok", STATUSTEXT: "info", HEARTBEAT: "ok",
};

export function Timeline({ events, onPick, max = 400 }: { events: TimelineEvent[]; onPick?: (e: TimelineEvent) => void; max?: number }) {
  if (!events.length) return <Empty title="NO EVENTS" text="No timeline events in this window." />;
  return (
    <div className="tl">
      {events.slice(-max).map((e) => (
        <div key={e.id} className={`ev ${TL_TONE[e.type] || "info"}`} onClick={() => onPick?.(e)}>
          <div className="meta">{time(e.t, true)} · {e.type}</div>
          <div className="title">{e.title}</div>
        </div>
      ))}
    </div>
  );
}

export function JsonView({ data, maxHeight = 360 }: { data: any; maxHeight?: number }) {
  return <pre className="code" style={{ maxHeight }}>{JSON.stringify(data, null, 2)}</pre>;
}

export function useAsync<T>(fn: () => Promise<T>, deps: any[], interval?: number): { data: T | undefined; error: any; loading: boolean; reload: () => void } {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<any>();
  const [loading, setLoading] = useState(true);
  const [n, setN] = useState(0);
  useEffect(() => {
    let alive = true;
    const run = () => fn().then((d) => alive && (setData(d), setError(undefined))).catch((e) => alive && setError(e)).finally(() => alive && setLoading(false));
    run();
    const h = interval ? setInterval(run, interval) : undefined;
    return () => {
      alive = false;
      if (h) clearInterval(h);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, n]);
  return { data, error, loading, reload: () => setN((x) => x + 1) };
}

export function ErrorNote({ error }: { error: any }) {
  if (!error) return null;
  return <div className="notice crit">{error?.body?.type ? <strong>{error.body.type}: </strong> : null}{error?.message || String(error)}</div>;
}

export function Copy({ text, label = "Copy" }: { text: string; label?: string }) {
  const [ok, setOk] = useState(false);
  return (
    <button className="btn sm" onClick={() => navigator.clipboard?.writeText(text).then(() => { setOk(true); setTimeout(() => setOk(false), 1200); })}>
      {ok ? "Copied" : label}
    </button>
  );
}
