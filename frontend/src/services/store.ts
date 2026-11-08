// Minimal external store + reconnecting WebSocket channels. Components subscribe
// with selectors so 10 Hz telemetry does not re-render the whole workspace.
import { useSyncExternalStore, useRef } from "react";
import type { Alert, Health, IdsSnapshot, Incident, Packet, Telemetry, TimelineEvent } from "../types";

export interface LiveState {
  telemetry: Telemetry;
  track: [number, number, number, number][];
  ids: IdsSnapshot | null;
  health: Health | null;
  alerts: Alert[];
  incidents: Record<string, Incident>;
  timeline: TimelineEvent[];
  packets: Packet[];
  packetsPaused: boolean;
  connection: any;
  ws: Record<string, "open" | "closed" | "connecting">;
  cases: Record<string, any>;
  results: any[];
  builder: { nodes?: any; traces: any[] };
  sessionId: string | null;
  toasts: { id: number; text: string; kind: string }[];
}

const initial: LiveState = {
  telemetry: {}, track: [], ids: null, health: null, alerts: [], incidents: {}, timeline: [], packets: [], packetsPaused: false,
  connection: null, ws: {}, cases: {}, results: [], builder: { traces: [] }, sessionId: null, toasts: [],
};

let state: LiveState = initial;
const listeners = new Set<() => void>();
let scheduled = false;

export function getState() {
  return state;
}

export function setState(patch: Partial<LiveState> | ((s: LiveState) => Partial<LiveState>)) {
  const p = typeof patch === "function" ? patch(state) : patch;
  state = { ...state, ...p };
  if (!scheduled) {
    scheduled = true;
    requestAnimationFrame(() => {
      scheduled = false;
      listeners.forEach((l) => l());
    });
  }
}

function subscribe(l: () => void) {
  listeners.add(l);
  return () => listeners.delete(l);
}

export function useLive<T>(selector: (s: LiveState) => T): T {
  const sel = useRef(selector);
  sel.current = selector;
  return useSyncExternalStore(subscribe, () => sel.current(state));
}

let toastId = 1;
export function toast(text: string, kind: "info" | "error" | "ok" | "warn" = "info") {
  const id = toastId++;
  setState((s) => ({ toasts: [...s.toasts.slice(-4), { id, text, kind }] }));
  setTimeout(() => setState((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })), kind === "error" ? 7000 : 4000);
}

// ------------------------------------------------------------------ websockets
const MAX_PACKETS = 5000;

function onMessage(channel: string, msg: { type: string; data: any }) {
  const { type, data } = msg;
  if (channel === "telemetry" && type === "state") {
    setState((s) => {
      const sid = data?.session_id ?? null;
      let track = s.track;
      if (sid !== s.sessionId) track = [];
      const tp = data?.track_point;
      if (tp && (!track.length || track[track.length - 1][0] !== tp[0])) {
        track = track.length > 20000 ? [...track.slice(-15000), tp] : [...track, tp];
      }
      const reset = sid !== s.sessionId;
      return {
        telemetry: data, track, sessionId: sid,
        ...(reset ? { alerts: [], incidents: {}, timeline: [], packets: [], results: [] } : {}),
      };
    });
  } else if (type === "detectors") {
    setState({ ids: data });
  } else if (type === "health") {
    setState({ health: data });
  } else if (type === "alert") {
    setState((s) => {
      const others = s.alerts.filter((a) => a.alert_id !== data.alert_id);
      return { alerts: [data, ...others].slice(0, 1000) };
    });
  } else if (type === "incident") {
    const isNew = !getState().incidents[data.incident_id];
    setState((s) => ({ incidents: { ...s.incidents, [data.incident_id]: data } }));
    if (isNew) toast(`${data.incident_id}: ${data.title} (${data.state})`, "warn");
  } else if (type === "case") {
    setState((s) => ({ cases: { ...s.cases, [data.case_id]: { ...(s.cases[data.case_id] || {}), ...data } } }));
  } else if (type === "timeline") {
    setState((s) => ({ timeline: [...s.timeline.slice(-2999), data] }));
  } else if (type === "packets") {
    if (getState().packetsPaused) return;
    setState((s) => {
      const merged = s.packets.concat(data as Packet[]);
      return { packets: merged.length > MAX_PACKETS ? merged.slice(merged.length - MAX_PACKETS) : merged };
    });
  } else if (type === "connection") {
    setState({ connection: data });
  } else if (type === "result") {
    setState((s) => ({ results: [...s.results.slice(-1999), data] }));
  } else if (type === "system") {
    toast(data.message, data.severity === "HIGH" ? "error" : "info");
  } else if (type === "resync") {
    setState({ track: [], alerts: [], timeline: [], packets: [], results: [], incidents: {} });
  } else if (type === "trace") {
    setState((s) => ({ builder: { ...s.builder, traces: [data, ...s.builder.traces].slice(0, 50) } }));
  } else if (type === "nodes") {
    setState((s) => ({ builder: { ...s.builder, nodes: data } }));
  }
}

const sockets: Record<string, WebSocket | null> = {};

export function connectChannel(channel: string) {
  let delay = 500;
  const open = () => {
    setState((s) => ({ ws: { ...s.ws, [channel]: "connecting" } }));
    const proto = location.protocol === "https:" ? "wss" : "ws";
    let tk: string | null = null;
    try {
      tk = localStorage.getItem("pushpak.token");
    } catch {
      /* private mode */
    }
    const ws = new WebSocket(`${proto}://${location.host}/ws/${channel}${tk ? `?token=${encodeURIComponent(tk)}` : ""}`);
    sockets[channel] = ws;
    ws.onopen = () => {
      delay = 500;
      setState((s) => ({ ws: { ...s.ws, [channel]: "open" } }));
    };
    ws.onmessage = (e) => {
      try {
        onMessage(channel, JSON.parse(e.data));
      } catch {
        /* ignore malformed */
      }
    };
    ws.onclose = () => {
      setState((s) => ({ ws: { ...s.ws, [channel]: "closed" } }));
      setTimeout(open, delay);
      delay = Math.min(delay * 2, 8000);
    };
    ws.onerror = () => ws.close();
  };
  open();
}

export function startRealtime() {
  ["telemetry", "ids", "incidents", "events", "health", "builder"].forEach(connectChannel);
}
