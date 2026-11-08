// Formatting helpers. Unknown values are always "N/A", never 0.
export const NA = "N/A";

export function num(v: any, digits = 1, unit = ""): string {
  if (v === null || v === undefined || typeof v !== "number" || !isFinite(v)) return NA;
  return `${v.toFixed(digits)}${unit ? ` ${unit}` : ""}`;
}

export function pct(v: any): string {
  if (v === null || v === undefined || typeof v !== "number") return NA;
  return `${Math.round(v * 100)}%`;
}

export function time(t: number | null | undefined, ms = false): string {
  if (!t) return NA;
  const d = new Date(t * 1000);
  const s = d.toISOString().substring(11, ms ? 23 : 19);
  return s;
}

export function dateTime(t: number | string | null | undefined): string {
  if (!t) return NA;
  const d = typeof t === "number" ? new Date(t * 1000) : new Date(t);
  if (isNaN(d.getTime())) return NA;
  return d.toISOString().replace("T", " ").substring(0, 19) + "Z";
}

export function ago(sec: number | null | undefined): string {
  if (sec === null || sec === undefined) return NA;
  if (sec < 1) return "<1 s";
  if (sec < 60) return `${sec.toFixed(0)} s`;
  if (sec < 3600) return `${(sec / 60).toFixed(0)} min`;
  return `${(sec / 3600).toFixed(1)} h`;
}

export function bytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return NA;
  if (n < 1024) return `${n} B`;
  if (n < 1 << 20) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1 << 30) return `${(n / (1 << 20)).toFixed(1)} MB`;
  return `${(n / (1 << 30)).toFixed(2)} GB`;
}

export function hexDump(hex: string | null | undefined): string {
  if (!hex) return "";
  const b = hex.match(/.{1,2}/g) || [];
  const lines: string[] = [];
  for (let i = 0; i < b.length; i += 16) {
    const chunk = b.slice(i, i + 16);
    const ascii = chunk.map((x) => {
      const c = parseInt(x, 16);
      return c >= 32 && c < 127 ? String.fromCharCode(c) : ".";
    });
    lines.push(`${i.toString(16).padStart(4, "0")}  ${chunk.join(" ").padEnd(48)}  ${ascii.join("")}`);
  }
  return lines.join("\n");
}

export function fmtVal(v: any): string {
  if (v === null || v === undefined) return NA;
  if (typeof v === "boolean") return v ? "TRUE" : "FALSE";
  if (typeof v === "number") return Number.isInteger(v) ? String(v) : v.toFixed(Math.abs(v) < 10 ? 3 : 2).replace(/0+$/, "").replace(/\.$/, "");
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

export const SEV_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
export const STATE_ORDER = ["NORMAL", "CLEAR", "OBSERVED", "ANOMALOUS", "SUSPECTED", "CORRELATED", "CONFIRMED"];

export function stateTone(s: string | null | undefined): string {
  switch ((s || "").toUpperCase()) {
    case "CONFIRMED": case "CRITICAL": case "ERROR": case "LOST": case "INVALID SIGNATURE": return "crit";
    case "SUSPECTED": case "CORRELATED": case "HIGH": return "high";
    case "ANOMALOUS": case "MEDIUM": case "DEGRADED": case "STALE": case "RECONNECTING": case "CONNECTING": return "warn";
    case "OBSERVED": case "LOW": case "WAITING_FOR_DATA": case "INFO": return "info";
    case "NORMAL": case "CLEAR": case "ONLINE": case "CONNECTED": case "VALID": case "HEALTHY": case "AVAILABLE": case "RESOLVED": return "ok";
    case "DISABLED": case "DISCONNECTED": case "UNAVAILABLE": case "FALSE_POSITIVE": return "muted";
    default: return "muted";
  }
}
