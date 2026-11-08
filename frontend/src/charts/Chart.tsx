// ECharts wrapper: multiple series, dual axis, zoom/pan, hover, incident/event
// markers (clickable), CSV export, time synchronisation via `cursor`.
import { useEffect, useRef } from "react";
import * as echarts from "echarts";
import { downloadText } from "../services/api";
import { useTheme } from "../lib/theme";

export interface Series { name: string; points: [number, number][]; axis?: 0 | 1; color?: string; step?: boolean; area?: boolean }
export interface Mark { t: number; label: string; tone?: "crit" | "high" | "warn" | "info"; onClick?: () => void }

const TONE: Record<string, string> = { crit: "#ff5470", high: "#ff8a3d", warn: "#f2b84b", info: "#7aa7ff" };
const PALETTE = ["#2f6bf0", "#22c7bd", "#9b9cf9", "#f2a93b", "#e5484d", "#2fbf80", "#7b61ff", "#f47c8a"];

export default function Chart({ series, marks, height = 220, yNames, cursor, relative = false, title, exportName, onClickTime }: {
  series: Series[]; marks?: Mark[]; height?: number | string; yNames?: [string, string?]; cursor?: number | null; relative?: boolean;
  title?: string; exportName?: string; onClickTime?: (t: number) => void;
}) {
  const el = useRef<HTMLDivElement>(null);
  const inst = useRef<echarts.ECharts | null>(null);
  const theme = useTheme();
  const markRef = useRef<Mark[] | undefined>(marks);
  markRef.current = marks;

  useEffect(() => {
    if (!el.current) return;
    const c = echarts.init(el.current, undefined, { renderer: "canvas" });
    inst.current = c;
    c.on("click", (p: any) => {
      if (p.componentType === "markLine" && p.data?.idx !== undefined) markRef.current?.[p.data.idx]?.onClick?.();
      else if (p.value && onClickTime) onClickTime(Array.isArray(p.value) ? p.value[0] : p.value);
    });
    const ro = new ResizeObserver(() => c.resize());
    ro.observe(el.current);
    return () => {
      ro.disconnect();
      c.dispose();
      inst.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const c = inst.current;
    if (!c) return;
    const css = getComputedStyle(document.documentElement);
    const text = css.getPropertyValue("--text-2").trim() || "#9fb0bf";
    const line = css.getPropertyValue("--line").trim() || "#22303c";
    const panel = css.getPropertyValue("--panel").trim() || "#ffffff";
    const fg = css.getPropertyValue("--text").trim() || "#1c2434";
    const t0 = relative ? Math.min(...series.flatMap((s) => (s.points[0] ? [s.points[0][0]] : [])).concat([Infinity])) : 0;
    const fmtT = (v: number) => (relative ? `${(v).toFixed(0)}s` : new Date(v * 1000).toISOString().substring(11, 19));
    const dual = series.some((s) => s.axis === 1);
    c.setOption(
      {
        animation: false,
        backgroundColor: "transparent",
        color: PALETTE,
        title: title ? { text: title, textStyle: { color: text, fontSize: 11, fontWeight: 600 }, left: 6, top: 2 } : undefined,
        grid: { left: 48, right: dual ? 48 : 16, top: title ? 30 : 24, bottom: 46 },
        tooltip: { trigger: "axis", backgroundColor: panel, borderColor: line, textStyle: { color: fg, fontSize: 11 },
          axisPointer: { type: "line" }, valueFormatter: (v: any) => (typeof v === "number" ? v.toFixed(3) : v) },
        legend: { top: 2, right: 8, textStyle: { color: text, fontSize: 11 }, itemWidth: 12, itemHeight: 6 },
        xAxis: { type: "value", min: "dataMin", max: "dataMax", axisLabel: { color: text, fontSize: 10, formatter: (v: number) => fmtT(v - (relative ? 0 : 0)) },
          axisLine: { lineStyle: { color: line } }, splitLine: { show: false } },
        yAxis: [
          { type: "value", name: yNames?.[0], nameTextStyle: { color: text, fontSize: 10 }, scale: true, axisLabel: { color: text, fontSize: 10 }, splitLine: { lineStyle: { color: line } } },
          ...(dual ? [{ type: "value", name: yNames?.[1], nameTextStyle: { color: text, fontSize: 10 }, scale: true, axisLabel: { color: text, fontSize: 10 }, splitLine: { show: false } }] : []),
        ],
        dataZoom: [{ type: "inside", filterMode: "none" }, { type: "slider", height: 16, bottom: 6, borderColor: line, textStyle: { color: text, fontSize: 9 }, filterMode: "none" }],
        series: series.map((s, i) => ({
          name: s.name, type: "line", showSymbol: false, sampling: "lttb", step: s.step ? "end" : undefined, yAxisIndex: s.axis ?? 0,
          lineStyle: { width: 1.5, color: s.color }, itemStyle: { color: s.color }, areaStyle: s.area ? { opacity: 0.12 } : undefined,
          data: s.points.map((p) => [relative ? p[0] - t0 : p[0], p[1]]),
          markLine: i === 0 && (marks?.length || cursor) ? {
            symbol: "none", silent: false, animation: false,
            data: [
              ...(marks || []).map((m, idx) => ({ xAxis: relative ? m.t - t0 : m.t, idx, label: { formatter: m.label, color: TONE[m.tone || "info"], fontSize: 9, position: "insideEndTop" },
                lineStyle: { color: TONE[m.tone || "info"], type: "dashed", width: 1 } })),
              ...(cursor ? [{ xAxis: relative ? cursor - t0 : cursor, label: { show: false }, lineStyle: { color: fg, width: 1 } }] : []),
            ],
          } : undefined,
        })),
      },
      { notMerge: true },
    );
  }, [series, marks, cursor, relative, yNames, title, theme]);

  const exportCsv = () => {
    const rows: string[] = ["series,t,value"];
    series.forEach((s) => s.points.forEach((p) => rows.push(`${s.name},${p[0]},${p[1]}`)));
    downloadText(`${exportName || "chart"}.csv`, rows.join("\n"), "text/csv");
  };

  return (
    <div style={{ position: "relative", height }}>
      <div ref={el} className="chart" style={{ height: "100%" }} />
      <button className="btn sm ghost" style={{ position: "absolute", right: 4, bottom: 22, opacity: 0.7 }} onClick={exportCsv} title="Export CSV">CSV</button>
      {!series.some((s) => s.points.length) && <div className="muted small" style={{ position: "absolute", inset: 0, display: "grid", placeItems: "center", pointerEvents: "none" }}>NO DATA — source has not provided these fields</div>}
    </div>
  );
}

export function Heatmap({ labels, matrix, height = 320 }: { labels: string[]; matrix: (number | null)[][]; height?: number }) {
  const el = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!el.current) return;
    const c = echarts.init(el.current);
    const data: any[] = [];
    matrix.forEach((row, i) => row.forEach((v, j) => data.push([j, i, v === null ? "-" : v])));
    c.setOption({
      tooltip: { formatter: (p: any) => `${labels[p.value[1]]} × ${labels[p.value[0]]}: ${p.value[2]}` },
      grid: { left: 110, right: 20, top: 10, bottom: 80 },
      xAxis: { type: "category", data: labels, axisLabel: { rotate: 40, color: "#9fb0bf", fontSize: 10 } },
      yAxis: { type: "category", data: labels, axisLabel: { color: "#9fb0bf", fontSize: 10 } },
      visualMap: { min: -1, max: 1, calculable: false, orient: "horizontal", left: "center", bottom: 0, itemHeight: 120, textStyle: { color: "#9fb0bf" },
        inRange: { color: ["#2f6bf0", "#f4f6f9", "#e86a2c"] } },
      series: [{ type: "heatmap", data, label: { show: true, color: "#1c2434", fontSize: 10 } }],
    });
    const ro = new ResizeObserver(() => c.resize());
    ro.observe(el.current);
    return () => {
      ro.disconnect();
      c.dispose();
    };
  }, [labels, matrix]);
  return <div ref={el} style={{ height }} />;
}
