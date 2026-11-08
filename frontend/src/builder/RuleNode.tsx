import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import type { NodeTypeSpec } from "../types";
import { fmtVal } from "../lib/format";

export interface RuleNodeData {
  spec: NodeTypeSpec;
  type: string;
  label: string;
  params: Record<string, any>;
  value?: any;
  fired?: boolean;
  error?: string | null;
  source?: string;
  [key: string]: unknown;
}

function summary(type: string, p: Record<string, any>): string {
  if (p.msg && p.field) return `${p.msg}.${p.field}${p.scale && p.scale !== 1 ? ` ×${p.scale}` : ""}`;
  if (p.msg) return p.msg;
  if (type === "threshold") return `${p.op ?? ">"} ${p.value ?? "?"}`;
  if (type === "persistence") return `≥ ${p.duration_s ?? "?"} s`;
  if (p.window_s !== undefined) return `window ${p.window_s} s`;
  if (p.window !== undefined) return `window ${p.window}`;
  if (p.detector) return String(p.detector);
  if (p.detectors) return (p.detectors as string[]).join(", ");
  if (p.mode) return String(p.mode);
  if (p.field) return String(p.field);
  if (p.title) return String(p.title);
  return "";
}

function RuleNodeView({ data, selected }: NodeProps) {
  const d = data as RuleNodeData;
  const spec = d.spec;
  const hasOut = spec.output !== "none";
  const v = d.value;
  const vcls = v === true ? "t" : v === false ? "f" : "";
  const inputs = spec.inputs;
  return (
    <div className={`rnode ${selected ? "selected" : ""} ${d.error ? "err" : ""} ${v === true && d.fired !== undefined ? "live-true" : ""}`} title={d.error || spec.description}>
      <div className="nh">
        <span className={`badge outline cat-${spec.category}`} style={{ fontSize: 9 }}>{spec.category}</span>
        <strong style={{ fontSize: 11.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{d.label || spec.label}</strong>
      </div>
      <div className="nb">
        <span className="muted" style={{ fontSize: 10.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{spec.label !== d.label ? spec.label + " · " : ""}{summary(d.type, d.params)}</span>
        {spec.output !== "none" && (
          <span className={`val ${vcls}`}>{v === undefined ? <span className="muted" style={{ fontWeight: 400 }}>value —</span> : fmtVal(v)}</span>
        )}
        {d.error && <span className="err-text" style={{ fontSize: 10 }}>⚠ {d.error}</span>}
        {d.source && <span className="muted" style={{ fontSize: 10 }}>source: {d.source}</span>}
      </div>
      {inputs.map((inp, i) => {
        const top = inputs.length === 1 ? 50 : 28 + (i * 60) / Math.max(1, inputs.length - 1);
        return (
          <div key={inp.name}>
            <Handle type="target" position={Position.Left} id={inp.name} style={{ top: `${top}%` }} />
            {inputs.length > 1 && <span className="handle-label" style={{ top: `${top}%` }}>{inp.name}{inp.optional ? "?" : ""}</span>}
          </div>
        );
      })}
      {hasOut && <Handle type="source" position={Position.Right} id="out" />}
    </div>
  );
}

export default memo(RuleNodeView);
