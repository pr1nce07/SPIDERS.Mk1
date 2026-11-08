// GCS Custom Ruleset (spec §12–17, §59–61). The GUI edits rule *definitions* only;
// the backend validates against the MAVLink registry and executes fixed node
// implementations — no code is generated or evaluated.
import { useTheme } from "../lib/theme";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ReactFlow, Background, Controls, addEdge, applyEdgeChanges, applyNodeChanges,
  type Connection, type Edge, type EdgeChange, type Node, type NodeChange, type ReactFlowInstance,
} from "@xyflow/react";
import { api } from "../services/api";
import { toast, useLive } from "../services/store";
import { go, openDrawer, useRoute } from "../lib/nav";
import RuleNodeView, { type RuleNodeData } from "./RuleNode";
import Chart from "../charts/Chart";
import { Badge, Confidence, Empty, ErrorNote, KV, Modal, State, Tabs, TraceView } from "../components/ui";
import type { DetectorHealth, RegistryMessage, Rule, RuleCatalog, RuleNode, ValidationResult } from "../types";
import { fmtVal } from "../lib/format";

const nodeTypes = { rule: RuleNodeView };
const CATS = ["INPUT", "TRANSFORM", "LOGIC", "CORRELATION", "OUTPUT"];
const SCENARIO_DATASETS = ["NORMAL_FLIGHT", "GPS_DRIFT", "GPS_JUMP", "GPS_IMU_MISMATCH", "MAVLINK_SEQUENCE_GAP", "HEARTBEAT_LOSS", "UNKNOWN_SOURCE",
  "COMMAND_BURST", "PARAMETER_CHANGE", "MISSION_CHANGE", "RC_DEGRADATION", "MULTI_SIGNAL_INCIDENT", "PUSHPAK_CONFIRMATION", "LUA_BINDING_MISMATCH"];

function blankRule(): Rule {
  return {
    rule_id: `RULE-${Math.random().toString(36).slice(2, 7).toUpperCase()}`, name: "New rule", description: "", enabled: true, severity: "MEDIUM",
    domain: "RULE", persistence_s: 0, cooldown_s: 10, evidence_window_s: 30, correlation_window_s: 10, min_evidence: 0,
    confidence: { method: "weighted_evidence", threshold: 0 }, graph: { nodes: [], edges: [] }, tests: [],
  };
}

export default function Builder() {
  const theme = useTheme();
  const route = useRoute();
  const [catalog, setCatalog] = useState<RuleCatalog | null>(null);
  const [registry, setRegistry] = useState<RegistryMessage[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [detectors, setDetectors] = useState<DetectorHealth[]>([]);
  const [rule, setRule] = useState<Rule | null>(null);
  const [dirty, setDirty] = useState(false);
  const [sel, setSel] = useState<string | null>(null);
  const [val, setVal] = useState<ValidationResult | null>(null);
  const [test, setTest] = useState<any>(null);
  const [testing, setTesting] = useState(false);
  const [dataset, setDataset] = useState("scenario:GPS_IMU_MISMATCH");
  const [datasets, setDatasets] = useState<{ ref: string; label: string; kind: string }[]>([]);
  const [leftTab, setLeftTab] = useState("nodes");
  const [modal, setModal] = useState<null | "history" | "trace" | "results" | "expect">(null);
  const [traceRows, setTraceRows] = useState<any[] | null>(null);
  const [history, setHistory] = useState<any[]>([]);
  const [expect, setExpect] = useState<any>(null);
  const [liveOn, setLiveOn] = useState(false);
  const undo = useRef<Rule[]>([]);
  const redo = useRef<Rule[]>([]);
  const rf = useRef<ReactFlowInstance<Node, Edge> | null>(null);
  const liveNodes = useLive((s) => s.builder.nodes);
  const liveTraces = useLive((s) => s.builder.traces);

  const loadRules = () => api.get<Rule[]>("/api/rules").then(setRules).catch((e) => toast(e.message, "error"));
  useEffect(() => {
    api.get<RuleCatalog>("/api/rules/catalog").then(setCatalog);
    api.get("/api/mavlink/registry").then((r) => setRegistry(r.messages));
    api.get("/api/ids/detectors").then(setDetectors).catch(() => {});
    api.get("/api/replay/datasets").then(setDatasets).catch(() => {});
    loadRules();
  }, []);

  useEffect(() => {
    const id = route.id;
    if (id && (!rule || rule.rule_id !== id)) {
      api.get<Rule>(`/api/rules/${encodeURIComponent(id)}`).then((r) => { setRule(r); setDirty(false); undo.current = []; redo.current = []; setVal(null); setTest(null); setSel(null); })
        .catch(() => toast(`Rule ${id} not found`, "error"));
    } else if (!id && !rule && rules.length) {
      go(`builder/${rules[0].rule_id}`);
    }
  }, [route.id, rules.length]);

  const canvasRef = useRef<HTMLDivElement>(null);
  useEffect(() => {  // re-fit after nodes are measured and whenever the canvas cell is resized
    const fit = () => rf.current?.fitView({ padding: 0.12 });
    const h = setTimeout(fit, 150);
    const el = canvasRef.current;
    let t: ReturnType<typeof setTimeout> | undefined;
    const ro = el ? new ResizeObserver(() => { clearTimeout(t); t = setTimeout(fit, 60); }) : null;
    if (el && ro) ro.observe(el);
    return () => { clearTimeout(h); clearTimeout(t); ro?.disconnect(); };
  }, [rule?.rule_id, rule?.version]);

  const update = useCallback((fn: (r: Rule) => Rule, record = true) => {
    setRule((cur) => {
      if (!cur) return cur;
      if (record) {
        undo.current.push(cur);
        if (undo.current.length > 100) undo.current.shift();
        redo.current = [];
      }
      return fn(structuredClone(cur));
    });
    setDirty(true);
  }, []);

  const doUndo = () => {
    const prev = undo.current.pop();
    if (prev && rule) { redo.current.push(rule); setRule(prev); setDirty(true); }
  };
  const doRedo = () => {
    const nx = redo.current.pop();
    if (nx && rule) { undo.current.push(rule); setRule(nx); setDirty(true); }
  };
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "z") { e.preventDefault(); e.shiftKey ? doRedo() : doUndo(); }
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "y") { e.preventDefault(); doRedo(); }
    };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  });

  // ---------------------------------------------------------------- flow model
  const errByNode = useMemo(() => {
    const m: Record<string, string> = {};
    val?.errors.forEach((e) => { if (e.node && !m[e.node]) m[e.node] = e.message; });
    return m;
  }, [val]);
  const lastTestValues = useMemo(() => {
    const out: Record<string, any> = {};
    if (test?.series) Object.entries(test.series).forEach(([k, pts]: any) => { if (pts.length) out[k] = pts[pts.length - 1][1]; });
    if (test?.triggers?.[0]?.trace) test.triggers[0].trace.forEach((r: any) => { out[r.node_id] = r.value; });
    return out;
  }, [test]);

  const nodes: Node[] = useMemo(() => {
    if (!rule || !catalog) return [];
    const live = liveOn && liveNodes?.rule_id === rule.rule_id ? liveNodes.values : null;
    return rule.graph.nodes.map((n) => {
      const spec = catalog.node_types[n.type];
      const lv = live?.[n.id];
      return {
        id: n.id, type: "rule", position: n.position || { x: 0, y: 0 }, selected: sel === n.id,
        data: {
          spec: spec || { category: "INPUT", label: n.type, inputs: [], output: "any", params: [], description: "unknown type" },
          type: n.type, label: n.label || "", params: n.params || {}, error: errByNode[n.id] || (!spec ? "unknown node type" : null),
          value: lv ? lv.value : lastTestValues[n.id], fired: lv ? lv.fired : undefined,
          source: spec?.category === "INPUT" ? (n.params?.msg ? "MAVLink" : n.type === "pushpak_fc" || n.type === "lua_event" ? "FC/Lua" : n.type === "detector_state" ? "Ground IDS" : "Vehicle") : undefined,
        } as RuleNodeData,
      };
    });
  }, [rule, catalog, sel, errByNode, lastTestValues, liveNodes, liveOn]);

  const edges: Edge[] = useMemo(() => (rule?.graph.edges || []).map((e) => {
    const srcVal = liveOn && liveNodes?.values?.[e.source]?.value;
    return {
      id: e.id || `${e.source}->${e.target}:${e.targetHandle}`, source: e.source, target: e.target, targetHandle: e.targetHandle || "in", sourceHandle: "out",
      animated: srcVal === true, style: { stroke: srcVal === true ? "var(--crit)" : "var(--accent-2)", strokeWidth: 1.6 },
    };
  }), [rule, liveNodes, liveOn]);

  const onNodesChange = (changes: NodeChange[]) => {
    const removals = changes.filter((c) => c.type === "remove").map((c: any) => c.id);
    const moves = changes.filter((c) => c.type === "position" && (c as any).position);
    const selects = changes.filter((c) => c.type === "select" && (c as any).selected);
    if (selects.length) setSel((selects[0] as any).id);
    if (removals.length) {
      update((r) => {
        r.graph.nodes = r.graph.nodes.filter((n) => !removals.includes(n.id));
        r.graph.edges = r.graph.edges.filter((e) => !removals.includes(e.source) && !removals.includes(e.target));
        return r;
      });
      setSel(null);
    } else if (moves.length) {
      const dragging = moves.some((m: any) => m.dragging);
      update((r) => {
        const applied = applyNodeChanges(moves, r.graph.nodes.map((n) => ({ id: n.id, position: n.position, data: {} })) as Node[]);
        r.graph.nodes.forEach((n) => { const a = applied.find((x) => x.id === n.id); if (a) n.position = { x: Math.round(a.position.x), y: Math.round(a.position.y) }; });
        return r;
      }, !dragging);
    }
  };
  const onEdgesChange = (changes: EdgeChange[]) => {
    const rem = changes.filter((c) => c.type === "remove").map((c: any) => c.id);
    if (!rem.length) return;
    update((r) => {
      const cur = applyEdgeChanges(changes, edges);
      r.graph.edges = r.graph.edges.filter((e) => cur.some((c) => c.id === (e.id || `${e.source}->${e.target}:${e.targetHandle}`)));
      return r;
    });
  };
  const onConnect = (c: Connection) => {
    if (!c.source || !c.target) return;
    update((r) => {
      const handle = c.targetHandle || "in";
      r.graph.edges = r.graph.edges.filter((e) => !(e.target === c.target && (e.targetHandle || "in") === handle));
      const next = addEdge({ ...c, id: `${c.source}->${c.target}:${handle}` }, []);
      r.graph.edges.push({ id: next[0].id, source: c.source, target: c.target, targetHandle: handle });
      return r;
    });
  };

  const addNode = (type: string, pos?: { x: number; y: number }) => {
    if (!catalog || !rule) return;
    const spec = catalog.node_types[type];
    const params: Record<string, any> = {};
    spec.params.forEach((p) => { if (p.default !== null && p.default !== undefined) params[p.name] = p.default; });
    if (spec.params.find((p) => p.name === "msg" && p.options?.length)) params.msg = spec.params.find((p) => p.name === "msg")!.options![0];
    let id = type.replace(/^(input_|out_)/, "");
    let n = 1;
    while (rule.graph.nodes.some((x) => x.id === `${id}${n}`)) n++;
    id = `${id}${n}`;
    const position = pos || { x: 80 + rule.graph.nodes.length * 24, y: 60 + rule.graph.nodes.length * 18 };
    update((r) => { r.graph.nodes.push({ id, type, position, params, label: "" }); return r; });
    setSel(id);
  };

  // ---------------------------------------------------------------- actions
  const validate = async () => {
    if (!rule) return;
    const v = await api.post<ValidationResult>("/api/rules/validate", rule);
    setVal(v);
    toast(v.valid ? "Rule is valid" : `${v.errors.length} validation error(s)`, v.valid ? "ok" : "error");
    return v;
  };
  const runTest = async (ds = dataset) => {
    if (!rule) return;
    setTesting(true);
    try {
      const r = await api.post("/api/rules/test", { rule, dataset: ds });
      if (r.valid === false) { setVal(r.validation); toast("Fix validation errors before testing", "error"); return; }
      setVal(r.validation);
      setTest(r);
      setModal("results");
    } catch (e: any) { toast(e.message, "error"); } finally { setTesting(false); }
  };
  const simulateAll = async () => {
    if (!rule) return;
    if (!rule.tests?.length) { toast("Add expectations (Tests) in the rule inspector first", "warn"); return; }
    setTesting(true);
    try {
      const r = await api.post("/api/rules/test-expectations", { rule });
      setExpect(r);
      setModal("expect");
    } catch (e: any) { toast(e.message, "error"); } finally { setTesting(false); }
  };
  const save = async () => {
    if (!rule) return;
    try {
      const r = await api.post("/api/rules", rule);
      setVal(r.validation);
      toast(`Saved draft v${r.version}${r.validation.valid ? "" : " (has validation errors)"}`, r.validation.valid ? "ok" : "warn");
      setDirty(false);
      const fresh = await api.get<Rule>(`/api/rules/${encodeURIComponent(r.rule_id)}`);
      setRule(fresh);
      loadRules();
      if (route.id !== r.rule_id) go(`builder/${r.rule_id}`);
    } catch (e: any) { toast(e.message, "error"); }
  };
  const publish = async () => {
    if (!rule) return;
    if (dirty) { toast("Save the draft before publishing", "warn"); return; }
    const r = await api.post("/api/rules/publish", { rule_id: rule.rule_id, version: rule.version });
    if (!r.published) { setVal(r.validation); toast("Publish rejected: rule is invalid", "error"); return; }
    toast(`Published ${rule.rule_id} v${r.version} — active in the live pipeline`, "ok");
    setRule(await api.get(`/api/rules/${encodeURIComponent(rule.rule_id)}`));
    loadRules();
  };
  const toggleEnabled = async () => {
    if (!rule) return;
    const on = rule.status === "DISABLED" || rule.enabled === false;
    await api.post(`/api/rules/${encodeURIComponent(rule.rule_id)}/${on ? "enable" : "disable"}`);
    toast(`${rule.rule_id} ${on ? "enabled" : "disabled"}`, "ok");
    setRule(await api.get(`/api/rules/${encodeURIComponent(rule.rule_id)}`));
    loadRules();
  };
  const clone = async () => {
    if (!rule) return;
    const nid = prompt("New rule ID", `${rule.rule_id}-COPY`);
    if (!nid) return;
    try {
      await api.post(`/api/rules/${encodeURIComponent(rule.rule_id)}/clone`, { new_id: nid });
      await loadRules();
      go(`builder/${nid}`);
    } catch (e: any) { toast(e.message, "error"); }
  };
  const showHistory = async () => {
    if (!rule) return;
    setHistory(await api.get(`/api/rules/${encodeURIComponent(rule.rule_id)}/history`));
    setModal("history");
  };
  const liveTest = async () => {
    if (!rule) return;
    if (liveOn) { await api.del("/api/rules/live-test"); setLiveOn(false); return; }
    try {
      const r = await api.post("/api/rules/live-test", { rule, seconds: 300 });
      if (!r.started) { setVal(r.validation); toast("Rule invalid", "error"); return; }
      setLiveOn(true);
      toast(`Live debugging on ${r.session_id} until ${r.until.substring(11, 19)} (shadow mode: no incidents)`, "ok");
    } catch (e: any) { toast(e.message, "error"); }
  };

  const newRule = () => {
    const r = blankRule();
    setRule(r);
    setDirty(true);
    setVal(null); setTest(null); setSel(null);
    undo.current = []; redo.current = [];
    if (route.id) go("builder");
  };

  if (!catalog) return <Empty title="LOADING BUILDER" />;
  const selNode = rule?.graph.nodes.find((n) => n.id === sel) || null;

  return (
    <div className="col">
      <div className="page-title">
        <h2>Custom Ruleset</h2>
        {rule && <><span className="mono">{rule.rule_id}</span><Badge v={`v${rule.version ?? "new"}`} outline /><State s={dirty ? "UNSAVED" : rule.status || "DRAFT"} />
          {rule.published_version ? <Badge v={`published v${rule.published_version}`} tone="ok" /> : <Badge v="not published" tone="muted" />}</>}
        <div className="grow" />
        {liveOn && <Badge v="LIVE DEBUG" tone="crit" />}
        <span className="small muted">Rules are data: validated against the MAVLink registry, never executed as code.</span>
      </div>
      <div className="builder">
        <div className="panel lib">
          <div className="pb">
            <Tabs value={leftTab} onChange={setLeftTab} tabs={[{ id: "nodes", label: "Data & nodes" }, { id: "detectors", label: "Detectors" }, { id: "rules", label: `Rules (${rules.length})` }]} />
            {leftTab === "nodes" && CATS.map((cat) => (
              <div key={cat}>
                <div className={`libgroup cat-${cat}`}>{cat}</div>
                {Object.entries(catalog.node_types).filter(([, s]) => s.category === cat).map(([t, s]) => (
                  <div key={t} className="libitem" draggable onDragStart={(e) => e.dataTransfer.setData("application/pushpak-node", t)}
                    onDoubleClick={() => addNode(t)} title={`${s.description}\n(drag onto canvas or double-click)`}>
                    <span className="grow">{s.label}</span><span className="muted small">{s.output !== "none" ? s.output : "→"}</span>
                  </div>
                ))}
              </div>
            ))}
            {leftTab === "detectors" && (
              <div className="col gap-s">
                <div className="small muted">Ground detector library. Use a <em>Ground Detector State</em> or <em>Cross Detector</em> node to reference one.</div>
                {detectors.map((d) => (
                  <div key={d.detector} className="libitem" style={{ flexDirection: "column", alignItems: "stretch", cursor: "default" }}>
                    <div className="row sp"><strong>{d.name}</strong><State s={d.enabled ? d.health : "DISABLED"} /></div>
                    <div className="small dim">{d.description}</div>
                    <div className="small muted">{d.data_sources.join(", ") || "all messages"}</div>
                  </div>
                ))}
              </div>
            )}
            {leftTab === "rules" && (
              <div className="col gap-s">
                <button className="btn sm" onClick={newRule}>+ New rule</button>
                {rules.map((r) => (
                  <div key={r.rule_id} className="libitem" style={{ flexDirection: "column", alignItems: "stretch", borderColor: r.rule_id === rule?.rule_id ? "var(--accent)" : undefined }} onClick={() => go(`builder/${r.rule_id}`)}>
                    <div className="row sp"><strong className="mono small">{r.rule_id}</strong><State s={r.status} /></div>
                    <div className="small">{r.name}</div>
                    <div className="small muted">v{r.version} · published {r.published_version ? `v${r.published_version}` : "—"} · {r.severity}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="canvas" ref={canvasRef} onDragOver={(e) => e.preventDefault()} onDrop={(e) => {
          const t = e.dataTransfer.getData("application/pushpak-node");
          if (!t || !rf.current) return;
          addNode(t, rf.current.screenToFlowPosition({ x: e.clientX, y: e.clientY }));
        }}>
          {rule ? (
            <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} onConnect={onConnect}
              onInit={(i) => (rf.current = i)} onPaneClick={() => setSel(null)} fitView fitViewOptions={{ padding: 0.12 }} minZoom={0.15} maxZoom={2} colorMode={theme} deleteKeyCode={["Backspace", "Delete"]}
              proOptions={{ hideAttribution: true }} defaultEdgeOptions={{ type: "smoothstep" }}>
              <Background gap={20} color="var(--line)" />
              <Controls />
            </ReactFlow>
          ) : <Empty title="NO RULE OPEN" text="Pick a rule on the left or create a new one." action={<button className="btn primary" onClick={newRule}>New rule</button>} />}
        </div>

        <div className="panel insp">
          <div className="pb">
            {rule && selNode ? (
              <NodeInspector node={selNode} catalog={catalog} registry={registry} detectors={detectors.map((d) => d.detector)} errors={val?.errors.filter((e) => e.node === selNode.id) || []}
                liveValue={liveOn ? liveNodes?.values?.[selNode.id] : undefined} series={test?.series?.[selNode.id]}
                onChange={(fn) => update((r) => { const n = r.graph.nodes.find((x) => x.id === selNode.id); if (n) fn(n); return r; })}
                onDelete={() => { update((r) => { r.graph.nodes = r.graph.nodes.filter((n) => n.id !== selNode.id); r.graph.edges = r.graph.edges.filter((e) => e.source !== selNode.id && e.target !== selNode.id); return r; }); setSel(null); }} />
            ) : rule ? (
              <RuleInspector rule={rule} onChange={(fn) => update((r) => { fn(r); return r; })} val={val} />
            ) : null}
          </div>
        </div>

        <div className="toolbar">
          <button className="btn" onClick={validate} disabled={!rule}>Validate</button>
          <select className="in" value={dataset} onChange={(e) => setDataset(e.target.value)} title="Test dataset">
            <optgroup label="Synthetic scenarios">{SCENARIO_DATASETS.map((s) => <option key={s} value={`scenario:${s}`}>scenario: {s}</option>)}</optgroup>
            <optgroup label="Recorded flights / cases / imports">{datasets.map((d) => <option key={d.ref} value={d.ref}>{d.kind}: {d.label}</option>)}</optgroup>
          </select>
          <button className="btn primary" onClick={() => runTest()} disabled={!rule || testing}>{testing ? "Running…" : "Test"}</button>
          <button className="btn" onClick={simulateAll} disabled={!rule || testing} title="Run every expected trigger / non-trigger test">Simulate expectations</button>
          <button className={`btn ${liveOn ? "on" : ""}`} onClick={liveTest} disabled={!rule} title="Attach to the active session in shadow mode (no incidents)">{liveOn ? "Stop live debug" : "Live debug"}</button>
          <span className="grow" />
          <button className="btn" onClick={doUndo} disabled={!undo.current.length} title="Undo (Ctrl/⌘+Z)">↶ Undo</button>
          <button className="btn" onClick={doRedo} disabled={!redo.current.length} title="Redo (Ctrl/⌘+Shift+Z)">↷ Redo</button>
          <button className="btn" onClick={save} disabled={!rule}>Save draft</button>
          <button className="btn primary" onClick={publish} disabled={!rule || dirty}>Publish</button>
          <button className="btn" onClick={showHistory} disabled={!rule?.version}>Versions</button>
          <button className="btn" onClick={clone} disabled={!rule?.version}>Clone</button>
          <button className="btn danger" onClick={toggleEnabled} disabled={!rule?.published_version}>{rule?.status === "DISABLED" ? "Enable" : "Disable"}</button>
          {val && <span className={`small ${val.valid ? "t-ok" : "t-crit"}`}>{val.valid ? "✓ valid" : `✕ ${val.errors.length} error(s)`}{val.warnings?.length ? ` · ${val.warnings.length} warning(s)` : ""}</span>}
          {liveOn && liveTraces.length > 0 && <button className="btn sm" onClick={() => { setTraceRows(liveTraces[0].result.trace); setModal("trace"); }}>OPEN RULE TRACE (live: {liveTraces.length})</button>}
        </div>
      </div>

      <Modal open={modal === "results" && !!test} onClose={() => setModal(null)} title={`Test: ${test?.rule_id} v${test?.version} on ${test?.dataset}`}>
        {test && (
          <div className="col">
            <div className="row wrap">
              <Badge v={test.triggered ? "TRIGGERED" : "NOT TRIGGERED"} tone={test.triggered ? "crit" : "ok"} />
              {test.expectation && <Badge v={`expected ${test.expectation.expect}: ${test.expectation.passed ? "PASS" : "FAIL"}`} tone={test.expectation.passed ? "ok" : "crit"} />}
              <span className="small muted">{test.records} records · {test.evaluations} evaluations · {test.duration_s}s · node errors {test.node_errors}</span>
            </div>
            {test.triggers.length === 0 && <div className="notice small">The rule did not fire on this dataset. Select a node and inspect its sampled values below to see which condition stayed false.</div>}
            {test.triggers.map((t: any, i: number) => (
              <div key={i} className="panel"><div className="pb">
                <div className="row sp"><span className="row gap-s"><State s={t.state} /><strong>{t.title}</strong></span><span className="mono small">+{t.offset_s}s · <Confidence v={t.confidence} /></span></div>
                <div className="row mt"><button className="btn sm" onClick={() => { setTraceRows(t.trace); setModal("trace"); }}>OPEN RULE TRACE</button>
                  <span className="small muted">packets: {t.packet_refs.slice(0, 8).join(", ")}{t.packet_refs.length > 8 ? "…" : ""}</span></div>
              </div></div>
            ))}
            <div className="small muted">Input → transformation → condition → correlation → result, sampled at 2 Hz:</div>
            <Chart height={240} relative series={Object.entries(test.series).filter(([k]) => rule?.graph.nodes.some((n) => n.id === k)).slice(0, 8).map(([k, pts]: any) => ({
              name: rule?.graph.nodes.find((n) => n.id === k)?.label || k, points: pts.filter((p: any) => p[1] !== null), step: true, axis: (catalog.node_types[rule?.graph.nodes.find((n) => n.id === k)?.type || ""]?.output === "bool" ? 1 : 0) as 0 | 1 }))}
              marks={(() => {
                const firsts = Object.values(test.series).map((pts: any) => pts.find((p: any) => p[1] !== null)?.[0]).filter((x: any) => x !== undefined) as number[];
                const t0 = firsts.length ? Math.min(...firsts) : 0;
                return test.triggers.map((t: any) => ({ t: t.offset_s + t0, label: "TRIGGER", tone: "crit" as const }));
              })()} />
          </div>
        )}
      </Modal>
      <Modal open={modal === "trace"} onClose={() => setModal(test ? "results" : null)} title="Rule trace (live rule debugger)">
        <TraceView rows={traceRows} />
      </Modal>
      <Modal open={modal === "expect"} onClose={() => setModal(null)} title="Expected trigger / non-trigger tests">
        {expect && (
          <table className="tbl"><thead><tr><th>Dataset</th><th>Expect</th><th>Triggered</th><th>Result</th></tr></thead><tbody>
            {expect.results.map((r: any) => <tr key={r.dataset}><td className="mono small">{r.dataset}</td><td>{r.expect}</td><td>{r.triggered ? `yes (${r.triggers})` : "no"}</td><td><Badge v={r.passed ? "PASS" : "FAIL"} tone={r.passed ? "ok" : "crit"} /></td></tr>)}
          </tbody></table>
        )}
      </Modal>
      <Modal open={modal === "history"} onClose={() => setModal(null)} title={`Version history — ${rule?.rule_id}`}>
        <div className="small muted mb">Versions are immutable; forensic cases reference the exact version (and SHA-256) that produced their evidence.</div>
        <table className="tbl"><thead><tr><th>Version</th><th>Status</th><th>Created</th><th>Author</th><th>SHA-256</th><th /></tr></thead><tbody>
          {history.map((h) => (
            <tr key={h.version}><td>v{h.version}</td><td><State s={h.status} /></td><td className="mono small">{h.created?.substring(0, 19)}</td><td>{h.author}</td><td className="mono small">{h.sha256?.slice(0, 16)}…</td>
              <td><button className="btn sm" onClick={async () => { setRule(await api.get(`/api/rules/${encodeURIComponent(rule!.rule_id)}?version=${h.version}`)); setDirty(false); setModal(null); }}>Open</button></td></tr>
          ))}
        </tbody></table>
      </Modal>
    </div>
  );
}

// ------------------------------------------------------------------ inspectors
function NodeInspector({ node, catalog, registry, detectors, errors, onChange, onDelete, liveValue, series }: {
  node: RuleNode; catalog: RuleCatalog; registry: RegistryMessage[]; detectors: string[]; errors: { field: string | null; message: string }[];
  onChange: (fn: (n: RuleNode) => void) => void; onDelete: () => void; liveValue?: any; series?: [number, any][];
}) {
  const spec = catalog.node_types[node.type];
  if (!spec) return <div className="notice crit">Unknown node type {node.type}</div>;
  const msgInfo = registry.find((m) => m.name === node.params.msg);
  const setP = (k: string, v: any) => onChange((n) => { n.params = { ...n.params, [k]: v }; });
  return (
    <div className="col">
      <div className="row sp"><span className={`badge outline cat-${spec.category}`}>{spec.category}</span><span className="mono small muted">{node.id}</span></div>
      <strong>{spec.label}</strong>
      <div className="small dim">{spec.description}</div>
      <label className="fld">Display name<input className="in" value={node.label || ""} placeholder={spec.label} onChange={(e) => onChange((n) => { n.label = e.target.value; })} /></label>
      {spec.params.map((p) => {
        const v = node.params[p.name] ?? p.default ?? "";
        const err = errors.find((e) => e.field === p.name);
        let input: any;
        if (p.type === "message") {
          const opts = p.options?.length ? p.options : registry.map((m) => m.name);
          input = <select className="in" value={v} onChange={(e) => { setP("msg", e.target.value); }}><option value="">— select —</option>{opts.map((o) => <option key={o} value={o}>{o} {registry.find((m) => m.name === o) ? `(#${registry.find((m) => m.name === o)!.id})` : ""}</option>)}</select>;
        } else if (p.type === "field") {
          input = <select className="in" value={v} onChange={(e) => setP("field", e.target.value)}><option value="">— select —</option>{(msgInfo?.fields || []).filter((f) => f.numeric).map((f) => <option key={f.name} value={f.name}>{f.name} {f.units ? `[${f.units}]` : ""} {f.extension ? "(ext)" : ""}</option>)}</select>;
        } else if (p.type === "enum") {
          input = <select className="in" value={v} onChange={(e) => setP(p.name, e.target.value)}>{(p.options || []).map((o) => <option key={o}>{o}</option>)}</select>;
        } else if (p.type === "detector") {
          input = <select className="in" value={v} onChange={(e) => setP(p.name, e.target.value)}><option value="">— select —</option>{detectors.map((o) => <option key={o}>{o}</option>)}</select>;
        } else if (p.type === "detectors") {
          const cur: string[] = Array.isArray(v) ? v : [];
          input = <div className="col gap-s" style={{ maxHeight: 160, overflow: "auto" }}>{detectors.map((d) => (
            <label key={d} className="row small" style={{ textTransform: "none", letterSpacing: 0 }}><input type="checkbox" checked={cur.includes(d)} onChange={(e) => setP(p.name, e.target.checked ? [...cur, d] : cur.filter((x) => x !== d))} />{d}</label>))}</div>;
        } else if (p.type === "numbers") {
          input = <input className="in" value={Array.isArray(v) ? v.join(", ") : v} onChange={(e) => setP(p.name, e.target.value.split(",").map((x) => parseFloat(x.trim())).filter((x) => !isNaN(x)))} />;
        } else if (p.type === "number" || p.type === "int") {
          input = <input className="in" type="number" step={p.type === "int" ? 1 : "any"} value={v} onChange={(e) => setP(p.name, e.target.value === "" ? null : Number(e.target.value))} />;
        } else {
          input = <input className="in" value={v} onChange={(e) => setP(p.name, e.target.value)} />;
        }
        return (
          <label key={p.name} className="fld">
            <span>{p.name.replace(/_/g, " ")}{p.required ? " *" : ""}{p.min !== undefined ? <span className="muted"> (≥ {p.min})</span> : null}</span>
            {input}
            {err && <span className="err-text">{err.message}</span>}
          </label>
        );
      })}
      {msgInfo && node.params.field && (() => {
        const f = msgInfo.fields.find((x) => x.name === node.params.field);
        return f ? <div className="small muted">{msgInfo.name} (#{msgInfo.id}).{f.name}: {f.type}{f.units ? `, ${f.units}` : ""}{f.enum ? `, enum ${f.enum}` : ""}</div> : null;
      })()}
      {errors.filter((e) => !e.field).map((e, i) => <div key={i} className="err-text">⚠ {e.message}</div>)}
      <div className="small muted">Inputs: {spec.inputs.map((i) => `${i.name}:${i.type}${i.optional ? "?" : ""}`).join(", ") || "none"} · Output: {spec.output}</div>
      {liveValue && <KV rows={[["Live value", fmtVal(liveValue.value)], ["Updated this step", liveValue.fired ? "yes" : "no"], ["Detail", JSON.stringify(liveValue.extra || {})]]} />}
      {series && series.length > 0 && <Chart height={140} relative series={[{ name: node.label || node.id, points: series.filter((p) => p[1] !== null) as [number, number][], step: true }]} />}
      <button className="btn danger sm" onClick={onDelete}>Delete node</button>
    </div>
  );
}

function RuleInspector({ rule, onChange, val }: { rule: Rule; onChange: (fn: (r: Rule) => void) => void; val: ValidationResult | null }) {
  const set = (k: keyof Rule, v: any) => onChange((r) => { (r as any)[k] = v; });
  const numIn = (k: keyof Rule, label: string) => (
    <label className="fld">{label}<input className="in" type="number" min={0} step="any" value={(rule as any)[k] ?? 0} onChange={(e) => set(k, Number(e.target.value))} /></label>
  );
  return (
    <div className="col">
      <strong>Rule</strong>
      <label className="fld">Rule ID<input className="in mono" value={rule.rule_id} disabled={!!rule.version} onChange={(e) => set("rule_id", e.target.value.toUpperCase().replace(/[^A-Z0-9_-]/g, ""))} /></label>
      <label className="fld">Name<input className="in" value={rule.name} onChange={(e) => set("name", e.target.value)} /></label>
      <label className="fld">Description<textarea className="in" rows={3} value={rule.description} onChange={(e) => set("description", e.target.value)} /></label>
      <div className="grid g2">
        <label className="fld">Severity<select className="in" value={rule.severity} onChange={(e) => set("severity", e.target.value)}>{["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].map((s) => <option key={s}>{s}</option>)}</select></label>
        <label className="fld">Domain<select className="in" value={rule.domain || "RULE"} onChange={(e) => set("domain", e.target.value)}>{["RULE", "GPS_INTEGRITY", "MAVLINK_SECURITY", "LINK", "MISSION", "SENSOR"].map((s) => <option key={s}>{s}</option>)}</select></label>
        {numIn("persistence_s", "Persistence (s)")}
        {numIn("cooldown_s", "Cooldown (s)")}
        {numIn("evidence_window_s", "Evidence window (s)")}
        {numIn("correlation_window_s", "Correlation window (s)")}
        {numIn("min_evidence", "Minimum evidence")}
        <label className="fld">Confidence model<select className="in" value={rule.confidence.method} onChange={(e) => set("confidence", { ...rule.confidence, method: e.target.value })}><option value="weighted_evidence">weighted evidence</option><option value="fixed">fixed</option></select></label>
      </div>
      {rule.confidence.method === "fixed"
        ? <label className="fld">Fixed confidence (0–1)<input className="in" type="number" step="0.05" min={0} max={1} value={rule.confidence.value ?? 0.5} onChange={(e) => set("confidence", { ...rule.confidence, value: Number(e.target.value) })} /></label>
        : <label className="fld">Evidence threshold (0–1)<input className="in" type="number" step="0.05" min={0} max={1} value={rule.confidence.threshold ?? 0} onChange={(e) => set("confidence", { ...rule.confidence, threshold: Number(e.target.value) })} /></label>}
      <div className="small muted">Weighted evidence = fraction of upstream boolean conditions that are true when the output fires.</div>
      <strong className="mt">Tests (expected trigger / non-trigger)</strong>
      {(rule.tests || []).map((t, i) => (
        <div key={i} className="row">
          <input className="in grow mono small" value={t.dataset} onChange={(e) => onChange((r) => { r.tests![i].dataset = e.target.value; })} />
          <select className="in" value={t.expect} onChange={(e) => onChange((r) => { r.tests![i].expect = e.target.value; })}><option value="trigger">trigger</option><option value="no_trigger">no_trigger</option></select>
          <button className="btn sm ghost" onClick={() => onChange((r) => { r.tests!.splice(i, 1); })}>✕</button>
        </div>
      ))}
      <button className="btn sm" onClick={() => onChange((r) => { r.tests = [...(r.tests || []), { dataset: "scenario:NORMAL_FLIGHT", expect: "no_trigger" }]; })}>+ Add test</button>
      <KV rows={[["Version", rule.version ? `v${rule.version}` : "unsaved"], ["Status", rule.status], ["Author", rule.author], ["Created", rule.created?.substring(0, 19)], ["Modified", rule.modified?.substring(0, 19)], ["SHA-256", rule.sha256 ? <span className="mono small">{rule.sha256.slice(0, 20)}…</span> : null]]} />
      {val && !val.valid && (
        <div className="notice crit small">{val.errors.map((e, i) => <div key={i}>{e.node ? <span className="mono">[{e.node}] </span> : null}{e.message}</div>)}</div>
      )}
      {val?.warnings?.length ? <div className="notice small">{val.warnings.map((w, i) => <div key={i}>{w.node ? `[${w.node}] ` : ""}{w.message}</div>)}</div> : null}
      <div className="small muted">Select a node on the canvas to edit it. Drag nodes from the library; connect outputs (right) to inputs (left). Delete with Backspace.</div>
    </div>
  );
}
