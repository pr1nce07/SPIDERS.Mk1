// Security: MAVLink signing key lifecycle (GAP-08), evidence/audit signing (GAP-12), approved baselines (GAP-11).
// Secrets never reach the browser: the API returns key IDs, fingerprints and public keys only.
import { useState } from "react";
import { api } from "../services/api";
import { toast } from "../services/store";
import { dateTime } from "../lib/format";
import { Badge, Copy, ErrorNote, KV, Panel, State, useAsync } from "./ui";

const run = async (fn: () => Promise<any>, ok: string, after?: () => void) => {
  try {
    const r = await fn();
    toast(ok, "ok");
    after?.();
    return r;
  } catch (e: any) {
    toast(e.message, "error");
  }
};

export default function SecuritySettings() {
  return (
    <div className="col">
      <SigningKeys />
      <div className="grid g2">
        <EvidenceKeys />
        <AuditCheckpoints />
      </div>
      <Baseline />
    </div>
  );
}

function SigningKeys() {
  const { data, error, reload } = useAsync<any>(() => api.get("/api/security/keys"), []);
  const [note, setNote] = useState("");
  const [revoke, setRevoke] = useState<{ id: string; reason: string } | null>(null);
  const [exported, setExported] = useState<any>(null);
  if (error) return <ErrorNote error={error} />;
  const m = data?.mavlink;
  return (
    <Panel title="MAVLink signing keys" right={m?.active_key_id ? <Badge v={`active ${m.active_key_id}`} tone="ok" /> : <Badge v="no active key" tone="warn" />}>
      <div className="small muted mb">
        The GCS only validates signatures; it never signs or sends anything to the vehicle. Load a key onto the vehicle over a wired or
        otherwise secure maintenance connection, never over the telemetry link. Signing authenticates frames; it does not encrypt them.
        {m?.config_file_key && <strong> mavlink.signing_key_file is set in config and overrides the keyring.</strong>}
      </div>
      <table className="tbl mb"><thead><tr><th>Key ID</th><th>Status</th><th>Created</th><th>Activated</th><th>Provisioning exports</th><th /></tr></thead>
        <tbody>
          {(m?.keys || []).map((k: any) => (
            <tr key={k.key_id}>
              <td className="mono">{k.key_id}{k.note ? <div className="small muted">{k.note}</div> : null}</td>
              <td><State s={k.status.toUpperCase()} />{k.revoked_reason && <div className="small muted">{k.revoked_reason}</div>}</td>
              <td className="small">{dateTime(k.created_at)}<div className="muted">{k.created_by}</div></td>
              <td className="small">{k.activated_at ? dateTime(k.activated_at) : "—"}</td>
              <td className="small">{k.provisioning_exports?.length || 0}</td>
              <td className="right">
                {k.status !== "revoked" && <span className="row gap-s" style={{ justifyContent: "flex-end" }}>
                  {k.status !== "active" && <button className="btn sm" onClick={() => run(() => api.post(`/api/security/mavlink-keys/${k.key_id}/activate`), `Key ${k.key_id} active`, reload)}>Activate</button>}
                  <button className="btn sm" onClick={async () => { const r = await run(() => api.post(`/api/security/mavlink-keys/${k.key_id}/export`), "Provisioning file written", reload); if (r) setExported(r); }}>Export for vehicle</button>
                  <button className="btn sm danger" onClick={() => setRevoke({ id: k.key_id, reason: "" })}>Revoke</button>
                </span>}
              </td>
            </tr>
          ))}
          {!m?.keys?.length && <tr><td colSpan={6} className="muted small">No keys. Generate one, export it for the vehicle, then activate it here.</td></tr>}
        </tbody>
      </table>
      {revoke && <div className="notice crit mb row wrap">
        <span>Revoke <span className="mono">{revoke.id}</span>? The secret is destroyed and cannot be reactivated.</span>
        <input className="in grow" placeholder="Reason (required)" value={revoke.reason} onChange={(e) => setRevoke({ ...revoke, reason: e.target.value })} />
        <button className="btn sm danger" disabled={revoke.reason.trim().length < 3}
          onClick={() => run(() => api.post(`/api/security/mavlink-keys/${revoke.id}/revoke`, { reason: revoke.reason }), "Key revoked", () => { setRevoke(null); reload(); })}>Revoke key</button>
        <button className="btn sm" onClick={() => setRevoke(null)}>Cancel</button>
      </div>}
      {exported && <div className="notice warn mb">Written to <span className="mono">{exported.file}</span>. {exported.instructions}</div>}
      <div className="row">
        <input className="in grow" placeholder="Note for the new key (vehicle / link)" value={note} maxLength={200} onChange={(e) => setNote(e.target.value)} />
        <button className="btn primary" onClick={() => run(() => api.post("/api/security/mavlink-keys", { note }), "Key generated", () => { setNote(""); reload(); })}>Generate key</button>
      </div>
    </Panel>
  );
}

function EvidenceKeys() {
  const { data } = useAsync<any>(() => api.get("/api/security/keys"), []);
  return (
    <Panel title="Evidence & approval signing keys">
      <div className="small muted mb">Ed25519 public keys. Give them to whoever must verify exported cases, audit checkpoints or approved baselines independently of this machine.</div>
      {["evidence", "approval"].map((p) => data?.[p] && (
        <div key={p} className="row mb"><Badge v={p} tone="info" /><span className="mono grow">{data[p].key_id}</span><Copy text={data[p].public_key_pem} label="Copy public key" /></div>
      ))}
    </Panel>
  );
}

function AuditCheckpoints() {
  const [res, setRes] = useState<any>(null);
  const verify = async (mirror: boolean) => setRes(await run(() => api.get(`/api/audit/checkpoints/verify?mirror=${mirror}`), "Checkpoints verified"));
  return (
    <Panel title="Audit checkpoints">
      <div className="small muted mb">Signed copies of the audit-chain head (automatic every N entries). Kept in a separately administered mirror, they reveal a chain that was rewritten locally.</div>
      <div className="row mb">
        <button className="btn" onClick={() => run(() => api.post("/api/audit/checkpoint"), "Checkpoint written")}>Write checkpoint now</button>
        <button className="btn" onClick={() => verify(false)}>Verify local</button>
        <button className="btn" onClick={() => verify(true)}>Verify mirror</button>
      </div>
      {res && <div className={`notice ${res.status === "VALID" ? "" : res.status === "NO_CHECKPOINTS" ? "warn" : "crit"}`}>
        {res.status} — {res.checkpoints} checkpoint(s){res.problems?.length ? `; ${res.problems.length} problem(s): ${res.problems.map((p: any) => p.problem).join(", ")}` : ""}
      </div>}
    </Panel>
  );
}

function Baseline() {
  const { data, error, reload } = useAsync<any>(() => api.get("/api/baseline"), [], 5000);
  const [f, setF] = useState({ reason: "", profile_version: "", names: "", include_mission: false });
  if (error) return <ErrorNote error={error} />;
  const approve = () => run(() => api.post("/api/baseline/approve", {
    reason: f.reason, profile_version: f.profile_version, include_mission: f.include_mission,
    parameter_names: f.names.trim() ? f.names.split(/[\s,]+/).filter(Boolean) : null,
  }), "Baseline approved (applies from the next session)", reload);
  const live = data?.live;
  return (
    <Panel title="Approved mission / parameter baseline" right={data && <State s={data.status} />}>
      <div className="small muted mb">Runtime detectors learn from what they first see; an approved baseline is never re-learned. Mismatches are reported as BASELINE_MISMATCH, and arming with mismatches is flagged HIGH.</div>
      {data && data.status !== "NO_APPROVED_BASELINE" && <KV rows={[
        ["Profile", `${data.profile_version ?? "—"} · digest ${String(data.digest || "").slice(0, 16)}`],
        ["Approved", `${data.approval?.approved_by ?? "—"} · ${dateTime(data.created_at)} · ${data.approval?.reason ?? ""}`],
        ["Vehicle", JSON.stringify(data.vehicle || {})],
        ["Contents", `${data.parameter_count} parameters · mission ${data.mission_count ?? "not included"}`],
        ["Live comparison", live ? `${live.parameters_verified}/${live.parameters_approved} verified · mismatched: ${(live.parameters_mismatched || []).join(", ") || "none"} · not yet observed: ${live.parameters_not_yet_observed}` : "no active session"],
      ]} />}
      <div className="col mt">
        <div className="small muted">Approve a new baseline from the vehicle's currently reported values (engineer role). The previous digest is recorded.</div>
        <div className="row wrap">
          <input className="in" placeholder="Profile version" value={f.profile_version} maxLength={40} onChange={(e) => setF({ ...f, profile_version: e.target.value })} />
          <input className="in grow" placeholder="Reason (required)" value={f.reason} maxLength={500} onChange={(e) => setF({ ...f, reason: e.target.value })} />
        </div>
        <div className="row wrap">
          <input className="in grow" placeholder="Only these parameters (comma separated; empty = all observed)" value={f.names} onChange={(e) => setF({ ...f, names: e.target.value })} />
          <label className="row gap-s small"><input type="checkbox" checked={f.include_mission} onChange={(e) => setF({ ...f, include_mission: e.target.checked })} /> include last observed mission</label>
          <button className="btn primary" disabled={f.reason.trim().length < 3 || !f.profile_version.trim()} onClick={approve}>Approve baseline</button>
        </div>
      </div>
    </Panel>
  );
}
