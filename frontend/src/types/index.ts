// Shared frontend types. The backend is the source of truth for every schema;
// these mirror its JSON. Unknown values are `null` and rendered as N/A.

export type Availability = "AVAILABLE" | "STALE" | "UNAVAILABLE" | "INVALID";
export interface FieldValue { value: any; source: string; t: string; age_s: number; quality: string; availability: Availability }
export type VehicleFields = Record<string, FieldValue>;

export interface ConnectionStats {
  sysid: number | null; compid: number | null; mavlink_version: number | null; wire_version: number | null;
  packet_rate_hz: number; heartbeat_age_s: number | null; received: number; bad_frames: number;
  estimated_loss_pct: number | null; signing: string; latency_ms: number | null; latency_note: string;
  state?: string; detail?: string;
}

export interface ReplayStatus {
  ref: string; speed: number; paused: boolean; finished: boolean; position: number; total: number;
  t_start: number; t_end: number; t_current: number; offset_s: number; duration_s: number; reverse_playback: string;
}

export interface Telemetry {
  connected?: boolean; session_id?: string; kind?: string; t?: number; ts?: string; vehicle?: VehicleFields;
  connection?: ConnectionStats; home?: { lat: number; lon: number; alt_m: number } | null;
  track_point?: [number, number, number, number] | null; armed?: boolean | null; mode?: string | null; airborne?: boolean | null;
  replay?: ReplayStatus | null; scenario?: string | null;
}

export interface DetectorHealth {
  detector: string; name: string; version: string; health: string; state: string; confidence: number | null;
  last_update: string | null; events: number; results: number; errors: number; last_error: string | null; latency_ms: number;
  data_sources: string[]; methods: string[]; domain: string; enabled: boolean; severity: string; description: string; metrics: any;
}

export interface ComparisonRow {
  detector: string;
  fc: { state: string; confidence: number; evidence: any; t: number } | null;
  lua: { class: string; confidence: number; t: number } | null;
  ground: { state: string; detector: string | null; all: Record<string, string | null> };
  correlated: string | null;
}
export interface GnssIntegrityHorizon {
  index: number; duration_s: number; status: string[]; reason: string; armed?: boolean; valid?: boolean; expired?: boolean;
  warn?: boolean; alarm?: boolean; extended?: boolean; heading_free_only?: boolean; elapsed_s?: number;
  position_residual_m?: number; velocity_residual_mps?: number; position_test?: number; velocity_test?: number;
  delta_speed_test?: number; position_sigma_m?: number; velocity_sigma_mps?: number; yaw_sigma_rad?: number;
}
export interface GnssIntegrity {
  t: number; boot: number; seq: number; version: number; state: string; confidence: number; armed: number[]; valid: number[];
  warn: number[]; alarm: number[]; flags: string[]; fix_age_ms: number; applied_lag_ms: number; delta_speed_residual_mps: number;
  baro_residual_m: number; accel_bias_norm_mps2: number; horizons: GnssIntegrityHorizon[];
}
export interface Comparison { rows: ComparisonRow[]; lua_health: Record<string, any>; event_delivery?: Record<string, any> | null; gnss_integrity?: GnssIntegrity | null; jamming: string; fc_available: boolean; lua_available: boolean; firmware_note: string | null }
export interface IdsSnapshot { detectors: DetectorHealth[]; comparison: Comparison; rules?: { rule_id: string; version: number; evaluations: number; triggers: number; errors: number }[] }

export interface Alert {
  alert_id: string; session_id: string; t: number; ts: string; result_id: string; detector: string; severity: string;
  confidence: number | null; source: string; state: string; status: string; incident_id: string | null; title: string;
  domain: string; evidence_count: number; rule_id?: string | null; rule_version?: number | null; sysid?: number | null;
  history?: any[];
}

export interface Observation {
  result_id: string; t: number; ts: string; detector: string; title: string; state: string; severity: string;
  confidence: number | null; source: string; context: boolean; rule_id?: string | null; rule_version?: number | null; packet_refs: number[];
}
export interface Contributor { label: string; detector: string; source: string; value: number; basis: string }
export interface Incident {
  incident_id: string; session_id: string; first_seen: number; last_seen: number; first_seen_iso: string; last_seen_iso: string;
  status: string; state: string; severity: string; confidence: number; domain: string; title: string; detectors: string[];
  observations: Observation[]; evidence: number[]; sources: string[]; rule_versions: { rule_id: string; version: number }[];
  actors: number[]; contributors: Contributor[]; limitations: string[]; creation_reason: string; case_id: string | null;
  explanation?: Explanation; workflow?: any[];
}
export interface Explanation {
  what: string; why: string; when: string; source: string; evidence: string[]; rule: string; confidence: string;
  contributors: any[]; limitations: string[]; state_policy?: string;
  independence?: { lines: string[][]; count: number; policy: string } | null;
}
export interface TraceRow { node_id: string; type: string; category: string; label: string; value: any; inputs: Record<string, any>; detail: string }
export interface DetectorResult {
  result_id: string; detector: string; state: string; title: string; t: number; ts: string; severity: string;
  confidence: number | null; source: string; domain: string; method: string | null; parameters: any; inputs: any;
  score: number | null; threshold: number | null; window: string | null; rule_id: string | null; rule_version: number | null;
  detector_version: string | null; packet_refs: number[]; sysid: number | null; compid: number | null; explanation: Explanation;
  trace: TraceRow[] | null; kind: string; session_id?: string;
}

export interface Packet {
  idx: number; t: number; sysid: number | null; compid: number | null; seq: number | null; msg_id: number | null; msg: string;
  source: string; link: string; signed: boolean | null; sig: string | null; err: string | null; len: number; ver: number | null;
  fields?: Record<string, any>; raw_hex?: string | null; header?: any; definition?: any; ts?: string;
}

export interface TimelineEvent { id: string; t: number; ts: string; type: string; title: string; ref: any; session_id: string }

export interface HealthIssue { component: string; status: string; message: string }
export interface Health {
  status: string; score: number; issues: HealthIssue[]; mavlink: string; recording: boolean; database: string; websocket: string;
  ids: string; forensics: string; session: { session_id: string; kind: string; source: string } | null; connection: any; read_only: boolean;
  subsystems: any; resources: { cpu_pct: number; ram_mb: number; system_ram_pct: number; disk_free_mb: number; disk_used_pct: number };
  errors_recent: any[]; uptime_s: number; version: string; server_time: string;
}

export interface ParamSpec { name: string; type: string; required: boolean; default: any; options?: string[]; min?: number; max?: number }
export interface NodeTypeSpec { category: string; label: string; inputs: { name: string; type: string; optional?: boolean }[]; output: string; params: ParamSpec[]; description: string }
export interface RuleCatalog {
  node_types: Record<string, NodeTypeSpec>; operators: string[]; copter_modes: string[]; vehicle_fields: Record<string, string>;
  pushpak_detectors: string[]; ground_detectors: string[]; limits: any;
}
export interface RuleNode { id: string; type: string; label?: string; position: { x: number; y: number }; params: Record<string, any> }
export interface RuleEdge { id?: string; source: string; target: string; targetHandle?: string }
export interface Rule {
  rule_id: string; name: string; description: string; enabled: boolean; severity: string; domain?: string;
  persistence_s: number; cooldown_s: number; evidence_window_s: number; correlation_window_s: number; min_evidence: number;
  confidence: { method: string; threshold?: number; value?: number }; graph: { nodes: RuleNode[]; edges: RuleEdge[] };
  tests?: { dataset: string; expect: string }[]; version?: number; status?: string; published_version?: number | null;
  created?: string; modified?: string; author?: string; sha256?: string; limitations?: string;
}
export interface ValidationResult { valid: boolean; errors: { node: string | null; field: string | null; message: string }[]; warnings: { node: string | null; message: string }[] }

export interface CaseSummary {
  case_id: string; status: string; incident_id: string | null; created_at?: string; finalized_at?: string; trigger?: any;
  capture_window?: any; vehicle?: any; session?: any; evidence_counts?: any; artifact_count?: number; revisions?: any[];
}

export interface RegistryMessage { id: number; name: string; crc_extra: number; fields: { name: string; type: string; numeric: boolean; array_length: number; units: string | null; enum: string | null; extension: boolean }[] }
