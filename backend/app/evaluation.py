"""Detector evaluation on a labelled corpus (GAP-02, V-004/V-005).

A corpus manifest lists recorded flights (tlog / DataFlash / JSONL), each with a
label ("benign" or an attack class), attack windows relative to the start of
the log, a partition (tune | validation | locked | external) and metadata
(vehicle, firmware, environment). Every run is replayed through the same
pipeline the GCS uses live, then scored:

* per attack class and per detector: TP/FN per attack window, detection
  latency, precision, recall, F1 with Wilson 95 % intervals;
* false alarms per flight-hour on benign time, with an exact Poisson interval;
* everything broken down by run, platform and environment — never only a
  single aggregate number.

The locked partition is refused unless the detector configuration is frozen
(its hash given on the command line), so it cannot be used for tuning.
"""
from __future__ import annotations

import hashlib
import json
import math
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

PARTITIONS = ("tune", "validation", "locked", "external")
ALARM = ("ANOMALOUS", "SUSPECTED", "CONFIRMED")


@dataclass
class Run:
    run_id: str
    file: Optional[str]
    label: str                                   # "benign" or attack class
    partition: str
    attack_windows: list[tuple[float, float]] = field(default_factory=list)  # seconds from log start
    meta: dict = field(default_factory=dict)     # vehicle, board, firmware, environment, pilot/mission profile, ...
    expected_detectors: list[str] = field(default_factory=list)


@dataclass
class RunResult:
    run: Run
    duration_s: float
    alerts: list[dict]                           # {"t": seconds from start, "detector", "state", "source"}
    incidents: list[dict]
    file_sha256: Optional[str] = None


# ------------------------------------------------------------------ statistics
def wilson(k: int, n: int, z: float = 1.96) -> Optional[tuple[float, float]]:
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(max(0.0, c - h), 4), round(min(1.0, c + h), 4))


def poisson_rate_ci(events: int, exposure_h: float) -> Optional[tuple[float, float]]:
    """Exact (Garwood) 95 % interval for an event rate per hour."""
    if exposure_h <= 0:
        return None
    from scipy.stats import chi2
    lo = 0.0 if events == 0 else chi2.ppf(0.025, 2 * events) / 2
    hi = chi2.ppf(0.975, 2 * events + 2) / 2
    return (round(lo / exposure_h, 4), round(hi / exposure_h, 4))


# ------------------------------------------------------------------ scoring
def _in(t: float, windows, tol: float) -> Optional[int]:
    for i, (a, b) in enumerate(windows):
        if a - tol <= t <= b + tol:
            return i
    return None


def score(results: Iterable[RunResult], tolerance_s: float = 2.0, alert_states=ALARM) -> dict:
    """Window-based scoring. An alert inside an attack window (± tolerance) is a TP for that window;
    an alert outside every window is a false alarm. Each window counts once (detected or missed)."""
    per_class: dict[str, dict] = defaultdict(lambda: {"windows": 0, "detected": 0, "latencies": [], "runs": 0})
    per_det: dict[str, dict] = defaultdict(lambda: {"tp_windows": 0, "false_alarms": 0, "alerts": 0})
    benign_h, fa_total, fa_by_run = 0.0, 0, []
    by_group: dict[str, dict] = defaultdict(lambda: {"runs": 0, "hours": 0.0, "false_alarms": 0, "windows": 0, "detected": 0})
    rows = []
    for rr in results:
        run = rr.run
        alerts = [a for a in rr.alerts if a["state"] in alert_states]
        windows = run.attack_windows if run.label != "benign" else []
        hit: dict[int, float] = {}
        dets_hit: dict[str, set] = defaultdict(set)
        fa = 0
        for a in alerts:
            w = _in(a["t"], windows, tolerance_s)
            per_det[a["detector"]]["alerts"] += 1
            if w is None:
                fa += 1
                per_det[a["detector"]]["false_alarms"] += 1
            else:
                hit.setdefault(w, a["t"])
                hit[w] = min(hit[w], a["t"])
                dets_hit[a["detector"]].add(w)
        for d, ws in dets_hit.items():
            per_det[d]["tp_windows"] += len(ws)
        benign_time = rr.duration_s - sum(min(b, rr.duration_s) - max(a, 0) for a, b in windows)
        benign_h += max(0.0, benign_time) / 3600
        fa_total += fa
        if run.label != "benign":
            c = per_class[run.label]
            c["runs"] += 1
            c["windows"] += len(windows)
            c["detected"] += len(hit)
            c["latencies"] += [round(t - windows[i][0], 3) for i, t in hit.items()]
        for gk in ("vehicle", "board", "firmware", "environment"):
            g = by_group[f"{gk}={run.meta.get(gk, 'unspecified')}"]
            g["runs"] += 1
            g["hours"] += rr.duration_s / 3600
            g["false_alarms"] += fa
            g["windows"] += len(windows)
            g["detected"] += len(hit)
        rows.append({"run_id": run.run_id, "label": run.label, "partition": run.partition, "duration_s": round(rr.duration_s, 1),
                     "file_sha256": rr.file_sha256, "windows": len(windows), "detected_windows": len(hit),
                     "false_alarms": fa, "incidents": len(rr.incidents),
                     "incident_states": sorted({i.get("state") for i in rr.incidents}), "meta": run.meta,
                     "first_alert_latency_s": {str(i): round(t - windows[i][0], 3) for i, t in hit.items()}})
        fa_by_run.append(fa)

    classes = {}
    for name, c in per_class.items():
        lat = sorted(c["latencies"])
        classes[name] = {"runs": c["runs"], "attack_windows": c["windows"], "detected": c["detected"],
                         "recall": round(c["detected"] / c["windows"], 4) if c["windows"] else None,
                         "recall_ci95": wilson(c["detected"], c["windows"]),
                         "latency_s": {"median": lat[len(lat) // 2] if lat else None, "p95": lat[int(0.95 * (len(lat) - 1))] if lat else None,
                                       "max": lat[-1] if lat else None}}
    detectors = {}
    for d, v in per_det.items():
        tp, fa = v["tp_windows"], v["false_alarms"]
        prec_n = tp + fa
        detectors[d] = {"alerts": v["alerts"], "true_positive_windows": tp, "false_alarms": fa,
                        "precision_windows": round(tp / prec_n, 4) if prec_n else None, "precision_ci95": wilson(tp, prec_n),
                        "false_alarms_per_flight_hour": round(fa / benign_h, 3) if benign_h else None}
    total_w = sum(c["windows"] for c in per_class.values())
    total_hit = sum(c["detected"] for c in per_class.values())
    rec = total_hit / total_w if total_w else None
    prec = total_hit / (total_hit + fa_total) if (total_hit + fa_total) else None
    return {"runs": rows, "per_attack_class": classes, "per_detector": detectors,
            "false_alarms": {"count": fa_total, "benign_flight_hours": round(benign_h, 4),
                             "per_flight_hour": round(fa_total / benign_h, 4) if benign_h else None,
                             "per_flight_hour_ci95": poisson_rate_ci(fa_total, benign_h)},
            "overall_reference_only": {"recall": None if rec is None else round(rec, 4), "precision": None if prec is None else round(prec, 4),
                                       "f1": round(2 * prec * rec / (prec + rec), 4) if prec and rec else None,
                                       "note": "Do not quote this without the per-class, per-run and per-platform tables."},
            "by_group": dict(by_group), "tolerance_s": tolerance_s,
            "independent_flights": len({(r["meta"].get("vehicle"), r["meta"].get("flight_id") or r["run_id"]) for r in rows})}


# ------------------------------------------------------------------ corpus / replay
def load_corpus(path: Path) -> tuple[dict, list[Run]]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    base = Path(path).parent
    runs = []
    for r in doc["runs"]:
        if r.get("partition") not in PARTITIONS:
            raise ValueError(f"run {r.get('run_id')}: partition must be one of {PARTITIONS}")
        if r.get("label") != "benign" and not r.get("attack_windows"):
            raise ValueError(f"run {r.get('run_id')}: attack runs need attack_windows (ground truth)")
        f = r.get("file")
        runs.append(Run(run_id=r["run_id"], file=str((base / f).resolve()) if f else None, label=r["label"], partition=r["partition"],
                        attack_windows=[tuple(w) for w in r.get("attack_windows", [])], meta=r.get("meta", {}),
                        expected_detectors=r.get("expected_detectors", [])))
    return doc, runs


def config_fingerprint(config) -> str:
    """Hash of everything that changes detector behaviour: thresholds, rules, detector versions."""
    from .ids.builtin_rules import BUILTIN_RULES
    from .ids.engine import DETECTOR_PLUGINS
    body = {"ids": config.get("ids"), "mavlink": {k: config.get(f"mavlink.{k}") for k in ("trusted_gcs_sysids", "signing_expected", "signing_policy")},
            "rules": BUILTIN_RULES, "detectors": sorted(DETECTOR_PLUGINS)}
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


def replay(run: Run, config, items=None) -> RunResult:
    """Replay one recorded run through a fresh pipeline (no DB, no recorder, no snapshots)."""
    from .core.errors import ErrorRegistry
    from .core.pipeline import Pipeline
    from .ids.builtin_rules import BUILTIN_RULES
    from .ids.correlation import IncidentIdAllocator
    from .ids.rules import compile_rule
    from .mavlink.registry import DialectRegistry
    from .sources.files import open_source

    reg = DialectRegistry()
    p = Pipeline(session_id=f"EVAL-{run.run_id}", kind="evaluation", source_desc=run.file or run.run_id, config=config,
                 registry=reg, errors=ErrorRegistry(), capabilities={}, allocator=IncidentIdAllocator())
    p.set_rules([compile_rule(dict(r, version=1), reg, list(p.engine.detectors)) for r in BUILTIN_RULES])
    digest = None
    if items is None:
        digest = hashlib.sha256(Path(run.file).read_bytes()).hexdigest()
        items = open_source(Path(run.file))
    t0 = t1 = None
    for it in items:
        if t0 is None:
            t0 = it.t
        t1 = it.t
        p.handle_item(it)
    t0 = t0 or 0.0
    alerts = [{"t": a["t"] - t0, "detector": a["detector"], "state": a["state"], "source": a.get("source")}
              for a in p.alerts.values()]
    incidents = [{"state": i["state"], "t": i["first_seen"] - t0, "independence": (i.get("independence") or {}).get("count")}
                 for i in p.correlator.incidents.values()]
    return RunResult(run=run, duration_s=(t1 or t0) - t0, alerts=alerts, incidents=incidents, file_sha256=digest)


def markdown(report: dict) -> str:
    L = [f"# Detector evaluation — corpus `{report['corpus']}`", "",
         f"Partitions: {', '.join(report['partitions'])} · config fingerprint `{report['config_fingerprint'][:16]}` · "
         f"{report['score']['independent_flights']} independent flights · tolerance ±{report['score']['tolerance_s']} s", "",
         "## Per attack class", "", "| Class | Runs | Windows | Detected | Recall (95 % CI) | Median / p95 latency (s) |", "|---|---|---|---|---|---|"]
    for k, c in sorted(report["score"]["per_attack_class"].items()):
        L.append(f"| {k} | {c['runs']} | {c['attack_windows']} | {c['detected']} | {c['recall']} {c['recall_ci95']} | "
                 f"{c['latency_s']['median']} / {c['latency_s']['p95']} |")
    fa = report["score"]["false_alarms"]
    L += ["", "## False alarms", "", f"{fa['count']} false alarms in {fa['benign_flight_hours']} benign flight-hours = "
          f"**{fa['per_flight_hour']} per flight-hour** (95 % CI {fa['per_flight_hour_ci95']}).", "",
          "## Per detector", "", "| Detector | Alerts | TP windows | False alarms | Precision (95 % CI) | FA / flight-hour |", "|---|---|---|---|---|---|"]
    for d, v in sorted(report["score"]["per_detector"].items()):
        L.append(f"| {d} | {v['alerts']} | {v['true_positive_windows']} | {v['false_alarms']} | {v['precision_windows']} {v['precision_ci95']} | "
                 f"{v['false_alarms_per_flight_hour']} |")
    L += ["", "## Per run", "", "| Run | Label | Partition | Duration (s) | Windows detected | False alarms | Incidents |", "|---|---|---|---|---|---|---|"]
    for r in report["score"]["runs"]:
        L.append(f"| {r['run_id']} | {r['label']} | {r['partition']} | {r['duration_s']} | {r['detected_windows']}/{r['windows']} | "
                 f"{r['false_alarms']} | {r['incidents']} {r['incident_states']} |")
    L += ["", "## By platform / environment", "", "| Group | Runs | Hours | Windows detected | False alarms |", "|---|---|---|---|---|"]
    for g, v in sorted(report["score"]["by_group"].items()):
        L.append(f"| {g} | {v['runs']} | {round(v['hours'], 3)} | {v['detected']}/{v['windows']} | {v['false_alarms']} |")
    L += ["", "> " + report["score"]["overall_reference_only"]["note"], ""]
    return "\n".join(L)
