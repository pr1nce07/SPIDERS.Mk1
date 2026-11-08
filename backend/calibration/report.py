"""Build a simulation-only calibration report with flight-level bootstrap intervals."""
from __future__ import annotations

import argparse
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

from .sweep import ATTACKS, EXPECTED, classify


POLICY_DETECTORS = {"RULE:CMD-BURST-001", "MAVLINK_RATE", "PARAMETER", "MISSION"}


def _trusted_policy_incident(incident: dict, result: dict) -> bool:
    """Mark only incidents fully explained by modeled trusted operator activity."""
    detectors = set(incident.get("detectors", []))
    env = result.get("env", {})
    if not detectors or not detectors.issubset(POLICY_DETECTORS):
        return False
    near = [a for a in result.get("alerts", []) if abs(a.get("t", 0) - incident.get("t", 0)) <= 30]
    causes = {
        "RULE:CMD-BURST-001": env.get("busy_operator", False),
        "MAVLINK_RATE": ((env.get("busy_operator", False) or env.get("operator_mission_edit", False))
                         and any(a["detector"] == "MAVLINK_RATE" and a["title"] == "Message burst" for a in near)),
        "PARAMETER": (env.get("operator_param_edits", False)
                      and any(a["detector"] == "PARAMETER" and a.get("sysid") == 255 for a in near)),
        "MISSION": (env.get("operator_mission_edit", False)
                    and any(a["detector"] == "MISSION" and a.get("sysid") == 255 for a in near)),
    }
    return all(causes.get(detector, False) for detector in detectors)


def quantile(values: list[float], q: float) -> float:
    """Linear-interpolated quantile for a non-empty sample."""
    xs = sorted(values)
    if not xs:
        return float("nan")
    pos = (len(xs) - 1) * q
    lo, hi = int(pos), min(int(pos) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (pos - lo)


def bootstrap_ci(rows, statistic, seed: int, reps: int = 2000) -> tuple[float, float]:
    """Percentile 95% interval from resampling independent flights."""
    if not rows:
        return float("nan"), float("nan")
    rng = random.Random(seed)
    estimates = []
    for _ in range(reps):
        sample = [rows[rng.randrange(len(rows))] for _ in rows]
        estimates.append(statistic(sample))
    return quantile(estimates, 0.025), quantile(estimates, 0.975)


def _rate_hour(rows, detector: str | None = None) -> float:
    count = sum(row["counts"].get(detector, 0) if detector else sum(row["counts"].values()) for row in rows)
    hours = sum(row["duration"] for row in rows) / 3600
    return count / hours if hours else 0.0


def _mean(rows, field: str) -> float:
    return sum(row[field] for row in rows) / len(rows) if rows else float("nan")


def _summary(results: list[dict]) -> dict:
    benign = []
    attacks: dict[str, list[dict]] = defaultdict(list)
    fp_detectors = set()
    for result in results:
        cls = classify(result)
        if result["scenario"] == "NORMAL_FLIGHT":
            counts = Counter(a["detector"] for a in cls["fp"])
            fp_detectors.update(counts)
            policy_incidents = [i for i in cls["fp_incidents"] if _trusted_policy_incident(i, result)]
            benign.append({"counts": counts, "duration": result["duration"],
                           "fp_incident": bool(cls["fp_incidents"]),
                           "fp_incident_ex_policy": bool(len(policy_incidents) < len(cls["fp_incidents"])),
                           "confirmed": sum(i["state"] == "CONFIRMED" for i in result["incidents"]),
                           "fp_flight": bool(cls["fp"])})
        else:
            attacks[result["scenario"]].append({"result": result, "class": cls})
    return {"benign": benign, "attack": attacks, "fp_detectors": fp_detectors}


def _format_ci(point: float, ci: tuple[float, float], digits: int = 2, scale: float = 1.0) -> str:
    if point != point:
        return "n/a"
    return f"{point * scale:.{digits}f} ({ci[0] * scale:.{digits}f}–{ci[1] * scale:.{digits}f})"


def _fp_metrics(rows: list[dict], detectors: list[str], seed: int) -> dict:
    out = {}
    for j, detector in enumerate(detectors):
        stat = lambda sample, d=detector: _rate_hour(sample, d)
        out[detector] = (_rate_hour(rows, detector), bootstrap_ci(rows, stat, seed + j))
    stat = lambda sample: _rate_hour(sample)
    out["ALL"] = (_rate_hour(rows), bootstrap_ci(rows, stat, seed + len(detectors)))
    inc = [r["fp_incident"] for r in rows]
    inc_ex_policy = [r["fp_incident_ex_policy"] for r in rows]
    conf = [r["confirmed"] for r in rows]
    out["INCIDENT"] = (_mean([{"x": x} for x in inc], "x"),
                       bootstrap_ci([{"x": x} for x in inc], lambda s: _mean(s, "x"), seed + len(detectors) + 1))
    out["INCIDENT_EX_POLICY"] = (_mean([{"x": x} for x in inc_ex_policy], "x"),
                                 bootstrap_ci([{"x": x} for x in inc_ex_policy], lambda s: _mean(s, "x"), seed + len(detectors) + 3))
    out["CONFIRMED"] = (sum(conf), bootstrap_ci([{"x": x} for x in conf], lambda s: sum(r["x"] for r in s), seed + len(detectors) + 2))
    return out


def _attack_metrics(rows: list[dict], seed: int) -> dict:
    scenarios = {}
    for scenario, flights in rows.items():
        expected = EXPECTED.get(scenario, set())
        if not expected:
            scenarios[scenario] = {"expected": [], "detect": None, "detect_ci": (float("nan"), float("nan")),
                                   "detectors": {}, "n": len(flights)}
            continue
        per_flight = []
        detector_hits = defaultdict(list)
        detector_lat = defaultdict(list)
        for flight in flights:
            c = flight["class"]
            per_flight.append(int(not c["missed"]))
            for detector in expected:
                hit = detector in c["tp"]
                detector_hits[detector].append(int(hit))
                if hit:
                    detector_lat[detector].append(c["latency"][detector])
        det = {}
        for j, detector in enumerate(sorted(expected)):
            hits = detector_hits[detector]
            lat = detector_lat[detector]
            lat_stats = {}
            for qname, q in (("median", 0.5), ("p95", 0.95)):
                stat = lambda sample, q=q: quantile([x["lat"] for x in sample], q)
                pairs = [{"lat": x} for x in lat]
                lat_stats[qname] = (quantile(lat, q), bootstrap_ci(pairs, stat, seed + j * 7 + int(q * 10))) if lat else (float("nan"), (float("nan"), float("nan")))
            det[detector] = {"hits": sum(hits), "n": len(hits),
                             "rate": _mean([{"x": x} for x in hits], "x"),
                             "rate_ci": bootstrap_ci([{"x": x} for x in hits], lambda s: _mean(s, "x"), seed + j),
                             "latency": lat_stats, "latency_n": len(lat)}
        scenarios[scenario] = {"expected": sorted(expected), "detect": sum(per_flight) / len(per_flight),
                               "detect_ci": bootstrap_ci([{"x": x} for x in per_flight], lambda s: _mean(s, "x"), seed),
                               "detectors": det, "n": len(flights)}
    return scenarios


def _read(paths: list[str]) -> dict[float, tuple[dict, dict]]:
    out = {}
    for path in paths:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        meta = data.get("summary", {}).get("meta", {})
        harsh = round(float(meta.get("harsh", 0.75)), 2)
        out[harsh] = (data, _summary(data["results"]))
    return out


def _run_table(label: str, data: dict) -> list[str]:
    meta = data.get("summary", {}).get("meta", {})
    runs = meta.get("runs", len(data.get("results", [])))
    benign = sum(r["scenario"] == "NORMAL_FLIGHT" for r in data.get("results", []))
    attacks = Counter(r["scenario"] for r in data.get("results", []) if r["scenario"] != "NORMAL_FLIGHT")
    atk_counts = sorted(set(attacks.values()))
    seeds = meta.get("seed", "n/a")
    seconds = meta.get("seconds", "n/a")
    hours = data.get("summary", {}).get("benign", {}).get("flight_hours", "n/a")
    profile = "boundary" if meta.get("boundary_attacks") else "nominal"
    return [f"| {label} | {meta.get('harsh', 'n/a')} | {profile} | {seeds} | {benign} | {', '.join(map(str, atk_counts)) or 0} per attack | {runs} | {hours} | {seconds} |"]


def _roc(data: dict, config_name: str) -> list[str]:
    rows = []
    bins = {
        "GPS_DRIFT": ("drift_rate", [0.05, 0.25, 0.5, 1.0, 1.5, 2.00001]),
        "GPS_JUMP": ("jump_m", [5, 25, 50, 100, 200, 300.00001]),
        "GPS_IMU_MISMATCH": ("mismatch_vel", [3, 5, 8, 12, 18, 25.00001]),
    }
    for scenario, (key, edges) in bins.items():
        flights = [r for r in data["results"] if r["scenario"] == scenario]
        for lo, hi in zip(edges, edges[1:]):
            selected = [r for r in flights if lo <= r["attack"][key] < hi]
            if not selected:
                continue
            vals = [{"x": int("GPS_INTEGRITY" in classify(r)["tp"])} for r in selected]
            rate = _mean(vals, "x")
            ci = bootstrap_ci(vals, lambda s: _mean(s, "x"), seed=round(lo * 1000) + len(scenario))
            rows.append(f"| {config_name} | {scenario} | {lo:g}–{hi:g} | {len(selected)} | {_format_ci(rate, ci, 3, 100)}% |")
    return rows


def _smallest_95(data: dict, config_name: str) -> list[str]:
    specs = {
        "GPS_DRIFT": ("drift_rate", [0.05, 0.25, 0.5, 1.0, 1.5, 2.00001], "m/s"),
        "GPS_JUMP": ("jump_m", [5, 25, 50, 100, 200, 300.00001], "m"),
        "GPS_IMU_MISMATCH": ("mismatch_vel", [3, 5, 8, 12, 18, 25.00001], "m/s"),
    }
    out = []
    for scenario, (key, edges, unit) in specs.items():
        flights = [r for r in data["results"] if r["scenario"] == scenario]
        found = None
        for lo, hi in zip(edges, edges[1:]):
            selected = [r for r in flights if lo <= r["attack"][key] < hi]
            if selected and sum("GPS_INTEGRITY" in classify(r)["tp"] for r in selected) / len(selected) >= 0.95:
                found = f"{lo:g}–{hi:g} {unit}"
                break
        out.append(f"| {config_name} | {scenario} | {found or 'not reached'} |")
    return out


def _grid_section(path: str) -> list[str]:
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    meta = data.get("_meta", {})
    elapsed = sum(v.get("meta", {}).get("seconds", 0.0) for k, v in data.items() if k != "_meta")
    selected = ("baseline", "cmdrule_8", "cmdrule_12", "policy_ignore_trusted_cmd_rule",
                "policy_downgrade_trusted_edits", "policy_both_trusted_options")
    lines = ["", "## Policy options and tuning trade-offs", "",
             (f"Common-random-number grid: root seed {meta.get('seed', 'n/a')}, harshness {meta.get('harsh', 'n/a')}, "
              f"{meta.get('benign_per_variant', 'n/a')} benign and {meta.get('attack_per_scenario', 'n/a')} per attack per variant, "
              f"extended environment={meta.get('extended', 'n/a')}, {elapsed:.1f} s summed variant runtime. All variants reused the same flights. "
              "FP/hour includes all non-justified alerts. Incident percentages are shown both strict and with modeled trusted-operator policy incidents excluded."), "",
             "| Variant | FP/hour (95% CI) | FP-incident flights (strict / excluding trusted policy) | FP CONFIRMED (95% CI) | COMMAND_BURST detection; Δmedian/Δp95 latency | PARAMETER_CHANGE detection; Δmedian/Δp95 latency | MISSION_CHANGE detection; Δmedian/Δp95 latency |", "|---|---:|---:|---:|---|---|---|"]
    base = data.get("baseline", {})
    base_rows = _summary(base.get("results", []))
    base_fp = _fp_metrics(base_rows["benign"], [], 202600)
    base_attack = _attack_metrics(base_rows["attack"], 202601)
    for i, name in enumerate(selected):
        variant = data.get(name)
        if not variant:
            continue
        metrics = _summary(variant.get("results", []))
        fp = _fp_metrics(metrics["benign"], [], 202610 + i * 10)
        n_benign = len(metrics["benign"])
        attack = _attack_metrics(metrics["attack"], 202620 + i * 10)
        scenario_cells = []
        for scenario in ("COMMAND_BURST", "PARAMETER_CHANGE", "MISSION_CHANGE"):
            item = attack.get(scenario)
            if not item or item["detect"] is None:
                scenario_cells.append("n/a")
                continue
            detector = next(iter(item["detectors"].values()))
            rate = _format_ci(item["detect"], item["detect_ci"], 3, 100) + "%"
            base_item = base_attack.get(scenario)
            rate_delta = (item["detect"] - base_item["detect"]) * 100 if base_item and base_item["detect"] is not None else 0.0
            med, med_ci = detector["latency"]["median"]
            p95, p95_ci = detector["latency"]["p95"]
            base_detector = next(iter(base_item["detectors"].values())) if base_item and base_item["detectors"] else None
            base_med = base_detector["latency"]["median"][0] if base_detector else float("nan")
            base_p95 = base_detector["latency"]["p95"][0] if base_detector else float("nan")
            scenario_cells.append(f"{rate} ({rate_delta:+.1f}pp); Δmed {med-base_med:+.2f}s / Δp95 {p95-base_p95:+.2f}s")
        strict = _format_ci(*fp["INCIDENT"], 1, 100) + "%"
        policy = _format_ci(*fp["INCIDENT_EX_POLICY"], 1, 100) + "%"
        confirmed, confirmed_ci = fp["CONFIRMED"]
        confirmed_text = f"{confirmed:.0f} ({confirmed_ci[0]:.0f}–{confirmed_ci[1]:.0f})"
        delta = fp["ALL"][0] - base_fp["ALL"][0]
        point, ci = fp["ALL"]
        lines.append(f"| {name} | {_format_ci(point, ci, 2)} ({delta:+.2f}/h) | {strict} / {policy} | {confirmed_text} | {scenario_cells[0]} | {scenario_cells[1]} | {scenario_cells[2]} |")
    lines.extend(["", "The policy variants are calibration-only emulations. Option (a) suppresses trusted GCS COMMAND_LONG from the command-burst rule while preserving it for other detectors. Option (c) converts trusted PARAMETER and MISSION anomalies to OBSERVED and records audit entries. These variants change no files under `app/ids/`.", ""])
    baseline_attack = _attack_metrics(base_rows["attack"], 202699)
    baseline_lat = {(scenario, detector): row["latency"]["median"][0]
                    for scenario, item in baseline_attack.items() if item["detect"] is not None
                    for detector, row in item["detectors"].items()}
    points = []
    for i, (name, variant) in enumerate((k, v) for k, v in data.items() if k != "_meta" and v.get("results")):
        metrics = _summary(variant["results"])
        fp = _fp_metrics(metrics["benign"], [], 202700 + i)
        attack = _attack_metrics(metrics["attack"], 202800 + i)
        rates = [x["detect"] for x in attack.values() if x["detect"] is not None]
        all_rates = [x["detect"] for x in attack.values() if x["detect"] is not None]
        latency_ratios = []
        latency_ok = True
        for scenario, item in attack.items():
            if item["detect"] is None:
                continue
            for detector, row in item["detectors"].items():
                ref = baseline_lat.get((scenario, detector))
                med = row["latency"]["median"][0]
                if ref is not None and ref > 0 and med == med:
                    latency_ratios.append(med / ref)
                    latency_ok = latency_ok and med <= 1.5 * ref
        point = {"name": name, "fp": fp["ALL"][0], "incident": fp["INCIDENT_EX_POLICY"][0],
                 "confirmed": fp["CONFIRMED"][0], "detection": min(rates) if rates else 0.0,
                 "latency_ratio": max(latency_ratios) if latency_ratios else float("inf"),
                 "latency_ok": latency_ok, "all_detection": all_rates}
        point["feasible"] = (point["fp"] <= 5.0 and point["incident"] <= 0.05 and point["confirmed"] == 0
                             and bool(all_rates) and all(rate >= 0.99 for rate in all_rates) and latency_ok)
        points.append(point)
    def dominates(a, b):
        av = (a["fp"], a["incident"], a["confirmed"], -a["detection"], a["latency_ratio"])
        bv = (b["fp"], b["incident"], b["confirmed"], -b["detection"], b["latency_ratio"])
        return all(x <= y for x, y in zip(av, bv)) and any(x < y for x, y in zip(av, bv))
    frontier = [p for p in points if not any(dominates(q, p) for q in points if q is not p)]
    feasible = [p for p in points if p["feasible"]]
    lines.extend(["", "### Selection targets and Pareto frontier", "",
                  f"Grid variants meeting all point-estimate targets: **{len(feasible)} of {len(points)}**. "
                  "Targets are <=5 FP/hour, <=5% benign FP-incident flights after excluding modeled trusted-policy-only incidents, zero benign CONFIRMED incidents, >=99% detection for every scored attack scenario, and median latency no more than 1.5x the same-flight baseline.", "",
                  "If this count is zero, no tested setting meets every target; the table shows nondominated trade-offs, and any held-out point is an explicitly selected compromise.", "",
                  "| Pareto variant | FP/hour | FP incidents after policy exclusions | FP CONFIRMED | Minimum scored attack detection | Worst median latency / baseline | Meets all targets |", "|---|---:|---:|---:|---:|---:|---|"])
    for point in sorted(frontier, key=lambda p: (p["fp"], p["incident"], -p["detection"])):
        ratio = "n/a" if point["latency_ratio"] == float("inf") else f"{point['latency_ratio']:.2f}x"
        lines.append(f"| {point['name']} | {point['fp']:.2f} | {point['incident']*100:.1f}% | {point['confirmed']:.0f} | {point['detection']*100:.1f}% | {ratio} | {'yes' if point['feasible'] else 'no'} |")
    return lines


def build_report(baseline_paths: list[str], candidate_paths: list[str] | None = None,
                 analyses: list[str] | None = None, long_paths: list[str] | None = None,
                 grid_path: str | None = None, roc_current_path: str | None = None,
                 roc_candidate_path: str | None = None,
                 output: str = "../data/simulations/CODEX_CALIBRATION_REPORT.md") -> None:
    baseline = _read(baseline_paths)
    candidate = _read(candidate_paths or [])
    lines = ["# SPIDERS / PUSHPAK IDS Monte Carlo calibration", "",
             "**Simulation-only evidence.** The simulator does not model hardware timing, RF propagation, real autopilot firmware, GPS multipath geometry, or field operator behavior beyond the injected profiles.", "",
             "## Runs", "", "| Set | Harshness | Attack profile | Root seed | Benign | Attacks | Flights | Benign hours | Runtime seconds |", "|---|---:|---|---:|---:|---:|---:|---:|---:|"]
    for label, entries in (("Baseline", baseline), ("Proposed held-out", candidate)):
        for level, (data, _) in sorted(entries.items()):
            lines.extend(_run_table(label, data))
    lines.extend(["", "## False positives", "", "Rates are FP alerts per benign flight-hour. Parentheses show flight-bootstrap 95% percentile confidence intervals. Incident percentages and CONFIRMED counts use benign flights as the resampling unit. Justified sequence-loss alerts (true loss >= 8%) are excluded.", ""])
    levels = sorted(set(baseline) | set(candidate))
    for level in levels:
        pairs = []
        if level in baseline:
            pairs.append(("Baseline", baseline[level][1]["benign"], 1000 + int(level * 100)))
        if level in candidate:
            pairs.append(("Proposed", candidate[level][1]["benign"], 9000 + int(level * 100)))
        detectors = sorted(set().union(*(m["fp_detectors"] for _label, m, _seed in pairs)))
        lines.extend([f"### Harshness {level:g}", "", "| Set | Detector / measure | Rate |", "|---|---|---:|"])
        for label, metrics, seed in pairs:
            fp = _fp_metrics(metrics["benign"], detectors, seed)
            for detector in ["ALL", "INCIDENT", "INCIDENT_EX_POLICY", "CONFIRMED", *detectors]:
                point, ci = fp[detector]
                if detector in ("INCIDENT", "INCIDENT_EX_POLICY"):
                    text = _format_ci(point, ci, 1, 100) + "% flights"
                elif detector == "CONFIRMED":
                    text = f"{point:.0f} flights (bootstrap {ci[0]:.0f}–{ci[1]:.0f})"
                else:
                    text = _format_ci(point, ci, 2)
                lines.append(f"| {label} | {detector} | {text} |")
    lines.extend(["", "## Attack detection and latency", "", "Detection and latency intervals resample flights. Latency is conditional on detection; n shows the number of detections used for the latency distribution. Scenarios with no expected detector are marked unscored by the harness.", "", "| Harshness | Set | Scenario | Expected detector(s) | Detection rate (95% CI) | Detector latency median / p95 seconds (95% CI) |", "|---:|---|---|---|---:|---|"])
    for level in levels:
        for label, entries, seed in (("Baseline", baseline, 1000 + int(level * 100)), ("Proposed", candidate, 9000 + int(level * 100))):
            if level not in entries:
                continue
            for scenario, m in sorted(_attack_metrics(entries[level][1]["attack"], seed).items()):
                if m["detect"] is None:
                    lines.append(f"| {level:g} | {label} | {scenario} | none | unscored | n/a |")
                    continue
                detect = _format_ci(m["detect"], m["detect_ci"], 3, 100) + "%"
                for detector, d in m["detectors"].items():
                    med, medci = d["latency"]["median"]
                    p95, p95ci = d["latency"]["p95"]
                    lat = (f"{_format_ci(med, medci, 2)} / {_format_ci(p95, p95ci, 2)} "
                           f"(n={d['latency_n']}/{d['n']})")
                    lines.append(f"| {level:g} | {label} | {scenario} | {detector} | {detect} | {lat} |")
    if grid_path:
        lines.extend(_grid_section(grid_path))
    lines.extend(["", "## GPS detection by attack strength", "", "Separate boundary-strength runs use harshness 0.75 and held-out ROC seeds, independent from nominal validation. Rates use fixed strength bins; intervals bootstrap individual flights. The smallest >=95% bin is the first bin whose point estimate reaches 95%; this is a simulation estimate, not an operational guarantee.", "", "| Set | Attack | Strength bin | Flights | GPS detection (95% CI) |", "|---|---|---:|---:|---:|"])
    roc_sets = []
    if roc_current_path:
        roc_sets.append(("Current config", json.loads(Path(roc_current_path).read_text(encoding="utf-8-sig"))))
    if roc_candidate_path:
        roc_sets.append(("Proposed config", json.loads(Path(roc_candidate_path).read_text(encoding="utf-8-sig"))))
    for label, data in roc_sets:
        lines.extend(_roc(data, label))
    lines.extend(["", "### Smallest bin reaching 95% GPS detection", "", "| Set | Attack | Smallest observed strength bin >=95% |", "|---|---|---|"])
    for label, data in roc_sets:
        lines.extend(_smallest_95(data, label))
    if long_paths:
        lines.extend(["", "## Long-flight false-positive rates", "", "These runs use 20–40 minute benign flights; intervals bootstrap whole flights.", "", "| Harshness | Flights | Benign hours | FP alerts/hour (95% CI) | FP incident flights (95% CI) |", "|---:|---:|---:|---:|---:|"])
        for index, path in enumerate(long_paths):
            data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
            metrics = _summary(data["results"])
            benign = metrics["benign"]
            fp = _fp_metrics(benign, [], 4500 + index)
            level = data.get("summary", {}).get("meta", {}).get("harsh", "n/a")
            hours = sum(r["duration"] for r in benign) / 3600
            incident = fp["INCIDENT_EX_POLICY"]
            lines.append(f"| {level} | {len(benign)} | {hours:.2f} | {_format_ci(*fp['ALL'], 2)} | {_format_ci(*incident, 1, 100)}% |")
    if analyses:
        lines.extend(["", "## False-positive drivers", ""])
        for path in analyses:
            p = Path(path)
            try:
                data = json.loads(p.read_text(encoding="utf-8-sig"))
            except OSError:
                continue
            lines.extend([f"### {p.stem}", "", "| Signature | Flights hit | Top associated factors (rank-correlation / rate difference) |", "|---|---:|---|"])
            for row in data.get("drivers", [])[:10]:
                drivers = ", ".join(f"{k} {v:+.3f}" for k, v in row["top_drivers"])
                lines.append(f"| {row['signature']} | {row['flights_hit']}/{row['flights']} | {drivers} |")
    lines.extend(["", "## Interpretation limits", "", "These results describe this simulator and configured random profile only. The simulator does not model real RF propagation, hardware scheduler jitter, multipath geometry, firmware-specific estimator behavior, or the full range of operator workflows. The report must state measured FP, detection, latency, and profile for each proposed change; protected detector and rule changes are proposals only until approved.", ""])
    Path(output).write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--baseline", nargs="+", required=True, help="baseline JSON files, one per harshness level")
    ap.add_argument("--candidate", nargs="*", default=[], help="held-out candidate JSON files")
    ap.add_argument("--analysis", nargs="*", default=[], help="analyze.py driver output JSON files")
    ap.add_argument("--long", nargs="*", default=[], help="20–40 minute benign flight JSON files")
    ap.add_argument("--grid", help="common-random-number tuning grid JSON")
    ap.add_argument("--roc-current", help="current-config boundary ROC JSON")
    ap.add_argument("--roc-candidate", help="candidate-config boundary ROC JSON")
    ap.add_argument("--out", default="../data/simulations/CODEX_CALIBRATION_REPORT.md")
    args = ap.parse_args()
    build_report(args.baseline, args.candidate, args.analysis, args.long, args.grid,
                 args.roc_current, args.roc_candidate, args.out)


if __name__ == "__main__":
    main()
