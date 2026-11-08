"""One-at-a-time threshold grid on a fixed set of randomised flights (common random numbers).

  PYTHONPATH=. python -m calibration.grid --out ../data/simulations/grid.json
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from .sweep import make_jobs, run_jobs, summarize

D = "ids.detectors"


def ov(pairs: dict) -> dict:
    out: dict = {}
    for dotted, v in pairs.items():
        cur = out
        parts = dotted.split(".")
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = v
    return out


VARIANTS = {
    "baseline": {},
    "rate_k1.0": {"ov": {f"{D}.MAVLINK_RATE.cusum_k": 1.0}},
    "rate_k1.5": {"ov": {f"{D}.MAVLINK_RATE.cusum_k": 1.5}},
    "rate_k2.0": {"ov": {f"{D}.MAVLINK_RATE.cusum_k": 2.0}},
    "rate_k2.5": {"ov": {f"{D}.MAVLINK_RATE.cusum_k": 2.5}},
    "rate_k3.0": {"ov": {f"{D}.MAVLINK_RATE.cusum_k": 3.0}},
    "rate_k1.5_h12": {"ov": {f"{D}.MAVLINK_RATE.cusum_k": 1.5, f"{D}.MAVLINK_RATE.cusum_h": 12.0}},
    "rate_h20": {"ov": {f"{D}.MAVLINK_RATE.cusum_h": 20.0}},
    "rate_h30": {"ov": {f"{D}.MAVLINK_RATE.cusum_h": 30.0}},
    "rate_h40": {"ov": {f"{D}.MAVLINK_RATE.cusum_h": 40.0}},
    "rate_burst6": {"ov": {f"{D}.MAVLINK_RATE.burst_factor": 6.0}},
    "rate_burst8": {"ov": {f"{D}.MAVLINK_RATE.burst_factor": 8.0}},
    "rate_minhz1": {"ov": {f"{D}.MAVLINK_RATE.min_baseline_hz": 1.0}},
    "rate_minhz2": {"ov": {f"{D}.MAVLINK_RATE.min_baseline_hz": 2.0}},
    "rate_minhz3": {"ov": {f"{D}.MAVLINK_RATE.min_baseline_hz": 3.0}},
    "rate_minhz3_f6": {"ov": {f"{D}.MAVLINK_RATE.min_baseline_hz": 3.0, f"{D}.MAVLINK_RATE.burst_factor": 6.0}},
    "rc_slope-2.5": {"ov": {f"{D}.RC_LINK.degrade_slope_per_s": -2.5}},
    "rc_slope-3.5": {"ov": {f"{D}.RC_LINK.degrade_slope_per_s": -3.5}},
    "rc_slope-2.5_a0.1": {"ov": {f"{D}.RC_LINK.degrade_slope_per_s": -2.5, f"{D}.RC_LINK.ewma_alpha": 0.1}},
    "rc_rssi80": {"ov": {f"{D}.RC_LINK.rssi_low": 80}},
    "rc_slope-3_a0.1": {"ov": {f"{D}.RC_LINK.degrade_slope_per_s": -3.0, f"{D}.RC_LINK.ewma_alpha": 0.1}},
    "rc_radio_patch": {"patches": ["rc_radio"]},
    "rc_radio_err8": {"patches": ["rc_radio"], "ov": {f"{D}.RC_LINK.radio_err_rate_per_s": 8.0}},
    "rc_radio_noise20": {"patches": ["rc_radio"], "ov": {f"{D}.RC_LINK.radio_noise_rise": 20.0}},
    "rc_radio_persist5": {"patches": ["rc_radio"], "ov": {f"{D}.RC_LINK.radio_persistence_s": 5.0}},
    "imu_accel450": {"ov": {f"{D}.IMU_CONSISTENCY.accel_residual_mg": 450}},
    "imu_gyro200": {"ov": {f"{D}.IMU_CONSISTENCY.gyro_residual_mrads": 200}},
    "imu_baro35": {"ov": {f"{D}.IMU_CONSISTENCY.baro_gps_alt_residual_m": 35}},
    "imu_persist5": {"ov": {f"{D}.IMU_CONSISTENCY.persistence_s": 5.0}},
    "seq_loss15": {"ov": {f"{D}.MAVLINK_SEQUENCE.loss_ratio_threshold": 0.15}},
    "seq_loss20_w15": {"ov": {f"{D}.MAVLINK_SEQUENCE.loss_ratio_threshold": 0.20, f"{D}.MAVLINK_SEQUENCE.window_s": 15}},
    "gps_var1.0": {"ov": {f"{D}.GPS_INTEGRITY.ekf_variance_threshold": 1.0}},
    "gps_var1.2": {"ov": {f"{D}.GPS_INTEGRITY.ekf_variance_threshold": 1.2}},
    "gps_pos20": {"ov": {f"{D}.GPS_INTEGRITY.position_residual_m": 20.0}},
    "gps_vel4": {"ov": {f"{D}.GPS_INTEGRITY.velocity_residual_ms": 4.0}},
    "gps_robust5": {"ov": {f"{D}.GPS_INTEGRITY.robust_z": 5.0}},
    "gps_cusum_h20": {"ov": {f"{D}.GPS_INTEGRITY.cusum_h": 20.0}},
    "gps_cusum_h30": {"ov": {f"{D}.GPS_INTEGRITY.cusum_h": 30.0}},
    "gps_cusum_k1.5": {"ov": {f"{D}.GPS_INTEGRITY.cusum_k": 1.5}},
    "gps_persist5": {"ov": {f"{D}.GPS_INTEGRITY.persistence_s": 5.0}},
    "gps_jump40_f4": {"ov": {f"{D}.GPS_INTEGRITY.jump_min_m": 40.0, f"{D}.GPS_INTEGRITY.jump_speed_factor": 4.0}},
    "gps_jump40_f5": {"ov": {f"{D}.GPS_INTEGRITY.jump_min_m": 40.0, f"{D}.GPS_INTEGRITY.jump_speed_factor": 5.0}},
    "gps_cusum_clip": {"patches": ["gps_cusum_clip"]},
    "gps_cusum_clip_h20": {"patches": ["gps_cusum_clip"], "ov": {f"{D}.GPS_INTEGRITY.cusum_h": 20.0}},
    "cmd_repeat5": {"ov": {f"{D}.COMMAND.repeat_count": 5}},
    "cmdrule_8": {"rule": {"CMD-BURST-001": {"thr": {"value": 8}}}},
    "cmdrule_12": {"rule": {"CMD-BURST-001": {"thr": {"value": 12}}}},
    "policy_ignore_trusted_cmd_rule": {"patches": ["trusted_cmd_rule"]},
    "policy_downgrade_trusted_edits": {"patches": ["trusted_edits_observed"]},
    "policy_both_trusted_options": {"patches": ["trusted_cmd_rule", "trusted_edits_observed"]},
    "hb_stale4": {"ov": {"mavlink.heartbeat_stale_s": 4.0}},
    "hb_stale5": {"ov": {"mavlink.heartbeat_stale_s": 5.0}},
    "hb_loss8": {"ov": {"mavlink.heartbeat_loss_s": 8.0}},
    "hb_rule_persist5": {"rule": {"HEARTBEAT-RATE-001": {"pers": {"duration_s": 5.0}}}},
    "hb_rule_persist8": {"rule": {"HEARTBEAT-RATE-001": {"pers": {"duration_s": 8.0}}}},
    "cmd_burst8": {"ov": {f"{D}.COMMAND.burst_count": 8}},
    "cmd_burst10_w7": {"ov": {f"{D}.COMMAND.burst_count": 10, f"{D}.COMMAND.burst_window_s": 7}},
    "param_burst8": {"ov": {f"{D}.PARAMETER.burst_count": 8}},
    "ml_score-0.1": {"ov": {f"{D}.ML_BASELINE.score_threshold": -0.1}},
    "ml_score0": {"ov": {f"{D}.ML_BASELINE.score_threshold": 0.0}},
    "ml_contamination0.01": {"ov": {f"{D}.ML_BASELINE.contamination": 0.01}},
    "ml_contamination0.05": {"ov": {f"{D}.ML_BASELINE.contamination": 0.05}},
    "corr_suspect55": {"ov": {"ids.suspected_threshold": 0.55}},
    "corr_confirmed80": {"ov": {"ids.confirmed_threshold": 0.8}},
    "corr_window15_min3": {"ov": {"ids.correlation_window_seconds": 15, "ids.min_correlated_detectors": 3}},
}


def compact(s: dict) -> dict:
    b = s["benign"]
    atk = s["attack"]
    return {"fp_per_h": b["fp_alerts_per_hour"], "fp_flights": b["flights_with_fp_alert"], "fp_inc_flights": b["flights_with_fp_incident"],
            "fp_by_detector": b["fp_by_detector"],
            "detect_all": {k: f"{v['all_expected_detected']}/{v['runs']}" for k, v in atk.items()},
            "latency": {k: v["median_latency_s"] for k, v in atk.items()},
            "confirmed": {k: v["confirmed_rate"] for k, v in atk.items()},
            "incident": {k: v["incident_rate"] for k, v in atk.items()}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign", type=int, default=160)
    ap.add_argument("--attack", type=int, default=12)
    ap.add_argument("--seed", type=int, default=777)
    ap.add_argument("--harsh", type=float, default=0.75)
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--workers", type=int, default=14)
    ap.add_argument("--extended", action="store_true")
    ap.add_argument("--boundary-attacks", action="store_true", help="use attack-boundary strengths for ROC screening")
    ap.add_argument("--duration-min", type=int, default=120)
    ap.add_argument("--duration-max", type=int, default=300)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    out = {}
    out["_meta"] = {"seed": a.seed, "harsh": a.harsh, "benign_per_variant": a.benign,
                    "attack_per_scenario": a.attack, "workers": a.workers, "extended": a.extended,
                    "boundary_attacks": a.boundary_attacks,
                    "duration_range": [a.duration_min, a.duration_max], "variants_requested": len(a.only or VARIANTS)}
    for name, v in VARIANTS.items():
        if a.only and name not in a.only:
            continue
        t = time.time()
        jobs = make_jobs(a.benign, a.attack, a.seed, ov(v.get("ov", {})), a.harsh,
                         rule_patch=v.get("rule"), patches=v.get("patches"),
                         duration_range=(a.duration_min, a.duration_max), extended=a.extended,
                         boundary_attacks=a.boundary_attacks)
        checkpoint = Path(a.out).with_name(f"{Path(a.out).name}.{name}.{time.time_ns()}.partial.jsonl")
        results = run_jobs(jobs, a.workers, checkpoint)
        summary = summarize(results)
        out[name] = {**compact(summary), "summary": summary,
                     "meta": {"seconds": round(time.time() - t, 1), "seed": a.seed, "harsh": a.harsh},
                     "results": results}
        print(f"{name:22s} fp/h={out[name]['fp_per_h']:7.2f} fp_inc_flights={out[name]['fp_inc_flights']:3d} "
              f"({time.time() - t:.0f}s) {out[name]['fp_by_detector']}", flush=True)
        Path(a.out).write_text(json.dumps(out, default=list, indent=1), encoding="utf-8")
        checkpoint.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
