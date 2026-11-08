"""Attribute false positives to environment factors and attack misses to attack magnitude.

  PYTHONPATH=. python -m calibration.analyze ../data/simulations/phase1_harsh.json
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict

from .sweep import classify

NUM = ["noise_scale", "gps_lag_s", "multipath_p", "multipath_m", "gps_alt_walk", "sats", "sat_dip_p", "hdop", "ekf_base",
       "ekf_spike_p", "ekf_spike_max", "imu_vib_mg", "imu_bias_mg", "gyro_bias", "gyro_noise", "rssi_base", "rssi_fade",
       "rxerr_p", "radio_noise_jit", "batt_v_noise", "current_spike_p", "link_loss", "burst_per_min", "ts_jitter",
       "gust_mps", "gps_fix_drop_p", "gps2_offset_m", "gps2_noise_m", "repeated_flight_cycles", "rate_change_scale",
       "aggressive_accel_ms2", "aggressive_attitude_rate_rads",
       "low_battery_sag_v", "pack_voltage_offset_v"]
BOOL = ["busy_operator", "operator_param_edits", "operator_mission_edit", "rtk_transitions", "aggressive_maneuvers",
        "hover_loiter", "companion_link", "gcs_reconnect", "radio_reboot", "pack_swap", "rtl_commands"]


def _rank_corr(xs, ys):
    def ranks(v):
        order = sorted(range(len(v)), key=lambda i: v[i])
        r = [0.0] * len(v)
        for k, i in enumerate(order):
            r[i] = k
        return r
    rx, ry = ranks(xs), ranks(ys)
    n = len(xs)
    mx, my = sum(rx) / n, sum(ry) / n
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    den = (sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry)) ** 0.5
    return num / den if den else 0.0


def drivers(results, top=12):
    """For every FP signature: share of flights hit and the env factors most associated with it."""
    rows = [(r, classify(r)) for r in results if r["scenario"] == "NORMAL_FLIGHT"]
    sigs = defaultdict(lambda: [0] * len(rows))
    for j, (r, c) in enumerate(rows):
        for a in c["fp"]:
            sigs[f"{a['detector']} | {a['title']}"][j] += 1
    out = []
    for sig, counts in sorted(sigs.items(), key=lambda kv: -sum(1 for x in kv[1] if x)):
        hit = [1 if x else 0 for x in counts]
        assoc = []
        for k in NUM:
            assoc.append((k, round(_rank_corr([r["env"][k] for r, _ in rows], hit), 3)))
        for k in BOOL:
            on = [h for (r, _), h in zip(rows, hit) if r["env"][k]]
            off = [h for (r, _), h in zip(rows, hit) if not r["env"][k]]
            if on and off:
                assoc.append((k, round(sum(on) / len(on) - sum(off) / len(off), 3)))
        assoc.sort(key=lambda kv: -abs(kv[1]))
        out.append({"signature": sig, "flights_hit": sum(hit), "flights": len(rows), "alerts": sum(counts),
                    "top_drivers": assoc[:4]})
    return out[:top]


def threshold_curve(results, factor, sig_prefix, bins=5):
    rows = [(r, classify(r)) for r in results if r["scenario"] == "NORMAL_FLIGHT"]
    vals = sorted(r["env"][factor] for r, _ in rows)
    edges = [vals[int(len(vals) * i / bins)] for i in range(bins)] + [vals[-1] + 1e-9]
    out = []
    for lo, hi in zip(edges, edges[1:]):
        sel = [c for r, c in rows if lo <= r["env"][factor] < hi]
        hit = sum(1 for c in sel if any(f"{a['detector']} | {a['title']}".startswith(sig_prefix) for a in c["fp"]))
        out.append({"range": [round(lo, 4), round(hi, 4)], "flights": len(sel), "fp_rate": round(hit / max(1, len(sel)), 3)})
    return out


def misses(results):
    """Attack-detection rate vs attack magnitude for scenarios whose magnitude is randomised."""
    key = {"GPS_DRIFT": "drift_rate", "PUSHPAK_CONFIRMATION": "drift_rate", "GPS_JUMP": "jump_m", "GPS_IMU_MISMATCH": "mismatch_vel",
           "MULTI_SIGNAL_INCIDENT": "mismatch_vel"}
    out = {}
    for sc, k in key.items():
        rs = sorted((r for r in results if r["scenario"] == sc), key=lambda r: r["attack"][k])
        if not rs:
            continue
        third = max(1, len(rs) // 3)
        bands = [rs[:third], rs[third:2 * third], rs[2 * third:]]
        out[sc] = [{"magnitude": [round(b[0]["attack"][k], 2), round(b[-1]["attack"][k], 2)],
                    "gps_detected": round(sum("GPS_INTEGRITY" in classify(r)["tp"] for r in b) / len(b), 2)} for b in bands if b]
    return out


def main():
    data = json.load(open(sys.argv[1]))
    res = data["results"]
    print(json.dumps({"drivers": drivers(res), "misses": misses(res)}, indent=1))


if __name__ == "__main__":
    main()
