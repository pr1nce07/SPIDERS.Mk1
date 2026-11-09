"""GAP-02 harness: window scoring, intervals, locked-partition guard, and a real replay of recorded tlogs."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from app.config import Config
from app.evaluation import Run, RunResult, load_corpus, poisson_rate_ci, replay, score, wilson
from app.mavlink.decoder import tlog_record
from app.sources.simulation import FlightSimulator

ROOT = Path(__file__).resolve().parents[2]


def _rr(label, windows, alerts, dur=600.0, meta=None):
    return RunResult(Run("r-" + label + str(len(alerts)), None, label, "tune", windows, meta or {"vehicle": "V1"}),
                     dur, [{"t": t, "detector": d, "state": "SUSPECTED"} for t, d in alerts], [])


def test_window_scoring_counts_each_window_once_and_false_alarms_per_hour():
    res = score([
        _rr("gps_spoof", [(100, 110), (300, 320)], [(101, "GPS_INTEGRITY"), (102, "GPS_INTEGRITY"), (500, "GPS_INTEGRITY")]),
        _rr("benign", [], [(50, "HEARTBEAT")], dur=3600.0),
    ])
    c = res["per_attack_class"]["gps_spoof"]
    assert (c["attack_windows"], c["detected"], c["recall"]) == (2, 1, 0.5)
    assert c["latency_s"]["median"] == 1.0
    assert res["false_alarms"]["count"] == 2
    assert res["per_detector"]["GPS_INTEGRITY"]["false_alarms"] == 1
    assert res["false_alarms"]["per_flight_hour_ci95"][0] < res["false_alarms"]["per_flight_hour"] < res["false_alarms"]["per_flight_hour_ci95"][1]


def test_interval_helpers():
    lo, hi = wilson(9, 10)
    assert lo < 0.9 < hi <= 1.0
    assert poisson_rate_ci(0, 10.0)[0] == 0.0 and poisson_rate_ci(0, 10.0)[1] > 0  # zero false alarms is still an interval


def test_corpus_requires_ground_truth_and_valid_partitions(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"runs": [{"run_id": "a", "label": "gps_spoof", "partition": "tune"}]}))
    with pytest.raises(ValueError, match="attack_windows"):
        load_corpus(p)
    p.write_text(json.dumps({"runs": [{"run_id": "a", "label": "benign", "partition": "test"}]}))
    with pytest.raises(ValueError, match="partition"):
        load_corpus(p)


def _tlog(path: Path, scenario: str, dur: float) -> Path:
    with open(path, "wb") as fh:
        for fr in FlightSimulator(scenario, duration_s=dur).frames():
            fh.write(tlog_record(fr.t, fr.data))
    return path


def test_replay_of_recorded_tlogs_through_the_real_pipeline(tmp_path):
    cfg = Config.load()
    benign = replay(Run("n", str(_tlog(tmp_path / "n.tlog", "NORMAL_FLIGHT", 90)), "benign", "tune"), cfg)
    # ground truth covers the 6 s jump plus the snap-back when the position returns (alerts up to ~56 s)
    attack = replay(Run("g", str(_tlog(tmp_path / "g.tlog", "GPS_JUMP", 90)), "gps_jump", "tune", [(45.0, 57.0)]), cfg)
    assert benign.file_sha256 and 85 < benign.duration_s < 95
    res = score([benign, attack])
    assert res["per_attack_class"]["gps_jump"]["detected"] == 1
    assert res["false_alarms"]["count"] == 0


def test_cli_refuses_locked_partition_without_frozen_fingerprint(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"runs": [{"run_id": "a", "label": "benign", "partition": "locked", "file": "x.tlog"}]}))
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "evaluate_detectors.py"), str(p), "--partition", "locked"],
                       capture_output=True, text=True)
    assert r.returncode == 2 and "refusing to evaluate the locked partition" in r.stderr
