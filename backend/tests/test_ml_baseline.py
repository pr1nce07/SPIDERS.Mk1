"""GAP-16 / V-024: a contaminated session start must not silently become a trusted baseline."""
import json
import random
from types import SimpleNamespace

import pytest

from app.ids import ml as ML
from app.ids.ml_profiles import build_profile, load_profile, save_profile
from app.security.keys import KeyStore

pytestmark = pytest.mark.skipif(not ML.SKLEARN, reason="scikit-learn not installed")


def _ctx(t, states=None):
    return SimpleNamespace(t=t, mono=t, vehicle_sysid=1, elapsed=t, detector_states=states or {})


def _row(rng, speed=8.0):
    return [speed + rng.gauss(0, .2), speed + rng.gauss(0, .2), abs(rng.gauss(0, .1)), rng.gauss(0, .3), 14.0, .8,
            50 + rng.gauss(0, 2), 0.0, 0.0, 16.0 + rng.gauss(0, .05), 200.0, .01]


def _feed(det, row, t, states=None):
    det.cur = dict(zip(ML.FEATURES, row))
    det.counts = {"msgs": int(row[6]), "cmds": 0}
    return det.tick(_ctx(t, states), seq_gaps=0)


def _profile(tmp_path, rng, **kw):
    keys = KeyStore(tmp_path / "keys")
    rows = [_row(rng) for _ in range(120)]
    args = dict(profile_id="quad-x-v1", airframe="Quad X / Pixhawk 6C", corpus_version="2026.11",
                flights=[{"file": "f1.tlog", "sha256": "ab", "label": "benign"}], approved_by="eng", keys=keys)
    args.update(kw)
    doc = build_profile(rows, ML.FEATURES, ML.FEATURE_VERSION, **args)
    path = save_profile(doc, tmp_path / "ml" / "quad-x-v1.json")
    return keys, path


def test_session_training_pauses_while_other_detectors_alarm():
    rng = random.Random(1)
    det = ML.MLBaselineDetector({"min_samples": 10, "training_seconds": 5})
    for t in range(20):
        _feed(det, _row(rng, speed=30.0), t, {"GPS_INTEGRITY": "SUSPECTED"})  # attack in progress at boot
    assert det.model is None and det.train == [] and det.skipped_contaminated == 20
    for t in range(20, 40):
        _feed(det, _row(rng), t, {"GPS_INTEGRITY": "NORMAL"})
    assert det.model is not None and det.model_meta["trust"].startswith("session-local")


def test_approved_profile_is_used_and_named_on_every_alert(tmp_path):
    rng = random.Random(2)
    keys, path = _profile(tmp_path, rng)
    body, status = load_profile(path, keys.trusted_public_keys("approval"))
    # threshold set explicitly: the shipped default (-0.15) is an untuned GAP-02 value, not what this test is about
    det = ML.MLBaselineDetector({"profile": "quad-x-v1", "score_threshold": 0.0}, body, status)
    assert det.model is not None and det.model_meta["trust"] == "approved-profile"
    assert _feed(det, _row(rng), 0) == []          # a normal row scores ≈ +0.17 on this corpus: no alert
    out = []
    bad = _row(rng)
    bad[2], bad[6] = 2.0, 120.0     # velocity residual and message rate outside the corpus, the rest normal
    for t in range(20, 60, 20):
        out += _feed(det, bad, t)
    alerts = [r for r in out if r.state == "ANOMALOUS"]
    assert alerts and any("profile=quad-x-v1 corpus=2026.11" in e for e in alerts[0].explanation["evidence"])


def test_tampered_profile_disables_ml_without_session_fallback(tmp_path):
    rng = random.Random(3)
    keys, path = _profile(tmp_path, rng)
    doc = json.loads(path.read_text())
    doc["body"]["rows"][0][0] = 99.0
    path.write_text(json.dumps(doc))
    body, status = load_profile(path, keys.trusted_public_keys("approval"))
    assert status == "INVALID"
    det = ML.MLBaselineDetector({"profile": "quad-x-v1"}, body, status)
    assert not det.enabled and det.health_state == "ERROR"
    assert det.tick(_ctx(100.0)) == [] and det.train == []


def test_out_of_distribution_input_is_not_called_an_anomaly(tmp_path):
    rng = random.Random(4)
    keys, path = _profile(tmp_path, rng)
    det = ML.MLBaselineDetector({"profile": "quad-x-v1"}, *load_profile(path, keys.trusted_public_keys("approval")))
    alien = [80.0, 80.0, 0.05, 25.0, 30.0, 0.3, 400.0, 0.0, 0.0, 50.0, 90.0, 0.5]  # different airframe/regime entirely
    out = _feed(det, alien, 0)
    assert out and out[0].state == "OBSERVED" and out[0].title == "ML input outside training distribution"


def test_profiles_only_from_benign_flights_and_collect_mode_never_scores(tmp_path):
    rng = random.Random(5)
    with pytest.raises(ValueError):
        _profile(tmp_path, rng, flights=[{"file": "attack.tlog", "label": "gps_spoof"}])
    det = ML.MLBaselineDetector({"mode": "collect"})
    for t in range(80):
        assert _feed(det, _row(rng), t) == []
    assert len(det.collected) == 80 and det.model is None
