"""GAP-09 / V-017: shared raw evidence must not earn independence credit."""
from types import SimpleNamespace

from app.config import Config
from app.ids.correlation import Correlator, IncidentIdAllocator
from app.ids.lineage import evidence_lines, lineage_for
from app.models.events import DetectorResult


def _ctx(mono):
    return SimpleNamespace(mono=mono, vehicle_sysid=1, is_trusted_gcs=lambda s: s == 255, fc_states={"GPS": {}})


def _r(detector, source, conf, domain="GPS_INTEGRITY", family=None, state="SUSPECTED", method=None):
    return DetectorResult(detector=detector, state=state, title=f"{source} {detector}", t=100.0, severity="HIGH",
                          confidence=conf, source=source, domain=domain, method=method, sysid=1,
                          inputs={"detector": family} if family else {})


def _feed(results):
    c = Correlator(Config.load(), IncidentIdAllocator(), "T")
    for i, r in enumerate(results):
        c.ingest(r, _ctx(10.0 + i * 0.1))
    assert len(c.incidents) == 1
    return next(iter(c.incidents.values()))


def test_three_tiers_on_one_gps_are_one_line_not_confirmed():
    inc = _feed([_r("GPS_INTEGRITY", "GROUND", 0.95),
                 _r("PUSHPAK_FC", "FC", 0.95, family="GPS", state="CONFIRMED"),
                 _r("PUSHPAK_FC", "LUA", 0.95, family="GPS", state="CONFIRMED")])
    assert inc["independence"]["count"] == 1
    assert inc["state"] != "CONFIRMED"
    assert any("corroboration, not independent confirmation" in x for x in inc["limitations"])
    ind = [c for c in inc["contributors"] if c["independent"]]
    assert len(ind) == 1 and all(c["value"] < c["raw_value"] for c in inc["contributors"] if not c["independent"])


def test_distinct_modalities_count_as_independent_lines():
    inc = _feed([_r("GPS_INTEGRITY", "GROUND", 1.0),
                 _r("IMU_CONSISTENCY", "GROUND", 1.0, domain="GPS_INTEGRITY"),
                 _r("PUSHPAK_FC", "FC", 1.0, family="GPS", state="CONFIRMED")])
    assert inc["independence"]["count"] == 2  # {GNSS,EKF} and {IMU}; FC GPS corroborates the GNSS line
    assert inc["state"] == "CONFIRMED"


def test_baro_gps_residual_shares_gnss_line():
    r = _r("IMU_CONSISTENCY", "GROUND", 0.8, method="EKF(baro) ↔ GPS altitude residual (offset-corrected)")
    assert set(lineage_for(r)) == {"BARO", "GNSS", "EKF"}
    assert len(evidence_lines([lineage_for(r), lineage_for(_r("GPS_INTEGRITY", "GROUND", 0.9))])) == 1


def test_ml_baseline_adds_no_independent_line():
    assert lineage_for(_r("ML_BASELINE", "GROUND", 0.9)) is None
