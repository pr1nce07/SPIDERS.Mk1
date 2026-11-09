"""GAP-08 key lifecycle, GAP-11 approved baselines, GAP-12 signed evidence and audit checkpoints."""
import json
from types import SimpleNamespace

import pytest
from sqlalchemy import select, update

from app.core.audit import AuditLog
from app.forensic.hashing import verify_case
from app.forensic.snapshot import SnapshotManager
from app.ids.baseline import BaselineDetector
from app.ids.mavlink import SigningDetector
from app.models.events import TelemetryEvent
from app.security.baseline import BaselineStore, make_body, verify_doc
from app.security.evidence import CHECKPOINTS, verify_case_signature, verify_checkpoints, write_checkpoint
from app.security.keys import KeyStore, sign_json
from app.storage import db as D


# ------------------------------------------------------------------ GAP-08 keys
def test_mavlink_key_lifecycle_never_exposes_secret(tmp_path):
    ks = KeyStore(tmp_path / "keys")
    a = ks.generate_mavlink_key("eng", "vehicle 1")
    secret = ks.secret(a["key_id"])
    listing = json.dumps(ks.mavlink_keys())
    assert secret.hex() not in listing and "file" not in listing
    ks.activate(a["key_id"], "eng")
    b = ks.generate_mavlink_key("eng")
    ks.activate(b["key_id"], "eng")                       # rotation retires the old key
    st = {k["key_id"]: k["status"] for k in ks.mavlink_keys()}
    assert st == {a["key_id"]: "retired", b["key_id"]: "active"}
    assert ks.active_mavlink_secret()[0] == b["key_id"]
    ks.revoke(b["key_id"], "eng", "GCS laptop lost")
    assert ks.active_mavlink_secret() == (None, None)
    with pytest.raises(ValueError):
        ks.activate(b["key_id"], "eng")                   # revoked keys stay dead
    out = ks.export_for_provisioning(a["key_id"], "eng")
    assert out.read_text().strip() == secret.hex()
    assert ks.mavlink_keys()[0]["provisioning_exports"][0]["file"] == out.name


def _ev(name, fields, sysid=1, link="udp:a", signed=False, mav=2):
    return TelemetryEvent(idx=1, t=1.0, mono_ns=0, source="LIVE", link=link, sysid=sysid, compid=1, msg_id=0,
                          msg_name=name, sequence=0, fields=fields, mavlink_version=mav, signed=signed)


def _ctx(**kw):
    base = dict(t=1.0, mono=100.0, vehicle_sysid=1, armed=False, airborne=False, mode="STABILIZE")
    base.update(kw)
    return SimpleNamespace(**base, is_trusted_gcs=lambda s: s == 255)


def test_signing_policy_is_per_link_and_facts_stay_separate():
    d = SigningDetector({}, policy={"default": "optional", "links": {"udp:secure": "required"}})
    assert d.process(_ev("HEARTBEAT", {}, link="udp:plain"), _ctx()) == []
    out = d.process(_ev("HEARTBEAT", {}, link="udp:secure"), _ctx(mono=500.0))
    assert out and out[0].title == "Unsigned traffic while signing is expected"
    d.process(_ev("HEARTBEAT", {}, sysid=42, signed=True), _ctx())
    f = d.facts((42, 1))
    assert f["signature_present"] and not f["signature_verified"] and f["source_authorized"] is False


# ------------------------------------------------------------------ GAP-12 evidence
class _Cfg:
    def get(self, key, default=None):
        return default


def _case(tmp_path, ks):
    mgr = SnapshotManager(tmp_path / "cases", _Cfg(), SimpleNamespace(record=lambda *a, **k: None), keystore=ks)
    cid = mgr.trigger(incident=None, reason="t", t=10.0, session={"session_id": "S"}, frozen={}, pre_events=[],
                      pre_results=[], pre_states=[{"t": 9.5}], pre_timeline=[], pre_s=5, post_s=0)
    mgr.finalize_all(wait=True)
    return mgr, cid, tmp_path / "cases" / cid


def test_sealed_case_is_signed_and_tampering_is_caught(tmp_path):
    ks = KeyStore(tmp_path / "keys")
    trusted = ks.trusted_public_keys("evidence")
    mgr, cid, d = _case(tmp_path, ks)
    assert verify_case(d)["status"] == "VALID"               # signature file is outside the hash list
    assert verify_case_signature(d, trusted)["status"] == "VALID"
    m = json.loads((d / "manifest.json").read_text())
    assert m["custody"][0]["event"] == "ACQUIRED" and "clock" in m["acquisition"]

    mgr.add_custody_event(cid, "TRANSFERRED", "inv1", to="lab", note="sealed bag 7")
    sig = verify_case_signature(d, trusted)
    assert sig["status"] == "VALID" and sig["revision"] == 1

    other = KeyStore(tmp_path / "other").trusted_public_keys("evidence")
    assert verify_case_signature(d, other)["status"] == "UNTRUSTED_KEY"

    # an attacker who edits a file AND rewrites manifest.json + hashes.sha256 passes the hash check,
    # but not the signature check
    from app.forensic.hashing import sha256_file, write_hash_file
    (d / "timeline.jsonl").write_bytes(b'{"forged": true}\n')
    m = json.loads((d / "manifest.json").read_text())
    for a in m["artifacts"]:
        if a["filename"] == "timeline.jsonl":
            a["sha256"] = sha256_file(d / "timeline.jsonl")
    (d / "manifest.json").write_bytes(json.dumps(m, indent=2).encode())
    write_hash_file(d)
    assert verify_case(d)["status"] == "VALID"
    assert verify_case_signature(d, trusted)["status"] == "CONTENT_CHANGED"


def test_unsigned_case_reports_unsigned(tmp_path):
    _, _, d = _case(tmp_path, None)
    assert verify_case_signature(d, KeyStore(tmp_path / "keys").trusted_public_keys("evidence"))["status"] == "UNSIGNED"


def test_audit_checkpoint_detects_rewritten_chain(tmp_path):
    eng = D.make_engine("sqlite:///audit.db", tmp_path)
    audit = AuditLog(eng, tmp_path)
    for i in range(5):
        audit.record("ACTION", str(i))
    ks = KeyStore(tmp_path / "keys")
    mirror = tmp_path / "mirror"
    write_checkpoint(audit, ks.signing_key("evidence"), tmp_path, mirror)
    trusted = ks.trusted_public_keys("evidence")
    assert verify_checkpoints(audit, trusted, mirror / CHECKPOINTS)["status"] == "VALID"
    # local admin edits entry 2 and recomputes the whole hash chain: the chain itself verifies again ...
    with eng.begin() as c:
        rows = [dict(r._mapping) for r in c.execute(select(D.audit_log).order_by(D.audit_log.c.seq))]
        prev = "0" * 64
        for r in rows:
            if r["seq"] == 2:
                r["target"] = "forged"
            r["prev_hash"] = prev
            r["hash"] = AuditLog._digest(r)
            prev = r["hash"]
            c.execute(update(D.audit_log).where(D.audit_log.c.seq == r["seq"]).values(target=r["target"], prev_hash=r["prev_hash"], hash=r["hash"]))
    assert audit.verify()["status"] == "VALID"
    # ... but the signed checkpoint copied to the mirror does not match any more
    res = verify_checkpoints(audit, trusted, mirror / CHECKPOINTS)
    assert res["status"] == "PROBLEMS" and res["problems"][0]["problem"] == "AUDIT_CHAIN_REWRITTEN"


# ------------------------------------------------------------------ GAP-11 baselines
def _baseline(tmp_path, **kw):
    ks = KeyStore(tmp_path / "keys")
    store = BaselineStore(tmp_path / "baselines", ks)
    args = dict(vehicle={"sysid": 1}, parameters={"FENCE_ENABLE": 1, "RTL_ALT": 1500},
                mission_items=[(0, 16, 3, 0, 0, 0, 0, 0, 0, 0), (1, 16, 3, 129718453, 775946053, 40, 0, 0, 0, 0)],
                approved_by="eng", reason="release 1.0 configuration", profile_version="1.0")
    args.update(kw)
    res = store.approve(**args)
    return store, ks, res


def test_value_wrong_from_boot_is_caught_and_baseline_never_relearned(tmp_path):
    store, ks, _ = _baseline(tmp_path)
    det = BaselineDetector({}, store.active(), ks.trusted_public_keys("approval"))
    out = det.process(_ev("PARAM_VALUE", {"param_id": "FENCE_ENABLE", "param_value": 0.0}), _ctx())
    assert out and out[0].title.startswith("BASELINE_MISMATCH") and out[0].lineage
    assert det.process(_ev("PARAM_VALUE", {"param_id": "RTL_ALT", "param_value": 1500.0}), _ctx()) == []
    assert det.params["FENCE_ENABLE"] == 1.0                    # detector did not learn the bad value
    det.was_armed = False
    armed = det.process(_ev("HEARTBEAT", {}), _ctx(armed=True))
    assert armed and armed[0].title == "Vehicle armed with baseline mismatches" and armed[0].severity == "HIGH"


def test_mission_compared_against_signed_digest(tmp_path):
    store, ks, _ = _baseline(tmp_path)
    det = BaselineDetector({}, store.active(), ks.trusted_public_keys("approval"))
    ctx = _ctx()
    det.process(_ev("MISSION_COUNT", {"count": 2, "mission_type": 0}), ctx)
    det.process(_ev("MISSION_ITEM_INT", {"seq": 0, "command": 16, "frame": 3, "x": 0, "y": 0, "z": 0, "mission_type": 0}), ctx)
    out = det.process(_ev("MISSION_ITEM_INT", {"seq": 1, "command": 16, "frame": 3, "x": 129718453, "y": 775999999,
                                               "z": 40, "mission_type": 0}), ctx)
    assert out and out[0].title == "BASELINE_MISMATCH: Mission differs from approved baseline"


def test_tampered_or_foreign_manifests_are_rejected(tmp_path):
    store, ks, res = _baseline(tmp_path)
    trusted = ks.trusted_public_keys("approval")
    doc = store.active()
    assert verify_doc(doc, trusted, {"sysid": 1})["status"] == "VALID"
    assert verify_doc(doc, trusted, {"sysid": 7})["status"] == "WRONG_VEHICLE"
    forged = json.loads(json.dumps(doc))
    forged["body"]["parameters"]["FENCE_ENABLE"] = 0.0
    assert verify_doc(forged, trusted)["status"] == "INVALID"
    other = KeyStore(tmp_path / "rogue")
    rogue = {"body": doc["body"], "signature": sign_json(other.signing_key("approval"), doc["body"])}
    assert verify_doc(rogue, trusted)["status"] == "UNTRUSTED_KEY"
    det = BaselineDetector({}, forged, trusted)
    assert det.health_state == "ERROR" and not det.active


def test_approvals_chain_previous_digest_and_require_reason(tmp_path):
    store, ks, first = _baseline(tmp_path)
    _, _, second = _baseline(tmp_path, parameters={"FENCE_ENABLE": 1}, reason="fence-only profile")
    assert second["previous_digest"] == first["digest"]
    assert len(list((tmp_path / "baselines" / "history").glob("*.json"))) == 2
    with pytest.raises(ValueError):
        make_body(vehicle={}, parameters={"A": 1}, mission_items=None, approved_by="x", reason=" ",
                  previous_digest=None, profile_version="1")
