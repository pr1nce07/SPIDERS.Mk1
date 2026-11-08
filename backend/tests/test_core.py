"""Detector / rule / forensic tests (spec §76, §102). Run: PYTHONPATH=. pytest -q"""
import json
import pytest

from app.config import Config
from app.core.errors import ErrorRegistry
from app.core.pipeline import Pipeline
from app.forensic.hashing import verify_case, write_hash_file
from app.ids.builtin_rules import BUILTIN_RULES
from app.ids.correlation import IncidentIdAllocator
from app.ids.rules import compile_rule, validate_rule
from app.mavlink.decoder import Decoder, iter_tlog, tlog_record
from app.mavlink.pushpak import StatusTextAssembler, decode_evidence, parse_statustext
from app.mavlink.registry import DialectRegistry
from app.sources.files import SourceItem
from app.sources.simulation import FlightSimulator

CFG, REG = Config.load(), DialectRegistry()


def run(scenario, rules=True, fault=None, duration=120):
    err = ErrorRegistry()
    p = Pipeline(session_id="T", kind="test", source_desc=scenario, config=CFG, registry=REG, errors=err, capabilities={},
                 allocator=IncidentIdAllocator())
    if rules:
        p.set_rules([compile_rule(dict(r, version=1), REG, list(p.engine.detectors)) for r in BUILTIN_RULES])
    if fault:
        p.engine.fault_injection.add(fault)
    for fr in FlightSimulator(scenario, duration_s=duration).frames():
        p.handle_item(SourceItem("frame", fr.t, fr.data, fr.link, "SIMULATION"))
    return p, err


def dets(p):
    return {a["detector"] for a in p.alerts.values() if a["state"] in ("ANOMALOUS", "SUSPECTED", "CONFIRMED")}


def test_known_good_flight_has_no_alerts():
    p, _ = run("NORMAL_FLIGHT")
    assert not dets(p) and not p.correlator.incidents


@pytest.mark.parametrize("scenario,detector", [
    ("GPS_JUMP", "GPS_INTEGRITY"), ("GPS_IMU_MISMATCH", "GPS_INTEGRITY"), ("HEARTBEAT_LOSS", "HEARTBEAT"),
    ("MAVLINK_SEQUENCE_GAP", "MAVLINK_SEQUENCE"), ("COMMAND_BURST", "COMMAND"), ("PARAMETER_CHANGE", "PARAMETER"),
    ("MISSION_CHANGE", "MISSION"), ("RC_DEGRADATION", "RC_LINK"), ("PUSHPAK_CONFIRMATION", "PUSHPAK_FC")])
def test_known_anomaly_flights(scenario, detector):
    p, _ = run(scenario)
    assert detector in dets(p)


def test_new_source_alone_is_not_escalated():
    p, _ = run("UNKNOWN_SOURCE")
    assert not p.correlator.incidents
    assert any(a["title"] == "NEW SOURCE OBSERVED" and a["state"] == "OBSERVED" for a in p.alerts.values())


def test_multi_signal_confirmed_incident():
    p, _ = run("MULTI_SIGNAL_INCIDENT")
    assert any(i["state"] == "CONFIRMED" and i["domain"] == "MAVLINK_SECURITY" for i in p.correlator.incidents.values())


def test_detector_exception_is_isolated():
    p, err = run("GPS_JUMP", fault="GPS_INTEGRITY")
    assert p.engine.get("GPS_INTEGRITY").health_state == "ERROR"
    assert "HEARTBEAT" in {d.detector_id for d in p.engine.detectors.values() if d.events > 0}
    assert p.idx > 5000 and err.list()


def test_malformed_bytes_preserved():
    dec = Decoder(REG, "l", "TEST")
    items = dec.feed(b"\xfd\x09\x00\x00\x01\x01\x01\x00\x00\x00" + b"\x00" * 9 + b"\xde\xad")  # bad CRC
    evs = [dec.to_event(i, n, 0.0, 0) for n, i in enumerate(items)]
    assert evs and all(e.raw for e in evs if e.msg_name == "BAD_DATA")


def test_tlog_roundtrip_and_resync():
    frames = [fr.data for fr in FlightSimulator("NORMAL_FLIGHT", duration_s=3).frames()][:50]
    data = b"".join(tlog_record(1.79e9 + i, f) for i, f in enumerate(frames))
    corrupt = data[:100] + b"\x00GARBAGE" + data[100:]
    skipped = []
    out = list(iter_tlog(corrupt, on_skip=lambda pos, b: skipped.append(b)))
    assert len(out) >= 49 and skipped


def test_pushpak_formats_from_source():
    r = parse_statustext("PIDS|1|FC|GPS|2|0.820|32777|0.000|0")
    assert r["detector"] == "GPS" and r["state"] == "CONFIRMED" and "PERSISTENCE" in r["evidence"]["bits"] and r["evidence"]["undocumented"] == ["BIT15"]
    g = parse_statustext("PUSHPAK IDS: GPS CONFIRMED conf=0.86 pos=14.2m vel=3.1m/s robust=0.91 cusum=0.77")
    assert g["confidence"] == 0.86 and g["metrics"]["position_residual_m"] == 14.2
    c = parse_statustext("PUSHPAK IDS: COMMAND_INJECTION_CANDIDATE conf=0.81 evidence=0x0280")
    assert c["detector"] == "COMMAND" and set(c["evidence"]["bits"]) == {"SOURCE", "CONTEXT"}
    e = parse_statustext("Lua: @ROMFS/scripts/gps_confirm.lua:104: attempt to call a nil value (method 'gps_confidence')")
    assert e["kind"] == "LUA_RUNTIME" and e["missing_method"] == "gps_confidence"
    assert parse_statustext("PreArm: GPS not healthy") is None
    assert decode_evidence(0)["bits"] == []


def test_chunked_statustext():
    a = StatusTextAssembler()
    t1, _ = a.push(1, 1, {"text": "x" * 50, "id": 7, "chunk_seq": 0}, 0.0)
    t2, _ = a.push(1, 1, {"text": "yz", "id": 7, "chunk_seq": 1}, 0.1)
    assert t1 is None and t2 == "x" * 50 + "yz"


def test_rule_validation_rejects_bad_rules():
    r = json.loads(json.dumps(BUILTIN_RULES[0]))
    r["graph"]["nodes"] += [{"id": "x", "type": "telemetry_field", "params": {"msg": "NOPE", "field": "a"}},
                            {"id": "y", "type": "threshold", "params": {"op": "~", "value": float("nan")}},
                            {"id": "z", "type": "persistence", "params": {"duration_s": -1}}]
    r["graph"]["edges"] += [{"source": "y", "target": "z", "targetHandle": "in"}, {"source": "z", "target": "y", "targetHandle": "in"}]
    v = validate_rule(r, REG, ["GPS_INTEGRITY"])
    msgs = " ".join(e["message"] for e in v["errors"])
    assert not v["valid"] and "unknown MAVLink message" in msgs and "circular" in msgs and "negative" in msgs


def test_builtin_rule_expectations():
    for rule in BUILTIN_RULES:
        for t in rule["tests"]:
            err = ErrorRegistry()
            p = Pipeline(session_id="R", kind="t", source_desc="", config=CFG, registry=REG, errors=err, capabilities={},
                         allocator=IncidentIdAllocator(), correlate=False)
            rt = compile_rule(dict(rule, version=1), REG, list(p.engine.detectors))
            p.set_rules([rt])
            for fr in FlightSimulator(t["dataset"].split(":")[1], duration_s=120).frames():
                p.handle_item(SourceItem("frame", fr.t, fr.data, fr.link, "SIMULATION"))
            assert (rt.triggers > 0) == (t["expect"] == "trigger"), (rule["rule_id"], t)


def test_hash_verification(tmp_path):
    (tmp_path / "a.txt").write_text("evidence")
    write_hash_file(tmp_path)
    assert verify_case(tmp_path)["status"] == "VALID"
    (tmp_path / "a.txt").write_text("tampered")
    assert verify_case(tmp_path)["status"] == "MODIFIED"
    (tmp_path / "a.txt").unlink()
    assert verify_case(tmp_path)["status"] == "MISSING"
    (tmp_path / "hashes.sha256").write_text("junk")
    assert verify_case(tmp_path)["status"] == "UNVERIFIABLE"
