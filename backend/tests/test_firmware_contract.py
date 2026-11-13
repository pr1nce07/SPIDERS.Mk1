"""GCS side of the firmware contract in firmware/FIRMWARE_WORK_REQUIRED.md (FW-03, FW-04, FW-06).

The firmware does not emit these yet; these tests pin the wire formats so the
firmware team has a fixed target and the GCS is ready the day it lands.
"""
from types import SimpleNamespace

from app.ids.pushpak_fc import PushpakFCDetector
from app.mavlink.pushpak import EventDeliveryTracker, parse_statustext
from app.models.events import TelemetryEvent
from app.sources.files import open_source


def _ctx():
    return SimpleNamespace(t=10.0, mono=10.0, vehicle_sysid=1, airborne=True, armed=True, fc_states={}, lua_states={})


def _ev(name, fields, source="LIVE"):
    return TelemetryEvent(idx=1, t=10.0, mono_ns=0, source=source, link="l", sysid=1, compid=1, msg_id=None,
                          msg_name=name, sequence=0, fields=fields)


def test_pids_v2_statustext_carries_boot_and_sequence():
    r = parse_statustext("PIDS|2|FC|GPS|2|0.910|24|12.50|0|3735928559|17")
    assert r["boot_id"] == 3735928559 and r["seq"] == 17 and r["state"] == "CONFIRMED"
    assert parse_statustext("PIDS|1|FC|GPS|2|0.910|24|12.50|0")["boot_id"] is None   # v1 still parses


def test_dataflash_idse_record_becomes_fc_result_and_dedupes_with_live_line():
    det = PushpakFCDetector({})
    df = {"TimeUS": 1, "Boot": 77, "Seq": 5, "Det": 0, "St": 2, "Ev": 24, "Conf": 0.91, "Met": 12.5, "Inst": 0}
    out = det.process(_ev("DF_IDSE", df, "DATAFLASH"), _ctx())
    assert out and out[0].source == "FC" and out[0].inputs["detector"] == "GPS" and out[0].state == "CONFIRMED"
    again = det.process(_ev("STATUSTEXT", {"text": "PIDS|2|FC|GPS|2|0.910|24|12.50|0|77|5"}), _ctx())
    assert again == [] and det.delivery.native_duplicates == 1


def test_dataflash_loss_counters_and_faults_are_visible():
    det = PushpakFCDetector({})
    out = det.process(_ev("DF_IDSH", {"TimeUS": 1, "Boot": 77, "Health": 255, "Scr": 0, "QOcc": 8, "QDrop": 3, "LogDrop": 0, "Age": 40},
                          "DATAFLASH"), _ctx())
    assert out and "ring dropped 3" in out[0].title
    out = det.process(_ev("DF_IDSF", {"TimeUS": 2, "Boot": 77, "Code": 4, "Sub": 1, "Rec": 1}, "DATAFLASH"), _ctx())
    assert out and out[0].kind == "health"


def test_sync_with_native_boot_id_and_drop_counter():
    t = EventDeliveryTracker()
    t.on_sync(parse_statustext("PUSHPAK IDS: SYNC up=100 seq=4 ev=2 boot=11 drop=0"))
    r = t.on_sync(parse_statustext("PUSHPAK IDS: SYNC up=110 seq=9 ev=2 boot=11 drop=2"))
    assert r["new_ring_drops"] == 2 and not r["reboot"]
    r = t.on_sync(parse_statustext("PUSHPAK IDS: SYNC up=500 seq=0 ev=0 boot=12 drop=0"))
    assert r["reboot"]          # boot ID changed even though uptime did not go backwards


def test_dataflash_idsw_maps_to_param_set_with_real_sender(tmp_path):
    log = tmp_path / "idsw.log"
    log.write_text("FMT, 128, 89, FMT, BBnNZ, Type,Length,Name,Format,Columns\n"
                   "FMT, 200, 40, IDSW, QIBBBBNfBB, TimeUS,Boot,Sys,Comp,Chan,Sig,Name,Val,Typ,Res\n"
                   "IDSW, 1000000, 7, 42, 190, 1, 0, FENCE_ENABLE, 0, 9, 2\n")
    items = [i for i in open_source(log) if i.data.get("msg_name") == "PARAM_SET"]
    assert len(items) == 1
    d = items[0].data
    assert d["sysid"] == 42 and d["compid"] == 190
    assert d["fields"]["param_id"] == "FENCE_ENABLE" and d["fields"]["onboard_result"] == "REJECTED"


# ---------------------------------------------------------------- FW-13 GNSSIntegrity (IDSG / IDSR)
import re as _re
from pathlib import Path as _Path

from app.ids.lineage import evidence_lines, lineage_for
from app.mavlink.pushpak import EVIDENCE_BITS, IDSG_FORMAT, IDSG_LABELS, IDSR_FORMAT, IDSR_LABELS, decode_evidence
from app.models.events import DetectorResult

_ROOT = _Path(__file__).resolve().parents[2]
_LOG_H = _ROOT / "firmware" / "native" / "AP_IDS" / "GNSSIntegrity" / "GNSSIntegrityLog.h"


def _define(name):
    m = _re.search(rf'#define {name}\s+"([^"]+)"', _LOG_H.read_text(encoding="utf-8"))
    assert m, name
    return m.group(1)


def test_idsg_idsr_contract_matches_firmware_header():
    assert _define("GNSSINT_IDSG_FORMAT") == IDSG_FORMAT and _define("GNSSINT_IDSG_LABELS") == IDSG_LABELS
    assert _define("GNSSINT_IDSR_FORMAT") == IDSR_FORMAT and _define("GNSSINT_IDSR_LABELS") == IDSR_LABELS
    for fmt, labels in ((IDSG_FORMAT, IDSG_LABELS), (IDSR_FORMAT, IDSR_LABELS)):
        assert len(fmt) <= 16 and len(labels) < 64          # ArduPilot FMT record limits
        assert len(labels.split(",")) == len(fmt)
    hdr = _LOG_H.read_text(encoding="utf-8")
    assert int(_re.search(r"kEvidenceInsPrediction = (\d+)", hdr).group(1)) in EVIDENCE_BITS
    assert int(_re.search(r"kEvidencePhysConstraint = (\d+)", hdr).group(1)) in EVIDENCE_BITS


def test_physics_evidence_bits_do_not_collide_with_lua_bits():
    lua = (_ROOT / "firmware" / "scripts" / "modules" / "ids_common.lua").read_text(encoding="utf-8")
    lua_bits = {int(v) for v in _re.findall(r"M\.EVID_[A-Z_]+ = (\d+)", lua)}
    assert lua_bits and {4096, 8192}.isdisjoint(lua_bits)
    assert decode_evidence(4096 | 8192 | 1)["bits"] == ["PERSISTENCE", "INS_PREDICTION", "PHYS_CONSTRAINT"]


def _idsg_log(tmp_path, rows):
    log = tmp_path / "idsg.log"
    log.write_text("FMT, 128, 89, FMT, BBnNZ, Type,Length,Name,Format,Columns\n"
                   f"FMT, 210, 66, IDSR, {IDSR_FORMAT}, {IDSR_LABELS}\n"
                   f"FMT, 211, 52, IDSG, {IDSG_FORMAT}, {IDSG_LABELS}\n" + "".join(r + "\n" for r in rows))
    return log


def _idsr(seq, h, st, rsn=0, tv=0.4):
    return (f"IDSR, {1000000 + seq * 1000}, 9, {seq}, {h}, {[2, 5, 15, 30, 60][h]}, {st}, {rsn}, "
            f"1.5, 0.8, 0.3, 0.2, {tv}, 0.1, 3.2, 0.5, 0.03")


def _idsg(seq, st, wm=0, xm=0, fl=0x23, conf=0.0):
    return f"IDSG, {1000000 + seq * 1000}, 9, {seq}, 1, {st}, 31, 31, {wm}, {xm}, {fl}, 100, 0, {conf}, 0.1, 0.2, 0.03"


def _feed_log(det, log):
    out = []
    for item in open_source(log):
        d = item.data
        if d.get("msg_name") in ("DF_IDSG", "DF_IDSR"):
            out += det.process(_ev(d["msg_name"], d["fields"], "DATAFLASH"), _ctx())
    return out


def test_idsg_records_decode_and_drive_fc_gps_results(tmp_path):
    rows = [_idsr(1, h, 3) for h in range(5)] + [_idsg(1, 4)]                         # VALID
    rows += [_idsr(2, h, 3 | (8 if h == 0 else 0), tv=24.4 if h == 0 else 0.4) for h in range(5)]
    rows += [_idsg(2, 6, wm=1, conf=0.48)]                                              # WARNING (2 s horizon)
    rows += [_idsg(2, 6, wm=1, conf=0.48)]                                              # replayed duplicate Seq
    rows += [_idsr(3, h, 3 | 16) for h in range(5)]
    rows += [_idsg(3, 7, wm=3, xm=3, fl=0x23 | (1 << 21), conf=0.71)]                   # ALARM (latched)
    det = PushpakFCDetector({})
    out = _feed_log(det, _idsg_log(tmp_path, rows))
    assert [r.state for r in out] == ["ANOMALOUS", "SUSPECTED"]                         # never auto-CONFIRMED
    warn, alarm = out
    assert warn.source == "FC" and warn.domain == "GPS_INTEGRITY" and warn.inputs["detector"] == "GPS"
    assert warn.inputs["warn_horizons_s"] == [2] and warn.confidence == 0.48
    assert set(warn.lineage) == {"GNSS", "IMU"}                                          # GNSS vs IMU-only prediction
    assert "ALARM_LATCHED" in alarm.inputs["flags"] and alarm.inputs["alarm_horizons_s"] == [2, 5]
    assert any("2 s horizon" in e for e in alarm.explanation["evidence"])
    st = det.gnss_integrity_status()
    assert st["state"] == "ALARM" and len(st["horizons"]) == 5 and st["horizons"][0]["alarm"]


def test_idsg_degraded_is_health_not_an_attack(tmp_path):
    rows = [_idsg(1, 4), _idsr(2, 4, 1, rsn=2), _idsg(2, 5, fl=0x40)]                  # IMU gap -> DEGRADED
    out = _feed_log(PushpakFCDetector({}), _idsg_log(tmp_path, rows))
    assert len(out) == 1 and out[0].kind == "health" and out[0].state == "OBSERVED"
    assert "IMU_GAP" in out[0].explanation["why"]


def test_idsg_baro_only_warning_uses_baro_lineage(tmp_path):
    rows = [_idsg(1, 4), _idsg(2, 6, fl=0x23 | (1 << 14), conf=0.3)]
    out = _feed_log(PushpakFCDetector({}), _idsg_log(tmp_path, rows))
    assert len(out) == 1 and set(out[0].lineage) == {"GNSS", "BARO"}


def test_physics_evidence_merges_with_gps_and_imu_lines():
    """The INS/GNSS residual shares GNSS with GPS_INTEGRITY and IMU with IMU_CONSISTENCY: one line, not three."""
    def r(det, method=None, inputs=None, domain="GPS_INTEGRITY"):
        return DetectorResult(detector=det, state="SUSPECTED", title=det, t=1.0, domain=domain, method=method, inputs=inputs or {})

    fc_gps_plain = r("PUSHPAK_FC", inputs={"detector": "GPS", "evidence": decode_evidence(1 | 8)})
    fc_gps_ins = r("PUSHPAK_FC", inputs={"detector": "GPS", "evidence": decode_evidence(1 | 4096)})
    idsg = r("PUSHPAK_FC", method="IMU-propagated GNSS integrity (IDSG)", inputs={"detector": "GPS"})
    assert set(lineage_for(fc_gps_plain)) == {"GNSS", "EKF"}          # family default unchanged
    assert set(lineage_for(fc_gps_ins)) == {"GNSS", "EKF", "IMU"}
    assert set(lineage_for(idsg)) == {"GNSS", "IMU"}
    lines = evidence_lines([lineage_for(r("GPS_INTEGRITY")), lineage_for(r("IMU_CONSISTENCY", domain="SENSOR")),
                            lineage_for(idsg)])
    assert len(lines) == 1
