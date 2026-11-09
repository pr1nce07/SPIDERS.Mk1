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


def test_dataflash_pids_record_becomes_fc_result_and_dedupes_with_live_line():
    det = PushpakFCDetector({})
    df = {"TimeUS": 1, "Boot": 77, "Seq": 5, "Det": 0, "St": 2, "Ev": 24, "Conf": 0.91, "Met": 12.5, "Inst": 0}
    out = det.process(_ev("DF_PIDS", df, "DATAFLASH"), _ctx())
    assert out and out[0].source == "FC" and out[0].inputs["detector"] == "GPS" and out[0].state == "CONFIRMED"
    again = det.process(_ev("STATUSTEXT", {"text": "PIDS|2|FC|GPS|2|0.910|24|12.50|0|77|5"}), _ctx())
    assert again == [] and det.delivery.native_duplicates == 1


def test_dataflash_loss_counters_and_faults_are_visible():
    det = PushpakFCDetector({})
    out = det.process(_ev("DF_PIDH", {"TimeUS": 1, "Boot": 77, "Health": 255, "Scr": 0, "QOcc": 8, "QDrop": 3, "LogDrop": 0, "Age": 40},
                          "DATAFLASH"), _ctx())
    assert out and "ring dropped 3" in out[0].title
    out = det.process(_ev("DF_PIDF", {"TimeUS": 2, "Boot": 77, "Code": 4, "Sub": 1, "Rec": 1}, "DATAFLASH"), _ctx())
    assert out and out[0].kind == "health"


def test_sync_with_native_boot_id_and_drop_counter():
    t = EventDeliveryTracker()
    t.on_sync(parse_statustext("PUSHPAK IDS: SYNC up=100 seq=4 ev=2 boot=11 drop=0"))
    r = t.on_sync(parse_statustext("PUSHPAK IDS: SYNC up=110 seq=9 ev=2 boot=11 drop=2"))
    assert r["new_ring_drops"] == 2 and not r["reboot"]
    r = t.on_sync(parse_statustext("PUSHPAK IDS: SYNC up=500 seq=0 ev=0 boot=12 drop=0"))
    assert r["reboot"]          # boot ID changed even though uptime did not go backwards


def test_dataflash_pidw_maps_to_param_set_with_real_sender(tmp_path):
    log = tmp_path / "pidw.log"
    log.write_text("FMT, 128, 89, FMT, BBnNZ, Type,Length,Name,Format,Columns\n"
                   "FMT, 200, 40, PIDW, QIBBBBNfBB, TimeUS,Boot,Sys,Comp,Chan,Sig,Name,Val,Typ,Res\n"
                   "PIDW, 1000000, 7, 42, 190, 1, 0, FENCE_ENABLE, 0, 9, 2\n")
    items = [i for i in open_source(log) if i.data.get("msg_name") == "PARAM_SET"]
    assert len(items) == 1
    d = items[0].data
    assert d["sysid"] == 42 and d["compid"] == 190
    assert d["fields"]["param_id"] == "FENCE_ENABLE" and d["fields"]["onboard_result"] == "REJECTED"
