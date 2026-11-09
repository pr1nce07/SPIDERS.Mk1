"""GAP-07 / V-013 / V-014: bridge re-announcement, loss visibility and duplicate handling."""
import pytest

from app.mavlink.pushpak import EventDeliveryTracker, PIDS_STATE_MAP, parse_statustext


def Script(name):
    """Lua bridge tests need lupa (Lua 5.4); the tracker tests below do not."""
    pytest.importorskip("lupa.lua54")
    from tests.test_lua_scripts import Script as _Script
    return _Script(name)


def _kinds(s):
    return [r["kind"] for r in s.parsed()]


def test_bridge_announces_version_state_map_and_sync():
    s = Script("ids_gcs_bridge.lua")
    s.run(25, lambda W: setattr(W, "gcs_last", W.now))
    recs = s.parsed()
    bridge = next(r for r in recs if r["kind"] == "BRIDGE")
    assert bridge["protocol_version"] == 2 and bridge["binding"] == ["report_confirmed", "event_sequence"]
    assert next(r for r in recs if r["kind"] == "STATEMAP")["state_map"] == PIDS_STATE_MAP
    assert _kinds(s).count("SYNC") >= 2


def test_gcs_connecting_late_still_learns_bridge_version():
    s = Script("ids_gcs_bridge.lua")
    s.W.gcs_last = 0
    s.run(20)                                   # no GCS yet: only the boot announcement
    s.lua.execute("W.texts = {}")
    s.run(3, lambda W: setattr(W, "gcs_last", W.now))  # GCS appears
    assert {"BRIDGE", "STATEMAP", "SYNC"} <= set(_kinds(s))


def test_sync_counts_fc_events():
    s = Script("ids_gcs_bridge.lua")
    s.run(2, lambda W: setattr(W, "gcs_last", W.now))
    s.W.seq = 3
    s.run(2, lambda W: setattr(W, "gcs_last", W.now))
    s.W.seq = 4
    s.run(12, lambda W: setattr(W, "gcs_last", W.now))
    syncs = [r for r in s.parsed() if r["kind"] == "SYNC"]
    assert syncs[-1]["events_sent"] == 2 and syncs[-1]["sequence"] == 4


def _sync(up, seq, ev):
    return parse_statustext(f"PUSHPAK IDS: SYNC up={up} seq={seq} ev={ev}")


def _fc(seq, delta):
    return parse_statustext(f"PUSHPAK IDS: FC_EVENT seq={seq} delta={delta}")


def test_tracker_separates_pre_connection_history_from_loss():
    t = EventDeliveryTracker()
    first = t.on_sync(_sync(100, 7, 5))         # 5 events happened before we connected
    assert first["pre_connection_events"] == 5 and first["new_missing"] == 0
    t.on_fc_event(_fc(8, 1))
    assert t.on_sync(_sync(110, 8, 6))["new_missing"] == 0
    # two FC_EVENT lines lost on the link
    assert t.on_sync(_sync(120, 10, 8))["new_missing"] == 2
    assert t.on_sync(_sync(130, 10, 8))["new_missing"] == 0   # reported once
    assert t.status()["events_missed_total"] == 2


def test_tracker_ignores_duplicates_and_flags_sequence_jumps():
    t = EventDeliveryTracker()
    t.on_sync(_sync(10, 0, 0))
    assert t.on_fc_event(_fc(1, 1)) == {"duplicate": False, "gap": False}
    assert t.on_fc_event(_fc(1, 1))["duplicate"] is True
    assert t.on_fc_event(_fc(4, 1))["gap"] is True              # seq 2..3 lines never arrived
    assert t.status()["duplicates_ignored"] == 1


def test_tracker_detects_reboot_and_restarts_numbering():
    t = EventDeliveryTracker()
    t.on_sync(_sync(500, 9, 3))
    t.on_fc_event(_fc(10, 1))
    r = t.on_sync(_sync(4, 0, 0))
    assert r["reboot"] and t.boot_epoch == 1
    assert t.on_fc_event(_fc(10, 1))["duplicate"] is False     # same seq, new boot: not a duplicate


def test_old_bridge_line_still_parses():
    r = parse_statustext("PUSHPAK IDS: BRIDGE binding=report_confirmed,event_sequence")
    assert r["kind"] == "BRIDGE" and r["protocol_version"] == 1
