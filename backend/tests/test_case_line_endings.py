"""Case files must have the same bytes on every OS (no Windows newline translation)."""
from types import SimpleNamespace

from app.forensic.hashing import verify_case
from app.forensic.snapshot import SnapshotManager


class _Cfg:
    def get(self, key, default=None):
        return default


class _Errs:
    def record(self, *a, **k):
        raise AssertionError(f"unexpected error: {a}")


def _event(idx, msg, fields):
    return SimpleNamespace(idx=idx, t=1000.0 + idx, raw=b"", parse_error=None, msg_name=msg, fields=fields,
                           timestamp_utc=f"2026-01-01T00:00:{idx:02d}Z", sysid=1, compid=1,
                           to_dict=lambda include_raw=False, i=idx, m=msg: {"idx": i, "msg": m})


def test_case_files_have_exact_line_endings(tmp_path):
    mgr = SnapshotManager(tmp_path / "cases", _Cfg(), _Errs())
    events = [_event(i, "GPS_RAW_INT", {"lat": 129718453, "lon": 775946053, "alt": 939972, "vel": 791,
                                        "fix_type": 3, "satellites_visible": 14, "eph": 80}) for i in range(3)]
    events += [_event(3 + i, "ATTITUDE", {"roll": 0.1, "pitch": 0.2, "yaw": 0.3}) for i in range(3)]
    case_id = mgr.trigger(incident=None, reason="test", t=1003.0, session={"session_id": "T"}, frozen={},
                          pre_events=events, pre_results=[], pre_states=[{"t": 1001.0, "x": 1}], pre_timeline=[],
                          pre_s=10, post_s=0)
    mgr.finalize_all(wait=True)
    d = tmp_path / "cases" / case_id

    for name in ("gps_track.csv", "attitude.csv", "battery.csv"):
        data = (d / name).read_bytes()
        assert b"\r\r" not in data, name
        assert data.endswith(b"\r\n") and data.count(b"\r\n") == data.count(b"\n"), name  # RFC 4180 CRLF rows
    assert (d / "gps_track.csv").read_bytes().count(b"\r\n") == 4  # header + 3 GPS rows

    for name in ("telemetry.jsonl", "mavlink_decoded.jsonl", "manifest.json", "incident.json", "README.txt", "hashes.sha256"):
        assert b"\r" not in (d / name).read_bytes(), name

    assert verify_case(d)["status"] == "VALID"
    mgr.add_artifact(case_id, "screenshots/s.png", b"\x89PNG", "test")
    assert b"\r" not in (d / "manifest.json").read_bytes()
    assert b"\r" not in (d / "hashes.sha256").read_bytes()
    assert verify_case(d)["status"] == "VALID"
