"""GAP-15 / V-023: canonical observation contract; unavailable fields are explicit, never zero."""
from app.models.events import TelemetryEvent
from app.models.observation import UNAVAILABLE, from_mavlink_event


def _ev(**kw):
    base = dict(idx=7, t=1.5, mono_ns=1500, source="LIVE", link="udp:1", sysid=1, compid=1, msg_id=23, msg_name="PARAM_SET",
                sequence=4, fields={"param_id": "FENCE_ENABLE", "param_value": 0.0}, mavlink_version=2, signed=False)
    base.update(kw)
    return TelemetryEvent(**base)


def test_param_set_maps_to_canonical_type_with_explicit_unavailable_fields():
    o = from_mavlink_event(_ev()).to_dict()
    assert o["event_type"] == "PARAM_WRITE_REQUEST" and o["source_platform"] == "ArduPilot"
    assert o["boot_id"] == UNAVAILABLE and o["authentication_status"] == "NONE"
    assert o["raw_reference"]["index"] == 7 and o["normalized_fields"]["param_id"] == "FENCE_ENABLE"


def test_authentication_states_are_distinct():
    assert from_mavlink_event(_ev(signed=True, signature_status="UNVERIFIED")).authentication_status == "PRESENT_UNVERIFIED"
    assert from_mavlink_event(_ev(signed=True, signature_status="VALID")).authentication_status == "VERIFIED"
    assert from_mavlink_event(_ev(msg_name="BAD_DATA", signature_status="INVALID", parse_error="Invalid signature")).to_dict()["data_quality"] == "PARSE_ERROR"


def test_unknown_messages_are_marked_unmapped_not_guessed():
    assert from_mavlink_event(_ev(msg_name="VIBRATION")).event_type == "UNMAPPED:VIBRATION"
    assert from_mavlink_event(_ev(sysid=None)).vehicle_id == UNAVAILABLE
