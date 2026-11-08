import random

from calibration.sweep import PerturbedSimulator, append_checkpoint, make_jobs, sample_attack, sample_env
from pymavlink.dialects.v20 import ardupilotmega as mav


def test_extended_environment_factors_are_disabled_by_default():
    env = sample_env(random.Random(9))

    assert env["gust_mps"] == 0
    assert env["gps_fix_drop_p"] == 0
    assert env["gps2_offset_m"] == 0
    assert env["aggressive_accel_ms2"] == 0
    assert env["aggressive_attitude_rate_rads"] == 0
    assert env["rtk_transitions"] is False
    assert env["companion_link"] is False
    assert env["gcs_reconnect"] is False
    assert env["radio_reboot"] is False
    assert env["low_battery_sag_v"] == 0
    assert env["pack_swap"] is False


def test_extended_environment_profile_enables_reproducible_field_disturbances():
    env = sample_env(random.Random(9), harsh=0.75, extended=True)

    assert env["gust_mps"] > 0
    assert env["gps_fix_drop_p"] > 0
    assert env["gps2_offset_m"] > 0
    assert env["low_battery_sag_v"] > 0
    if env["aggressive_maneuvers"]:
        assert 2.0 <= env["aggressive_accel_ms2"] <= 4.0
        assert 1.0 <= env["aggressive_attitude_rate_rads"] <= 2.0
    else:
        assert env["aggressive_accel_ms2"] == 0
        assert env["aggressive_attitude_rate_rads"] == 0
    assert env == sample_env(random.Random(9), harsh=0.75, extended=True)

    samples = [sample_env(random.Random(seed), harsh=0.75, extended=True) for seed in range(100)]
    for factor in ("rtk_transitions", "companion_link", "gcs_reconnect", "radio_reboot", "pack_swap"):
        assert any(item[factor] for item in samples)


def test_nominal_attack_sampling_keeps_existing_test_strength_ranges():
    attack = sample_attack(random.Random(18))

    assert 0.2 <= attack["drift_rate"] <= 2.0
    assert 20 <= attack["jump_m"] <= 300
    assert 9 <= attack["mismatch_vel"] <= 25
    assert "command_burst_count" not in attack


def test_attack_boundary_sampling_covers_command_and_slow_parameter_cases():
    attack = sample_attack(random.Random(18), boundary=True)

    assert 2 <= attack["command_burst_count"] <= 15
    assert 1 <= attack["param_interval_s"] <= 60
    assert 0.01 <= attack["unknown_hz"] <= 1.0


def test_jobs_can_sample_twenty_to_forty_minute_flights():
    jobs = make_jobs(8, 0, 27, None, scenarios=[], duration_range=(1200, 2400), extended=True)

    assert len(jobs) == 8
    assert all(1200 <= job["duration"] <= 2400 for job in jobs)


def test_gps2_receiver_is_emitted_only_when_a_second_receiver_is_configured():
    base = sample_env(random.Random(27))
    dual = dict(base, gps2_offset_m=1.5, gps2_noise_m=0.5, link_loss=0.0, burst_per_min=0.0)

    def message_ids(env):
        frames = PerturbedSimulator("NORMAL_FLIGHT", env, duration_s=1.0).frames()
        return {frame.data[7] | frame.data[8] << 8 | frame.data[9] << 16 for frame in frames if frame.data[0] == 0xFD}

    assert mav.MAVLink_gps2_raw_message.id not in message_ids(base)
    frames = list(PerturbedSimulator("NORMAL_FLIGHT", dual, duration_s=1.0).frames())
    assert mav.MAVLink_gps2_raw_message.id in {frame.data[7] | frame.data[8] << 8 | frame.data[9] << 16
                                               for frame in frames if frame.data[0] == 0xFD}
    vehicle_seq = [frame.data[4] for frame in frames if frame.data[0] == 0xFD and frame.data[5:7] == b"\x01\x01"]
    assert all((b - a) % 256 == 1 for a, b in zip(vehicle_seq, vehicle_seq[1:]))


def test_requested_stream_rate_change_changes_vehicle_gps_output_rate():
    env = dict(sample_env(random.Random(27)), rate_change_scale=2.0, link_loss=0.0, burst_per_min=0.0)
    frames = list(PerturbedSimulator("NORMAL_FLIGHT", env, duration_s=20.0).frames())
    gps_raw = mav.MAVLink_gps_raw_int_message.id
    before = sum(1 for frame in frames if frame.t < 1_790_000_007 and (frame.data[7] | frame.data[8] << 8 | frame.data[9] << 16) == gps_raw)
    after = sum(1 for frame in frames if frame.t >= 1_790_000_007 and (frame.data[7] | frame.data[8] << 8 | frame.data[9] << 16) == gps_raw)

    assert after > before * 2
    vehicle_seq = [frame.data[4] for frame in frames if frame.data[0] == 0xFD and frame.data[5:7] == b"\x01\x01"]
    assert all((b - a) % 256 == 1 for a, b in zip(vehicle_seq, vehicle_seq[1:]))


def test_requested_half_stream_rate_halves_vehicle_gps_output_rate():
    env = dict(sample_env(random.Random(27)), rate_change_scale=0.5, link_loss=0.0, burst_per_min=0.0)
    sim = PerturbedSimulator("NORMAL_FLIGHT", env, duration_s=40.0)
    frames = list(sim.frames())
    gps_raw = mav.MAVLink_gps_raw_int_message.id
    cut = sim.t0 + sim.rate_change_at
    before = sum(1 for frame in frames if frame.t < cut and frame.data[0] == 0xFD
                 and frame.data[5:7] == b"\x01\x01"
                 and (frame.data[7] | frame.data[8] << 8 | frame.data[9] << 16) == gps_raw)
    after = sum(1 for frame in frames if frame.t >= cut and frame.data[0] == 0xFD
                and frame.data[5:7] == b"\x01\x01"
                and (frame.data[7] | frame.data[8] << 8 | frame.data[9] << 16) == gps_raw)

    assert after / (40.0 - sim.rate_change_at) < before / sim.rate_change_at * 0.75


def test_hover_loiter_segment_reduces_horizontal_speed():
    env = dict(sample_env(random.Random(27)), hover_loiter=True)
    sim = PerturbedSimulator("NORMAL_FLIGHT", env, duration_s=100.0)
    sim.t = 32.0
    sim._physics()

    assert (sim.vn ** 2 + sim.ve ** 2) ** 0.5 < 2.0


def test_low_rate_unknown_source_attack_is_suppressed_to_its_sampled_rate():
    env = sample_env(random.Random(27))
    sim = PerturbedSimulator("UNKNOWN_SOURCE", env, attack={"unknown_hz": 0.1},
                             duration_s=100.0, inject_at=20.0)
    frames = list(sim.frames())
    count = sum(1 for frame in frames if frame.data[0] == 0xFD and frame.data[5] == 42
                and (frame.data[7] | frame.data[8] << 8 | frame.data[9] << 16) == mav.MAVLink_heartbeat_message.id)

    assert 7 <= count <= 9


def test_command_count_sample_does_not_change_unrelated_gps_jump_magnitude():
    env = sample_env(random.Random(27))
    sim = PerturbedSimulator("GPS_JUMP", env,
                             attack={"jump_m": 42.0, "command_burst_count": 15},
                             duration_s=10.0, inject_at=1.0)
    sim.t = 1.0
    sim._physics()

    assert sim.gps_off_n == 42.0


def test_checkpoint_appends_each_completed_job_as_jsonl(tmp_path):
    path = tmp_path / "runs.partial.jsonl"
    append_checkpoint(path, 4, {"scenario": "NORMAL_FLIGHT", "alerts": []})

    assert path.read_text(encoding="utf-8") == '{"index": 4, "result": {"scenario": "NORMAL_FLIGHT", "alerts": []}}\n'
