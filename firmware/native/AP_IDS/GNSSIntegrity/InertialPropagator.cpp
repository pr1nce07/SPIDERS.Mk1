#include "InertialPropagator.h"
#include "InertialSampleBuffer.h"

namespace GNSSInt {

void InertialPropagator::reset()
{
    *this = InertialPropagator();
}

void InertialPropagator::step(const IMUSample &s, uint8_t sample_flags, float yaw_mid, uint32_t heading_epoch,
                              float q_accel, const Config &cfg)
{
    if (!_started) {
        _started = true;
        _t0_us = s.time_us;
        _cur.time_us = s.time_us;
        _cur.t_s = 0.0;
        _last_hist_us = s.time_us;
        push_history();
        return;  // first sample only establishes the time base
    }
    if (sample_flags & SAMPLE_GAP_BEFORE) {
        _cur.gap_count++;
    }
    if (sample_flags & SAMPLE_OVERFLOW_BEFORE) {
        _cur.overflow_count++;
    }
    if (s.accel_clipping) {
        _cur.clip_count++;
    }
    _cur.heading_epoch = heading_epoch;

    const bool usable = s.delta_velocity_valid && s.accel_healthy && s.roll_pitch_valid &&
                        s.delta_velocity_mps.is_finite() && isfinite(s.roll_rad) && isfinite(s.pitch_rad) &&
                        s.delta_velocity_dt_s > 0.0f;
    const double t_new = double(s.time_us - _t0_us) / double(1000000u);
    if (!usable) {
        // Motion during this interval is unknown: count it as a gap, never integrate a guess.
        _cur.gap_count++;
        if (!s.roll_pitch_valid) {
            _cur.attitude_invalid_count++;
        }
        _cur.time_us = s.time_us;
        _cur.t_s = t_new;
        return;
    }

    const float dt = s.delta_velocity_dt_s;
    const double ddt = double(dt);
    const Mat3 R = Mat3::from_euler(s.roll_rad, s.pitch_rad, yaw_mid);
    Vec3 dv_n = R * s.delta_velocity_mps;
    if (cfg.delta_velocity_is_specific_force) {
        dv_n.z += kGravityMss * dt;
    }
    const DVec3 dvn = DVec3::from(dv_n);

    const double half_dt = double(0.5f) * ddt;
    _cur.P += _cur.V * ddt + dvn * half_dt;
    _cur.V += dvn;
    _cur.M2.add_scaled(_cur.M1, ddt);
    _cur.M2.add_scaled(R, half_dt * ddt);
    _cur.M1.add_scaled(R, ddt);

    const double q = double(q_accel);
    const double tm = t_new - half_dt;
    _cur.Q0 += q * ddt;
    _cur.Q1 += q * tm * ddt;
    _cur.Q2 += q * tm * tm * ddt;

    _cur.time_us = s.time_us;
    _cur.t_s = t_new;

    // Gravity-convention monitor: when the gyro is still, |specific force| must be ~g.
    const float rate = (s.delta_angle_valid && s.delta_angle_dt_s > 0.0f) ? s.delta_angle_rad.norm() / s.delta_angle_dt_s : 1.0f;
    const float sf = s.delta_velocity_mps.norm() / dt;
    if (rate < 0.05f) {
        _still_s += dt;
        const float a = clampf(dt / 0.5f, 0.0f, 1.0f);
        _sf_mean += a * (sf - _sf_mean);
        if (_still_s > 2.0f) {
            const bool looks_specific = fabsf(_sf_mean - kGravityMss) < 2.0f;
            const bool looks_kinematic = _sf_mean < 2.0f;
            _gravity_fault = cfg.delta_velocity_is_specific_force ? looks_kinematic : looks_specific;
        }
    } else {
        _still_s = 0.0f;
        _sf_mean = sf;
    }

    if (s.time_us - _last_hist_us >= HISTORY_SPACING_US) {
        push_history();
        _last_hist_us = s.time_us;
    }
}

void InertialPropagator::push_history()
{
    _hist[_hist_head] = _cur;
    _hist_head = uint8_t((_hist_head + 1) % HISTORY);
    if (_hist_count < HISTORY) {
        _hist_count++;
    }
}

uint64_t InertialPropagator::oldest_time_us() const
{
    if (_hist_count == 0) {
        return _cur.time_us;
    }
    const uint8_t oldest = uint8_t((_hist_head + HISTORY - _hist_count) % HISTORY);
    return _hist[oldest].time_us;
}

static double lerp(double a, double b, double f) { return a + (b - a) * f; }

static void lerp_snapshot(const Snapshot &a, const Snapshot &b, double f, uint64_t time_us, Snapshot &out)
{
    out.time_us = time_us;
    out.t_s = lerp(a.t_s, b.t_s, f);
    out.V = DVec3(lerp(a.V.x, b.V.x, f), lerp(a.V.y, b.V.y, f), lerp(a.V.z, b.V.z, f));
    out.P = DVec3(lerp(a.P.x, b.P.x, f), lerp(a.P.y, b.P.y, f), lerp(a.P.z, b.P.z, f));
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            out.M1.m[i][j] = lerp(a.M1.m[i][j], b.M1.m[i][j], f);
            out.M2.m[i][j] = lerp(a.M2.m[i][j], b.M2.m[i][j], f);
        }
    }
    out.Q0 = lerp(a.Q0, b.Q0, f);
    out.Q1 = lerp(a.Q1, b.Q1, f);
    out.Q2 = lerp(a.Q2, b.Q2, f);
    // Event counters: take the later sample (conservative: an event inside the
    // bracket counts as having happened before the interpolated time).
    out.gap_count = b.gap_count;
    out.overflow_count = b.overflow_count;
    out.clip_count = b.clip_count;
    out.attitude_invalid_count = b.attitude_invalid_count;
    out.heading_epoch = b.heading_epoch;
}

bool InertialPropagator::at(uint64_t time_us, uint32_t max_extrapolation_us, Snapshot &out) const
{
    if (!_started || _hist_count == 0) {
        return false;
    }
    if (time_us >= _cur.time_us) {
        if (time_us - _cur.time_us > max_extrapolation_us) {
            return false;  // IMU has not reached the fix epoch yet: excessive extrapolation
        }
        out = _cur;  // within tolerance: use the newest state (error bounded by timing sigma)
        out.time_us = time_us;
        return true;
    }
    if (time_us < oldest_time_us()) {
        return false;
    }
    // Walk from newest to oldest; the current state acts as the newest entry.
    const Snapshot *later = &_cur;
    for (uint8_t k = 0; k < _hist_count; k++) {
        const uint8_t idx = uint8_t((_hist_head + HISTORY - 1 - k) % HISTORY);
        const Snapshot *earlier = &_hist[idx];
        if (earlier->time_us <= time_us) {
            const uint64_t span = later->time_us - earlier->time_us;
            const double f = span > 0 ? double(time_us - earlier->time_us) / double(span) : double(0.0f);
            lerp_snapshot(*earlier, *later, f, time_us, out);
            return true;
        }
        later = earlier;
    }
    return false;
}

} // namespace GNSSInt
