#include "HeadingManager.h"

namespace GNSSInt {

void HeadingManager::reset()
{
    *this = HeadingManager();
}

float HeadingManager::propagate(const IMUSample &s, const Config &cfg)
{
    _reject_limit = cfg.heading_reject_limit;
    _last_us = s.time_us;
    if (!s.delta_angle_valid || !s.gyro_healthy || !s.roll_pitch_valid) {
        _attitude_invalid++;
        return _yaw;
    }
    const float cr = cosf(s.roll_rad), sr = sinf(s.roll_rad), cp = cosf(s.pitch_rad);
    if (fabsf(cp) < 0.2f) {
        // Near gimbal lock the Euler yaw-rate relation is ill conditioned.
        _attitude_invalid++;
        return _yaw;
    }
    // Euler yaw rate from body rates: psi_dot = (q sin(phi) + r cos(phi)) / cos(theta)
    const float dyaw = (s.delta_angle_rad.y * sr + s.delta_angle_rad.z * cr) / cp;
    const float mid = wrap_pi(_yaw + 0.5f * dyaw);
    _yaw = wrap_pi(_yaw + dyaw);
    return mid;
}

float HeadingManager::sigma(uint64_t time_us, const Config &cfg) const
{
    if (!_absolute) {
        return kPi;
    }
    const float T = time_us > _t_ref_us ? float(time_us - _t_ref_us) * 1.0e-6f : 0.0f;
    const float var = _var_ref + sqf(cfg.gyro_bias_sigma_rps * T) + sqf(cfg.gyro_arw) * T;
    return sqrtf(var);
}

bool HeadingManager::observe(const HeadingObservation &h, const Config &cfg)
{
    _reject_limit = cfg.heading_reject_limit;
    if (!h.valid || !isfinite(h.yaw_rad) || !(h.sigma_rad > 0.0f)) {
        return false;
    }
    const uint64_t t = h.time_us > _last_us ? h.time_us : _last_us;
    if (!_absolute) {
        // First absolute reference: the relative track jumps to it.
        _yaw = wrap_pi(h.yaw_rad);
        _var_ref = sqf(h.sigma_rad);
        _t_ref_us = t;
        _absolute = true;
        _epoch++;
        _rejects = 0;
        return true;
    }
    const float s_now = sigma(t, cfg);
    const float var_now = s_now * s_now;
    const float innov = wrap_pi(h.yaw_rad - _yaw);
    const float S = var_now + sqf(h.sigma_rad);
    if (sqf(innov) > sqf(cfg.heading_gate_sigma) * S) {
        // Magnetic disturbance or a bad reference: keep gyro propagation, let uncertainty grow.
        if (_rejects < 255) {
            _rejects++;
        }
        return false;
    }
    const float K = var_now / S;
    _yaw = wrap_pi(_yaw + K * innov);
    _var_ref = (1.0f - K) * var_now;
    _t_ref_us = t;
    _rejects = 0;
    return true;
}

} // namespace GNSSInt
