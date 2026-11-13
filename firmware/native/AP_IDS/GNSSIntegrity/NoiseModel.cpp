#include "NoiseModel.h"

namespace GNSSInt {

float NoiseModel::accel_noise_rate(const IMUSample &s, const Config &cfg)
{
    const float vib = s.vibration.is_finite() ? s.vibration.norm() : cfg.vibration_max_mss;
    const float k = cfg.vibration_ref_mss > 0.0f ? vib / cfg.vibration_ref_mss : 0.0f;
    return sqf(cfg.accel_vrw) * (1.0f + k * k);
}

static float clamp_sigma(float model, float reported, float cap_factor)
{
    if (!(reported > 0.0f) || !isfinite(reported)) {
        return model;
    }
    return clampf(reported, model, model * cap_factor);
}

GNSSNoise NoiseModel::gnss(const GNSSObservation &obs, const Config &cfg)
{
    GNSSNoise n;
    const float ph = clamp_sigma(cfg.gnss_pos_sigma_h_m, obs.h_acc_m, cfg.gnss_sigma_cap_factor);
    const float pv = clamp_sigma(cfg.gnss_pos_sigma_v_m, obs.v_acc_m, cfg.gnss_sigma_cap_factor);
    const float vh = clamp_sigma(cfg.gnss_vel_sigma_h_mps, obs.s_acc_mps, cfg.gnss_sigma_cap_factor);
    float vv = clamp_sigma(cfg.gnss_vel_sigma_v_mps, obs.s_acc_mps, cfg.gnss_sigma_cap_factor);
    if (!obs.have_vertical_velocity) {
        vv = 1.0e3f;  // receiver gives no vertical velocity: that axis carries no information
    }
    n.pos_var = Vec3(ph * ph, ph * ph, pv * pv);
    n.vel_var = Vec3(vh * vh, vh * vh, vv * vv);
    return n;
}

} // namespace GNSSInt
