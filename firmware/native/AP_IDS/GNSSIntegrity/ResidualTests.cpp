#include "ResidualTests.h"

namespace GNSSInt {

InsUncertainty ResidualTests::ins_uncertainty(float T, float pos0_h, float pos0_v, float vel0_h, float vel0_v,
                                              float bias_sigma, float noise_v, float noise_p, float yaw_sigma,
                                              const Vec3 &dv_ins, const Vec3 &dp_ins, const Config &cfg)
{
    // Constant-acceleration error from residual bias and FC tilt error (g * tilt, horizontal only).
    const float bias_var = sqf(bias_sigma);
    const float acc_h = bias_var + sqf(kGravityMss * cfg.tilt_sigma_rad);
    const float T2 = T * T;
    const float vh = sqf(vel0_h) + acc_h * T2 + noise_v;
    const float vz = sqf(vel0_v) + bias_var * T2 + noise_v;
    const float ph = sqf(pos0_h) + sqf(vel0_h) * T2 + acc_h * T2 * T2 * 0.25f + noise_p;
    const float pz = sqf(pos0_v) + sqf(vel0_v) * T2 + bias_var * T2 * T2 * 0.25f + noise_p;
    // A yaw error rotates the horizontal part of the inertially accumulated change.
    const float yv = sqf(yaw_sigma * dv_ins.norm_xy());
    const float yp = sqf(yaw_sigma * dp_ins.norm_xy());
    InsUncertainty u;
    u.vel_var = Vec3(vh + yv, vh + yv, vz);
    u.pos_var = Vec3(ph + yp, ph + yp, pz);
    return u;
}

float ResidualTests::chi2(const Vec3 &r, const Vec3 &var)
{
    float s = 0.0f;
    s += var.x > 0.0f ? r.x * r.x / var.x : 0.0f;
    s += var.y > 0.0f ? r.y * r.y / var.y : 0.0f;
    s += var.z > 0.0f ? r.z * r.z / var.z : 0.0f;
    return s;
}

void ResidualTests::delta_speed(const Vec3 &dv_gnss, const Vec3 &dv_ins, bool use_vertical,
                                float var_ins, float var_gnss, float &residual, float &statistic)
{
    const float g = use_vertical ? dv_gnss.norm() : dv_gnss.norm_xy();
    const float i = use_vertical ? dv_ins.norm() : dv_ins.norm_xy();
    residual = g - i;
    // Both GNSS endpoints carry measurement noise.
    const float var = var_ins + 2.0f * var_gnss;
    statistic = var > 0.0f ? residual * residual / var : 0.0f;
}

} // namespace GNSSInt
