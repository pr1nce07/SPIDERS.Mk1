#include "BiasEstimator.h"

namespace GNSSInt {

static void set_diag(float P[3][3], float v)
{
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            P[i][j] = (i == j) ? v : 0.0f;
        }
    }
}

static Mat3 to_mat(const float P[3][3])
{
    Mat3 m;
    for (int i = 0; i < 3; i++) { for (int j = 0; j < 3; j++) { m.m[i][j] = P[i][j]; } }
    return m;
}

static void from_mat(const Mat3 &m, float P[3][3])
{
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            P[i][j] = 0.5f * (m.m[i][j] + m.m[j][i]);   // keep symmetric
        }
    }
}

// One linear Kalman update x += K y, P = (I-KH)P. Returns NIS, or -1 if S is singular.
static float kf_update(Vec3 &x, float P[3][3], const Mat3 &H, const Vec3 &y, const Vec3 &R, const Config &cfg)
{
    const Mat3 Pm = to_mat(P);
    const Mat3 Ht = H.transposed();
    Mat3 S = H * Pm * Ht;
    S.m[0][0] += R.x;
    S.m[1][1] += R.y;
    S.m[2][2] += R.z;
    Mat3 Si;
    if (!S.inverse(Si)) {
        return -1.0f;
    }
    const Mat3 K = Pm * Ht * Si;
    Vec3 dx = K * y;
    const float n = dx.norm();
    if (n > cfg.accel_bias_max_step && n > 0.0f) {
        dx = dx * (cfg.accel_bias_max_step / n);   // rate limit: no step absorbs a sudden residual
    }
    x += dx;
    const float cap = 3.0f * cfg.accel_bias_prior_sigma;
    x.x = clampf(x.x, -cap, cap);
    x.y = clampf(x.y, -cap, cap);
    x.z = clampf(x.z, -cap, cap);
    const Mat3 IKH = Mat3::identity() - K * H;
    from_mat(IKH * Pm, P);
    return y.dot(Si * y);
}

void BiasEstimator::reset(const Config &cfg)
{
    _b = Vec3();
    _c = Vec3();
    set_diag(_P, sqf(cfg.accel_bias_prior_sigma));
    set_diag(_Pc, sqf(cfg.accel_bias_prior_sigma));
    _nis_body = 3.0f;
    _nis_ned = 3.0f;
    _yaw_ref_set = false;
    _last_us = 0;
    _high_nis = 0;
    _change_point = false;
    _ned_preferred = false;
    _updates = 0;
}

float BiasEstimator::sigma() const
{
    return sqrtf((_P[0][0] + _P[1][1] + _P[2][2]) / 3.0f);
}

void BiasEstimator::add_process_noise(uint64_t time_us, const Config &cfg)
{
    if (_last_us != 0 && time_us > _last_us) {
        const float dt = float(time_us - _last_us) * 1.0e-6f;
        const float q = sqf(cfg.accel_bias_instability) * dt;
        const float cap = sqf(cfg.accel_bias_prior_sigma);
        for (int i = 0; i < 3; i++) {
            _P[i][i] = fminf(_P[i][i] + q, cap);
            _Pc[i][i] = fminf(_Pc[i][i] + q, cap);
        }
    }
    _last_us = time_us;
}

void BiasEstimator::update(const Mat3 &dM1, const Vec3 &r, const Vec3 &R_var, const Vec3 &b_h, float T, float yaw,
                           uint64_t time_us, const Config &cfg)
{
    if (!r.is_finite() || !(T > 0.0f)) {
        return;
    }
    add_process_noise(time_us, cfg);

    // Body-fixed bias hypothesis.
    Mat3 H;
    for (int i = 0; i < 3; i++) { for (int j = 0; j < 3; j++) { H.m[i][j] = -dM1.m[i][j]; } }
    const Vec3 y = r + dM1 * (_b - b_h);
    const float nis_b = kf_update(_b, _P, H, y, R_var, cfg);

    // NED-fixed offset hypothesis (horizons never apply it, so c_h = 0).
    Mat3 Hc;
    Hc.m[0][0] = Hc.m[1][1] = Hc.m[2][2] = -T;
    const Vec3 yc = r + _c * T;
    const float nis_c = kf_update(_c, _Pc, Hc, yc, R_var, cfg);

    if (nis_b < 0.0f || nis_c < 0.0f) {
        return;
    }
    _updates++;
    _nis_body += 0.3f * (nis_b - _nis_body);
    _nis_ned += 0.3f * (nis_c - _nis_ned);

    // Change point: repeated innovations far outside the model -> re-open the bias covariance.
    if (nis_b > cfg.chi2_3_alarm) {
        if (_high_nis < 255) {
            _high_nis++;
        }
    } else {
        _high_nis = 0;
        if (nis_b < cfg.chi2_3_warn) {
            _change_point = false;
        }
    }
    if (_high_nis >= 2 && !_change_point) {
        _change_point = true;
        const float add = sqf(0.5f * cfg.accel_bias_prior_sigma);
        for (int i = 0; i < 3; i++) {
            _P[i][i] += add;
        }
    }

    if (!_yaw_ref_set) {
        _yaw_ref = yaw;
        _yaw_ref_set = true;
    }
    const bool rotated = fabsf(wrap_pi(yaw - _yaw_ref)) > 0.5f;
    _ned_preferred = rotated && _updates >= 4 && _nis_ned < 0.5f * _nis_body;
}

} // namespace GNSSInt
