#include "HorizonManager.h"
#include "BarometerCheck.h"
#include "ResidualTests.h"

namespace GNSSInt {

const uint16_t kHorizonDurationS[NUM_HORIZONS] = {2, 5, 15, 30, 60};

// Typical acceleration used to turn timestamp uncertainty into velocity uncertainty.
static const float kTimingAccelMss = 3.0f;

void Horizon::init(uint8_t index, uint16_t duration_s)
{
    _index = index;
    _duration_s = duration_s;
    _armed = false;
    _expired = false;
    _seed = HorizonSeed();
    _S0 = Snapshot();
    _res = HorizonResult();
    _res.duration_s = duration_s;
    _res.reason = HorizonReason::NOT_ARMED;
    _have_bias_meas = false;
}

void Horizon::arm(const HorizonSeed &seed, const Snapshot &S0)
{
    _seed = seed;
    _S0 = S0;
    _armed = true;
    _expired = false;
    _have_bias_meas = false;
    _res = HorizonResult();
    _res.duration_s = _duration_s;
    _res.armed = true;
    _res.reason = HorizonReason::NONE;
}

void Horizon::disarm(HorizonReason why)
{
    _armed = false;
    _expired = false;
    _have_bias_meas = false;
    _res.armed = false;
    _res.valid = false;
    _res.vector_valid = false;
    _res.warn = false;
    _res.alarm = false;
    _res.reason = why;
}

void Horizon::mark_expired()
{
    if (!_armed || _expired) {
        return;
    }
    _expired = true;
    _expiries++;
    _res.expired = true;
    _res.warn = false;
    _res.alarm = false;
    _res.reason = HorizonReason::EXPIRED;   // residuals of the final evaluation are retained
}

bool Horizon::predict(const Snapshot &S, Vec3 &p, Vec3 &v) const
{
    if (!_armed) {
        return false;
    }
    const double T = S.t_s - _S0.t_s;
    const DVec3 v0 = DVec3::from(_seed.v0);
    const DVec3 p0 = DVec3::from(_seed.p0);
    const DMat3 dM1 = S.M1 - _S0.M1;
    const DMat3 dM2 = (S.M2 - _S0.M2) - (_S0.M1 * T);
    const DVec3 dV = S.V - _S0.V;
    const DVec3 dP = (S.P - _S0.P) - (_S0.V * T);
    const DVec3 vb = dM1 * _seed.bias;
    const DVec3 pb = dM2 * _seed.bias;
    v = (v0 + dV - vb).to_float();
    p = (p0 + v0 * T + dP - pb).to_float();
    return true;
}

bool Horizon::evaluate(const HorizonEvalInput &in, const Config &cfg, bool allow_extension)
{
    if (!_armed || _expired || in.S.time_us <= _seed.time_us) {
        return false;
    }
    const float T = float(in.S.time_us - _seed.time_us) * 1.0e-6f;
    const bool extended = T > float(_duration_s);
    if (extended && !allow_extension) {
        return false;
    }
    HorizonResult r = _res;
    r.armed = true;
    r.expired = false;
    r.elapsed_s = T;
    r.valid = false;
    r.vector_valid = false;
    r.warn = false;
    r.alarm = false;
    r.baro_valid = false;
    r.extended = extended;
    r.elevated = false;
    r.reason = HorizonReason::NONE;
    r.yaw_sigma_rad = in.yaw_sigma;

    const Snapshot &S = in.S;
    if (S.attitude_invalid_count != _S0.attitude_invalid_count) {
        r.reason = HorizonReason::ATTITUDE_INVALID;
    } else if (S.overflow_count != _S0.overflow_count) {
        r.reason = HorizonReason::IMU_OVERFLOW;
    } else if (S.gap_count != _S0.gap_count) {
        r.reason = HorizonReason::IMU_GAP;
    } else if (S.clip_count != _S0.clip_count) {
        r.reason = HorizonReason::ACCEL_CLIPPING;
    }
    if (r.reason != HorizonReason::NONE) {
        _have_bias_meas = false;
        _res = r;
        return true;   // evaluated: no test can be supported
    }

    Vec3 p, v;
    predict(S, p, v);
    const double t = S.t_s;
    const double A0 = S.Q0 - _S0.Q0, A1 = S.Q1 - _S0.Q1, A2 = S.Q2 - _S0.Q2;
    const double zero = double(0.0f);
    const float noise_v = float(A0 > zero ? A0 : zero);
    const double np = t * t * A0 - double(2.0f) * t * A1 + A2;
    const float noise_p = float(np > zero ? np : zero);
    const Vec3 dv_ins = v - _seed.v0;
    const Vec3 dp_ins = p - _seed.p0 - _seed.v0 * T;

    const bool heading_ok = in.heading_valid && S.heading_epoch == _S0.heading_epoch;
    const bool epoch_ok = S.heading_epoch == _S0.heading_epoch;
    const InsUncertainty u = ResidualTests::ins_uncertainty(T, _seed.pos_sigma, _seed.pos_sigma_v, _seed.vel_sigma, _seed.vel_sigma_v, _seed.bias_sigma,
                                                            noise_v, noise_p, heading_ok ? in.yaw_sigma : 0.0f,
                                                            dv_ins, dp_ins, cfg);
    const float pos_sigma_ins = sqrtf(u.pos_var.x);
    const float vel_sigma_ins = sqrtf(u.vel_var.x);
    r.position_sigma_m = sqrtf(u.pos_var.x + u.pos_var.y + u.pos_var.z);
    r.velocity_sigma_mps = sqrtf(u.vel_var.x + u.vel_var.y + u.vel_var.z);

    const bool pos_ok = heading_ok && pos_sigma_ins <= cfg.pos_sigma_max_m;
    const bool vel_ok = heading_ok && vel_sigma_ins <= cfg.vel_sigma_max_mps;
    // Heading-free test: velocity uncertainty without the yaw term (a yaw error preserves |dv|).
    const InsUncertainty u_noyaw = ResidualTests::ins_uncertainty(T, _seed.pos_sigma, _seed.pos_sigma_v, _seed.vel_sigma,
                                                                  _seed.vel_sigma_v, _seed.bias_sigma, noise_v, noise_p,
                                                                  0.0f, dv_ins, dp_ins, cfg);
    const float dv_var = in.use_vertical_velocity ? fmaxf(u_noyaw.vel_var.x, u_noyaw.vel_var.z) : u_noyaw.vel_var.x;
    const bool dv_ok = epoch_ok && sqrtf(dv_var) <= cfg.vel_sigma_max_mps;

    if (!epoch_ok) {
        r.reason = HorizonReason::HEADING_EPOCH_CHANGED;
    } else if (!in.heading_valid) {
        r.reason = HorizonReason::HEADING_INVALID;
    } else if (!pos_ok && pos_sigma_ins > cfg.pos_sigma_max_m) {
        r.reason = HorizonReason::POS_SIGMA_LIMIT;
    } else if (!vel_ok && vel_sigma_ins > cfg.vel_sigma_max_mps) {
        r.reason = HorizonReason::VEL_SIGMA_LIMIT;
    }

    const float tp = cfg.timing_sigma_s;
    const Vec3 rp = in.p_gnss - p;
    const Vec3 rv = in.v_gnss - v;
    const float tvar_p = sqf(tp * in.v_gnss.norm());
    const float tvar_v = sqf(tp * kTimingAccelMss);
    const Vec3 var_p = u.pos_var + in.gnss_pos_var + Vec3(tvar_p, tvar_p, tvar_p);
    const Vec3 var_v = u.vel_var + in.gnss_vel_var + Vec3(tvar_v, tvar_v, tvar_v);

    r.position_residual_m = rp.norm();
    r.velocity_residual_mps = in.use_vertical_velocity ? rv.norm() : rv.norm_xy();
    r.position_test_statistic = pos_ok ? ResidualTests::chi2(rp, var_p) : 0.0f;
    r.velocity_test_statistic = vel_ok ? ResidualTests::chi2(rv, var_v) : 0.0f;
    float dres = 0.0f, dstat = 0.0f;
    if (dv_ok) {
        ResidualTests::delta_speed(in.v_gnss - _seed.v0, dv_ins, in.use_vertical_velocity,
                                   dv_var + tvar_v, in.gnss_vel_var.x, dres, dstat);
    }
    r.delta_speed_residual_mps = dres;
    r.delta_speed_test_statistic = dstat;

    if (in.baro_valid && _seed.baro_valid) {
        float br = 0.0f, bs = 0.0f;
        BarometerCheck::evaluate(-(in.p_gnss.z - _seed.p0.z), in.baro_m - _seed.baro0_m, T, in.gnss_pos_var.z, cfg, br, bs);
        r.baro_valid = true;
        r.baro_residual_m = br;
        r.baro_test_statistic = bs;
    } else {
        r.baro_residual_m = 0.0f;
        r.baro_test_statistic = 0.0f;
    }

    r.vector_valid = pos_ok || vel_ok;
    r.valid = r.vector_valid || dv_ok;
    r.warn = (pos_ok && r.position_test_statistic >= cfg.chi2_3_warn) ||
             (vel_ok && r.velocity_test_statistic >= cfg.chi2_3_warn) ||
             (dv_ok && dstat >= cfg.chi2_1_warn);
    r.elevated = (pos_ok && r.position_test_statistic >= cfg.chi2_3_clear) ||
                 (vel_ok && r.velocity_test_statistic >= cfg.chi2_3_clear) ||
                 (dv_ok && dstat >= cfg.chi2_1_clear) ||
                 (r.baro_valid && r.baro_test_statistic >= cfg.chi2_1_clear);
    r.alarm = (pos_ok && r.position_test_statistic >= cfg.chi2_3_alarm) ||
              (vel_ok && r.velocity_test_statistic >= cfg.chi2_3_alarm) ||
              (dv_ok && dstat >= cfg.chi2_1_alarm);

    // Keep the measurement for the bias estimator (variance without the bias term).
    if (vel_ok) {
        const InsUncertainty u0 = ResidualTests::ins_uncertainty(T, _seed.pos_sigma, _seed.pos_sigma_v, _seed.vel_sigma, _seed.vel_sigma_v, 0.0f,
                                                                 noise_v, noise_p, in.yaw_sigma, dv_ins, dp_ins, cfg);
        _bm_dM1 = (S.M1 - _S0.M1).to_float();
        _bm_rv = rv;
        _bm_var = u0.vel_var + in.gnss_vel_var + Vec3(tvar_v, tvar_v, tvar_v);
        _bm_T = T;
        _have_bias_meas = true;
    } else {
        _have_bias_meas = false;
    }
    _res = r;
    return true;
}

bool Horizon::last_bias_measurement(Mat3 &dM1, Vec3 &r_v, Vec3 &var_nonbias, float &T) const
{
    if (!_have_bias_meas) {
        return false;
    }
    dM1 = _bm_dM1;
    r_v = _bm_rv;
    var_nonbias = _bm_var;
    T = _bm_T;
    return true;
}

} // namespace GNSSInt
