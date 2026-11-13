/*
 * Constrained accelerometer-bias estimator with change-point support.
 *
 * Measurement: the final velocity residual of an expired, valid horizon,
 *     r = v_gnss - v_pred ~= -dM1 (b_true - b_horizon) + noise,  dM1 = integral of R dt
 * which observes the body-frame bias through the rotation history. Only
 * directions excited by the rotation history are learned (the Kalman gain is
 * ~0 along unobservable directions); updates are rate limited and the estimate
 * is capped at 3 sigma of the prior.
 *
 * GNSS can corrupt a bias estimate (Sensors 2018, 18(5):1433), so the caller
 * updates ONLY while the trust gate is open. Each horizon freezes the bias at
 * its arm time, so an update never changes an active horizon's prediction.
 *
 * Change-point / frame hypothesis (supporting evidence, not classification):
 * a parallel filter fits a NED-fixed acceleration offset to the same residuals.
 * A body-fixed bias rotates in NED when heading changes; a navigation-frame
 * error does not. When the NED model explains the data consistently better
 * after significant heading change, FLAG_NED_FIXED_PREFERRED is reported.
 */
#pragma once

#include "GNSSIntegrityTypes.h"

namespace GNSSInt {

class BiasEstimator {
public:
    void reset(const Config &cfg);
    // H = dM1 (rotation integral over the horizon), r = velocity residual (NED),
    // R = residual variance from all non-bias terms, b_h = bias the horizon used,
    // T = horizon length, yaw = heading at the update.
    void update(const Mat3 &dM1, const Vec3 &r, const Vec3 &R_var, const Vec3 &b_h, float T, float yaw,
                uint64_t time_us, const Config &cfg);

    const Vec3 &bias() const { return _b; }
    float sigma() const;   // RMS 1-sigma over axes
    bool valid(const Config &cfg) const { return sigma() <= cfg.accel_bias_valid_sigma; }
    bool change_point() const { return _change_point; }
    bool ned_fixed_preferred() const { return _ned_preferred; }
    uint32_t updates() const { return _updates; }

private:
    void add_process_noise(uint64_t time_us, const Config &cfg);

    Vec3 _b;
    float _P[3][3];
    Vec3 _c;                 // NED-fixed offset hypothesis
    float _Pc[3][3];
    float _nis_body = 3.0f;  // EWMA of normalized innovation squared (expected 3)
    float _nis_ned = 3.0f;
    float _yaw_ref = 0.0f;
    bool _yaw_ref_set = false;
    uint64_t _last_us = 0;
    uint8_t _high_nis = 0;
    bool _change_point = false;
    bool _ned_preferred = false;
    uint32_t _updates = 0;
};

} // namespace GNSSInt
