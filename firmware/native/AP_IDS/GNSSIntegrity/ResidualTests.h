/*
 * Residual definitions and uncertainty-aware tests.
 *
 *   r_p     = p_gnss(t_fix) - p_ins(t_fix)                       (NED vector)
 *   r_v     = v_gnss(t_fix) - v_ins(t_fix)                       (NED vector)
 *   r_dv    = |v_gnss(t) - v0| - |v_ins(t) - v0|                 (heading-free)
 *   D2      = sum_i r_i^2 / S_ii
 *
 * S combines propagated initial-state uncertainty, inertial process noise,
 * accelerometer bias and tilt uncertainty, yaw uncertainty, GNSS measurement
 * noise and timestamp uncertainty. In this error model the NED axes are
 * uncorrelated, so the diagonal form is the full Mahalanobis distance.
 *
 * The magnitude test is invariant to a rotation about the vertical, so it
 * survives heading uncertainty, but a direction-only manipulation that keeps
 * speed can evade it. It supplements the vector tests; it never replaces them.
 *
 * The five horizons share IMU and GNSS data: they are NOT independent
 * witnesses. The decision uses the joint maximum across horizons plus
 * persistence; thresholds must be calibrated for the family-wise false-alarm
 * rate on replay data.
 */
#pragma once

#include "GNSSIntegrityTypes.h"

namespace GNSSInt {

struct InsUncertainty {
    Vec3 pos_var;
    Vec3 vel_var;
};

class ResidualTests {
public:
    // Inertial prediction covariance after T seconds.
    //   noise_v = integral q ds,  noise_p = integral q (t-s)^2 ds  (from the integrator moments)
    //   yaw contribution: rotation error of the accumulated inertial change.
    static InsUncertainty ins_uncertainty(float T, float pos0_h, float pos0_v, float vel0_h, float vel0_v, float bias_sigma,
                                          float noise_v, float noise_p, float yaw_sigma,
                                          const Vec3 &dv_ins, const Vec3 &dp_ins, const Config &cfg);

    static float chi2(const Vec3 &r, const Vec3 &var);

    // Heading-free speed-change residual. use_vertical=false compares horizontal speed change only.
    static void delta_speed(const Vec3 &dv_gnss, const Vec3 &dv_ins, bool use_vertical,
                            float var_ins, float var_gnss, float &residual, float &statistic);

    // Stationary-ground constraint: GNSS horizontal speed against zero.
    static bool ground_exceeds(const Vec3 &vel_gnss, const Config &cfg) { return vel_gnss.norm_xy() > cfg.ground_speed_max_mps; }
};

} // namespace GNSSInt
