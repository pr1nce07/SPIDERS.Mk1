/*
 * Shared, GNSS-free strapdown integrator with a short timestamped history.
 *
 * One cumulative integrator serves all five horizons. For every IMU increment:
 *
 *   R      = R(roll_fc, pitch_fc, yaw_engine)     body -> NED
 *   dv_n   = R * dv_b + g_ned * dt                (dv_b is specific force * dt)
 *   P     += V * dt + 0.5 * dv_n * dt
 *   V     += dv_n
 *   M2    += M1 * dt + 0.5 * R * dt^2
 *   M1    += R * dt                               (rotation integrals)
 *   Q0/1/2 += q dt, q t dt, q t^2 dt              (process-noise moments)
 *
 * A horizon armed at t0 with seed (p0, v0) and a FROZEN body-frame accel bias b
 * predicts, for T = t - t0:
 *
 *   v(t) = v0 + [V(t)-V0] - [M1(t)-M1_0] b
 *   p(t) = p0 + v0 T + [P(t)-P0-V0 T] - [M2(t)-M2_0-M1_0 T] b
 *
 * so the prediction depends only on the seed and on IMU/attitude/heading data:
 * GNSS observations after t0 cannot change it (tested invariant). Each horizon
 * keeps its own snapshot, bias and uncertainty.
 *
 * Doubles hold the cumulative sums so a multi-hour flight does not lose
 * precision. The history ring lets GNSS fixes be compared at their measurement
 * epoch, never at the predictor's current time.
 *
 * FRD/specific-force semantics of the delta velocity, coning/sculling
 * compensation and the gravity convention MUST be verified per IMU backend
 * (see Config::delta_velocity_is_specific_force and FLAG_GRAVITY_FAULT).
 */
#pragma once

#include "GNSSIntegrityTypes.h"

namespace GNSSInt {

struct Snapshot {
    uint64_t time_us = 0;
    double t_s = 0.0;             // seconds since integrator start
    DVec3 V, P;
    DMat3 M1, M2;
    double Q0 = 0.0, Q1 = 0.0, Q2 = 0.0;
    uint32_t gap_count = 0;
    uint32_t overflow_count = 0;
    uint32_t clip_count = 0;
    uint32_t attitude_invalid_count = 0;
    uint32_t heading_epoch = 0;
};

class InertialPropagator {
public:
    static const uint8_t HISTORY = 32;        // 0.8 s at 25 ms spacing
    static const uint32_t HISTORY_SPACING_US = 25000;

    void reset();
    void step(const IMUSample &s, uint8_t sample_flags, float yaw_mid, uint32_t heading_epoch,
              float q_accel, const Config &cfg);

    bool started() const { return _started; }
    const Snapshot &current() const { return _cur; }
    uint64_t oldest_time_us() const;
    uint64_t newest_time_us() const { return _cur.time_us; }
    // State at an arbitrary time inside the retained history (linear interpolation).
    bool at(uint64_t time_us, uint32_t max_extrapolation_us, Snapshot &out) const;

    bool gravity_fault() const { return _gravity_fault; }
    bool still() const { return _still_s >= 1.0f; }

private:
    void push_history();

    bool _started = false;
    uint64_t _t0_us = 0;
    Snapshot _cur;
    Snapshot _hist[HISTORY];
    uint8_t _hist_head = 0;   // next write
    uint8_t _hist_count = 0;
    uint64_t _last_hist_us = 0;
    // Gravity-convention monitor (stationary, gyro still)
    float _still_s = 0.0f;
    float _sf_mean = 0.0f;
    bool _gravity_fault = false;
};

} // namespace GNSSInt
