/*
 * Five independent horizon records (2 / 5 / 15 / 30 / 60 s).
 *
 * Each record stores its own start epoch, trusted p0/v0, frozen bias and its
 * uncertainty, and an integrator snapshot. Rules:
 *   - an active horizon is NEVER re-seeded from a new GNSS fix;
 *   - at expiry the final result is retained and the horizon expires exactly once;
 *   - re-arming requires a newly qualified trusted state (trust gate);
 *   - IMU gaps, queue overflow, accel clipping, attitude loss, a heading-epoch
 *     change or uncertainty beyond the configured bounds invalidate the
 *     affected tests. Invalid/degraded is never reported as spoofing.
 */
#pragma once

#include "GNSSIntegrityTypes.h"
#include "InertialPropagator.h"

namespace GNSSInt {

struct HorizonSeed {
    uint64_t time_us;
    Vec3 p0;
    Vec3 v0;
    float pos_sigma;            // horizontal
    float vel_sigma;
    float pos_sigma_v;          // vertical
    float vel_sigma_v;
    Vec3 bias;
    float bias_sigma;
    bool baro_valid;
    float baro0_m;
    SeedProvenance provenance;
};

struct HorizonEvalInput {
    Snapshot S;                 // integrator state at the fix epoch
    Vec3 p_gnss, v_gnss;        // NED, fix epoch
    Vec3 gnss_pos_var, gnss_vel_var;
    bool use_vertical_velocity;
    float yaw_sigma;
    bool heading_valid;
    bool baro_valid;
    float baro_m;
};

class Horizon {
public:
    void init(uint8_t index, uint16_t duration_s);
    void arm(const HorizonSeed &seed, const Snapshot &S0);
    void disarm(HorizonReason why);
    // Prediction from the snapshot (IMU-only). False if not armed.
    bool predict(const Snapshot &S, Vec3 &p, Vec3 &v) const;
    // Evaluate one fix. Returns false (and leaves the last result) if the fix is past expiry.
    // allow_extension: evaluate past the nominal duration (suspicion active, no fresh reference possible).
    bool evaluate(const HorizonEvalInput &in, const Config &cfg, bool allow_extension);
    void mark_expired();

    bool armed() const { return _armed; }
    bool expired() const { return _expired; }
    bool due(uint64_t time_us) const { return _armed && !_expired && time_us > _seed.time_us + uint64_t(_duration_s) * 1000000u; }
    uint64_t start_us() const { return _seed.time_us; }
    uint16_t duration_s() const { return _duration_s; }
    const HorizonSeed &seed() const { return _seed; }
    const Snapshot &snapshot() const { return _S0; }
    const HorizonResult &result() const { return _res; }
    // Inputs for the bias estimator from the last valid evaluation.
    bool last_bias_measurement(Mat3 &dM1, Vec3 &r_v, Vec3 &var_nonbias, float &T) const;
    uint32_t expiries() const { return _expiries; }

private:
    uint8_t _index = 0;
    uint16_t _duration_s = 0;
    bool _armed = false;
    bool _expired = false;
    HorizonSeed _seed;
    Snapshot _S0;
    HorizonResult _res;
    uint32_t _expiries = 0;
    // last valid vector evaluation, kept for the bias estimator
    bool _have_bias_meas = false;
    Mat3 _bm_dM1;
    Vec3 _bm_rv;
    Vec3 _bm_var;
    float _bm_T = 0.0f;
};

} // namespace GNSSInt
