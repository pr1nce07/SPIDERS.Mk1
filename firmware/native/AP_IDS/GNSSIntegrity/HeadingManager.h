/*
 * Engine-owned yaw track, independent of GNSS.
 *
 * Gravity constrains roll and pitch, never yaw, and a first acceleration does
 * not identify North. Absolute heading therefore comes only from a qualified
 * non-GNSS HeadingObservation (e.g. a calibrated, disturbance-checked
 * magnetometer). Between observations the yaw is propagated with gyro delta
 * angles and its uncertainty grows with gyro bias and angle random walk.
 *
 * Before the first absolute observation the track is *relative* (starts at 0).
 * Relative yaw is still useful: the heading-free speed-change test is invariant
 * to a constant yaw offset. Re-initialising the absolute reference changes the
 * heading epoch so horizons that span the jump can disable affected tests.
 */
#pragma once

#include "GNSSIntegrityTypes.h"

namespace GNSSInt {

class HeadingManager {
public:
    void reset();
    // Propagate across one IMU increment. Returns the mid-interval yaw to use for the rotation.
    float propagate(const IMUSample &s, const Config &cfg);
    // Fuse a non-GNSS heading observation (gated). Returns true if accepted.
    bool observe(const HeadingObservation &h, const Config &cfg);

    float yaw() const { return _yaw; }
    bool absolute() const { return _absolute; }
    float sigma(uint64_t time_us, const Config &cfg) const;
    bool valid(uint64_t time_us, const Config &cfg) const { return _absolute && sigma(time_us, cfg) <= cfg.yaw_sigma_max_rad; }
    uint32_t epoch() const { return _epoch; }
    bool disturbed() const { return _rejects >= _reject_limit; }
    uint32_t attitude_invalid_count() const { return _attitude_invalid; }

private:
    float _yaw = 0.0f;
    bool _absolute = false;
    float _var_ref = 0.0f;       // yaw variance at _t_ref_us
    uint64_t _t_ref_us = 0;
    uint64_t _last_us = 0;
    uint32_t _epoch = 0;
    uint8_t _rejects = 0;
    uint8_t _reject_limit = 10;
    uint32_t _attitude_invalid = 0;
};

} // namespace GNSSInt
