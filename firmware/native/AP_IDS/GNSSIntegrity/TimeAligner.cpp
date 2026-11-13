#include "TimeAligner.h"

namespace GNSSInt {

AlignResult TimeAligner::align(const GNSSObservation &obs, uint64_t newest_imu_us, uint64_t oldest_us, const Config &cfg)
{
    AlignResult r;
    r.status = AlignStatus::OK;
    r.measurement_time_us = 0;
    r.applied_lag_ms = int16_t(cfg.lag_compensation_ms);
    const uint32_t age = obs.message_time_ms - obs.fix_time_ms;   // wrap-safe
    r.fix_age_ms = age > 65535u ? 65535u : uint16_t(age);

    if (newest_imu_us == 0) {
        r.status = AlignStatus::NO_IMU;
        return r;
    }
    if (_have_fix_ms && obs.fix_time_ms == _last_fix_ms) {
        r.status = AlignStatus::DUPLICATE;
        return r;
    }
    // Unwrap the 32-bit millisecond fix time against the 64-bit IMU clock (same HAL time base).
    const uint32_t now_ms = uint32_t(newest_imu_us / 1000u);
    const int32_t behind_ms = int32_t(now_ms - obs.fix_time_ms);
    const int64_t fix_us = int64_t(newest_imu_us) - int64_t(behind_ms) * 1000 - int64_t(newest_imu_us % 1000u);
    const int64_t meas_us = fix_us - int64_t(cfg.lag_compensation_ms) * 1000;
    if (meas_us <= 0) {
        r.status = AlignStatus::OUTSIDE_HISTORY;
        return r;
    }
    r.measurement_time_us = uint64_t(meas_us);
    if (_have_last && r.measurement_time_us <= _last_meas_us) {
        r.status = AlignStatus::OUT_OF_ORDER;
        return r;
    }
    if (r.measurement_time_us < oldest_us) {
        r.status = AlignStatus::OUTSIDE_HISTORY;
        return r;
    }
    if (r.measurement_time_us > newest_imu_us + cfg.max_extrapolation_us) {
        r.status = AlignStatus::EXCESSIVE_EXTRAPOLATION;
        return r;
    }
    _have_fix_ms = true;
    _last_fix_ms = obs.fix_time_ms;
    return r;
}

} // namespace GNSSInt
