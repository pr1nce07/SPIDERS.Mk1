/*
 * GNSS fix-time alignment.
 *
 * AP_GPS::last_fix_time_ms() is used as the measurement epoch and
 * last_message_time_ms() only to recognise new data. A latency correction
 * (Config::lag_compensation_ms) is applied ONCE, and only if the configured
 * AP_GPS / backend lag is not already reflected in the fix time; the default is
 * 0. The aligned epoch is then matched against the inertial history: a fix that
 * is out of order, older than the retained history, or newer than the IMU data
 * by more than the extrapolation limit is rejected, never compared with the
 * predictor's current state.
 */
#pragma once

#include "GNSSIntegrityTypes.h"

namespace GNSSInt {

enum class AlignStatus : uint8_t {
    OK,
    DUPLICATE,          // same fix already evaluated (not an error)
    OUT_OF_ORDER,
    OUTSIDE_HISTORY,
    EXCESSIVE_EXTRAPOLATION,
    NO_IMU,
};

struct AlignResult {
    AlignStatus status;
    uint64_t measurement_time_us;
    uint16_t fix_age_ms;
    int16_t applied_lag_ms;
};

class TimeAligner {
public:
    void reset() { *this = TimeAligner(); }
    // newest_imu_us: time of the newest integrated IMU increment; oldest_us: oldest retained history.
    AlignResult align(const GNSSObservation &obs, uint64_t newest_imu_us, uint64_t oldest_us, const Config &cfg);
    void accept(const AlignResult &r) { _last_meas_us = r.measurement_time_us; _have_last = true; }

private:
    bool _have_last = false;
    uint64_t _last_meas_us = 0;
    bool _have_fix_ms = false;
    uint32_t _last_fix_ms = 0;
};

} // namespace GNSSInt
