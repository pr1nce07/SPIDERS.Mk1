#include "BarometerCheck.h"

namespace GNSSInt {

void BarometerCheck::observe(const BaroObservation &b)
{
    if (!b.healthy || !isfinite(b.altitude_m)) {
        return;
    }
    if (_count > 0) {
        const uint8_t newest = uint8_t((_head + HISTORY - 1) % HISTORY);
        if (b.time_us <= _hist[newest].time_us) {
            return;  // duplicate or out of order
        }
    }
    _hist[_head] = b;
    _head = uint8_t((_head + 1) % HISTORY);
    if (_count < HISTORY) {
        _count++;
    }
}

bool BarometerCheck::altitude_at(uint64_t time_us, float &alt_m) const
{
    if (_count == 0) {
        return false;
    }
    const BaroObservation *later = nullptr;
    for (uint8_t k = 0; k < _count; k++) {
        const BaroObservation &e = _hist[(_head + HISTORY - 1 - k) % HISTORY];
        if (e.time_us <= time_us) {
            if (later == nullptr) {
                // Fix is newer than the newest baro sample: accept only a small hold.
                if (time_us - e.time_us > MAX_BRACKET_US / 2) {
                    return false;
                }
                alt_m = e.altitude_m;
                return true;
            }
            const uint64_t span = later->time_us - e.time_us;
            if (span > MAX_BRACKET_US) {
                return false;
            }
            const float f = span > 0 ? float(time_us - e.time_us) / float(span) : 0.0f;
            alt_m = e.altitude_m + (later->altitude_m - e.altitude_m) * f;
            return true;
        }
        later = &e;
    }
    return false;
}

void BarometerCheck::evaluate(float gnss_up_change_m, float baro_change_m, float T_s, float gnss_vert_var,
                              const Config &cfg, float &residual_m, float &statistic)
{
    residual_m = gnss_up_change_m - baro_change_m;
    const float var = 2.0f * gnss_vert_var + 2.0f * sqf(cfg.baro_sigma_m) + sqf(cfg.baro_drift_mps * T_s);
    statistic = var > 0.0f ? residual_m * residual_m / var : 0.0f;
}

} // namespace GNSSInt
