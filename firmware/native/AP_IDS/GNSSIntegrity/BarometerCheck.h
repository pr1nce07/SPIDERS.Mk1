/*
 * Barometric altitude-change cross-check.
 *
 *   r_h = (h_gnss(t) - h_gnss(t0)) - (h_baro(t) - h_baro(t0))
 *
 * Changes are compared, never absolute altitudes: AP_Baro::get_altitude() is
 * relative to the last calibration and GNSS altitude may be ellipsoidal or AMSL.
 * Baro drift, prop wash and temperature can all cause disagreement, so this
 * test is supporting evidence: on its own it can raise WARNING, never ALARM.
 */
#pragma once

#include "GNSSIntegrityTypes.h"

namespace GNSSInt {

class BarometerCheck {
public:
    static const uint8_t HISTORY = 16;
    static const uint32_t MAX_BRACKET_US = 200000;

    void reset() { *this = BarometerCheck(); }
    void observe(const BaroObservation &b);
    // Baro altitude at a GNSS measurement epoch (interpolated). False if unavailable.
    bool altitude_at(uint64_t time_us, float &alt_m) const;
    // Residual and 1-dof statistic over a horizon of T seconds.
    static void evaluate(float gnss_up_change_m, float baro_change_m, float T_s, float gnss_vert_var,
                         const Config &cfg, float &residual_m, float &statistic);

private:
    BaroObservation _hist[HISTORY];
    uint8_t _head = 0;
    uint8_t _count = 0;
};

} // namespace GNSSInt
