/*
 * Noise models.
 *
 * Inertial process noise is conditioned on the FC vibration estimate. It models
 * the inertial prediction only; it says nothing about GNSS measurement noise.
 *
 * GNSS measurement noise comes from a configured, separately validated model.
 * Receiver-reported accuracy is secondary evidence: it may inflate the model
 * sigma, but only up to Config::gnss_sigma_cap_factor times the model, so a
 * receiver (or spoofer) reporting huge accuracy values cannot switch the tests
 * off, and a receiver reporting optimistic values cannot tighten them.
 */
#pragma once

#include "GNSSIntegrityTypes.h"

namespace GNSSInt {

struct GNSSNoise {
    Vec3 pos_var;   // NED, m^2
    Vec3 vel_var;   // NED, (m/s)^2
};

class NoiseModel {
public:
    // Velocity random-walk intensity q (m^2/s^3) for one IMU increment.
    static float accel_noise_rate(const IMUSample &s, const Config &cfg);
    static bool high_vibration(const IMUSample &s, const Config &cfg) { return s.vibration.norm() > cfg.vibration_max_mss; }
    static GNSSNoise gnss(const GNSSObservation &obs, const Config &cfg);
};

} // namespace GNSSInt
