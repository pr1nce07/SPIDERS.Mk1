/*
 * GNSSIntegrity: IMU-propagated GNSS integrity monitor for SPIDERS / PUSHPAK AP_IDS.
 *
 * Public interface and orchestration. Owned by AP_IDS (or its GPS detector, never
 * both). It reads nothing from ArduPilot itself: the AP_IDS adapter
 * (AP_IDS_GNSSIntegrity.cpp) builds the input structures at the device-API edge.
 *
 *   capture_imu()             fast path, once per INS update: bounded enqueue only
 *   update()                  drain + propagate (call at >= 50 Hz, e.g. after AP_GPS::update)
 *   observe_heading()         qualified NON-GNSS absolute heading
 *   observe_baro()            barometer altitude samples
 *   update_ground_state()     landed / moving-platform state
 *   observe_gnss()            once per new GNSS fix (drains first)
 *   reset_to_trusted_state()  explicit trust anchor with provenance
 *   get_result()              structured evidence for the GPS detector / logging
 *
 * The subsystem is passive: it has no outputs except get_result().
 */
#pragma once

#include "BarometerCheck.h"
#include "BiasEstimator.h"
#include "HeadingManager.h"
#include "HorizonManager.h"
#include "InertialPropagator.h"
#include "InertialSampleBuffer.h"
#include "NoiseModel.h"
#include "ResidualTests.h"
#include "TimeAligner.h"

namespace GNSSInt {

enum class SeedStatus : uint8_t {
    ACCEPTED,
    DISABLED,
    NOT_QUALIFIED,
    BAD_PROVENANCE,
    SUSPICION_ACTIVE,      // reseed during suspicion needs an independent anchor
    OUTSIDE_HISTORY,
};

class GNSSIntegrity {
public:
    void init(const Config &cfg);
    const Config &config() const { return _cfg; }

    bool capture_imu(const IMUSample &sample);
    void update();
    void observe_heading(const HeadingObservation &h);
    void observe_baro(const BaroObservation &b);
    void update_ground_state(const GroundState &g) { _ground = g; }
    void observe_gnss(const GNSSObservation &obs);
    SeedStatus reset_to_trusted_state(const TrustedNavigationSeed &seed);

    const Result &get_result() const { return _res; }
    const Counters &counters() const { return _cnt; }

    // Diagnostics / tests: IMU-only prediction of horizon i at a past time inside the history.
    bool predict_horizon(uint8_t i, uint64_t time_us, Vec3 &p, Vec3 &v) const;
    const Horizon &horizon(uint8_t i) const { return _h[i]; }
    const InertialPropagator &propagator() const { return _prop; }
    const HeadingManager &heading() const { return _heading; }
    const BiasEstimator &bias() const { return _bias; }
    bool trust_gate_open() const { return _gate_open; }

private:
    enum class Suspicion : uint8_t { NONE, WARNING, ALARM };

    Vec3 to_ned(int32_t lat_e7, int32_t lon_e7, int32_t alt_cm) const;
    void set_origin(int32_t lat_e7, int32_t lon_e7, int32_t alt_cm);
    bool horizon_enabled(uint8_t i) const { return (_cfg.horizon_mask >> i) & 1u; }
    void arm_horizon(uint8_t i, const HorizonSeed &seed, const Snapshot &S0);
    void finalize(State base_state, uint32_t extra_flags);

    Config _cfg;
    InertialSampleBuffer _buf;
    InertialPropagator _prop;
    HeadingManager _heading;
    BiasEstimator _bias;
    BarometerCheck _baro;
    TimeAligner _align;
    Horizon _h[NUM_HORIZONS];
    Result _res;
    Counters _cnt;
    GroundState _ground;

    bool _origin_valid = false;
    int32_t _lat0 = 0, _lon0 = 0, _alt0 = 0;
    float _lon_scale = 1.0f;

    bool _ever_seeded = false;
    bool _reseed_required = false;
    bool _gate_open = false;
    Suspicion _susp = Suspicion::NONE;
    uint8_t _warn_streak = 0;
    uint8_t _alarm_streak = 0;
    uint16_t _clean_streak = 0;      // fixes with tests and no warning (trust-gate requalification)
    uint8_t _clear_streak = 0;       // fixes that can clear a WARNING (sensitivity-aware)
    bool _susp_ins = false;          // suspicion raised by an INS-prediction test (not only baro/ground)
    float _onset_vel_sigma = 0.0f;   // most sensitive warning horizon at onset
    float _onset_pos_sigma = 0.0f;
    uint32_t _pending_flags = 0;     // sticky events since the previous result
    uint32_t _seq = 0;

    // GNSS re-arm candidates: a fix may seed a horizon only after rearm_confirm_fixes
    // later fixes were evaluated without any warning (the first spoofed fix can pass).
    struct Candidate {
        bool used;
        uint8_t confirmations;
        HorizonSeed seed;
    };
    static const uint8_t NUM_CANDIDATES = 4;
    Candidate _cand[NUM_CANDIDATES];
    uint8_t _cand_head = 0;
};

} // namespace GNSSInt
