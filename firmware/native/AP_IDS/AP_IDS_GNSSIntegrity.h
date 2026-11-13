/*
 * AP_IDS_GNSSIntegrity: ArduPilot adapter for the portable GNSSIntegrity engine.
 *
 * *** INTEGRATION TEMPLATE, NOT COMPILED IN THIS REPOSITORY ***
 * The SPIDERS GCS repository does not contain the native libraries/AP_IDS tree
 * (firmware/FIRMWARE_WORK_REQUIRED.md). Copy this file and GNSSIntegrity/ into
 * the matching ArduPilot fork at commit dbe79216 + local AP_IDS patches, then
 * verify every ArduPilot call below against THAT tree before building
 * (see firmware/native/README.md, "Verify before building").
 *
 * Device-API access stays here, at the edge. The numerical engine never calls
 * AP::ins(), AP::gps(), AP::ahrs() or AP::baro().
 *
 * Passive: nothing here changes mode, arming, navigation, EKF/GNSS inputs,
 * actuator outputs, MAVLink handling or failsafes. Disabled by default.
 */
#pragma once

#ifndef AP_IDS_GNSSINT_ENABLED
#define AP_IDS_GNSSINT_ENABLED 0   // opt-in until the FW-13 merge gates pass
#endif

#if AP_IDS_GNSSINT_ENABLED

#include <AP_Param/AP_Param.h>
#include "GNSSIntegrity/GNSSIntegrity.h"

class AP_IDS_GNSSIntegrity {
public:
    AP_IDS_GNSSIntegrity();
    CLASS_NO_COPY(AP_IDS_GNSSIntegrity);

    static const struct AP_Param::GroupInfo var_info[];

    void init();

    // FAST PATH. Call once per main loop immediately after AP_InertialSensor::update()
    // (Copter fast-task table). Bounded: reads the published increment, enqueues it.
    void capture_imu_sample();

    // Call right after AP_GPS::update() (50 Hz scheduler task): drains the IMU queue,
    // feeds baro/heading, evaluates each NEW GNSS fix exactly once, applies the seed policy.
    void update_observations();

    // Vehicle-level landed decision (Copter: ap.land_complete). Disarmed != stationary.
    void set_landed(bool valid, bool landed) { _landed_valid = valid; _landed = landed; }

    // Slow path, from AP_IDS::update() (5 Hz): bounded DataFlash IDSG/IDSR records.
    void update_logging(uint32_t boot_id);

    const GNSSInt::Result &result() const { return _engine.get_result(); }

    // Mapping into the existing GPS detector (reuse its identity; no ninth detector ID):
    // evidence bits to OR into the GPS detector's Ev mask, and whether the physics
    // engine asks the GPS detector to consider SUSPECTED. The GPS detector's own
    // persistence/confirmation policy decides the PIDS state; never auto-CONFIRMED.
    uint16_t evidence_bits() const;
    bool wants_suspected() const;
    float confidence() const { return _engine.get_result().confidence; }

    // Timing instrumentation (FW-01 / §20): worst-case microseconds per path.
    uint32_t capture_max_us() const { return _capture_max_us; }
    uint32_t observe_max_us() const { return _observe_max_us; }

private:
    void fill_config(GNSSInt::Config &cfg) const;
    bool build_gnss_observation(GNSSInt::GNSSObservation &obs);
    void feed_baro();
    void feed_heading();
    void apply_seed_policy(uint32_t prev_seq);
    void write_records(uint32_t boot_id);

    // Parameters (group prefix "GI_" under the AP_IDS group: e.g. IDS_GI_EN).
    // ArduPilot names are limited to 16 characters, so the guide's IDS_GNSSINT_* names are shortened.
    AP_Int8 _enable;        // IDS_GI_EN
    AP_Int8 _mask;          // IDS_GI_MASK
    AP_Int16 _lag_ms;       // IDS_GI_LAT_MS
    AP_Float _pos_max;      // IDS_GI_POS_MAX
    AP_Float _vel_max;      // IDS_GI_VEL_MAX
    AP_Int8 _ground;        // IDS_GI_GROUND
    AP_Int8 _log;           // IDS_GI_LOG
    AP_Int8 _moving;        // IDS_GI_MOVING (moving-platform launches: ground test off)
    AP_Int8 _dv_specific;   // IDS_GI_DV_SF   (1: delta velocity is specific force; prove per backend)

    GNSSInt::GNSSIntegrity _engine;

    uint32_t _last_gps_msg_ms = 0;
    uint32_t _last_baro_ms = 0;
    uint32_t _last_heading_ms = 0;
    uint32_t _last_clip_count = 0;
    uint32_t _imu_seq = 0;
    uint32_t _last_imu_us32 = 0;
    uint64_t _imu_us64_base = 0;
    bool _landed_valid = false;
    bool _landed = false;
    uint32_t _still_since_ms = 0;
    uint32_t _last_log_ms = 0;
    uint32_t _last_logged_seq = 0;
    uint8_t _last_logged_state = 0xFF;
    float _field_norm = 0.0f;
    uint32_t _capture_max_us = 0;
    uint32_t _observe_max_us = 0;
};

#endif // AP_IDS_GNSSINT_ENABLED
