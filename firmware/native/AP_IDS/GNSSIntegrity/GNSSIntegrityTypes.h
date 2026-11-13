/*
 * GNSSIntegrity: public data contract.
 *
 * The engine is a passive, detect-only GNSS integrity monitor. It compares each
 * GNSS fix with an inertial prediction that is NOT corrected by GNSS while a
 * horizon (2/5/15/30/60 s) is active. Nothing in this subsystem may change
 * flight mode, arming, navigation, EKF inputs, actuator outputs, MAVLink
 * handling or failsafe behaviour.
 *
 * Every numeric default below is an INITIAL VALUE TO VALIDATE against logs from
 * the target Pixhawk 6C / IMU / receiver, not a measured specification.
 */
#pragma once

#include "GNSSIntegrityMath.h"

namespace GNSSInt {

static const uint8_t NUM_HORIZONS = 5;
extern const uint16_t kHorizonDurationS[NUM_HORIZONS];   // {2, 5, 15, 30, 60}

// Values are part of the IDSG DataFlash contract (field St). Do not renumber.
enum class State : uint8_t {
    DISABLED = 0,
    INITIALIZING = 1,          // no IMU history yet
    NO_TRUSTED_SEED = 2,       // no armed horizon; needs a qualified seed
    HEADING_UNOBSERVABLE = 3,  // armed, but only heading-free tests are valid
    VALID = 4,
    DEGRADED = 5,              // armed, but no test can be supported (uncertainty, gaps). NOT spoofing.
    WARNING = 6,               // persistent test exceedance
    ALARM = 7,                 // persistent INS-prediction exceedance at alarm level
};

// IDSR field Rsn: why a horizon is not (fully) valid. Part of the contract.
enum class HorizonReason : uint8_t {
    NONE = 0,
    NOT_ARMED = 1,
    IMU_GAP = 2,
    IMU_OVERFLOW = 3,
    ACCEL_CLIPPING = 4,
    POS_SIGMA_LIMIT = 5,
    VEL_SIGMA_LIMIT = 6,
    HEADING_INVALID = 7,       // vector tests off; heading-free test may still run
    ATTITUDE_INVALID = 8,
    HEADING_EPOCH_CHANGED = 9, // absolute heading was (re)initialised during the horizon
    ORIGIN_RESET = 10,
    EXPIRED = 11,
};

// IDSG field Fl (32 bits). Part of the contract.
enum ResultFlag : uint32_t {
    FLAG_TRUSTED_SEED      = 1U << 0,
    FLAG_HEADING_VALID     = 1U << 1,
    FLAG_BIAS_VALID        = 1U << 2,
    FLAG_GROUND_TEST_VALID = 1U << 3,
    FLAG_BARO_TEST_VALID   = 1U << 4,
    FLAG_TRUST_GATE_OPEN   = 1U << 5,
    FLAG_IMU_GAP           = 1U << 6,   // since previous result
    FLAG_IMU_OVERFLOW      = 1U << 7,
    FLAG_IMU_DUPLICATE     = 1U << 8,
    FLAG_ACCEL_CLIPPING    = 1U << 9,
    FLAG_HIGH_VIBRATION    = 1U << 10,
    FLAG_FIX_UNALIGNABLE   = 1U << 11,
    FLAG_GRAVITY_FAULT     = 1U << 12,  // delta-velocity convention contradicts config
    FLAG_GROUND_WARN       = 1U << 13,
    FLAG_BARO_WARN         = 1U << 14,
    FLAG_BIAS_CHANGE_POINT = 1U << 15,
    FLAG_NED_FIXED_PREFERRED = 1U << 16, // supporting evidence only
    FLAG_HEADING_DISTURBED = 1U << 17,
    FLAG_RESEED_REQUIRED   = 1U << 18,
    FLAG_SEED_REJECTED     = 1U << 19,
    FLAG_ORIGIN_RESET      = 1U << 20,
    FLAG_ALARM_LATCHED     = 1U << 21,  // ALARM holds until an independent reseed
    FLAG_CLEAR_BLOCKED     = 1U << 22,  // WARNING cannot clear: no horizon sensitive enough remains
};

// IDSR field St (per horizon). Part of the contract.
enum HorizonStatusBit : uint8_t {
    HSTAT_ARMED = 1U << 0,
    HSTAT_VALID = 1U << 1,
    HSTAT_EXPIRED = 1U << 2,
    HSTAT_WARN = 1U << 3,
    HSTAT_ALARM = 1U << 4,
    HSTAT_HEADING_FREE_ONLY = 1U << 5,
    HSTAT_BARO_VALID = 1U << 6,
    HSTAT_EXTENDED = 1U << 7,          // kept past its nominal duration while suspicion is active
};

struct IMUSample {
    uint64_t time_us;            // sample (not processing) time, AP_HAL::micros64 basis
    uint32_t sequence;
    float delta_angle_dt_s;
    float delta_velocity_dt_s;
    Vec3 delta_angle_rad;        // body FRD
    Vec3 delta_velocity_mps;     // body FRD; see Config::delta_velocity_is_specific_force
    bool delta_angle_valid;
    bool delta_velocity_valid;
    bool gyro_healthy;
    bool accel_healthy;
    bool accel_clipping;
    Vec3 vibration;              // m/s/s, FC vibration estimate
    float roll_rad;
    float pitch_rad;
    bool roll_pitch_valid;
};

struct GNSSObservation {
    uint32_t fix_time_ms;        // AP_GPS::last_fix_time_ms() (system ms)
    uint32_t message_time_ms;    // AP_GPS::last_message_time_ms()
    int32_t lat_e7;
    int32_t lon_e7;
    int32_t alt_cm;              // receiver altitude datum; only *changes* are compared with baro
    Vec3 velocity_ned_mps;
    bool position_valid;
    bool velocity_valid;
    bool fix_valid;              // >= 3D fix
    bool have_vertical_velocity;
    float h_acc_m;               // receiver-reported accuracy; <= 0 when unknown (secondary only)
    float v_acc_m;
    float s_acc_mps;
};

struct BaroObservation {
    uint64_t time_us;
    float altitude_m;            // AP_Baro::get_altitude(): relative to last calibration
    bool healthy;
};

// Absolute heading from a qualified NON-GNSS source (e.g. tilt-compensated
// magnetometer with disturbance checks). Never pass EKF/AHRS yaw here if it can
// be GNSS-aided.
struct HeadingObservation {
    uint64_t time_us;
    float yaw_rad;
    float sigma_rad;
    bool valid;
};

struct GroundState {
    bool landed_valid;           // vehicle-level landed/stationary decision is trustworthy
    bool landed;
    bool moving_platform;        // operator option: launches from boats/vehicles -> ground test off
};

enum class SeedProvenance : uint8_t {
    NONE = 0,
    PREFLIGHT_STATIONARY = 1,    // verified stationary on ground; v0 = 0 independent of GNSS
    EXTERNAL_REFERENCE = 2,      // independent navigation source (survey point, second system)
    OPERATOR = 3,                // explicit operator initialisation
    VALIDATED_GNSS_PERIOD = 4,   // GNSS agreed with armed horizons for the qualification period (engine-internal re-arm)
};

struct TrustedNavigationSeed {
    SeedProvenance provenance;
    bool qualified;              // adapter's trust policy passed (fix type, sats, EKF healthy, stillness...)
    uint64_t time_us;            // measurement epoch of the seed position/velocity
    int32_t lat_e7;
    int32_t lon_e7;
    int32_t alt_cm;
    Vec3 velocity_ned_mps;
    float pos_sigma_m;           // horizontal
    float vel_sigma_mps;         // horizontal
    float pos_sigma_v_m;         // vertical; <= 0 -> max(horizontal, GNSS vertical model)
    float vel_sigma_v_mps;       // vertical; <= 0 -> max(horizontal, GNSS vertical model)
};

struct Config {
    bool enabled = false;                         // IDS_GNSSINT_EN: off by default during development
    uint8_t horizon_mask = 0x1F;                  // IDS_GNSSINT_MASK
    bool delta_velocity_is_specific_force = true; // must be proven by the stationary-level test per backend
    uint16_t lag_compensation_ms = 0;             // IDS_GNSSINT_LAT_MS: only if AP_GPS lag is NOT already applied
    float pos_sigma_max_m = 50.0f;                // IDS_GNSSINT_POS_MAX
    float vel_sigma_max_mps = 5.0f;               // IDS_GNSSINT_VEL_MAX
    bool ground_test_enabled = true;              // IDS_GNSSINT_GROUND
    // IMU sampling
    uint32_t imu_max_gap_us = 20000;
    // Inertial noise model
    float accel_vrw = 0.03f;                      // m/s/sqrt(s), white accel noise
    float vibration_ref_mss = 15.0f;              // noise doubles in variance at this vibration level
    float vibration_max_mss = 60.0f;              // above this, report high vibration
    float tilt_sigma_rad = 0.0087f;               // FC roll/pitch error, 0.5 deg
    // Heading
    float yaw_sigma_max_rad = 0.1745f;            // 10 deg: above this vector residuals are invalid
    float gyro_bias_sigma_rps = 0.0017f;          // 0.1 deg/s uncompensated gyro bias
    float gyro_arw = 0.0035f;                     // rad/sqrt(s)
    float heading_gate_sigma = 3.0f;
    uint8_t heading_reject_limit = 10;
    // Accelerometer bias
    float accel_bias_prior_sigma = 0.5f;          // m/s/s INITIAL PRIOR TO VALIDATE, not a spec
    float accel_bias_valid_sigma = 0.05f;
    float accel_bias_instability = 0.0005f;       // m/s/s per sqrt(s) random walk
    float accel_bias_max_step = 0.02f;            // m/s/s per update (rate limit)
    // GNSS measurement model (receiver accuracy is secondary: clamped to [floor, cap])
    float gnss_pos_sigma_h_m = 2.5f;
    float gnss_pos_sigma_v_m = 5.0f;
    float gnss_vel_sigma_h_mps = 0.3f;
    float gnss_vel_sigma_v_mps = 0.5f;
    float gnss_sigma_cap_factor = 2.0f;
    float timing_sigma_s = 0.02f;
    uint32_t max_extrapolation_us = 5000;
    // Barometer
    float baro_sigma_m = 0.5f;
    float baro_drift_mps = 0.05f;
    // Ground constraint
    float ground_speed_max_mps = 1.0f;
    // Decision (chi-square per test; family-wise rate MUST be calibrated on replay data)
    float chi2_3_warn = 16.27f;                   // p = 1e-3, 3 dof
    float chi2_3_alarm = 25.90f;                  // p = 1e-5, 3 dof
    float chi2_1_warn = 10.83f;                   // p = 1e-3, 1 dof
    float chi2_1_alarm = 19.51f;                  // p = 1e-5, 1 dof
    float chi2_3_clear = 11.34f;                  // p = 1e-2: an elevated statistic pauses WARNING clearing
    float chi2_1_clear = 6.63f;
    uint8_t warn_persist = 3;
    uint8_t alarm_persist = 5;
    uint8_t clear_persist = 10;
    uint8_t requalify_fixes = 25;                 // clean fixes before GNSS may re-arm horizons
    uint8_t rearm_confirm_fixes = 2;              // a GNSS re-arm seed must be followed by this many clean fixes
    float clear_sensitivity_ratio = 2.0f;         // WARNING clears only via horizons at most this much less sensitive
    float origin_reset_distance_m = 100000.0f;
};

struct HorizonResult {
    uint16_t duration_s;
    bool armed;
    bool valid;                  // at least one test supported
    bool vector_valid;           // NED position/velocity tests supported (heading valid)
    bool expired;
    bool warn;
    bool alarm;
    bool baro_valid;
    bool extended;               // evaluated past its duration (suspicion active)
    bool elevated;               // a statistic is above the clear (hysteresis) threshold
    HorizonReason reason;
    float elapsed_s;
    float position_residual_m;
    float velocity_residual_mps;
    float delta_speed_residual_mps;
    float position_test_statistic;
    float velocity_test_statistic;
    float delta_speed_test_statistic;
    float position_sigma_m;
    float velocity_sigma_mps;
    float baro_residual_m;
    float baro_test_statistic;
    float yaw_sigma_rad;
};

struct Result {
    uint64_t time_us;            // GNSS measurement epoch of the last evaluation
    uint32_t sequence;           // evaluation counter (IDSG/IDSR Seq)
    State state;
    uint8_t armed_mask;
    uint8_t valid_mask;
    uint8_t warn_mask;
    uint8_t alarm_mask;
    uint32_t flags;              // ResultFlag
    bool trusted_seed_valid;
    bool heading_valid;
    bool bias_valid;
    bool ground_test_valid;
    bool altitude_test_valid;
    float accel_bias_norm_mps2;
    float baro_delta_residual_m;
    float delta_speed_residual_mps;
    float max_alarm_ratio;       // joint max over valid tests of statistic / alarm threshold
    float confidence;            // r/(1+r) with r = max_alarm_ratio (documented, monotonic)
    uint16_t fix_age_ms;         // message_time - fix_time
    int16_t applied_lag_ms;
    HorizonResult horizon[NUM_HORIZONS];
};

struct Counters {
    uint32_t imu_accepted;
    uint32_t imu_duplicates;
    uint32_t imu_gaps;
    uint32_t imu_overflows;
    uint32_t imu_invalid;
    uint32_t fixes_evaluated;
    uint32_t fixes_rejected;
    uint32_t horizon_expiries;
    uint32_t seeds_accepted;
    uint32_t seeds_rejected;
    uint32_t bias_updates;
    uint16_t buffer_high_water;
};

} // namespace GNSSInt
