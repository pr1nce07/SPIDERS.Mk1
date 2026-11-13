/*
 * AP_IDS_GNSSIntegrity: ArduPilot adapter (INTEGRATION TEMPLATE, see the header).
 *
 * Every AP_* call is marked VERIFY where its exact name/signature must be
 * checked against the pinned tree (ArduCopter 4.7.1, dbe79216 + AP_IDS patches).
 */
#include "AP_IDS_GNSSIntegrity.h"

#if AP_IDS_GNSSINT_ENABLED

#include <AP_AHRS/AP_AHRS.h>
#include <AP_Baro/AP_Baro.h>
#include <AP_Compass/AP_Compass.h>
#include <AP_GPS/AP_GPS.h>
#include <AP_HAL/AP_HAL.h>
#include <AP_InertialSensor/AP_InertialSensor.h>
#include <AP_Logger/AP_Logger.h>
#include <AP_Math/AP_Math.h>
#include "GNSSIntegrity/GNSSIntegrityLog.h"

extern const AP_HAL::HAL &hal;

using namespace GNSSInt;

const AP_Param::GroupInfo AP_IDS_GNSSIntegrity::var_info[] = {
    // @Param: EN
    // @DisplayName: GNSS integrity physics engine enable
    // @Description: Enables the passive IMU-propagated GNSS integrity monitor (detect-only). Requires reboot.
    // @Values: 0:Disabled,1:Enabled
    // @RebootRequired: True
    // @User: Advanced
    AP_GROUPINFO_FLAGS("EN", 1, AP_IDS_GNSSIntegrity, _enable, 0, AP_PARAM_FLAG_ENABLE),

    // @Param: MASK
    // @DisplayName: Enabled horizons
    // @Bitmask: 0:2s,1:5s,2:15s,3:30s,4:60s
    // @User: Advanced
    AP_GROUPINFO("MASK", 2, AP_IDS_GNSSIntegrity, _mask, 0x1F),

    // @Param: LAT_MS
    // @DisplayName: Extra GNSS latency compensation
    // @Description: Applied once to the fix time. Leave 0 unless the selected AP_GPS backend lag is proven NOT to be reflected in last_fix_time_ms.
    // @Units: ms
    // @Range: 0 500
    // @User: Advanced
    AP_GROUPINFO("LAT_MS", 3, AP_IDS_GNSSIntegrity, _lag_ms, 0),

    // @Param: POS_MAX
    // @DisplayName: Maximum usable position uncertainty
    // @Units: m
    // @Range: 5 500
    // @User: Advanced
    AP_GROUPINFO("POS_MAX", 4, AP_IDS_GNSSIntegrity, _pos_max, 50.0f),

    // @Param: VEL_MAX
    // @DisplayName: Maximum usable velocity uncertainty
    // @Units: m/s
    // @Range: 0.5 50
    // @User: Advanced
    AP_GROUPINFO("VEL_MAX", 5, AP_IDS_GNSSIntegrity, _vel_max, 5.0f),

    // @Param: GROUND
    // @DisplayName: Stationary-ground GNSS speed check
    // @Values: 0:Disabled,1:Enabled
    // @User: Advanced
    AP_GROUPINFO("GROUND", 6, AP_IDS_GNSSIntegrity, _ground, 1),

    // @Param: LOG
    // @DisplayName: Detail log level
    // @Values: 0:None,1:IDSG+IDSR at 1Hz and on transitions,2:every evaluated fix (development only)
    // @User: Advanced
    AP_GROUPINFO("LOG", 7, AP_IDS_GNSSIntegrity, _log, 1),

    // @Param: MOVING
    // @DisplayName: Moving-platform operations
    // @Description: Set when launching from boats or vehicles: disables the stationary-ground constraint.
    // @Values: 0:No,1:Yes
    // @User: Advanced
    AP_GROUPINFO("MOVING", 8, AP_IDS_GNSSIntegrity, _moving, 0),

    // @Param: DV_SF
    // @DisplayName: Delta-velocity convention
    // @Description: 1 if AP_InertialSensor delta velocity is specific force (gravity included). Must be proven by the stationary-level bench test for the IMU backend; a mismatch sets the GRAVITY_FAULT flag.
    // @Values: 0:Kinematic,1:SpecificForce
    // @User: Advanced
    AP_GROUPINFO("DV_SF", 9, AP_IDS_GNSSIntegrity, _dv_specific, 1),

    AP_GROUPEND
};

AP_IDS_GNSSIntegrity::AP_IDS_GNSSIntegrity()
{
    AP_Param::setup_object_defaults(this, var_info);
}

void AP_IDS_GNSSIntegrity::fill_config(Config &cfg) const
{
    cfg.enabled = _enable != 0;
    cfg.horizon_mask = uint8_t(_mask.get() & 0x1F);
    cfg.lag_compensation_ms = uint16_t(constrain_int16(_lag_ms.get(), 0, 500));
    cfg.pos_sigma_max_m = constrain_float(_pos_max.get(), 5.0f, 500.0f);
    cfg.vel_sigma_max_mps = constrain_float(_vel_max.get(), 0.5f, 50.0f);
    cfg.ground_test_enabled = _ground != 0;
    cfg.delta_velocity_is_specific_force = _dv_specific != 0;
}

void AP_IDS_GNSSIntegrity::init()
{
    Config cfg;
    fill_config(cfg);
    _engine.init(cfg);   // fixed-size member: no allocation
}

void AP_IDS_GNSSIntegrity::capture_imu_sample()
{
    if (_enable == 0) {
        return;
    }
    const uint32_t t_start = AP_HAL::micros();
    const AP_InertialSensor &ins = AP::ins();
    // Verified against 4.7.1 (dbe79216): AP_InertialSensor has get_first_usable_gyro/accel(); there is no get_primary_*.
    const uint8_t gi = ins.get_first_usable_gyro();
    const uint8_t ai = ins.get_first_usable_accel();

    IMUSample s = IMUSample();
    // VERIFY: get_last_update_usec() is the 32-bit time of the newest published sample.
    // Duplicate timestamps (no new sample this loop) are rejected by the engine.
    const uint32_t us32 = ins.get_last_update_usec();
    s.time_us = AP_HAL::micros64() - uint32_t(AP_HAL::micros() - us32);
    s.sequence = ++_imu_seq;

    Vector3f da, dv;
    float da_dt = 0.0f, dv_dt = 0.0f;
    // VERIFY: get_delta_angle(uint8_t, Vector3f&, float&) / get_delta_velocity(...) signatures; whether
    // coning/sculling compensation and bias correction are already applied by the backend.
    s.delta_angle_valid = ins.get_delta_angle(gi, da, da_dt);
    s.delta_velocity_valid = ins.get_delta_velocity(ai, dv, dv_dt);
    s.delta_angle_rad = Vec3(da.x, da.y, da.z);
    s.delta_velocity_mps = Vec3(dv.x, dv.y, dv.z);
    s.delta_angle_dt_s = da_dt;
    s.delta_velocity_dt_s = dv_dt;
    s.gyro_healthy = ins.get_gyro_health(gi);
    s.accel_healthy = ins.get_accel_health(ai);
    const uint32_t clips = ins.get_accel_clip_count(ai);   // VERIFY
    s.accel_clipping = clips != _last_clip_count;
    _last_clip_count = clips;
    const Vector3f vib = ins.get_vibration_levels(ai);      // VERIFY scale (m/s/s) and instance
    s.vibration = Vec3(vib.x, vib.y, vib.z);

    // Roll/pitch from the FC attitude solution. Its yaw is NOT used (it may be GNSS-aided).
    // VERIFY: accessor names; that AHRS roll/pitch timestamps match this INS sample.
    const AP_AHRS &ahrs = AP::ahrs();
    s.roll_rad = ahrs.get_roll_rad();
    s.pitch_rad = ahrs.get_pitch_rad();
    s.roll_pitch_valid = ahrs.healthy();

    _engine.capture_imu(s);   // enqueue only: no maths, logging or allocation here

    const uint32_t dt = AP_HAL::micros() - t_start;
    if (dt > _capture_max_us) {
        _capture_max_us = dt;
    }
}

void AP_IDS_GNSSIntegrity::feed_baro()
{
    const AP_Baro &baro = AP::baro();
    const uint32_t ms = baro.get_last_update();   // VERIFY
    if (ms == _last_baro_ms) {
        return;
    }
    _last_baro_ms = ms;
    BaroObservation b;
    b.time_us = AP_HAL::micros64() - uint64_t(AP_HAL::millis() - ms) * 1000U;
    b.altitude_m = baro.get_altitude();           // relative to last calibration; only changes are compared
    b.healthy = baro.healthy();
    _engine.observe_baro(b);
}

void AP_IDS_GNSSIntegrity::feed_heading()
{
    // Tilt-compensated magnetometer heading at 10 Hz. Compass::calculate_heading() uses only the
    // roll/pitch part of the matrix, so a yaw-free matrix is passed: no EKF/GNSS-aided yaw enters.
    const uint32_t now = AP_HAL::millis();
    if (now - _last_heading_ms < 100) {
        return;
    }
    _last_heading_ms = now;
    const Compass &compass = AP::compass();
    HeadingObservation h;
    h.time_us = AP_HAL::micros64();
    h.valid = compass.healthy() && compass.use_for_yaw();   // VERIFY
    if (!h.valid) {
        return;
    }
    // Field-strength disturbance check: reject samples far from the learned field norm.
    const float n = compass.get_field().length();
    if (_field_norm <= 0.0f) {
        _field_norm = n;
    } else if (fabsf(n - _field_norm) > 0.25f * _field_norm) {
        return;
    } else {
        _field_norm += 0.01f * (n - _field_norm);
    }
    Matrix3f tilt;
    tilt.from_euler(AP::ahrs().get_roll_rad(), AP::ahrs().get_pitch_rad(), 0.0f);
    // NOTE: COMPASS_AUTODEC derives declination from the GNSS position; a spoofed position can shift
    // it slightly. Prefer a fixed COMPASS_DEC for missions that rely on this monitor.
    h.yaw_rad = wrap_PI(compass.calculate_heading(tilt));
    h.sigma_rad = radians(5.0f);
    _engine.observe_heading(h);
}

bool AP_IDS_GNSSIntegrity::build_gnss_observation(GNSSObservation &obs)
{
    const AP_GPS &gps = AP::gps();
    const uint32_t msg_ms = gps.last_message_time_ms();
    if (msg_ms == _last_gps_msg_ms) {
        return false;   // no new data: each fix is processed once
    }
    _last_gps_msg_ms = msg_ms;
    obs = GNSSObservation();
    obs.message_time_ms = msg_ms;
    // VERIFY for the active backend: whether last_fix_time_ms() already reflects GPS lag (do not double-apply).
    obs.fix_time_ms = gps.last_fix_time_ms();
    const Location &loc = gps.location();
    obs.lat_e7 = loc.lat;
    obs.lon_e7 = loc.lng;
    obs.alt_cm = loc.alt;   // VERIFY frame: absolute (AMSL/ellipsoid); only changes are compared with baro
    const Vector3f &v = gps.velocity();
    obs.velocity_ned_mps = Vec3(v.x, v.y, v.z);
    obs.fix_valid = gps.status() >= AP_GPS::GPS_OK_FIX_3D;
    obs.position_valid = obs.fix_valid;
    obs.velocity_valid = obs.fix_valid;
    obs.have_vertical_velocity = gps.have_vertical_velocity();
    float acc = 0.0f;
    obs.h_acc_m = gps.horizontal_accuracy(acc) ? acc : -1.0f;
    obs.v_acc_m = gps.vertical_accuracy(acc) ? acc : -1.0f;
    obs.s_acc_mps = gps.speed_accuracy(acc) ? acc : -1.0f;
    return true;
}

void AP_IDS_GNSSIntegrity::apply_seed_policy(uint32_t prev_seq)
{
    // Trust policy (documented in firmware/native/README.md): PREFLIGHT_STATIONARY.
    // Disarmed AND vehicle-landed AND IMU-still for 5 s AND good 3D fix AND an absolute
    // non-GNSS heading. v0 = 0 comes from the verified stationary state, not from GNSS.
    // The seed POSITION is the GNSS fix: an attack already present before seeding cannot be
    // detected by this method (trust-anchor limitation).
    const Result &r = _engine.get_result();
    const uint32_t now = AP_HAL::millis();
    const bool still = _engine.propagator().still() && _landed_valid && _landed && _moving == 0 &&
                       !hal.util->get_soft_armed();
    if (!still) {
        _still_since_ms = 0;
        return;
    }
    if (_still_since_ms == 0) {
        _still_since_ms = now;
    }
    const bool need_seed = !r.trusted_seed_valid || (r.flags & FLAG_RESEED_REQUIRED);
    if (!need_seed || now - _still_since_ms < 5000 || r.sequence == prev_seq || !_engine.heading().absolute()) {
        return;   // r.sequence advanced => the last fix was aligned and evaluated
    }
    const AP_GPS &gps = AP::gps();
    if (gps.status() < AP_GPS::GPS_OK_FIX_3D || gps.num_sats() < 8 || gps.get_hdop() > 200) {
        return;
    }
    TrustedNavigationSeed sd = TrustedNavigationSeed();
    sd.provenance = SeedProvenance::PREFLIGHT_STATIONARY;
    sd.qualified = true;
    sd.time_us = r.time_us;
    const Location &loc = gps.location();
    sd.lat_e7 = loc.lat;
    sd.lon_e7 = loc.lng;
    sd.alt_cm = loc.alt;
    sd.velocity_ned_mps = Vec3();
    float acc = 0.0f;
    sd.pos_sigma_m = gps.horizontal_accuracy(acc) ? MAX(acc, 2.5f) : 2.5f;
    sd.vel_sigma_mps = 0.05f;
    _engine.reset_to_trusted_state(sd);
}

void AP_IDS_GNSSIntegrity::update_observations()
{
    if (_enable == 0) {
        return;
    }
    const uint32_t t_start = AP_HAL::micros();
    _engine.update();      // drain the IMU queue (bounded)
    feed_baro();
    feed_heading();
    GroundState g;
    g.landed_valid = _landed_valid;
    g.landed = _landed;
    g.moving_platform = _moving != 0;
    _engine.update_ground_state(g);

    GNSSObservation obs;
    if (build_gnss_observation(obs)) {
        const uint32_t prev_seq = _engine.get_result().sequence;
        _engine.observe_gnss(obs);
        apply_seed_policy(prev_seq);
        if (_log >= 2 && _engine.get_result().sequence != prev_seq) {
            write_records(0);
        }
    }
    const uint32_t dt = AP_HAL::micros() - t_start;
    if (dt > _observe_max_us) {
        _observe_max_us = dt;
    }
}

uint16_t AP_IDS_GNSSIntegrity::evidence_bits() const
{
    const Result &r = _engine.get_result();
    uint16_t bits = 0;
    if (r.state == State::WARNING || r.state == State::ALARM) {
        if (r.warn_mask != 0 || r.alarm_mask != 0 || r.state == State::ALARM) {
            bits |= kEvidenceInsPrediction;
        }
        if (r.flags & (FLAG_BARO_WARN | FLAG_GROUND_WARN)) {
            bits |= kEvidencePhysConstraint;
        }
    }
    return bits;   // DEGRADED / UNAVAILABLE contribute nothing: it is not evidence of spoofing
}

bool AP_IDS_GNSSIntegrity::wants_suspected() const
{
    const State st = _engine.get_result().state;
    return st == State::WARNING || st == State::ALARM;
}

void AP_IDS_GNSSIntegrity::update_logging(uint32_t boot_id)
{
#if HAL_LOGGING_ENABLED
    if (_enable == 0 || _log == 0) {
        return;
    }
    const Result &r = _engine.get_result();
    const uint32_t now = AP_HAL::millis();
    const bool transition = uint8_t(r.state) != _last_logged_state;
    if (r.sequence == _last_logged_seq && !transition) {
        return;
    }
    if (!transition && now - _last_log_ms < 1000) {
        return;   // bounded: 1 Hz plus state transitions
    }
    write_records(boot_id);
    _last_log_ms = now;
    _last_logged_seq = r.sequence;
    _last_logged_state = uint8_t(r.state);
#else
    (void)boot_id;
#endif
}

void AP_IDS_GNSSIntegrity::write_records(uint32_t boot_id)
{
#if HAL_LOGGING_ENABLED
    const Result &r = _engine.get_result();
    const uint64_t now_us = AP_HAL::micros64();
    // IDSR rows first, then the IDSG summary with the same Seq (GCS contract).
    for (uint8_t i = 0; i < NUM_HORIZONS; i++) {
        const HorizonResult &h = r.horizon[i];
        uint8_t st = 0;
        st |= h.armed ? HSTAT_ARMED : 0;
        st |= h.valid ? HSTAT_VALID : 0;
        st |= h.expired ? HSTAT_EXPIRED : 0;
        st |= h.warn ? HSTAT_WARN : 0;
        st |= h.alarm ? HSTAT_ALARM : 0;
        st |= (h.valid && !h.vector_valid) ? HSTAT_HEADING_FREE_ONLY : 0;
        st |= h.baro_valid ? HSTAT_BARO_VALID : 0;
        st |= h.extended ? HSTAT_EXTENDED : 0;
        // @LoggerMessage: IDSR
    // @Vehicles: Copter
    // @Description: GNSS integrity engine per-horizon detail, one row per horizon (H = 0..4 for 2/5/15/30/60 s). Written before the IDSG summary that shares the same Seq. 1 Hz and on state transitions.
    // @Field: TimeUS: Time since system startup
    // @Field: Boot: AP_IDS boot identifier
    // @Field: Seq: engine evaluation sequence, shared with IDSG
    // @Field: H: horizon index (0 = 2 s, 1 = 5 s, 2 = 15 s, 3 = 30 s, 4 = 60 s)
    // @Field: Dur: horizon nominal duration (s)
    // @Field: St: horizon status bits (armed, valid, expired, warn, alarm, heading-free only, baro valid, extended)
    // @Field: Rsn: reason the horizon is not fully valid
    // @Field: El: elapsed time since the horizon was armed (s)
    // @Field: RP: position residual magnitude (m)
    // @Field: RV: velocity residual magnitude (m/s)
    // @Field: TP: position test statistic
    // @Field: TV: velocity test statistic
    // @Field: TD: speed-change test statistic
    // @Field: SP: position sigma (m)
    // @Field: SV: velocity sigma (m/s)
    // @Field: YSd: yaw sigma (rad)
    AP::logger().Write("IDSR", "TimeUS,Boot,Seq,H,Dur,St,Rsn,El,RP,RV,TP,TV,TD,SP,SV,YSd", "QIIBBBBfffffffff",
                           now_us, boot_id, r.sequence, i, uint8_t(h.duration_s), st, uint8_t(h.reason),
                           h.elapsed_s, h.position_residual_m, h.velocity_residual_mps,
                           h.position_test_statistic, h.velocity_test_statistic, h.delta_speed_test_statistic,
                           h.position_sigma_m, h.velocity_sigma_mps, h.yaw_sigma_rad);
    }
    // @LoggerMessage: IDSG
    // @Vehicles: Copter
    // @Description: GNSS integrity engine summary, written once per evaluated sequence and on state transitions
    // @Field: TimeUS: Time since system startup
    // @Field: Boot: AP_IDS boot identifier
    // @Field: Seq: engine evaluation sequence
    // @Field: Ver: record version
    // @Field: St: engine state (0 disabled, 1 initialising, 2 no trusted seed, 3 heading unobservable, 4 valid, 5 degraded, 6 warning, 7 alarm)
    // @Field: AM: armed horizon mask (bit i = horizon i)
    // @Field: VM: valid horizon mask
    // @Field: WM: warning horizon mask
    // @Field: XM: alarm horizon mask
    // @Field: Fl: engine result flag bits
    // @Field: FAge: GNSS message time minus fix time (ms)
    // @Field: Lag: latency compensation applied by the engine (ms)
    // @Field: Conf: confidence, r/(1+r) with r the joint maximum statistic over the alarm threshold
    // @Field: DvR: heading-free speed-change residual of the worst horizon (m/s)
    // @Field: BrR: barometer altitude-change residual of the worst horizon (m)
    // @Field: BiN: accelerometer bias estimate norm (m/s/s)
    AP::logger().Write("IDSG", "TimeUS,Boot,Seq,Ver,St,AM,VM,WM,XM,Fl,FAge,Lag,Conf,DvR,BrR,BiN", "QIIBBBBBBIHhffff",
                       now_us, boot_id, r.sequence, kIDSGVersion, uint8_t(r.state),
                       r.armed_mask, r.valid_mask, r.warn_mask, r.alarm_mask, r.flags,
                       r.fix_age_ms, r.applied_lag_ms, r.confidence,
                       r.delta_speed_residual_mps, r.baro_delta_residual_m, r.accel_bias_norm_mps2);
#else
    (void)boot_id;
#endif
}

#endif // AP_IDS_GNSSINT_ENABLED
