#include "GNSSIntegrity.h"

#include <string.h>

namespace GNSSInt {

// Metres per 1e-7 degree of latitude (ArduPilot LOCATION_SCALING_FACTOR).
static const float kLocationScaling = 0.011131884502145034f;

void GNSSIntegrity::init(const Config &cfg)
{
    _cfg = cfg;
    _buf.reset();
    _buf.set_max_gap_us(cfg.imu_max_gap_us);
    _prop.reset();
    _heading.reset();
    _bias.reset(cfg);
    _baro.reset();
    _align.reset();
    for (uint8_t i = 0; i < NUM_HORIZONS; i++) {
        _h[i].init(i, kHorizonDurationS[i]);
    }
    memset(&_cnt, 0, sizeof(_cnt));
    _ground = GroundState();
    _origin_valid = false;
    _ever_seeded = false;
    _reseed_required = false;
    _gate_open = false;
    _susp = Suspicion::NONE;
    _warn_streak = _alarm_streak = 0;
    _clean_streak = 0;
    _clear_streak = 0;
    _susp_ins = false;
    _onset_vel_sigma = _onset_pos_sigma = 0.0f;
    for (uint8_t i = 0; i < NUM_CANDIDATES; i++) {
        _cand[i].used = false;
    }
    _cand_head = 0;
    _pending_flags = 0;
    _seq = 0;
    _res = Result();
    _res.state = cfg.enabled ? State::INITIALIZING : State::DISABLED;
    for (uint8_t i = 0; i < NUM_HORIZONS; i++) {
        _res.horizon[i] = _h[i].result();
    }
}

bool GNSSIntegrity::capture_imu(const IMUSample &sample)
{
    if (!_cfg.enabled) {
        return false;
    }
    switch (_buf.push(sample)) {
    case PushResult::Accepted:
        return true;
    case PushResult::Duplicate:
        _pending_flags |= FLAG_IMU_DUPLICATE;
        return false;
    case PushResult::QueueFull:
        _pending_flags |= FLAG_IMU_OVERFLOW;
        return false;
    }
    return false;
}

void GNSSIntegrity::update()
{
    IMUSample s;
    uint8_t flags = 0;
    // Bounded: at most one full buffer per call.
    for (uint16_t n = 0; n < InertialSampleBuffer::CAPACITY && _buf.pop(s, flags); n++) {
        const float yaw_mid = _heading.propagate(s, _cfg);
        const float q = NoiseModel::accel_noise_rate(s, _cfg);
        _prop.step(s, flags, yaw_mid, _heading.epoch(), q, _cfg);
        _cnt.imu_accepted++;
        if (flags & SAMPLE_GAP_BEFORE) {
            _pending_flags |= FLAG_IMU_GAP;
        }
        if (flags & SAMPLE_OVERFLOW_BEFORE) {
            _pending_flags |= FLAG_IMU_OVERFLOW;
        }
        if (s.accel_clipping) {
            _pending_flags |= FLAG_ACCEL_CLIPPING;
        }
        if (NoiseModel::high_vibration(s, _cfg)) {
            _pending_flags |= FLAG_HIGH_VIBRATION;
        }
        if (!s.delta_velocity_valid || !s.accel_healthy || !s.roll_pitch_valid) {
            _cnt.imu_invalid++;
        }
    }
    _cnt.imu_duplicates = _buf.duplicates();
    _cnt.imu_overflows = _buf.overflows();
    _cnt.imu_gaps = _buf.gaps();
    _cnt.buffer_high_water = _buf.high_water();
}

void GNSSIntegrity::observe_heading(const HeadingObservation &h)
{
    if (!_cfg.enabled) {
        return;
    }
    update();   // samples before the observation use the old heading
    _heading.observe(h, _cfg);
}

void GNSSIntegrity::observe_baro(const BaroObservation &b)
{
    if (_cfg.enabled) {
        _baro.observe(b);
    }
}

void GNSSIntegrity::set_origin(int32_t lat_e7, int32_t lon_e7, int32_t alt_cm)
{
    _lat0 = lat_e7;
    _lon0 = lon_e7;
    _alt0 = alt_cm;
    _lon_scale = cosf(float(lat_e7) * 1.0e-7f * kPi / 180.0f);
    if (_lon_scale < 0.01f) {
        _lon_scale = 0.01f;
    }
    _origin_valid = true;
}

Vec3 GNSSIntegrity::to_ned(int32_t lat_e7, int32_t lon_e7, int32_t alt_cm) const
{
    const int32_t dlat = lat_e7 - _lat0;
    int64_t dlon = int64_t(lon_e7) - int64_t(_lon0);
    if (dlon > 1800000000LL) {
        dlon -= 3600000000LL;
    } else if (dlon < -1800000000LL) {
        dlon += 3600000000LL;
    }
    return Vec3(float(dlat) * kLocationScaling,
                float(dlon) * kLocationScaling * _lon_scale,
                -float(alt_cm - _alt0) * 0.01f);
}

void GNSSIntegrity::arm_horizon(uint8_t i, const HorizonSeed &seed, const Snapshot &S0)
{
    _h[i].arm(seed, S0);
}

SeedStatus GNSSIntegrity::reset_to_trusted_state(const TrustedNavigationSeed &seed)
{
    if (!_cfg.enabled) {
        return SeedStatus::DISABLED;
    }
    update();
    SeedStatus st = SeedStatus::ACCEPTED;
    if (!seed.qualified) {
        st = SeedStatus::NOT_QUALIFIED;
    } else if (seed.provenance == SeedProvenance::NONE || seed.provenance == SeedProvenance::VALIDATED_GNSS_PERIOD) {
        // VALIDATED_GNSS_PERIOD is the engine's own re-arm policy; it cannot be asserted from outside.
        st = SeedStatus::BAD_PROVENANCE;
    } else if (_susp != Suspicion::NONE) {
        // A stationary, landed vehicle is NOT an independent anchor under suspicion: its GNSS fix is
        // exactly what may be spoofed. Only an external reference or an operator anchor may reseed.
        const bool independent = seed.provenance == SeedProvenance::EXTERNAL_REFERENCE ||
                                 seed.provenance == SeedProvenance::OPERATOR;
        if (!independent) {
            st = SeedStatus::SUSPICION_ACTIVE;
        }
    }
    Snapshot S0;
    if (st == SeedStatus::ACCEPTED && !_prop.at(seed.time_us, _cfg.max_extrapolation_us, S0)) {
        st = SeedStatus::OUTSIDE_HISTORY;
    }
    if (st != SeedStatus::ACCEPTED) {
        _cnt.seeds_rejected++;
        _pending_flags |= FLAG_SEED_REJECTED;
        return st;
    }

    // An independent anchor defines a new local origin; every horizon is re-armed from it.
    set_origin(seed.lat_e7, seed.lon_e7, seed.alt_cm);
    HorizonSeed hs;
    hs.time_us = seed.time_us;
    hs.p0 = Vec3();
    hs.v0 = seed.velocity_ned_mps;
    hs.pos_sigma = seed.pos_sigma_m;
    hs.vel_sigma = seed.vel_sigma_mps;
    hs.pos_sigma_v = seed.pos_sigma_v_m > 0.0f ? seed.pos_sigma_v_m : fmaxf(seed.pos_sigma_m, _cfg.gnss_pos_sigma_v_m);
    hs.vel_sigma_v = seed.vel_sigma_v_mps > 0.0f ? seed.vel_sigma_v_mps : fmaxf(seed.vel_sigma_mps, _cfg.gnss_vel_sigma_v_mps);
    hs.bias = _bias.bias();
    hs.bias_sigma = _bias.sigma();
    hs.baro_valid = _baro.altitude_at(seed.time_us, hs.baro0_m);
    if (!hs.baro_valid) {
        hs.baro0_m = 0.0f;
    }
    hs.provenance = seed.provenance;
    for (uint8_t i = 0; i < NUM_HORIZONS; i++) {
        if (horizon_enabled(i)) {
            arm_horizon(i, hs, S0);
        } else {
            _h[i].disarm(HorizonReason::NOT_ARMED);
        }
    }
    _ever_seeded = true;
    _reseed_required = false;
    _susp = Suspicion::NONE;
    _susp_ins = false;
    _warn_streak = _alarm_streak = 0;
    _clean_streak = 0;          // GNSS must agree for requalify_fixes before it may re-arm anything
    _clear_streak = 0;
    _gate_open = false;
    for (uint8_t i = 0; i < NUM_CANDIDATES; i++) {
        _cand[i].used = false;
    }
    _cnt.seeds_accepted++;
    return st;
}

bool GNSSIntegrity::predict_horizon(uint8_t i, uint64_t time_us, Vec3 &p, Vec3 &v) const
{
    if (i >= NUM_HORIZONS) {
        return false;
    }
    Snapshot S;
    if (!_prop.at(time_us, _cfg.max_extrapolation_us, S)) {
        return false;
    }
    return _h[i].predict(S, p, v);
}

void GNSSIntegrity::finalize(State base_state, uint32_t extra_flags)
{
    _res.sequence = ++_seq;
    _res.state = base_state;
    if (_susp == Suspicion::ALARM) {
        _res.state = State::ALARM;
    } else if (_susp == Suspicion::WARNING) {
        _res.state = State::WARNING;
    }
    uint32_t f = _pending_flags | extra_flags;
    _pending_flags = 0;
    _res.armed_mask = _res.valid_mask = _res.warn_mask = _res.alarm_mask = 0;
    bool any_armed = false;
    for (uint8_t i = 0; i < NUM_HORIZONS; i++) {
        const Horizon &h = _h[i];
        HorizonResult hr = h.result();
        hr.armed = h.armed() && !h.expired();
        hr.expired = h.expired();
        _res.horizon[i] = hr;
        if (hr.armed) {
            any_armed = true;
            _res.armed_mask |= uint8_t(1U << i);
            if (hr.valid) { _res.valid_mask |= uint8_t(1U << i); }
            if (hr.warn) { _res.warn_mask |= uint8_t(1U << i); }
            if (hr.alarm) { _res.alarm_mask |= uint8_t(1U << i); }
        }
    }
    bool any_valid = false;
    for (uint8_t i = 0; i < NUM_HORIZONS; i++) {
        any_valid = any_valid || (_res.horizon[i].armed && _res.horizon[i].valid);
    }
    if (_ever_seeded && ((!any_armed && !_gate_open) || (_susp != Suspicion::NONE && !any_valid))) {
        _reseed_required = true;
    }
    _res.trusted_seed_valid = any_armed;
    _res.heading_valid = _heading.valid(_res.time_us, _cfg);
    _res.bias_valid = _bias.valid(_cfg);
    _res.accel_bias_norm_mps2 = _bias.bias().norm();
    if (_res.trusted_seed_valid) { f |= FLAG_TRUSTED_SEED; }
    if (_res.heading_valid) { f |= FLAG_HEADING_VALID; }
    if (_res.bias_valid) { f |= FLAG_BIAS_VALID; }
    if (_res.ground_test_valid) { f |= FLAG_GROUND_TEST_VALID; }
    if (_res.altitude_test_valid) { f |= FLAG_BARO_TEST_VALID; }
    if (_gate_open) { f |= FLAG_TRUST_GATE_OPEN; }
    if (_prop.gravity_fault()) { f |= FLAG_GRAVITY_FAULT; }
    if (_bias.change_point()) { f |= FLAG_BIAS_CHANGE_POINT; }
    if (_bias.ned_fixed_preferred()) { f |= FLAG_NED_FIXED_PREFERRED; }
    if (_heading.disturbed()) { f |= FLAG_HEADING_DISTURBED; }
    if (_reseed_required) { f |= FLAG_RESEED_REQUIRED; }
    if (_susp == Suspicion::ALARM) { f |= FLAG_ALARM_LATCHED; }
    _res.flags = f;
    const float r = _res.max_alarm_ratio > 0.0f ? _res.max_alarm_ratio : 0.0f;
    _res.confidence = r / (1.0f + r);
}

void GNSSIntegrity::observe_gnss(const GNSSObservation &obs)
{
    if (!_cfg.enabled) {
        _res.state = State::DISABLED;
        return;
    }
    update();
    if (!_prop.started()) {
        _res.state = State::INITIALIZING;
        return;
    }
    const AlignResult a = _align.align(obs, _prop.newest_time_us(), _prop.oldest_time_us(), _cfg);
    if (a.status == AlignStatus::DUPLICATE) {
        return;   // same fix already evaluated
    }
    _res.fix_age_ms = a.fix_age_ms;
    _res.applied_lag_ms = a.applied_lag_ms;
    Snapshot S;
    if (a.status != AlignStatus::OK || !_prop.at(a.measurement_time_us, _cfg.max_extrapolation_us, S)) {
        // Never compare a delayed fix with the predictor's current time.
        _cnt.fixes_rejected++;
        _pending_flags |= FLAG_FIX_UNALIGNABLE;
        return;
    }
    _align.accept(a);
    if (!(obs.fix_valid && obs.position_valid && obs.velocity_valid)) {
        _cnt.fixes_rejected++;   // GNSS outage / no 3D fix: no evidence either way
        return;
    }
    _cnt.fixes_evaluated++;
    _res.time_us = a.measurement_time_us;

    uint32_t extra = 0;
    // --- Stationary-ground constraint (needs no origin and no horizon)
    _res.ground_test_valid = _cfg.ground_test_enabled && _ground.landed_valid && _ground.landed &&
                             !_ground.moving_platform && _prop.still();
    const bool ground_warn = _res.ground_test_valid && ResidualTests::ground_exceeds(obs.velocity_ned_mps, _cfg);
    if (ground_warn) {
        extra |= FLAG_GROUND_WARN;
    }

    // --- Horizon expiry and bias learning (only while the trust gate is open)
    for (uint8_t i = 0; i < NUM_HORIZONS; i++) {
        Horizon &h = _h[i];
        // While suspicion is active no fresh reference can be armed, so the pre-onset horizons are
        // kept (EXTENDED) instead of expiring: they are the only GNSS-independent evidence left.
        if (h.due(a.measurement_time_us) && _susp == Suspicion::NONE) {
            Mat3 dM1;
            Vec3 rv, var;
            float T = 0.0f;
            const bool learn = _gate_open && (i == 1 || i == 2) && !_prop.gravity_fault() &&
                               h.last_bias_measurement(dM1, rv, var, T);
            if (learn) {
                _bias.update(dM1, rv, var, h.seed().bias, T, _heading.yaw(), a.measurement_time_us, _cfg);
                _cnt.bias_updates++;
            }
            h.mark_expired();
            _cnt.horizon_expiries++;
        }
    }

    bool any_test = false, warn_now = ground_warn, alarm_now = false;
    float max_ratio = 0.0f;
    float baro_res = 0.0f, dv_res = 0.0f, dv_ratio = -1.0f, baro_ratio = -1.0f;
    _res.altitude_test_valid = false;
    if (_res.ground_test_valid) {
        any_test = true;
        max_ratio = obs.velocity_ned_mps.norm_xy() / (2.0f * _cfg.ground_speed_max_mps);
    }

    Vec3 p_gnss;
    bool have_ned = false;
    if (_origin_valid) {
        p_gnss = to_ned(obs.lat_e7, obs.lon_e7, obs.alt_cm);
        if (p_gnss.norm_xy() > _cfg.origin_reset_distance_m) {
            for (uint8_t i = 0; i < NUM_HORIZONS; i++) {
                _h[i].disarm(HorizonReason::ORIGIN_RESET);
            }
            _origin_valid = false;
            extra |= FLAG_ORIGIN_RESET;
        } else {
            have_ned = true;
        }
    }

    if (have_ned && !_prop.gravity_fault()) {
        const GNSSNoise n = NoiseModel::gnss(obs, _cfg);
        HorizonEvalInput in;
        in.S = S;
        in.p_gnss = p_gnss;
        in.v_gnss = obs.velocity_ned_mps;
        in.gnss_pos_var = n.pos_var;
        in.gnss_vel_var = n.vel_var;
        in.use_vertical_velocity = obs.have_vertical_velocity;
        in.yaw_sigma = _heading.sigma(a.measurement_time_us, _cfg);
        in.heading_valid = _heading.valid(a.measurement_time_us, _cfg);
        in.baro_valid = _baro.altitude_at(a.measurement_time_us, in.baro_m);
        if (!in.baro_valid) {
            in.baro_m = 0.0f;
        }
        for (uint8_t i = 0; i < NUM_HORIZONS; i++) {
            Horizon &h = _h[i];
            if (!h.evaluate(in, _cfg, _susp != Suspicion::NONE)) {
                continue;
            }
            const HorizonResult &hr = h.result();
            if (hr.valid) {
                any_test = true;
                warn_now = warn_now || hr.warn;
                alarm_now = alarm_now || hr.alarm;
                if (hr.vector_valid) {
                    max_ratio = fmaxf(max_ratio, fmaxf(hr.position_test_statistic, hr.velocity_test_statistic) / _cfg.chi2_3_alarm);
                }
                const float dr = hr.delta_speed_test_statistic / _cfg.chi2_1_alarm;
                max_ratio = fmaxf(max_ratio, dr);
                if (dr > dv_ratio) {
                    dv_ratio = dr;
                    dv_res = hr.delta_speed_residual_mps;
                }
            }
            if (hr.baro_valid && hr.elapsed_s >= 1.0f) {
                _res.altitude_test_valid = true;
                any_test = true;
                const float br = hr.baro_test_statistic / _cfg.chi2_1_alarm;
                if (br > baro_ratio) {
                    baro_ratio = br;
                    baro_res = hr.baro_residual_m;
                }
                if (hr.baro_test_statistic >= _cfg.chi2_1_warn) {
                    warn_now = true;               // supporting evidence: WARNING at most
                    extra |= FLAG_BARO_WARN;
                }
            }
        }
    }
    _res.delta_speed_residual_mps = dv_res;
    _res.baro_delta_residual_m = baro_res;
    _res.max_alarm_ratio = max_ratio;

    // --- Persistence and hysteresis on the JOINT result (horizons are correlated)
    // Most sensitive horizon currently warning / currently clean (for sensitivity-aware clearing).
    float warn_vel_sigma = 1.0e9f, warn_pos_sigma = 1.0e9f;
    bool ins_warn_now = false, sensitive_clean = false, elevated_now = false;
    for (uint8_t i = 0; i < NUM_HORIZONS; i++) {
        const Horizon &h = _h[i];
        if (!h.armed() || h.expired()) {
            continue;
        }
        const HorizonResult &hr = h.result();
        if (!hr.valid) {
            continue;
        }
        elevated_now = elevated_now || hr.elevated;
        if (hr.warn) {
            ins_warn_now = true;
            warn_vel_sigma = fminf(warn_vel_sigma, hr.velocity_sigma_mps);
            warn_pos_sigma = fminf(warn_pos_sigma, hr.position_sigma_m);
        } else if (_susp_ins &&
                   (hr.velocity_sigma_mps <= _cfg.clear_sensitivity_ratio * _onset_vel_sigma ||
                    hr.position_sigma_m <= _cfg.clear_sensitivity_ratio * _onset_pos_sigma)) {
            sensitive_clean = true;
        }
    }
    if (any_test) {
        if (warn_now) {
            if (_warn_streak < 255) { _warn_streak++; }
            _clean_streak = 0;
            _clear_streak = 0;
        } else {
            _warn_streak = 0;
            if (_clean_streak < 65535) { _clean_streak++; }
            // An INS-raised WARNING clears only through a horizon at least about as sensitive as the
            // one that raised it: long horizons are too loose to vouch for a short-horizon exceedance.
            // An elevated (sub-warning) statistic pauses clearing: hysteresis.
            if ((!_susp_ins || sensitive_clean) && !elevated_now) {
                if (_clear_streak < 255) { _clear_streak++; }
            }
        }
        if (alarm_now) {
            if (_alarm_streak < 255) { _alarm_streak++; }
        } else {
            _alarm_streak = 0;
        }
        if (_alarm_streak >= _cfg.alarm_persist) {
            _susp = Suspicion::ALARM;          // latched until an independent reseed
        } else if (_warn_streak >= _cfg.warn_persist && _susp == Suspicion::NONE) {
            _susp = Suspicion::WARNING;
            _susp_ins = ins_warn_now;
            _onset_vel_sigma = ins_warn_now ? warn_vel_sigma : 0.0f;
            _onset_pos_sigma = ins_warn_now ? warn_pos_sigma : 0.0f;
            _clear_streak = 0;
        } else if (_susp == Suspicion::WARNING && ins_warn_now && !_susp_ins) {
            _susp_ins = true;                  // a baro/ground warning later confirmed by the INS tests
            _onset_vel_sigma = warn_vel_sigma;
            _onset_pos_sigma = warn_pos_sigma;
        } else if (_susp == Suspicion::WARNING && _clear_streak >= _cfg.clear_persist) {
            _susp = Suspicion::NONE;
            _susp_ins = false;
            _clean_streak = 0;                 // requalify before GNSS may re-arm anything
        }
    }
    if (_susp == Suspicion::WARNING && _susp_ins && !sensitive_clean && !ins_warn_now) {
        extra |= FLAG_CLEAR_BLOCKED;
    }
    _gate_open = _ever_seeded && _susp == Suspicion::NONE && _clean_streak >= _cfg.requalify_fixes;

    // --- Re-arm candidates: each fix becomes a candidate seed; it is usable only after
    // rearm_confirm_fixes later fixes were evaluated with no warning of any kind.
    if (any_test && warn_now) {
        for (uint8_t i = 0; i < NUM_CANDIDATES; i++) {
            _cand[i].used = false;
        }
    } else if (any_test) {
        for (uint8_t i = 0; i < NUM_CANDIDATES; i++) {
            if (_cand[i].used && _cand[i].confirmations < 255) {
                _cand[i].confirmations++;
            }
        }
    }
    if (have_ned && !_prop.gravity_fault() && !(any_test && warn_now)) {
        const GNSSNoise n = NoiseModel::gnss(obs, _cfg);
        Candidate &c = _cand[_cand_head];
        _cand_head = uint8_t((_cand_head + 1) % NUM_CANDIDATES);
        c.used = true;
        c.confirmations = 0;
        c.seed.time_us = a.measurement_time_us;
        c.seed.p0 = p_gnss;
        c.seed.v0 = obs.velocity_ned_mps;
        c.seed.pos_sigma = sqrtf(n.pos_var.x);
        c.seed.pos_sigma_v = sqrtf(n.pos_var.z);
        c.seed.vel_sigma = sqrtf(n.vel_var.x);
        c.seed.vel_sigma_v = sqrtf(n.vel_var.z);
        c.seed.bias = _bias.bias();
        c.seed.bias_sigma = _bias.sigma();
        c.seed.baro_valid = _baro.altitude_at(a.measurement_time_us, c.seed.baro0_m);
        if (!c.seed.baro_valid) {
            c.seed.baro0_m = 0.0f;
        }
        c.seed.provenance = SeedProvenance::VALIDATED_GNSS_PERIOD;
    }

    // --- Re-arm expired / event-invalidated horizons from a confirmed candidate, only through the trust gate
    if (_gate_open && !_prop.gravity_fault()) {
        const Candidate *best = nullptr;
        for (uint8_t i = 0; i < NUM_CANDIDATES; i++) {
            const Candidate &c = _cand[i];
            if (c.used && c.confirmations >= _cfg.rearm_confirm_fixes &&
                (best == nullptr || c.seed.time_us > best->seed.time_us) &&
                c.seed.time_us >= _prop.oldest_time_us()) {
                best = &c;
            }
        }
        Snapshot S0;
        if (best != nullptr && _prop.at(best->seed.time_us, _cfg.max_extrapolation_us, S0)) {
            for (uint8_t i = 0; i < NUM_HORIZONS; i++) {
                if (!horizon_enabled(i)) {
                    continue;
                }
                const Horizon &h = _h[i];
                const HorizonReason why = h.result().reason;
                const bool event_invalid = why == HorizonReason::IMU_GAP || why == HorizonReason::IMU_OVERFLOW ||
                                           why == HorizonReason::ACCEL_CLIPPING || why == HorizonReason::ATTITUDE_INVALID ||
                                           why == HorizonReason::HEADING_EPOCH_CHANGED || why == HorizonReason::ORIGIN_RESET;
                if (!h.armed() || h.expired() || event_invalid) {
                    arm_horizon(i, best->seed, S0);
                }
            }
        }
    }

    // --- Base state (suspicion overrides it in finalize)
    bool any_active = false, any_valid = false, any_vector = false;
    for (uint8_t i = 0; i < NUM_HORIZONS; i++) {
        const Horizon &h = _h[i];
        if (h.armed() && !h.expired()) {
            any_active = true;
            any_valid = any_valid || h.result().valid;
            any_vector = any_vector || h.result().vector_valid;
        }
    }
    State base;
    if (!_ever_seeded || !any_active) {
        base = State::NO_TRUSTED_SEED;
    } else if (_prop.gravity_fault() || !any_valid) {
        base = State::DEGRADED;
    } else if (!any_vector) {
        base = State::HEADING_UNOBSERVABLE;
    } else {
        base = State::VALID;
    }
    finalize(base, extra);
}

} // namespace GNSSInt
