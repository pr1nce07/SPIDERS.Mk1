/*
 * Host unit tests for the portable GNSSIntegrity core (integration guide §19.1).
 *
 * Self-contained (no gtest) so it builds with any C++11 compiler:
 *   g++ -std=gnu++11 -O2 -Wall -Wextra -Werror -Wdouble-promotion -Wfloat-conversion \
 *       -I ../AP_IDS/GNSSIntegrity test_gnss_integrity.cpp <all GNSSIntegrity .cpp files> -o t
 * or simply: ./run_tests.sh   (also run by backend/tests/test_native_gnss_integrity.py)
 *
 * The simulator generates a level vehicle (roll/pitch configurable) with exact
 * NED kinematics, an IMU with optional bias/noise, a GNSS receiver with latency
 * and optional spoofing offsets, a barometer and a magnetometer-like heading.
 */
#include "GNSSIntegrity.h"
#include "GNSSIntegrityLog.h"

#include <stdio.h>
#include <string.h>

using namespace GNSSInt;

static int g_failures = 0;
static int g_checks = 0;
#define CHECK(cond) do { g_checks++; if (!(cond)) { g_failures++; printf("    FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define CHECK_NEAR(a, b, tol) do { g_checks++; const double _a = double(a), _b = double(b); if (!(fabs(_a - _b) <= double(tol))) { g_failures++; \
    printf("    FAIL %s:%d  %s=%.6f vs %s=%.6f (tol %g)\n", __FILE__, __LINE__, #a, _a, #b, _b, double(tol)); } } while (0)

// ------------------------------------------------------------------ RNG
struct Rng {
    uint64_t s;
    explicit Rng(uint64_t seed) : s(seed ? seed : 1) {}
    uint64_t next() { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }
    double uni() { return double(next() >> 11) * (1.0 / 9007199254740992.0); }
    double gauss() {
        double u1 = uni(), u2 = uni();
        if (u1 < 1e-300) { u1 = 1e-300; }
        return sqrt(-2.0 * log(u1)) * cos(2.0 * 3.141592653589793 * u2);
    }
};

// ------------------------------------------------------------------ simulator
struct Sim {
    GNSSIntegrity eng;
    Config cfg;
    // truth (double)
    double px = 0, py = 0, pz = 0, vx = 0, vy = 0, vz = 0;
    double ax = 0, ay = 0, az = 0;     // commanded NED acceleration
    double yaw = 0, yaw_rate = 0;
    float roll = 0.0f, pitch = 0.0f;
    uint64_t t_us = 1000000;
    uint32_t dt_us = 2500;
    uint32_t seq = 0;
    // sensor errors
    Vec3 accel_bias;
    double accel_noise = 0.0, gyro_noise = 0.0, gnss_pos_noise = 0.0, gnss_vel_noise = 0.0;
    double mag_noise = 0.0, mag_offset = 0.0;
    double baro_noise = 0.0, baro_offset = 0.0;
    bool kinematic_dv = false;          // feed gravity-removed delta velocity
    bool roll_pitch_valid = true;
    bool dv_valid = true;
    bool heading_enabled = true;
    // GNSS
    uint32_t gnss_period_us = 200000;
    uint32_t latency_us = 100000;
    double spoof_px = 0, spoof_py = 0, spoof_vx = 0, spoof_vy = 0, spoof_alt = 0;   // added to GNSS output
    double spoof_vel_rate = 0;   // drag-off: offset velocity grows the position offset
    bool spoof_ramp = false;
    struct PendingFix { bool used; uint64_t t_fix; GNSSObservation obs; };
    PendingFix pend[16];
    GNSSObservation last_obs;
    bool have_last_obs = false;
    uint64_t last_obs_fix_us = 0;
    static const int32_t LAT0 = 473977420, LON0 = 85455940, ALT0 = 48800;
    Rng imu_rng, gnss_rng, aux_rng;
    State worst = State::DISABLED;

    explicit Sim(uint64_t seed = 1) : imu_rng(seed), gnss_rng(seed * 7919 + 3), aux_rng(seed * 104729 + 11) {
        cfg.enabled = true;
        for (int i = 0; i < 16; i++) { pend[i].used = false; }
        last_obs = GNSSObservation();
    }
    void start() { eng.init(cfg); }

    IMUSample make_imu() {
        IMUSample s = IMUSample();
        const double dt = double(dt_us) * 1e-6;
        const double yaw_mid = yaw + 0.5 * yaw_rate * dt;
        const Mat3 R = Mat3::from_euler(roll, pitch, float(yaw_mid));
        const Vec3 a_n = Vec3(float(ax), float(ay), float(az));
        Vec3 f_b = R.transposed() * (kinematic_dv ? a_n : (a_n - Vec3(0.0f, 0.0f, kGravityMss)));
        f_b += accel_bias;
        Vec3 dv = f_b * float(dt);
        if (accel_noise > 0) {
            const double sd = accel_noise * sqrt(dt);   // velocity random walk per step
            dv += Vec3(float(imu_rng.gauss() * sd), float(imu_rng.gauss() * sd), float(imu_rng.gauss() * sd));
        }
        // level-ish body rates: yaw rate about NED down maps to body rates via R^T
        Vec3 w_b = R.transposed() * Vec3(0.0f, 0.0f, float(yaw_rate));
        // For the Euler relation used by the engine, express the yaw rate as body (q, r):
        const float cr = cosf(roll), sr = sinf(roll), cp = cosf(pitch);
        w_b = Vec3(0.0f, float(yaw_rate) * cp * sr, float(yaw_rate) * cp * cr);
        Vec3 da = w_b * float(dt);
        if (gyro_noise > 0) {
            const double sd = gyro_noise * sqrt(dt);
            da += Vec3(float(imu_rng.gauss() * sd), float(imu_rng.gauss() * sd), float(imu_rng.gauss() * sd));
        }
        s.time_us = t_us;
        s.sequence = ++seq;
        s.delta_angle_dt_s = float(dt);
        s.delta_velocity_dt_s = float(dt);
        s.delta_angle_rad = da;
        s.delta_velocity_mps = dv;
        s.delta_angle_valid = true;
        s.delta_velocity_valid = dv_valid;
        s.gyro_healthy = true;
        s.accel_healthy = true;
        s.accel_clipping = false;
        s.vibration = Vec3(2.0f, 2.0f, 3.0f);
        s.roll_rad = roll;
        s.pitch_rad = pitch;
        s.roll_pitch_valid = roll_pitch_valid;
        return s;
    }

    void advance_truth() {
        const double dt = double(dt_us) * 1e-6;
        px += vx * dt + 0.5 * ax * dt * dt;
        py += vy * dt + 0.5 * ay * dt * dt;
        pz += vz * dt + 0.5 * az * dt * dt;
        vx += ax * dt; vy += ay * dt; vz += az * dt;
        yaw += yaw_rate * dt;
        if (yaw > 3.141592653589793) { yaw -= 2 * 3.141592653589793; }
        if (yaw < -3.141592653589793) { yaw += 2 * 3.141592653589793; }
        t_us += dt_us;
        if (spoof_ramp) {
            spoof_px += spoof_vx * dt;
            spoof_py += spoof_vy * dt;
        }
    }

    GNSSObservation truth_fix() {
        GNSSObservation o = GNSSObservation();
        const double n = px + spoof_px + gnss_rng.gauss() * gnss_pos_noise;
        const double e = py + spoof_py + gnss_rng.gauss() * gnss_pos_noise;
        const double d = pz - spoof_alt + gnss_rng.gauss() * gnss_pos_noise * 1.5;
        const double lsf = 0.011131884502145034;
        const double lon_scale = cos(double(LAT0) * 1e-7 * 3.141592653589793 / 180.0);
        o.lat_e7 = LAT0 + int32_t(llround(n / lsf));
        o.lon_e7 = LON0 + int32_t(llround(e / (lsf * lon_scale)));
        o.alt_cm = ALT0 - int32_t(llround(d * 100.0));
        o.velocity_ned_mps = Vec3(float(vx + spoof_vx + gnss_rng.gauss() * gnss_vel_noise),
                                  float(vy + spoof_vy + gnss_rng.gauss() * gnss_vel_noise),
                                  float(vz + gnss_rng.gauss() * gnss_vel_noise));
        o.position_valid = o.velocity_valid = o.fix_valid = true;
        o.have_vertical_velocity = true;
        o.fix_time_ms = uint32_t(t_us / 1000);
        return o;
    }

    // One IMU period: truth, IMU capture, scheduled tasks.
    void tick() {
        advance_truth();
        eng.capture_imu(make_imu());
        if (seq % 8 == 0) { eng.update(); }                         // 50 Hz drain
        if (t_us % 20000 == 0) {                                   // 50 Hz baro
            BaroObservation b;
            b.time_us = t_us;
            b.altitude_m = float(-pz + baro_offset + aux_rng.gauss() * baro_noise);
            b.healthy = true;
            eng.observe_baro(b);
        }
        if (heading_enabled && t_us % 100000 == 0) {               // 10 Hz heading
            HeadingObservation h;
            h.time_us = t_us;
            h.yaw_rad = wrap_pi(float(yaw + mag_offset + aux_rng.gauss() * mag_noise));
            h.sigma_rad = 0.05f;
            h.valid = true;
            eng.observe_heading(h);
        }
        if (t_us % gnss_period_us == 0) {                          // GNSS epoch: queue with latency
            for (int i = 0; i < 16; i++) {
                if (!pend[i].used) { pend[i].used = true; pend[i].t_fix = t_us; pend[i].obs = truth_fix(); break; }
            }
        }
        for (int i = 0; i < 16; i++) {
            if (pend[i].used && t_us >= pend[i].t_fix + latency_us) {
                pend[i].obs.message_time_ms = uint32_t(t_us / 1000);
                deliver(pend[i].obs, pend[i].t_fix);
                pend[i].used = false;
            }
        }
    }

    void deliver(const GNSSObservation &o, uint64_t t_fix) {
        last_obs = o;
        have_last_obs = true;
        last_obs_fix_us = t_fix;
        eng.observe_gnss(o);
        const State s = eng.get_result().state;
        if (uint8_t(s) > uint8_t(worst) && (s == State::WARNING || s == State::ALARM)) { worst = s; }
        if (s == State::ALARM) { worst = State::ALARM; }
    }

    void run(double seconds) {
        const uint64_t n = uint64_t(seconds * 1e6 / double(dt_us));
        for (uint64_t i = 0; i < n; i++) { tick(); }
    }

    SeedStatus seed_stationary() {
        TrustedNavigationSeed sd = TrustedNavigationSeed();
        sd.provenance = SeedProvenance::PREFLIGHT_STATIONARY;
        sd.qualified = true;
        sd.time_us = last_obs_fix_us;
        sd.lat_e7 = last_obs.lat_e7;
        sd.lon_e7 = last_obs.lon_e7;
        sd.alt_cm = last_obs.alt_cm;
        sd.velocity_ned_mps = Vec3();
        sd.pos_sigma_m = 2.5f;
        sd.vel_sigma_mps = 0.05f;
        return eng.reset_to_trusted_state(sd);
    }
    SeedStatus seed_from_last(SeedProvenance prov) {
        TrustedNavigationSeed sd = TrustedNavigationSeed();
        sd.provenance = prov;
        sd.qualified = true;
        sd.time_us = last_obs_fix_us;
        sd.lat_e7 = last_obs.lat_e7;
        sd.lon_e7 = last_obs.lon_e7;
        sd.alt_cm = last_obs.alt_cm;
        sd.velocity_ned_mps = last_obs.velocity_ned_mps;
        sd.pos_sigma_m = 2.5f;
        sd.vel_sigma_mps = 0.3f;
        return eng.reset_to_trusted_state(sd);
    }
    // Typical realistic sensor errors.
    void realistic() {
        accel_noise = 0.02; gyro_noise = 0.002; gnss_pos_noise = 0.5; gnss_vel_noise = 0.05;
        mag_noise = 0.03; baro_noise = 0.1;
    }
    // Ground-up flight profile helper: piecewise accelerations with turns.
    void fly_pattern(double seconds) {
        const uint64_t n = uint64_t(seconds * 1e6 / double(dt_us));
        for (uint64_t i = 0; i < n; i++) {
            const double t = double(t_us) * 1e-6;
            const double ph = fmod(t, 40.0);
            ax = ph < 5 ? 1.0 : (ph < 10 ? -1.0 : (ph < 20 ? 0.5 * sin(t) : 0.0));
            ay = ph < 20 ? 0.0 : (ph < 25 ? 0.8 : (ph < 30 ? -0.8 : 0.3 * cos(0.5 * t)));
            az = ph < 3 ? -0.5 : (ph < 6 ? 0.5 : 0.0);
            yaw_rate = (ph > 12 && ph < 18) ? 0.3 : ((ph > 32 && ph < 36) ? -0.4 : 0.0);
            tick();
        }
    }
};

// ------------------------------------------------------------------ tests
static void test_log_contract()
{
    CHECK(strlen(GNSSINT_IDSG_FORMAT) <= 16);
    CHECK(strlen(GNSSINT_IDSR_FORMAT) <= 16);
    CHECK(strlen(GNSSINT_IDSG_LABELS) < 64);
    CHECK(strlen(GNSSINT_IDSR_LABELS) < 64);
    int commas = 0;
    for (const char *p = GNSSINT_IDSG_LABELS; *p; p++) { commas += *p == ','; }
    CHECK(commas + 1 == int(strlen(GNSSINT_IDSG_FORMAT)));
    commas = 0;
    for (const char *p = GNSSINT_IDSR_LABELS; *p; p++) { commas += *p == ','; }
    CHECK(commas + 1 == int(strlen(GNSSINT_IDSR_FORMAT)));
    CHECK(uint8_t(State::ALARM) == 7 && uint8_t(State::VALID) == 4);
    CHECK(kHorizonDurationS[0] == 2 && kHorizonDurationS[4] == 60);
}

static void test_stationary_level()
{
    Sim s; s.start();
    s.run(60.0);
    const Snapshot &S = s.eng.propagator().current();
    CHECK(S.V.to_float().norm() < 1e-3f);
    CHECK(S.P.to_float().norm() < 2e-2f);
    CHECK(!s.eng.propagator().gravity_fault());
}

static void test_constant_acceleration()
{
    Sim s; s.start();
    s.ax = 1.0; s.yaw = 0.7;      // NED acceleration with a non-zero, absolutely known heading
    s.run(0.2);                  // heading initialised at t=1.1 s
    const DVec3 V0 = s.eng.propagator().current().V;
    const DVec3 P0 = s.eng.propagator().current().P;
    const double vx0 = s.vx, px0 = s.px;
    s.run(10.0);
    const DVec3 dV = s.eng.propagator().current().V - V0;
    const DVec3 dP = s.eng.propagator().current().P - P0 - V0 * 10.0;
    CHECK_NEAR(dV.x, s.vx - vx0, 2e-3);
    CHECK_NEAR(dV.y, 0.0, 2e-3);
    CHECK_NEAR(dP.x, (s.px - px0) - vx0 * 10.0, 2e-2);
}

static void test_pure_rotation()
{
    Sim s; s.heading_enabled = false; s.start();
    s.yaw_rate = 0.5;
    s.run(10.0);
    const Snapshot &S = s.eng.propagator().current();
    CHECK(S.V.to_float().norm() < 1e-3f);
    CHECK_NEAR(fabsf(wrap_pi(s.eng.heading().yaw() - float(s.yaw))), 0.0, 2e-3);
    CHECK(!s.eng.heading().absolute());   // relative track only: gyro cannot find North
}

static void test_roll_pitch_gravity_projection()
{
    Sim s; s.start();
    s.roll = 0.3f; s.pitch = -0.2f;
    s.run(30.0);
    CHECK(s.eng.propagator().current().V.to_float().norm() < 2e-3f);
}

static void test_wrong_gravity_convention_detected()
{
    // IMU delivers gravity-removed (kinematic) increments, config says specific force.
    Sim a; a.kinematic_dv = true; a.start();
    a.run(4.0);
    CHECK(a.eng.propagator().gravity_fault());
    CHECK(a.eng.propagator().current().V.to_float().norm() > 20.0f);   // the misconfiguration is not silent
    // IMU delivers specific force, config claims kinematic: sign/convention regression.
    Sim b; b.cfg.delta_velocity_is_specific_force = false; b.start();
    b.run(4.0);
    CHECK(b.eng.propagator().gravity_fault());
    // Correct convention: no fault.
    Sim c; c.start(); c.run(4.0);
    CHECK(!c.eng.propagator().gravity_fault());
}

static void test_duplicate_timestamp_rejected()
{
    Sim s; s.start();
    s.run(1.0);              // at rest: the first sample only sets the time base
    s.ax = 2.0;
    s.run(0.5);
    s.advance_truth();
    const IMUSample smp = s.make_imu();
    CHECK(s.eng.capture_imu(smp));
    CHECK(!s.eng.capture_imu(smp));       // same increment offered twice
    s.eng.update();
    CHECK(s.eng.counters().imu_duplicates == 1);
    s.run(0.5);
    s.eng.update();
    CHECK_NEAR(s.eng.propagator().current().V.x, s.vx, 1e-3);   // integrated once, not twice
}

static void seed_after_still(Sim &s)
{
    s.run(2.0);
    CHECK(s.seed_stationary() == SeedStatus::ACCEPTED);
}

static void test_gap_invalidates_without_alarm()
{
    Sim s; s.realistic(); s.start();
    seed_after_still(s);
    s.ax = 0.5;
    s.run(1.0);
    // Drop 12 IMU increments (30 ms) while the truth keeps moving.
    for (int i = 0; i < 12; i++) { s.advance_truth(); }
    s.run(0.5);
    CHECK(s.eng.counters().imu_gaps >= 1);
    const Result &r = s.eng.get_result();
    CHECK(r.state == State::DEGRADED || r.state == State::NO_TRUSTED_SEED);
    CHECK(r.horizon[4].reason == HorizonReason::IMU_GAP);
    CHECK(s.worst != State::ALARM && s.worst != State::WARNING);
}

static void test_delta_valid_false_invalidates()
{
    Sim s; s.start();
    seed_after_still(s);
    s.dv_valid = false;
    s.run(0.05);
    s.dv_valid = true;
    s.run(0.5);
    CHECK(s.eng.get_result().horizon[4].reason == HorizonReason::IMU_GAP);
    CHECK(s.worst != State::ALARM);
}

static void test_attitude_invalid_degrades()
{
    Sim s; s.start();
    seed_after_still(s);
    s.roll_pitch_valid = false;
    s.run(0.1);
    s.roll_pitch_valid = true;
    s.run(0.5);
    CHECK(s.eng.get_result().horizon[3].reason == HorizonReason::ATTITUDE_INVALID);
    CHECK(s.eng.get_result().state == State::DEGRADED);
    CHECK(s.worst != State::ALARM);
}

static void test_overflow_counted_and_invalidates()
{
    Sim s; s.start();
    seed_after_still(s);
    for (int i = 0; i < 100; i++) {      // consumer stalls: more than CAPACITY samples
        s.advance_truth();
        s.eng.capture_imu(s.make_imu());
    }
    CHECK(s.eng.counters().imu_overflows == 0);   // counters are refreshed by update()
    s.eng.update();
    CHECK(s.eng.counters().imu_overflows > 0);
    CHECK(s.eng.counters().buffer_high_water == InertialSampleBuffer::CAPACITY - 1);
    s.run(0.6);
    CHECK(s.eng.get_result().horizon[4].reason == HorizonReason::IMU_OVERFLOW);
}

static void test_yaw_unavailable_heading_free_only()
{
    Sim s; s.heading_enabled = false; s.realistic(); s.start();
    seed_after_still(s);
    s.ax = 0.5;
    s.run(1.5);
    const Result &r = s.eng.get_result();
    CHECK(r.state == State::HEADING_UNOBSERVABLE);
    CHECK(r.horizon[1].valid && !r.horizon[1].vector_valid);
    CHECK(r.horizon[1].reason == HorizonReason::HEADING_INVALID);
    CHECK(!(r.flags & FLAG_HEADING_VALID));
}

static void test_prediction_independent_of_gnss()
{
    // THE invariant: once armed, GNSS after the start cannot change the inertial prediction.
    Sim a(42), b(42);
    a.realistic(); b.realistic();
    a.start(); b.start();
    seed_after_still(a);
    seed_after_still(b);
    a.fly_pattern(67.0);     // identical histories: the 60 s horizon has re-armed once (at ~63 s)
    b.fly_pattern(67.0);
    const uint64_t armed_at = a.eng.horizon(4).start_us();
    CHECK(armed_at == b.eng.horizon(4).start_us());
    CHECK(a.eng.horizon(4).seed().provenance == SeedProvenance::VALIDATED_GNSS_PERIOD);
    // b's receiver is now spoofed (3 m/s drag-off); a's stays clean.
    b.spoof_vx = 3.0; b.spoof_ramp = true;
    a.fly_pattern(20.0);
    b.fly_pattern(20.0);
    CHECK(a.eng.horizon(4).start_us() == armed_at && b.eng.horizon(4).start_us() == armed_at);
    const uint64_t t = a.t_us - 300000;
    Vec3 pa, va, pb, vb;
    CHECK(a.eng.predict_horizon(4, t, pa, va));
    CHECK(b.eng.predict_horizon(4, t, pb, vb));
    CHECK(memcmp(&pa, &pb, sizeof(pa)) == 0);
    CHECK(memcmp(&va, &vb, sizeof(va)) == 0);
    const Snapshot &sa = a.eng.propagator().current(), &sb = b.eng.propagator().current();
    CHECK(memcmp(&sa.V, &sb.V, sizeof(sa.V)) == 0 && memcmp(&sa.P, &sb.P, sizeof(sa.P)) == 0);
    CHECK(memcmp(&sa.M1, &sb.M1, sizeof(sa.M1)) == 0 && memcmp(&sa.M2, &sb.M2, sizeof(sa.M2)) == 0);
    // and the spoofed receiver was detected while the clean one was not
    CHECK(b.worst == State::ALARM);
    CHECK(a.worst != State::ALARM && a.worst != State::WARNING);
    CHECK(!b.eng.trust_gate_open());
}

static void test_clean_flight_no_false_alarm()
{
    for (uint64_t seed = 1; seed <= 3; seed++) {
        Sim s(seed); s.realistic(); s.accel_bias = Vec3(0.03f, -0.02f, 0.01f); s.start();
        seed_after_still(s);
        s.fly_pattern(180.0);
        CHECK(s.worst != State::WARNING && s.worst != State::ALARM);
        const Result &r = s.eng.get_result();
        CHECK(r.state == State::VALID);
        CHECK(r.flags & FLAG_TRUST_GATE_OPEN);
        CHECK(s.eng.counters().fixes_rejected == 0);
        if (s.worst == State::WARNING || s.worst == State::ALARM) {
            printf("    (seed %llu false alarm)\n", (unsigned long long)seed);
        }
    }
}

static uint64_t time_to(Sim &s, State want, double max_s)
{
    const uint64_t onset = s.t_us;
    for (int i = 0; i < int(max_s * 400); i++) {
        s.fly_pattern(0.0025);
        const State st = s.eng.get_result().state;
        if (st == want || (want == State::WARNING && st == State::ALARM)) {
            return s.t_us - onset;
        }
    }
    return 0;
}

static void test_spoof_velocity_drag_off_detected()
{
    Sim s(5); s.realistic(); s.start();
    seed_after_still(s);
    s.fly_pattern(60.0);
    CHECK(s.worst != State::WARNING && s.worst != State::ALARM);
    s.spoof_vx = 3.0; s.spoof_ramp = true;    // drag-off: 3 m/s velocity offset, position follows consistently
    const uint64_t dt_alarm = time_to(s, State::ALARM, 10.0);
    CHECK(dt_alarm != 0);
    printf("    3 m/s drag-off: ALARM %.1f s after onset\n", double(dt_alarm) * 1e-6);
    CHECK(!(s.eng.get_result().flags & FLAG_TRUST_GATE_OPEN));
    CHECK(s.eng.get_result().confidence > 0.5f);
    CHECK(s.eng.get_result().flags & FLAG_ALARM_LATCHED);

    Sim w(5); w.realistic(); w.start();
    seed_after_still(w);
    w.fly_pattern(60.0);
    w.spoof_vx = 2.0; w.spoof_ramp = true;    // weaker: WARNING expected with the default thresholds
    const uint64_t dt_warn = time_to(w, State::WARNING, 10.0);
    CHECK(dt_warn != 0);
    printf("    2 m/s drag-off: WARNING %.1f s after onset\n", double(dt_warn) * 1e-6);
}

static void test_position_step_detected()
{
    Sim s(11); s.realistic(); s.start();
    seed_after_still(s);
    s.fly_pattern(45.0);
    s.spoof_px = 25.0;      // abrupt 25 m position jump, velocity untouched
    const uint64_t dt = time_to(s, State::ALARM, 5.0);
    CHECK(dt != 0);
    printf("    25 m position step: ALARM %.1f s after onset\n", double(dt) * 1e-6);
}

static void test_altitude_only_mismatch_warns()
{
    Sim s(12); s.realistic(); s.start();
    seed_after_still(s);
    s.fly_pattern(45.0);
    s.spoof_alt = 30.0;     // GNSS altitude-only manipulation: baro (and the INS vertical channel) disagree
    const uint64_t dt = time_to(s, State::WARNING, 5.0);
    CHECK(dt != 0);
    CHECK(s.eng.get_result().flags & FLAG_BARO_WARN);
}

static void test_transient_warning_clears()
{
    Sim s(13); s.realistic(); s.start();
    seed_after_still(s);
    s.fly_pattern(60.0);
    s.spoof_vx = 2.0;       // 1.5 s receiver velocity glitch (position not dragged)
    CHECK(time_to(s, State::WARNING, 3.0) != 0);
    s.fly_pattern(1.0);
    s.spoof_vx = 0.0;
    s.fly_pattern(20.0);
    CHECK(s.eng.get_result().state == State::VALID);
    CHECK(s.eng.trust_gate_open());
}

static void test_bias_learning()
{
    Sim s(3); s.realistic(); s.accel_bias = Vec3(0.12f, -0.08f, 0.05f); s.start();
    seed_after_still(s);
    s.fly_pattern(240.0);
    const Vec3 b = s.eng.bias().bias();
    printf("    bias estimate (%.3f, %.3f, %.3f), truth (0.120, -0.080, 0.050), sigma %.3f, updates %u\n",
           double(b.x), double(b.y), double(b.z), double(s.eng.bias().sigma()), s.eng.bias().updates());
    CHECK(s.eng.bias().updates() > 10);
    CHECK_NEAR(b.x, 0.12, 0.04);
    CHECK_NEAR(b.y, -0.08, 0.04);
    CHECK_NEAR(b.z, 0.05, 0.04);
    CHECK(s.worst != State::WARNING && s.worst != State::ALARM);
}

static void test_alarm_latched_and_bias_frozen()
{
    Sim s(4); s.realistic(); s.start();
    seed_after_still(s);
    s.fly_pattern(40.0);
    s.spoof_vx = 3.0; s.spoof_ramp = true;
    CHECK(time_to(s, State::ALARM, 10.0) != 0);
    const uint32_t n = s.eng.bias().updates();
    const Vec3 b = s.eng.bias().bias();
    s.fly_pattern(5.0);
    bool extended = false;
    for (int i = 0; i < NUM_HORIZONS; i++) { extended = extended || s.eng.get_result().horizon[i].extended; }
    CHECK(extended);        // pre-onset references are kept past their duration instead of expiring
    s.fly_pattern(85.0);    // the spoofed receiver must not re-establish the baseline
    CHECK(s.eng.get_result().state == State::ALARM);
    CHECK(!s.eng.trust_gate_open());
    CHECK(s.eng.bias().updates() == n);
    CHECK(memcmp(&b, &s.eng.bias().bias(), sizeof(b)) == 0);
    CHECK(s.eng.get_result().valid_mask == 0);      // extended references finally exceeded their uncertainty bounds
    CHECK(s.eng.get_result().flags & FLAG_RESEED_REQUIRED);
}

static void test_heading_disturbance()
{
    Sim s; s.start();
    s.run(2.0);
    CHECK(s.eng.heading().absolute());
    const float sig0 = s.eng.heading().sigma(s.t_us, s.cfg);
    s.mag_offset = 1.0;     // magnetic disturbance: 57 deg
    s.run(3.0);
    CHECK(s.eng.heading().disturbed());
    CHECK(fabsf(wrap_pi(s.eng.heading().yaw() - float(s.yaw))) < 0.05f);   // not pulled by the disturbance
    CHECK(s.eng.heading().sigma(s.t_us, s.cfg) > sig0);
}

static void test_out_of_order_and_latency()
{
    Sim s; s.start();
    seed_after_still(s);
    s.run(1.0);
    const uint32_t rej = s.eng.counters().fixes_rejected;
    GNSSObservation old = s.last_obs;
    old.fix_time_ms -= 400;              // older than the last evaluated fix
    s.eng.observe_gnss(old);
    CHECK(s.eng.counters().fixes_rejected == rej + 1);
    GNSSObservation stale = s.last_obs;
    stale.fix_time_ms -= 3000;           // outside the retained inertial history
    s.eng.observe_gnss(stale);
    CHECK(s.eng.counters().fixes_rejected == rej + 2);
    GNSSObservation future = s.last_obs;
    future.fix_time_ms += 1000;          // ahead of the IMU: would need extrapolation
    s.eng.observe_gnss(future);
    CHECK(s.eng.counters().fixes_rejected == rej + 3);
    s.run(0.5);
    CHECK(s.eng.get_result().flags & FLAG_FIX_UNALIGNABLE || s.eng.counters().fixes_rejected == rej + 3);
    CHECK(s.eng.get_result().state == State::VALID);
}

static void test_horizon_expiry_once()
{
    Sim s; s.realistic(); s.start();
    seed_after_still(s);
    s.run(3.0);          // trust gate not open yet (requalify), so the 2 s horizon cannot re-arm
    CHECK(!s.eng.trust_gate_open());
    CHECK(s.eng.horizon(0).expiries() == 1);
    CHECK(s.eng.horizon(0).expired());
    CHECK(s.eng.get_result().horizon[0].expired);
    CHECK(s.eng.get_result().horizon[0].elapsed_s > 1.7f);   // final result retained
    s.run(1.0);
    CHECK(s.eng.horizon(0).expiries() == 1);
    s.run(4.0);          // gate opens -> re-armed from a validated GNSS period
    CHECK(s.eng.trust_gate_open());
    CHECK(s.eng.horizon(0).seed().provenance == SeedProvenance::VALIDATED_GNSS_PERIOD);
}

static void test_reseed_during_suspicion_rejected()
{
    Sim s(6); s.realistic(); s.start();
    seed_after_still(s);
    s.fly_pattern(30.0);
    s.spoof_vx = 3.0; s.spoof_ramp = true;
    s.fly_pattern(8.0);
    CHECK(s.eng.get_result().state == State::ALARM);
    GroundState g; g.landed_valid = true; g.landed = false; g.moving_platform = false;
    s.eng.update_ground_state(g);
    CHECK(s.seed_stationary() == SeedStatus::SUSPICION_ACTIVE);
    CHECK(s.seed_from_last(SeedProvenance::VALIDATED_GNSS_PERIOD) == SeedStatus::BAD_PROVENANCE);
    CHECK(s.eng.get_result().state == State::ALARM);
    CHECK(s.seed_from_last(SeedProvenance::OPERATOR) == SeedStatus::ACCEPTED);   // explicit independent anchor
}

// Regression: a stationary, landed vehicle is not an independent anchor. Its GNSS fix can be the
// spoofed quantity, so a landed PREFLIGHT_STATIONARY reseed during suspicion must also be refused.
static void test_landed_reseed_during_suspicion_rejected()
{
    Sim s(6); s.realistic(); s.start();
    seed_after_still(s);
    s.fly_pattern(30.0);
    s.spoof_vx = 3.0; s.spoof_ramp = true;
    s.fly_pattern(8.0);
    CHECK(s.eng.get_result().state == State::ALARM);
    GroundState g; g.landed_valid = true; g.landed = true; g.moving_platform = false;
    s.eng.update_ground_state(g);
    CHECK(s.seed_stationary() == SeedStatus::SUSPICION_ACTIVE);
    CHECK(s.eng.get_result().state == State::ALARM);   // still latched
}

static void test_ground_constraint()
{
    Sim s; s.start();
    GroundState g; g.landed_valid = true; g.landed = true; g.moving_platform = false;
    s.eng.update_ground_state(g);
    seed_after_still(s);
    s.run(2.0);
    CHECK(s.eng.get_result().ground_test_valid);
    CHECK(s.worst != State::WARNING);
    s.spoof_vx = 3.0;      // receiver claims 3 m/s while the vehicle sits on the ground
    s.run(2.0);
    CHECK(s.eng.get_result().flags & FLAG_GROUND_WARN);
    CHECK(s.worst == State::WARNING || s.worst == State::ALARM);

    Sim m; m.start();
    g.moving_platform = true;   // boat/vehicle launch: ground test must stay off
    m.eng.update_ground_state(g);
    seed_after_still(m);
    m.run(1.0);
    CHECK(!m.eng.get_result().ground_test_valid);
    GroundState un; un.landed_valid = false; un.landed = true; un.moving_platform = false;
    m.eng.update_ground_state(un);   // disarmed is not stationary: landed state must be valid
    m.run(1.0);
    CHECK(!m.eng.get_result().ground_test_valid);
}

static void test_baro_transient_warns_never_alarms()
{
    Sim s(8); s.realistic(); s.start();
    seed_after_still(s);
    s.fly_pattern(20.0);
    CHECK(s.eng.get_result().altitude_test_valid);
    s.baro_offset = 30.0;     // pressure transient / prop wash: baro jumps, GNSS and INS agree
    State worst_after = State::VALID;
    for (int i = 0; i < 10 * 400; i++) {
        s.fly_pattern(0.0025);
        const State st = s.eng.get_result().state;
        if (st == State::ALARM) { worst_after = State::ALARM; }
        else if (st == State::WARNING && worst_after != State::ALARM) { worst_after = State::WARNING; }
    }
    CHECK(worst_after == State::WARNING);
    CHECK(worst_after != State::ALARM);
}

static void test_disabled_is_passive()
{
    Sim s; s.cfg.enabled = false; s.start();
    s.run(3.0);
    CHECK(s.eng.get_result().state == State::DISABLED);
    CHECK(s.eng.counters().imu_accepted == 0);
    CHECK(s.seed_stationary() == SeedStatus::DISABLED);
}

int main()
{
    struct { const char *name; void (*fn)(); } tests[] = {
        {"log record contract", test_log_contract},
        {"stationary level IMU", test_stationary_level},
        {"known constant acceleration", test_constant_acceleration},
        {"pure rotation", test_pure_rotation},
        {"roll/pitch gravity projection", test_roll_pitch_gravity_projection},
        {"wrong gravity convention detected", test_wrong_gravity_convention_detected},
        {"repeated IMU timestamp rejected", test_duplicate_timestamp_rejected},
        {"dropped samples invalidate, no alarm", test_gap_invalidates_without_alarm},
        {"delta-valid false invalidates", test_delta_valid_false_invalidates},
        {"invalid attitude degrades", test_attitude_invalid_degrades},
        {"queue overflow counted", test_overflow_counted_and_invalidates},
        {"yaw unavailable -> heading-free only", test_yaw_unavailable_heading_free_only},
        {"GNSS after arm cannot change prediction", test_prediction_independent_of_gnss},
        {"clean flight: no false alarm", test_clean_flight_no_false_alarm},
        {"velocity drag-off detected", test_spoof_velocity_drag_off_detected},
        {"abrupt position step detected", test_position_step_detected},
        {"altitude-only mismatch warns", test_altitude_only_mismatch_warns},
        {"transient warning clears", test_transient_warning_clears},
        {"bias learning", test_bias_learning},
        {"alarm latched, bias frozen, no GNSS re-seed", test_alarm_latched_and_bias_frozen},
        {"heading disturbance", test_heading_disturbance},
        {"out-of-order / excessive latency", test_out_of_order_and_latency},
        {"horizon expires exactly once", test_horizon_expiry_once},
        {"reseed during suspicion rejected", test_reseed_during_suspicion_rejected},
        {"landed reseed during suspicion rejected", test_landed_reseed_during_suspicion_rejected},
        {"stationary-ground constraint", test_ground_constraint},
        {"baro transient: warning, never alarm", test_baro_transient_warns_never_alarms},
        {"disabled is passive", test_disabled_is_passive},
    };
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        const int before = g_failures;
        printf("[ RUN  ] %s\n", tests[i].name);
        tests[i].fn();
        printf("[ %s ] %s\n", g_failures == before ? " OK " : "FAIL", tests[i].name);
    }
    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
