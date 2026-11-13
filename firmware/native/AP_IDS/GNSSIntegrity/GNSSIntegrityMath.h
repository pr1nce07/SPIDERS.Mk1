/*
 * GNSSIntegrity: minimal fixed-size vector/matrix maths.
 *
 * The numerical core is deliberately independent of ArduPilot's AP_Math so it
 * can be unit-tested on a host compiler. The adapter at the AP_IDS boundary
 * converts Vector3f/Matrix3f to and from these types.
 *
 * Conventions (enforced by the tests in firmware/native/tests):
 *   body frame  : Forward-Right-Down (FRD), as ArduPilot
 *   nav frame   : North-East-Down (NED)
 *   rotations   : ZYX Euler (yaw, pitch, roll), body -> NED, identical to
 *                 ArduPilot Matrix3f::from_euler()
 *   units       : m, m/s, m/s^2, rad, microseconds
 *
 * Doubles are used only for the long-running cumulative integrals (see
 * InertialPropagator.h). The STM32H743 has a double-precision FPU. Every
 * float<->double conversion is explicit so the code is clean under
 * -Wdouble-promotion -Wfloat-conversion.
 */
#pragma once

#include <math.h>
#include <stdint.h>

namespace GNSSInt {

static const float kGravityMss = 9.80665f;
static const float kPi = 3.14159265358979f;

struct Vec3 {
    float x, y, z;
    Vec3() : x(0.0f), y(0.0f), z(0.0f) {}
    Vec3(float x_, float y_, float z_) : x(x_), y(y_), z(z_) {}
    Vec3 operator+(const Vec3 &o) const { return Vec3(x + o.x, y + o.y, z + o.z); }
    Vec3 operator-(const Vec3 &o) const { return Vec3(x - o.x, y - o.y, z - o.z); }
    Vec3 operator*(float s) const { return Vec3(x * s, y * s, z * s); }
    Vec3 &operator+=(const Vec3 &o) { x += o.x; y += o.y; z += o.z; return *this; }
    Vec3 &operator-=(const Vec3 &o) { x -= o.x; y -= o.y; z -= o.z; return *this; }
    float dot(const Vec3 &o) const { return x * o.x + y * o.y + z * o.z; }
    float norm_sq() const { return dot(*this); }
    float norm() const { return sqrtf(norm_sq()); }
    float norm_xy() const { return sqrtf(x * x + y * y); }
    bool is_finite() const { return isfinite(x) && isfinite(y) && isfinite(z); }
};

struct DVec3 {
    double x, y, z;
    DVec3() : x(0.0), y(0.0), z(0.0) {}
    DVec3(double x_, double y_, double z_) : x(x_), y(y_), z(z_) {}
    static DVec3 from(const Vec3 &v) { return DVec3(double(v.x), double(v.y), double(v.z)); }
    Vec3 to_float() const { return Vec3(float(x), float(y), float(z)); }
    DVec3 operator+(const DVec3 &o) const { return DVec3(x + o.x, y + o.y, z + o.z); }
    DVec3 operator-(const DVec3 &o) const { return DVec3(x - o.x, y - o.y, z - o.z); }
    DVec3 operator*(double s) const { return DVec3(x * s, y * s, z * s); }
    DVec3 &operator+=(const DVec3 &o) { x += o.x; y += o.y; z += o.z; return *this; }
};

// 3x3 float matrix, row major.
struct Mat3 {
    float m[3][3];
    Mat3() { set_zero(); }
    void set_zero() { for (int i = 0; i < 3; i++) { for (int j = 0; j < 3; j++) { m[i][j] = 0.0f; } } }
    static Mat3 identity() { Mat3 r; r.m[0][0] = r.m[1][1] = r.m[2][2] = 1.0f; return r; }
    Vec3 operator*(const Vec3 &v) const {
        return Vec3(m[0][0] * v.x + m[0][1] * v.y + m[0][2] * v.z,
                    m[1][0] * v.x + m[1][1] * v.y + m[1][2] * v.z,
                    m[2][0] * v.x + m[2][1] * v.y + m[2][2] * v.z);
    }
    Mat3 operator*(const Mat3 &o) const {
        Mat3 r;
        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 3; j++) {
                r.m[i][j] = m[i][0] * o.m[0][j] + m[i][1] * o.m[1][j] + m[i][2] * o.m[2][j];
            }
        }
        return r;
    }
    Mat3 operator+(const Mat3 &o) const { Mat3 r; for (int i = 0; i < 3; i++) { for (int j = 0; j < 3; j++) { r.m[i][j] = m[i][j] + o.m[i][j]; } } return r; }
    Mat3 operator-(const Mat3 &o) const { Mat3 r; for (int i = 0; i < 3; i++) { for (int j = 0; j < 3; j++) { r.m[i][j] = m[i][j] - o.m[i][j]; } } return r; }
    Mat3 transposed() const { Mat3 r; for (int i = 0; i < 3; i++) { for (int j = 0; j < 3; j++) { r.m[i][j] = m[j][i]; } } return r; }

    // Body(FRD) -> NED rotation from ZYX Euler angles (same as ArduPilot Matrix3f::from_euler).
    static Mat3 from_euler(float roll, float pitch, float yaw) {
        const float cp = cosf(pitch), sp = sinf(pitch);
        const float sr = sinf(roll), cr = cosf(roll);
        const float sy = sinf(yaw), cy = cosf(yaw);
        Mat3 r;
        r.m[0][0] = cp * cy;
        r.m[0][1] = (sr * sp * cy) - (cr * sy);
        r.m[0][2] = (cr * sp * cy) + (sr * sy);
        r.m[1][0] = cp * sy;
        r.m[1][1] = (sr * sp * sy) + (cr * cy);
        r.m[1][2] = (cr * sp * sy) - (sr * cy);
        r.m[2][0] = -sp;
        r.m[2][1] = sr * cp;
        r.m[2][2] = cr * cp;
        return r;
    }

    // Inverse of a general 3x3 matrix. Returns false if (near) singular.
    bool inverse(Mat3 &out) const {
        const float a = m[0][0], b = m[0][1], c = m[0][2];
        const float d = m[1][0], e = m[1][1], f = m[1][2];
        const float g = m[2][0], h = m[2][1], k = m[2][2];
        const float A = (e * k - f * h), B = -(d * k - f * g), C = (d * h - e * g);
        const float det = a * A + b * B + c * C;
        if (!isfinite(det) || fabsf(det) < 1e-12f) {
            return false;
        }
        const float inv = 1.0f / det;
        out.m[0][0] = A * inv;
        out.m[0][1] = -(b * k - c * h) * inv;
        out.m[0][2] = (b * f - c * e) * inv;
        out.m[1][0] = B * inv;
        out.m[1][1] = (a * k - c * g) * inv;
        out.m[1][2] = -(a * f - c * d) * inv;
        out.m[2][0] = C * inv;
        out.m[2][1] = -(a * h - b * g) * inv;
        out.m[2][2] = (a * e - b * d) * inv;
        return true;
    }
};

// 3x3 double matrix used by the cumulative integrals.
struct DMat3 {
    double m[3][3];
    DMat3() { set_zero(); }
    void set_zero() { for (int i = 0; i < 3; i++) { for (int j = 0; j < 3; j++) { m[i][j] = 0.0; } } }
    void add_scaled(const Mat3 &a, double s) {
        for (int i = 0; i < 3; i++) { for (int j = 0; j < 3; j++) { m[i][j] += double(a.m[i][j]) * s; } }
    }
    void add_scaled(const DMat3 &a, double s) {
        for (int i = 0; i < 3; i++) { for (int j = 0; j < 3; j++) { m[i][j] += a.m[i][j] * s; } }
    }
    DMat3 operator-(const DMat3 &o) const { DMat3 r; for (int i = 0; i < 3; i++) { for (int j = 0; j < 3; j++) { r.m[i][j] = m[i][j] - o.m[i][j]; } } return r; }
    DMat3 operator*(double s) const { DMat3 r; for (int i = 0; i < 3; i++) { for (int j = 0; j < 3; j++) { r.m[i][j] = m[i][j] * s; } } return r; }
    DVec3 operator*(const Vec3 &v) const {
        const double x = double(v.x), y = double(v.y), z = double(v.z);
        return DVec3(m[0][0] * x + m[0][1] * y + m[0][2] * z,
                     m[1][0] * x + m[1][1] * y + m[1][2] * z,
                     m[2][0] * x + m[2][1] * y + m[2][2] * z);
    }
    Mat3 to_float() const { Mat3 r; for (int i = 0; i < 3; i++) { for (int j = 0; j < 3; j++) { r.m[i][j] = float(m[i][j]); } } return r; }
};

inline float wrap_pi(float a) {
    while (a > kPi) { a -= 2.0f * kPi; }
    while (a < -kPi) { a += 2.0f * kPi; }
    return a;
}

inline float clampf(float v, float lo, float hi) { return v < lo ? lo : (v > hi ? hi : v); }
inline float sqf(float v) { return v * v; }

} // namespace GNSSInt
