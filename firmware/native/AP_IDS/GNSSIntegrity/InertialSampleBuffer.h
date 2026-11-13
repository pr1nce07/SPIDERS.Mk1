/*
 * Fixed-capacity single-producer / single-consumer IMU increment queue.
 *
 * Producer: the fast capture hook immediately after AP_InertialSensor::update().
 * Consumer: GNSSIntegrity::update() / observe_gnss() at the GPS-task rate.
 *
 * The pinned AP_InertialSensor::get_delta_*() accessors return the *currently
 * published* increment, not a FIFO, so the producer must be called once per INS
 * update. This buffer enforces "every increment exactly once":
 *   - a sample whose timestamp is not newer than the previous one is a
 *     duplicate and is rejected (never integrated twice);
 *   - a timestamp jump larger than Config::imu_max_gap_us, or a reported dt that
 *     covers much less than the elapsed interval, marks a gap;
 *   - a full queue drops the sample, counts it, and marks the next sample so the
 *     consumer invalidates every affected horizon.
 *
 * Both ends run on the ArduPilot main thread in the intended integration
 * (fast loop and scheduler tasks), so plain volatile indices are sufficient. If
 * the producer is ever moved to another thread, guard push/pop with a
 * HAL_Semaphore or replace the indices with proper atomics.
 */
#pragma once

#include "GNSSIntegrityTypes.h"

namespace GNSSInt {

enum SampleFlag : uint8_t {
    SAMPLE_GAP_BEFORE = 1U << 0,
    SAMPLE_OVERFLOW_BEFORE = 1U << 1,
};

enum class PushResult : uint8_t { Accepted, Duplicate, QueueFull };

class InertialSampleBuffer {
public:
    static const uint16_t CAPACITY = 64;  // 160 ms at 400 Hz; drain at >= 50 Hz

    void reset();
    void set_max_gap_us(uint32_t us) { _max_gap_us = us; }

    // Fast path: O(1), no allocation, no logging.
    PushResult push(const IMUSample &s);
    // Consumer: returns false when empty.
    bool pop(IMUSample &out, uint8_t &flags);

    uint16_t size() const { return uint16_t((_head - _tail + CAPACITY) % CAPACITY); }
    uint16_t high_water() const { return _high_water; }
    uint32_t duplicates() const { return _duplicates; }
    uint32_t overflows() const { return _overflows; }
    uint32_t gaps() const { return _gaps; }

private:
    struct Slot {
        IMUSample s;
        uint8_t flags;
    };
    Slot _slots[CAPACITY];
    volatile uint16_t _head = 0;   // next write (producer only)
    volatile uint16_t _tail = 0;   // next read (consumer only)
    bool _have_last = false;
    uint64_t _last_time_us = 0;
    uint8_t _pending_flags = 0;
    uint32_t _max_gap_us = 20000;
    uint32_t _duplicates = 0;
    uint32_t _overflows = 0;
    uint32_t _gaps = 0;
    uint16_t _high_water = 0;
};

} // namespace GNSSInt
