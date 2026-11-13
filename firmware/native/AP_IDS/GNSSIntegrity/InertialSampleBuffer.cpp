#include "InertialSampleBuffer.h"

namespace GNSSInt {

void InertialSampleBuffer::reset()
{
    _head = 0;
    _tail = 0;
    _have_last = false;
    _last_time_us = 0;
    _pending_flags = 0;
    _duplicates = 0;
    _overflows = 0;
    _gaps = 0;
    _high_water = 0;
}

PushResult InertialSampleBuffer::push(const IMUSample &s)
{
    if (_have_last && s.time_us <= _last_time_us) {
        _duplicates++;
        return PushResult::Duplicate;
    }
    uint8_t flags = _pending_flags;
    if (_have_last) {
        const uint64_t interval_us = s.time_us - _last_time_us;
        const float dt_us = (s.delta_velocity_valid ? s.delta_velocity_dt_s : s.delta_angle_dt_s) * 1.0e6f;
        // A capped or short dt cannot represent a longer missing interval.
        if (interval_us > _max_gap_us || dt_us < 0.5f * float(interval_us)) {
            flags |= SAMPLE_GAP_BEFORE;
            _gaps++;
        }
    }
    _have_last = true;
    _last_time_us = s.time_us;

    const uint16_t next = uint16_t((_head + 1) % CAPACITY);
    if (next == _tail) {
        _overflows++;
        _pending_flags = uint8_t(flags | SAMPLE_OVERFLOW_BEFORE);
        return PushResult::QueueFull;
    }
    _slots[_head].s = s;
    _slots[_head].flags = flags;
    _pending_flags = 0;
    _head = next;
    const uint16_t sz = size();
    if (sz > _high_water) {
        _high_water = sz;
    }
    return PushResult::Accepted;
}

bool InertialSampleBuffer::pop(IMUSample &out, uint8_t &flags)
{
    if (_tail == _head) {
        return false;
    }
    out = _slots[_tail].s;
    flags = _slots[_tail].flags;
    _tail = uint16_t((_tail + 1) % CAPACITY);
    return true;
}

} // namespace GNSSInt
