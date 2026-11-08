-- PUSHPAK UAV IDS common Lua helpers
-- Read / analyze / classify / report only. No flight-control operations.
--
-- Binding contract (verified against the Pixhawk6C ArduCopter V4.7.1 dbe79216
-- build): the `ids` singleton exposes ONLY
--     ids:report_confirmed(name, state, confidence, evidence, metric, instance, sequence) -> bool
--     ids:event_sequence() -> uint32
-- There are no per-detector accessors (gps_confidence(), gps_state(), ...), so
-- every confirmation script derives its own evidence from standard ArduPilot
-- bindings and pushes its result back through report_confirmed().

local M = {}

M.SEVERITY_INFO = 6
M.SEVERITY_WARNING = 4

M.STATE_CLEAR = 0
M.STATE_SUSPECTED = 1
M.STATE_CONFIRMED = 2

-- Evidence bits (unchanged meaning; decoded by the GCS)
M.EVID_PERSISTENCE = 1
M.EVID_ROBUST = 2
M.EVID_CUSUM = 8
M.EVID_CROSS = 16
M.EVID_KINEMATIC = 32
M.EVID_SOURCE = 128
M.EVID_SEQUENCE = 256
M.EVID_CONTEXT = 512
M.EVID_RATE = 1024
M.EVID_INTEGRITY = 2048
M.EVID_DEGRADED = 16384

M.SUSPECT_THRESHOLD = 0.45
M.CONFIRM_THRESHOLD = 0.78

function M.clamp01(x)
    if x == nil or x ~= x then return 0 end
    if x < 0 then return 0 end
    if x > 1 then return 1 end
    return x
end

function M.mean(samples)
    local n = #samples
    if n == 0 then return 0 end
    local sum = 0
    for i = 1, n do sum = sum + samples[i] end
    return sum / n
end

function M.median(samples)
    local n = #samples
    if n == 0 then return 0 end
    local copy = {}
    for i = 1, n do copy[i] = samples[i] end
    table.sort(copy)
    local mid = math.floor((n + 1) / 2)
    if n % 2 == 1 then return copy[mid] end
    return 0.5 * (copy[mid] + copy[mid + 1])
end

function M.mad(samples, center)
    if #samples == 0 then return 0 end
    local deviations = {}
    for i = 1, #samples do deviations[i] = math.abs(samples[i] - center) end
    return M.median(deviations)
end

function M.push_ring(ring, value, max_len)
    ring[#ring + 1] = value
    while #ring > max_len do table.remove(ring, 1) end
end

function M.count_recent(times, now, window_ms)
    local n = 0
    local keep = {}
    for i = 1, #times do
        if now - times[i] <= window_ms then
            n = n + 1
            keep[#keep + 1] = times[i]
        end
    end
    return n, keep
end

-- EWMA helper: returns new mean
function M.ewma(prev, x, alpha)
    if prev == nil then return x end
    return prev + alpha * (x - prev)
end

-- ArduPilot uint32_t userdata -> Lua number
function M.to_number(v)
    if v == nil then return 0 end
    if type(v) == "number" then return v end
    local ok, n = pcall(function() return v:toint() end)
    if ok and n then return n end
    return tonumber(tostring(v)) or 0
end

function M.now_ms()
    return M.to_number(millis())
end

function M.sequence()
    if not ids then return 0 end
    local ok, s = pcall(function() return ids:event_sequence() end)
    if ok then return M.to_number(s) end
    return 0
end

function M.safe_report(text)
    if gcs then
        gcs:send_text(M.SEVERITY_WARNING, "PUSHPAK IDS: " .. text)
    end
end

-- Publish a detector result:
--   * PIDS wire line (origin LUA) for the GCS parser
--   * ids:report_confirmed() into native AP_IDS (the only exported write path)
function M.publish(name, state, confidence, evidence, metric, instance)
    local conf = M.clamp01(confidence)
    local ev = math.floor(evidence or 0) & 0xFFFF
    if gcs then
        gcs:send_text(M.SEVERITY_INFO, string.format("PIDS|1|LUA|%s|%d|%.3f|%d|%.2f|%d",
            name, state, conf, ev, metric or 0, instance or 0))
    end
    if ids then
        pcall(function()
            return ids:report_confirmed(name, state, conf, ev, metric or 0, instance or 0, M.sequence())
        end)
    end
end

-- Hysteresis state machine shared by every confirmation script.
-- CLEAR -> SUSPECTED at SUSPECT_THRESHOLD; -> CONFIRMED when combined confidence
-- stays >= CONFIRM_THRESHOLD for `confirm_cycles` consecutive updates.
function M.new_tracker(name, confirm_cycles, cooldown_ms)
    return {
        name = name, state = M.STATE_CLEAR, above = 0, last_conf = -1, last_pub_ms = 0,
        last_report_ms = -1e9, confirm_cycles = confirm_cycles or 3, cooldown_ms = cooldown_ms or 5000,
    }
end

-- Returns true when the tracker just entered CONFIRMED (caller prints its class).
function M.track(t, conf, evidence, metric, instance)
    local now = M.now_ms()
    if conf >= M.CONFIRM_THRESHOLD then
        t.above = t.above + 1
    else
        t.above = 0
    end
    if t.above >= t.confirm_cycles then
        evidence = evidence | M.EVID_PERSISTENCE
    end
    local new_state = M.STATE_CLEAR
    if t.above >= t.confirm_cycles then
        new_state = M.STATE_CONFIRMED
    elseif conf >= M.SUSPECT_THRESHOLD then
        new_state = M.STATE_SUSPECTED
    end
    local changed = new_state ~= t.state
    if changed or (new_state ~= M.STATE_CLEAR and math.abs(conf - t.last_conf) >= 0.05 and now - t.last_pub_ms >= 1000) then
        M.publish(t.name, new_state, conf, evidence, metric, instance)
        t.last_pub_ms = now
        t.last_conf = conf
    end
    local entered = new_state == M.STATE_CONFIRMED and
        (t.state ~= M.STATE_CONFIRMED or now - t.last_report_ms > t.cooldown_ms)
    if entered then t.last_report_ms = now end
    t.state = new_state
    return entered, evidence
end

return M
