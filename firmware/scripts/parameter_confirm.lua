-- PUSHPAK UAV IDS: parameter-tampering confirmation
-- /APM/scripts/parameter_confirm.lua
--
-- Polls a sensitive-parameter watch list with param:get(). Original values are
-- captured at first read (and re-baselined only while disarmed).
--   * large relative deviation from original      -> ROBUST
--   * repeated small changes (EWMA/CUSUM drift)    -> CUSUM
--   * >= 3 changes in 10 s                         -> RATE
--   * change while armed                           -> CONTEXT
-- Writer identity is not observable from Lua on this build (no SOURCE bit).
-- Read/analyze/classify/report only.

-- shared helpers: firmware package.path includes @ROMFS/scripts/modules/?.lua and /APM/scripts/modules/?.lua
local common = require("ids_common")

local tracker = common.new_tracker("PARAMETER", 1, 5000)
-- Both pre-4.7 and 4.7+ names are listed (4.7 renamed RTL_ALT -> RTL_ALT_M, WPNAV_SPEED ->
-- WP_SPD, ANGLE_MAX -> ATC_ANGLE_MAX, ARMING_CHECK -> ARMING_SKIPCHK, GPS_TYPE -> GPS1_TYPE,
-- SYSID_MYGCS -> MAV_GCS_SYSID). param:get() returns nil for names a build lacks; those are skipped.
local WATCH = {
    "FENCE_ENABLE", "ARMING_CHECK", "ARMING_SKIPCHK", "FS_THR_ENABLE", "FS_GCS_ENABLE", "BATT_FS_LOW_ACT",
    "RTL_ALT", "RTL_ALT_M", "WPNAV_SPEED", "WP_SPD", "ANGLE_MAX", "ATC_ANGLE_MAX", "GPS_TYPE", "GPS1_TYPE",
    "EK3_SRC1_POSXY", "SCR_ENABLE", "MAV_GCS_SYSID", "SYSID_MYGCS", "DISARM_DELAY", "LOG_BACKEND_TYPE",
}
local original, current, drift = {}, {}, {}
local changes = {}
local hold_evidence, hold_conf, hold_until = 0, 0, 0
local last_name = ""

local function update()
    local now = common.now_ms()
    local armed = arming:is_armed()
    local evidence, conf = 0, 0

    for i = 1, #WATCH do
        local name = WATCH[i]
        local v = param:get(name)
        if v ~= nil then
            if original[name] == nil or (not armed and current[name] ~= v) then
                original[name] = v
            elseif current[name] ~= nil and v ~= current[name] then
                changes[#changes + 1] = now
                last_name = name
                local dev = math.abs(v - original[name]) / math.max(math.abs(original[name]), 1e-6)
                drift[name] = math.min((drift[name] or 0) + 1, 10)
                if dev > 0.5 then
                    evidence = evidence | common.EVID_ROBUST
                    conf = conf + 0.35
                end
                if drift[name] >= 3 then
                    evidence = evidence | common.EVID_CUSUM
                    conf = conf + 0.20
                end
                if armed then
                    evidence = evidence | common.EVID_CONTEXT
                    conf = conf + 0.35
                end
            end
            current[name] = v
        end
    end
    local recent
    recent, changes = common.count_recent(changes, now, 10000)
    if recent >= 3 then
        evidence = evidence | common.EVID_RATE
        conf = conf + 0.25
    end

    if conf > 0 then
        hold_evidence, hold_conf, hold_until = hold_evidence | evidence, math.max(hold_conf, conf), now + 5000
    elseif now > hold_until then
        hold_evidence, hold_conf = 0, 0
    end
    local combined = common.clamp01(hold_conf)

    local entered, ev = common.track(tracker, combined, hold_evidence, recent, 0)
    if entered then
        local class = "PARAMETER_TAMPERING_CANDIDATE"
        if (ev & common.EVID_CONTEXT) ~= 0 and (ev & common.EVID_ROBUST) ~= 0 then
            class = "AIRBORNE_PARAMETER_SOURCE_ANOMALY"
        elseif (ev & common.EVID_ROBUST) ~= 0 and (ev & common.EVID_CUSUM) ~= 0 then
            class = "LOW_AND_SLOW_PARAMETER_DRIFT"
        elseif (ev & common.EVID_RATE) ~= 0 then
            class = "PARAMETER_WRITE_BURST"
        end
        common.safe_report(string.format("%s conf=%.2f evidence=0x%04X", class, combined, ev))
    end
    return update, 500
end

return update, 1000
