-- PUSHPAK UAV IDS: external/offboard-control confirmation
-- /APM/scripts/offboard_confirm.lua
--
-- In GUIDED, compares vehicle:get_target_location() with ahrs:get_location():
--   * vehicle not converging on its target        -> KINEMATIC
--   * target jumping frequently (> 3 in 10 s)     -> RATE
--   * GUIDED entered by GCS command while the
--     configured GCS is silent                    -> SOURCE
--   * while flying                                -> CONTEXT
-- Setpoint streams themselves are not visible to Lua on this build.
-- Report-only: never changes a flight mode or target.

-- shared helpers: firmware package.path includes @ROMFS/scripts/modules/?.lua and /APM/scripts/modules/?.lua
local common = require("ids_common")

local tracker = common.new_tracker("OFFBOARD", 3, 5000)
local GUIDED = 4
local REASON_GCS_COMMAND = 2
local DIVERGENCE_M = 25
local last_target = nil
local last_dist = nil
local diverging_since = nil
local jumps = {}
local source_flag = false
local last_mode = nil

local function update()
    local now = common.now_ms()
    local mode = vehicle:get_mode()
    local flying = vehicle:get_likely_flying()
    if mode ~= last_mode and mode == GUIDED then
        local gcs_last = common.to_number(gcs:last_seen())
        source_flag = vehicle:get_control_mode_reason() == REASON_GCS_COMMAND and (gcs_last == 0 or now - gcs_last > 3000)
    end
    last_mode = mode
    if mode ~= GUIDED then
        last_target, last_dist, diverging_since, source_flag = nil, nil, nil, false
        common.track(tracker, 0, 0, 0, 0)
        return update, 500
    end

    local target = vehicle:get_target_location()
    local here = ahrs:get_location()
    local evidence, conf = 0, 0
    if target ~= nil and here ~= nil then
        local d = here:get_distance(target)
        if last_target ~= nil and target:get_distance(last_target) > 20 then
            jumps[#jumps + 1] = now
        end
        last_target = target
        local closing = last_dist ~= nil and d < last_dist - 0.05
        last_dist = d
        if d > DIVERGENCE_M and not closing then
            diverging_since = diverging_since or now
        else
            diverging_since = nil
        end
        if diverging_since and now - diverging_since > 5000 then
            evidence = evidence | common.EVID_KINEMATIC
            conf = conf + 0.35 + common.clamp01(d / (4 * DIVERGENCE_M)) * 0.2
        end
    end
    local recent
    recent, jumps = common.count_recent(jumps, now, 10000)
    if recent > 3 then
        evidence = evidence | common.EVID_RATE
        conf = conf + 0.25
    end
    if source_flag then
        evidence = evidence | common.EVID_SOURCE
        conf = conf + 0.30
    end
    if flying and evidence ~= 0 then
        evidence = evidence | common.EVID_CONTEXT
        conf = conf + 0.05
    end
    local combined = common.clamp01(conf)

    local entered, ev = common.track(tracker, combined, evidence, last_dist or 0, 0)
    if entered then
        local class = "EXTERNAL_CONTROL_ANOMALY"
        if (ev & common.EVID_SOURCE) ~= 0 and (ev & common.EVID_KINEMATIC) ~= 0 then
            class = "EXTERNAL_CONTROL_SOURCE_AND_KINEMATIC_ANOMALY"
        elseif (ev & common.EVID_RATE) ~= 0 then
            class = "EXTERNAL_CONTROL_RATE_ANOMALY"
        end
        common.safe_report(string.format("%s conf=%.2f evidence=0x%04X", class, combined, ev))
    end
    return update, 300
end

return update, 1000
