-- PUSHPAK UAV IDS: command-anomaly confirmation
-- /APM/scripts/command_confirm.lua
--
-- No command-stream binding exists on this build, so commands are observed by
-- their effect: mode/arming transitions and the reason ArduPilot records for
-- them (vehicle:get_control_mode_reason()).
--   * GCS-commanded mode change while flying              -> CONTEXT
--   * mode change commanded while the configured GCS
--     (MAV_GCS_SYSID) has been silent > 3 s              -> SOURCE (another sender)
--   * >= 3 commanded mode changes in 20 s                 -> RATE
--   * disarm observed while flying                        -> CONTEXT + INTEGRITY
-- Report-only: never changes mode or arming state.

-- shared helpers: firmware package.path includes @ROMFS/scripts/modules/?.lua and /APM/scripts/modules/?.lua
local common = require("ids_common")

local tracker = common.new_tracker("COMMAND", 1, 5000)
local REASON_GCS_COMMAND = 2   -- ModeReason::GCS_COMMAND
local last_mode = nil
local last_armed = nil
local was_flying = false
local changes = {}
local hold_evidence = 0
local hold_conf = 0
local hold_until = 0

local function update()
    local now = common.now_ms()
    local mode = vehicle:get_mode()
    local armed = arming:is_armed()
    local flying = vehicle:get_likely_flying()
    local reason = vehicle:get_control_mode_reason()
    local gcs_last = common.to_number(gcs:sysid_mygcs_last_seen_time_ms())
    local gcs_silent = gcs_last == 0 or (now - gcs_last) > 3000

    local evidence = 0
    local conf = 0
    if last_mode ~= nil and mode ~= last_mode then
        if reason == REASON_GCS_COMMAND then
            changes[#changes + 1] = now
            if was_flying then
                evidence = evidence | common.EVID_CONTEXT
                conf = conf + 0.30
            end
            if gcs_silent then
                evidence = evidence | common.EVID_SOURCE
                conf = conf + 0.50
            end
        end
    end
    local recent
    recent, changes = common.count_recent(changes, now, 20000)
    if recent >= 3 then
        evidence = evidence | common.EVID_RATE
        conf = conf + 0.25
    end
    if last_armed == true and armed == false and was_flying then
        evidence = evidence | common.EVID_CONTEXT | common.EVID_INTEGRITY
        conf = conf + 0.55
    end

    -- keep an observed event visible for 5 s so the state machine can publish it
    if conf > 0 then
        hold_evidence = hold_evidence | evidence
        hold_conf = math.max(hold_conf, conf)
        hold_until = now + 5000
    elseif now > hold_until then
        hold_evidence, hold_conf = 0, 0
    end

    local combined = common.clamp01(hold_conf)
    local entered, ev = common.track(tracker, combined, hold_evidence, mode or 0, 0)
    if entered then
        local class = "COMMAND_ANOMALY"
        if (ev & common.EVID_SOURCE) ~= 0 and (ev & common.EVID_CONTEXT) ~= 0 then
            class = "COMMAND_INJECTION_CANDIDATE"
        elseif (ev & common.EVID_RATE) ~= 0 then
            class = "COMMAND_FLOOD_OR_LOW_AND_SLOW_CANDIDATE"
        elseif (ev & common.EVID_INTEGRITY) ~= 0 then
            class = "COMMAND_INTEGRITY_ANOMALY"
        end
        common.safe_report(string.format("%s conf=%.2f evidence=0x%04X", class, combined, ev))
    end

    last_mode, last_armed, was_flying = mode, armed, flying
    return update, 300
end

return update, 1000
