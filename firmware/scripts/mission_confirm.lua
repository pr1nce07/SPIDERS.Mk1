-- PUSHPAK UAV IDS: mission-integrity confirmation
-- /APM/scripts/mission_confirm.lua
--
-- Fingerprints the stored mission with mission:num_commands()/get_item() and
-- watches mission:get_current_nav_index():
--   * fingerprint changed while armed/flying     -> INTEGRITY + CONTEXT
--   * current index jumps back or > 3 ahead      -> SEQUENCE
--   * change persisting (tracker)                -> PERSISTENCE
-- The script never modifies mission items.

-- shared helpers: firmware package.path includes @ROMFS/scripts/modules/?.lua and /APM/scripts/modules/?.lua
local common = require("ids_common")

local tracker = common.new_tracker("MISSION", 2, 5000)
local MAX_ITEMS = 200
local MOD = 2147483629
local baseline = nil
local last_index = nil
local hold_evidence, hold_conf, hold_until = 0, 0, 0

local function mix(h, v)
    return (h * 31 + math.floor(v or 0)) % MOD
end

local function fingerprint()
    local n = mission:num_commands() or 0
    local h = mix(7, n)
    for i = 0, math.min(n, MAX_ITEMS) - 1 do
        local it = mission:get_item(i)
        if it then
            h = mix(h, it:command())
            h = mix(h, it:x())
            h = mix(h, it:y())
            h = mix(h, (it:z() or 0) * 100)
            h = mix(h, (it:param1() or 0) * 100)
            h = mix(h, (it:param2() or 0) * 100)
        end
    end
    return h, n
end

local function update()
    local now = common.now_ms()
    local armed = arming:is_armed()
    local flying = vehicle:get_likely_flying()
    local fp, count = fingerprint()
    local evidence, conf = 0, 0

    if baseline == nil or not armed then
        baseline = fp            -- ground edits by the operator re-baseline the mission
    elseif fp ~= baseline then
        evidence = evidence | common.EVID_INTEGRITY
        conf = conf + 0.50
        if flying then
            evidence = evidence | common.EVID_CONTEXT
            conf = conf + 0.20
        end
    end

    local idx = mission:get_current_nav_index()
    if last_index ~= nil and idx ~= nil and vehicle:get_mode() == 3 then  -- AUTO
        if idx < last_index or idx > last_index + 3 then
            evidence = evidence | common.EVID_SEQUENCE
            conf = conf + 0.20
        end
    end
    last_index = idx

    if conf > 0 then
        hold_evidence, hold_conf, hold_until = hold_evidence | evidence, math.max(hold_conf, conf), now + 5000
    elseif now > hold_until then
        hold_evidence, hold_conf = 0, 0
    end
    local combined = common.clamp01(hold_conf)

    local entered, ev = common.track(tracker, combined, hold_evidence, count, 0)
    if entered and (ev & common.EVID_INTEGRITY) ~= 0 then
        local class = "MISSION_TAMPERING_CANDIDATE"
        if (ev & common.EVID_SEQUENCE) ~= 0 and (ev & common.EVID_CONTEXT) ~= 0 then
            class = "IN_FLIGHT_MISSION_INTEGRITY_ANOMALY"
        end
        common.safe_report(string.format("%s conf=%.2f evidence=0x%04X", class, combined, ev))
    end
    return update, 1000
end

return update, 1000
