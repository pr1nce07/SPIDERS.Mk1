-- PUSHPAK UAV IDS: RC / telemetry link (jamming candidate) confirmation
-- /APM/scripts/jamming_confirm.lua
--
-- Uses rc:has_valid_input() and gcs:last_seen(). The build
-- exposes no RSSI binding, so gradual RSSI trends are left to the GCS RC_LINK
-- detector; this script classifies loss patterns instead:
--   * RC input invalid                          -> DEGRADED
--   * repeated RC losses (>= 3 in 60 s)         -> RATE
--   * RC and telemetry lost together            -> CROSS (common RF cause)
--   * loss while flying                         -> CONTEXT
--   * loss persisting (tracker)                 -> PERSISTENCE
-- Report-only: never triggers failsafe or alters links.

-- shared helpers: firmware package.path includes @ROMFS/scripts/modules/?.lua and /APM/scripts/modules/?.lua
local common = require("ids_common")

local tracker = common.new_tracker("RC_LINK", 3, 5000)
local losses = {}
local rc_lost_since = nil

local function update()
    local now = common.now_ms()
    local valid = rc:has_valid_input()
    local flying = vehicle:get_likely_flying()
    local gcs_last = common.to_number(gcs:last_seen())
    local telem_lost = gcs_last ~= 0 and (now - gcs_last) > 3000

    if not valid then
        if rc_lost_since == nil then
            rc_lost_since = now
            losses[#losses + 1] = now
        end
    else
        rc_lost_since = nil
    end
    local recent
    recent, losses = common.count_recent(losses, now, 60000)

    local evidence = 0
    local conf = 0
    if not valid then
        evidence = evidence | common.EVID_DEGRADED
        conf = conf + 0.35 + common.clamp01((now - rc_lost_since) / 5000) * 0.2
    end
    if recent >= 3 then
        evidence = evidence | common.EVID_RATE
        conf = conf + 0.25
    end
    if not valid and telem_lost then
        evidence = evidence | common.EVID_CROSS
        conf = conf + 0.20
    end
    if flying and (not valid) then
        evidence = evidence | common.EVID_CONTEXT
        conf = conf + 0.10
    end
    local combined = common.clamp01(conf)

    local entered, ev = common.track(tracker, combined, evidence, recent, 0)
    if entered then
        local class = "LINK_FAILURE_CANDIDATE"
        if (ev & common.EVID_RATE) ~= 0 or (ev & common.EVID_CROSS) ~= 0 then
            class = "JAMMING_OR_LOW_LINK_DEGRADATION"
        end
        if flying and (ev & common.EVID_RATE) ~= 0 and (ev & common.EVID_PERSISTENCE) ~= 0 then
            class = "PERSISTENT_RF_DEGRADATION_CANDIDATE"
        end
        common.safe_report(string.format("%s conf=%.2f evidence=0x%04X", class, combined, ev))
    end
    return update, 300
end

return update, 1000
