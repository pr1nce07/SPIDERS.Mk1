-- PUSHPAK UAV IDS: MAVLink link confirmation
-- /APM/scripts/mavlink_confirm.lua
--
-- Lua cannot see individual MAVLink packets on this build (no packet/sequence
-- binding and no ids:mavlink_* accessors). Packet-level sequence/source/signing
-- evidence is therefore left to the native MAVLinkDetector and the GCS. This
-- script confirms link-level behaviour from gcs:sysid_mygcs_last_seen_time_ms():
--   * GCS heartbeat gap                        -> RATE
--   * gap persisting > 10 s                    -> PERSISTENCE (set by tracker)
--   * repeated loss/recovery (intermittent)    -> SEQUENCE
--   * gap while flying                         -> CONTEXT
-- Report-only.

-- shared helpers: firmware package.path includes @ROMFS/scripts/modules/?.lua and /APM/scripts/modules/?.lua
local common = require("ids_common")

local tracker = common.new_tracker("MAVLINK", 4, 5000)
local losses = {}
local in_loss = false
local GAP_MS = 3000

local function update()
    local now = common.now_ms()
    local last = common.to_number(gcs:sysid_mygcs_last_seen_time_ms())
    if last == 0 then
        return update, 1000  -- configured GCS never seen yet: nothing to judge
    end
    local gap = now - last
    local flying = vehicle:get_likely_flying()

    if gap > GAP_MS and not in_loss then
        in_loss = true
        losses[#losses + 1] = now
    elseif gap <= GAP_MS then
        in_loss = false
    end
    local recent
    recent, losses = common.count_recent(losses, now, 60000)

    local evidence = 0
    local gap_score = common.clamp01((gap - GAP_MS) / 5000)
    if gap > GAP_MS then evidence = evidence | common.EVID_RATE end
    if recent >= 3 then evidence = evidence | common.EVID_SEQUENCE end
    if flying and gap > GAP_MS then evidence = evidence | common.EVID_CONTEXT end

    local intermittency = math.min(recent, 4) / 4
    local combined = common.clamp01(0.55 * gap_score + 0.30 * intermittency + ((flying and gap > GAP_MS) and 0.15 or 0))

    local entered, ev = common.track(tracker, combined, evidence, gap / 1000.0, 0)
    if entered then
        local class = "MAVLINK_ANOMALY"
        if recent >= 3 then
            class = "MAVLINK_LOW_RATE_OR_DOS_CANDIDATE"
        end
        common.safe_report(string.format("%s conf=%.2f evidence=0x%04X", class, combined, ev))
    end
    return update, 250
end

return update, 1000
