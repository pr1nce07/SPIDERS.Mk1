-- PUSHPAK UAV IDS -> GCS bridge (protocol v2, GAP-07)
--
-- The compiled `ids` binding has no per-detector accessors, so this bridge can
-- no longer mirror native detector states (each *_confirm.lua now publishes its
-- own PIDS line with origin LUA). What the bridge CAN observe is the native
-- AP_IDS event counter: ids:event_sequence() advances whenever AP_IDS publishes.
--
-- Delivery model: strictly one-way, best-effort telemetry. The GCS never sends
-- anything back, so the bridge repeats its announcement and a periodic SYNC
-- line; a GCS that connects late or drops lines can tell what it missed.
--
-- Wire formats:
--   PUSHPAK IDS: BRIDGE binding=report_confirmed,event_sequence v=2   (start, GCS (re)contact, every 60 s)
--   PUSHPAK IDS: STATEMAP 0=CLEAR,1=SUSPECTED,2=CONFIRMED             (with every BRIDGE line)
--   PUSHPAK IDS: SYNC up=<s> seq=<n> ev=<k>                           (every 10 s)
--   PUSHPAK IDS: FC_EVENT seq=<n> delta=<k>                           (on change, <= 1 Hz)
-- `up` is uptime in seconds (a drop means the FC rebooted), `seq` the native event
-- counter and `ev` how many FC_EVENT lines this script has sent since boot.
-- No flight-control action.

-- shared helpers: firmware package.path includes @ROMFS/scripts/modules/?.lua and /APM/scripts/modules/?.lua
local common = require("ids_common")

local PROTOCOL_VERSION = 2
local ANNOUNCE_EVERY_MS = 60000
local SYNC_EVERY_MS = 10000
local GCS_LOST_MS = 5000

local last_seq = nil
local events_sent = 0
local last_announce = nil
local last_sync = nil
local gcs_present = false

local function gcs_seen(now)
    local last = common.to_number(gcs:last_seen())
    return last > 0 and (now - last) < GCS_LOST_MS
end

local function announce(binding)
    gcs:send_text(common.SEVERITY_INFO, string.format("PUSHPAK IDS: BRIDGE binding=%s v=%d", binding, PROTOCOL_VERSION))
    gcs:send_text(common.SEVERITY_INFO, string.format("PUSHPAK IDS: STATEMAP %d=CLEAR,%d=SUSPECTED,%d=CONFIRMED",
        common.STATE_CLEAR, common.STATE_SUSPECTED, common.STATE_CONFIRMED))
end

local function update()
    local now = common.now_ms()
    local binding = ids and "report_confirmed,event_sequence" or "absent"

    -- Re-announce on first contact / reconnection of the configured GCS, and periodically.
    local present = gcs_seen(now)
    local reconnected = present and not gcs_present
    gcs_present = present
    if last_announce == nil or reconnected or (now - last_announce) >= ANNOUNCE_EVERY_MS then
        announce(binding)
        last_announce = now
    end
    if not ids then
        return update, 1000
    end

    local seq = common.sequence()
    if last_seq ~= nil and seq ~= last_seq then
        events_sent = events_sent + 1
        gcs:send_text(common.SEVERITY_INFO, string.format("PUSHPAK IDS: FC_EVENT seq=%d delta=%d", seq, seq - last_seq))
    end
    last_seq = seq

    if last_sync == nil or reconnected or (now - last_sync) >= SYNC_EVERY_MS then
        gcs:send_text(common.SEVERITY_INFO, string.format("PUSHPAK IDS: SYNC up=%d seq=%d ev=%d",
            math.floor(now / 1000), seq, events_sent))
        last_sync = now
    end
    return update, 1000
end

return update, 1000
