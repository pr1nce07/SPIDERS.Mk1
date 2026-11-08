-- PUSHPAK UAV IDS -> GCS bridge
--
-- The compiled `ids` binding has no per-detector accessors, so this bridge can
-- no longer mirror native detector states (each *_confirm.lua now publishes its
-- own PIDS line with origin LUA). What the bridge CAN observe is the native
-- AP_IDS event counter: ids:event_sequence() advances whenever AP_IDS publishes.
--
-- Wire formats:
--   PUSHPAK IDS: BRIDGE binding=report_confirmed,event_sequence   (once, at start)
--   PUSHPAK IDS: FC_EVENT seq=<n> delta=<k>                       (on change, <= 1 Hz)
-- No flight-control action.

-- shared helpers: firmware package.path includes @ROMFS/scripts/modules/?.lua and /APM/scripts/modules/?.lua
local common = require("ids_common")

local announced = false
local last_seq = nil

local function update()
    if not ids then
        if not announced then
            gcs:send_text(common.SEVERITY_WARNING, "PUSHPAK IDS: BRIDGE binding=absent")
            announced = true
        end
        return update, 5000
    end
    if not announced then
        gcs:send_text(common.SEVERITY_INFO, "PUSHPAK IDS: BRIDGE binding=report_confirmed,event_sequence")
        announced = true
    end
    local seq = common.sequence()
    if last_seq ~= nil and seq ~= last_seq then
        gcs:send_text(common.SEVERITY_INFO, string.format("PUSHPAK IDS: FC_EVENT seq=%d delta=%d", seq, seq - last_seq))
    end
    last_seq = seq
    return update, 1000
end

return update, 1000
