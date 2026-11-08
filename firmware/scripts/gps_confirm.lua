-- PUSHPAK UAV IDS: GPS/GNSS confirmation
-- /APM/scripts/gps_confirm.lua
--
-- Independent evidence from standard bindings only (gps:, ahrs:). The build has
-- no ahrs:get_position() and no ids:gps_* accessors, so this script uses
-- ahrs:get_location() / ahrs:get_velocity_NED() / ahrs:get_variances().
--
-- Detection methods:
--   * GPS-vs-AHRS position residual            -> CROSS
--   * GPS-vs-AHRS velocity residual            -> KINEMATIC
--   * rolling median + MAD robust deviation    -> ROBUST
--   * one-sided CUSUM (slow drift/meaconing)   -> CUSUM
--   * GNSS quality-vs-navigation mismatch      -> INTEGRITY
--   * EKF velocity/position variance           -> DEGRADED
--   * redundant receiver disagreement          -> SOURCE
--   * persistence (hysteresis in ids_common)   -> PERSISTENCE
-- Read/analyze/classify/report only.

-- shared helpers: firmware package.path includes @ROMFS/scripts/modules/?.lua and /APM/scripts/modules/?.lua
local common = require("ids_common")

local tracker = common.new_tracker("GPS", 3, 5000)
local residuals = {}
local cusum = 0

local function update()
    local primary = gps:primary_sensor() or 0
    local status = gps:status(primary)
    if status == nil or status < 3 then
        return update, 500
    end

    local gps_pos = gps:location(primary)
    local ekf_pos = ahrs:get_location()
    local gps_vel = gps:velocity(primary)
    local ekf_vel = ahrs:get_velocity_NED()
    if gps_pos == nil or ekf_pos == nil or gps_vel == nil or ekf_vel == nil then
        return update, 500
    end

    local position_residual = gps_pos:get_distance(ekf_pos)
    local velocity_residual = (gps_vel - ekf_vel):length()

    common.push_ring(residuals, position_residual, 8)
    local median = common.median(residuals)
    local mad = common.mad(residuals, median) + 0.5
    local robust_z = math.abs(position_residual - median) / (3.0 * mad)

    local excess = (position_residual - median) / math.max(mad, 1.0) - 0.35
    cusum = math.min(math.max(0, cusum + excess), 6.0)
    local cusum_score = common.clamp01(cusum / 6.0)

    local hacc = gps:horizontal_accuracy(primary)
    local sats = gps:num_sats(primary)
    local hdop = gps:get_hdop(primary)
    local quality_mismatch = 0
    if hacc and hacc < 3.0 and position_residual > 8.0 then
        quality_mismatch = 0.85
    elseif sats and sats >= 10 and position_residual > 8.0 then
        quality_mismatch = 0.70
    elseif hdop and hdop < 150 and position_residual > 8.0 then  -- get_hdop() is in cm units
        quality_mismatch = 0.65
    end

    local ekf_score = 0
    local ok, _, vel_var, pos_var = pcall(function() return ahrs:get_variances() end)
    if ok and vel_var and pos_var then
        ekf_score = common.clamp01(math.max(vel_var, pos_var) / 1.0)
    end

    local redundancy = 0
    local sensor_count = gps:num_sensors()
    if sensor_count and sensor_count >= 2 then
        local secondary = (primary == 0) and 1 or 0
        local other_status = gps:status(secondary)
        local other_pos = gps:location(secondary)
        if other_status ~= nil and other_status >= 3 and other_pos ~= nil then
            redundancy = common.clamp01(gps_pos:get_distance(other_pos) / 10.0)
        end
    end

    local pos_score = common.clamp01(position_residual / 12.0)
    local vel_score = common.clamp01(velocity_residual / 4.0)
    local combined = common.clamp01(
        0.25 * pos_score + 0.20 * vel_score + 0.15 * common.clamp01(robust_z) +
        0.15 * cusum_score + 0.10 * quality_mismatch + 0.10 * ekf_score + 0.05 * redundancy)

    local evidence = 0
    if pos_score > 0.5 then evidence = evidence | common.EVID_CROSS end
    if vel_score > 0.5 then evidence = evidence | common.EVID_KINEMATIC end
    if robust_z > 1.0 then evidence = evidence | common.EVID_ROBUST end
    if cusum_score > 0.65 then evidence = evidence | common.EVID_CUSUM end
    if quality_mismatch > 0 then evidence = evidence | common.EVID_INTEGRITY end
    if ekf_score > 0.8 then evidence = evidence | common.EVID_DEGRADED end
    if redundancy > 0.5 then evidence = evidence | common.EVID_SOURCE end

    -- require a physical residual before confirmation (never a quality flag alone)
    if not (position_residual > 6.0 or velocity_residual > 2.0 or cusum_score > 0.65) then
        combined = math.min(combined, common.CONFIRM_THRESHOLD - 0.01)
    end

    local entered = common.track(tracker, combined, evidence, position_residual, primary)
    if entered then
        common.safe_report(string.format(
            "GPS CONFIRMED conf=%.2f pos=%.1fm vel=%.1fm/s robust=%.2f cusum=%.2f",
            combined, position_residual, velocity_residual, common.clamp01(robust_z), cusum_score))
    end
    return update, 200
end

return update, 1000
