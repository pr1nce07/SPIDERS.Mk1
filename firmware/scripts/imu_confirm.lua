-- PUSHPAK UAV IDS: IMU confirmation
-- /APM/scripts/imu_confirm.lua
--
-- Pixhawk 6C has two IMUs. Uses ins:get_accel(i), ins:get_gyro(i),
-- ins:get_accel_health(i), ins:get_gyro_health(i), ins:accels_consistent(t),
-- ins:gyros_consistent(t):
--   * cross-IMU accel/gyro residual (EWMA)     -> CROSS
--   * slow residual growth (CUSUM)             -> CUSUM
--   * sensor unhealthy                         -> DEGRADED
--   * ArduPilot consistency check failed       -> INTEGRITY
--   * while flying                             -> CONTEXT
-- Evidence fusion only; no actuator or sensor-selection changes.

-- shared helpers: firmware package.path includes @ROMFS/scripts/modules/?.lua and /APM/scripts/modules/?.lua
local common = require("ids_common")

local tracker = common.new_tracker("IMU", 5, 5000)
local ACC_THR = 3.0     -- m/s^2
local GYR_THR = 0.15    -- rad/s
local GYR_THR_DEG = 9   -- gyros_consistent() takes an integer deg/s (uint8)
local acc_ewma, gyr_ewma = nil, nil
local cusum = 0

local function update()
    local a0, a1 = ins:get_accel(0), ins:get_accel(1)
    local g0, g1 = ins:get_gyro(0), ins:get_gyro(1)
    if a0 == nil or a1 == nil or g0 == nil or g1 == nil then
        return update, 1000  -- second IMU not present
    end
    local acc_res = (a0 - a1):length()
    local gyr_res = (g0 - g1):length()
    acc_ewma = common.ewma(acc_ewma, acc_res, 0.2)
    gyr_ewma = common.ewma(gyr_ewma, gyr_res, 0.2)
    local ratio = math.max(acc_ewma / ACC_THR, gyr_ewma / GYR_THR)
    cusum = math.min(math.max(0, cusum + ratio - 0.5), 10)

    local unhealthy = not (ins:get_accel_health(0) and ins:get_accel_health(1) and ins:get_gyro_health(0) and ins:get_gyro_health(1))
    local inconsistent = not (ins:accels_consistent(ACC_THR) and ins:gyros_consistent(GYR_THR_DEG))
    local flying = vehicle:get_likely_flying()

    local evidence = 0
    if ratio > 1 then evidence = evidence | common.EVID_CROSS end
    if cusum > 6 then evidence = evidence | common.EVID_CUSUM end
    if unhealthy then evidence = evidence | common.EVID_DEGRADED end
    if inconsistent then evidence = evidence | common.EVID_INTEGRITY end
    if flying and evidence ~= 0 then evidence = evidence | common.EVID_CONTEXT end

    local combined = common.clamp01(0.35 * common.clamp01(ratio - 0.5) + 0.25 * common.clamp01(cusum / 10) +
        (unhealthy and 0.20 or 0) + (inconsistent and 0.20 or 0) + ((flying and evidence ~= 0) and 0.05 or 0))

    local entered, ev = common.track(tracker, combined, evidence, acc_ewma, 0)
    if entered then
        local class = ((ev & common.EVID_CUSUM) ~= 0) and "IMU_BIAS_DRIFT_CANDIDATE" or "IMU_CONSISTENCY_ANOMALY"
        if (ev & common.EVID_DEGRADED) ~= 0 and (ev & common.EVID_CROSS) ~= 0 then
            class = "IMU_SINGLE_SENSOR_OUTLIER_CANDIDATE"
        end
        common.safe_report(string.format("%s conf=%.2f evidence=0x%04X", class, combined, ev))
    end
    return update, 300
end

return update, 1000
