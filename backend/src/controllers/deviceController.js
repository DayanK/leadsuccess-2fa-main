// Backend/src/controllers/deviceController.js - Controller for managing 2FA devices
const User = require("../models/User");
const Device = require("../models/Device");
const { asyncHandler } = require("../middleware/errorHandler");

class DeviceController {
    // Get all user's devices
    getDevices = asyncHandler(async (req, res) => {
        const activeDevices = await Device.getActiveByUserId(req.user.twoFactorUserID);

        res.json({
            success: true,
            devices: activeDevices.map((device) => ({
                id: device.TwoFactorDeviceID,
                name: device.DeviceInfo,
                type: device.AuthMethod,
                created: device.CreatedAt,
                lastUsed: device.LastUsed,
                isActive: device.Inactive === 0,
                failedAttempts: device.FailedAttempts,
                lastFailedAttempt: device.LastFailedAttempt,
            })),
        });
    });

    // Remove a device
    removeDevice = asyncHandler(async (req, res) => {
        const { deviceId } = req.params;
        const userId = req.user.twoFactorUserID;

        // Verify that the device belongs to the user
        const device = await Device.getById(deviceId);
        if (!device || device.TwoFactorUserID !== userId) {
            await User.logAuditEvent(
                req.user.username,
                "DEVICE_REMOVE_ATTEMPT",
                false,
                `Attempt to remove device ${deviceId} (not found or not owned)`,
                "Access denied - Device not found or not owned by user",
                req
            );
            return res.status(403).json({
                success: false,
                error: "Access denied - Device not found or not owned by user",
            });
        }

        // Verify that it is not the last active device
        const activeDevices = await Device.getActiveByUserId(userId);
        // We filter out the device being removed to accurately check if it's the last one.
        const remainingActiveDevices = activeDevices.filter(d => d.TwoFactorDeviceID !== device.TwoFactorDeviceID);

        if (remainingActiveDevices.length < 1) {
            await User.logAuditEvent(
                req.user.username,
                "DEVICE_REMOVE_ATTEMPT",
                false,
                `Attempt to remove last active device ${deviceId}`,
                "Cannot remove the last active device",
                req
            );
            return res.status(400).json({
                success: false,
                error: "Cannot remove the last active device. Please add another device first to ensure 2FA remains active.",
                message: "You must have at least one active 2FA device.",
            });
        }

        // Deactivate the device
        await Device.deactivate(deviceId);

        await User.logAuditEvent(
            req.user.username,
            "DEVICE_REMOVED",
            true,
            `Device ${deviceId} (${device.DeviceInfo}) removed`,
            null,
            req
        );

        res.json({
            success: true,
            message: "Device removed successfully",
            removedDevice: {
                id: deviceId,
                name: device.DeviceInfo,
                type: device.AuthMethod,
            },
        });
    });
}

module.exports = new DeviceController();