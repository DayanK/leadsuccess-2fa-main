 // Backend/src/controllers/totpController.js - Controller for 2FA TOTP setup
const jwt = require("jsonwebtoken");
const { databaseConfig, sql } = require("../config/database");
const User = require("../models/User");
const Device = require("../models/Device");
const totpService = require("../services/totpService");
const sessionService = require("../services/sessionService");
const { asyncHandler } = require("../middleware/errorHandler");
const config = require("../config/config");

class TOTPController {
    // Initiate 2FA setup
    setup2FA = asyncHandler(async (req, res) => {
        const { username, deviceInfo } = req.body;

        const twoFactorUser = await User.ensureTwoFactorUser(username);
        const secret = totpService.generateSecret();

        // Generate the QR Code
        const { qrCode, uri } = await totpService.generateQRCode(secret.base32, username);

        // Create the device in the database (inactive until verified)
        const deviceID = await Device.create(
            twoFactorUser.TwoFactorUserID,
            "TOTP",
            deviceInfo || "Web Browser",
            secret.base32,
            true // Inactif jusqu'à vérification
        );

        await User.logAuditEvent(
            username,
            "2FA_SETUP_INITIATED",
            true,
            `Setup initiated for device: ${deviceInfo || "Web Browser"}`,
            null,
            req
        );

        res.json({
            success: true,
            message: "2FA setup initiated successfully",
            data: {
                deviceId: deviceID,
                deviceInfo: deviceInfo || "Web Browser",
                secret: secret.base32,
                qrCode: qrCode,
                uri: uri,
                manualEntry: {
                    account: username,
                    key: secret.base32,
                    issuer: config.totp.issuer,
                },
                instructions: [
                    "1. Open your authenticator app (Google Authenticator, Microsoft Authenticator, Authy, etc.)",
                    "2. Scan the QR code or manually enter the key",
                    "3. Enter the 6-digit code from your app to verify",
                ],
                config: totpService.getConfig(),
            },
        });
    });

    // Verify 2FA setup
    verifySetup = asyncHandler(async (req, res) => {
        const { deviceId, totpCode } = req.body;

        // Retrieve the device and user
        const device = await Device.getById(deviceId);
        if (!device) {
            return res.status(404).json({
                success: false,
                error: "Device not found",
                message: "The device you're trying to verify doesn't exist",
            });
        }

        const user = await User.getById(device.TwoFactorUserID);

        try {
            const verified = await totpService.verifyTOTP(
                device.SecretData,
                totpCode,
                device.TwoFactorUserID
            );

            if (!verified) {
                await User.logAuditEvent(
                    user.LoginName,
                    "2FA_VERIFY_FAILED",
                    false,
                    `Invalid TOTP for device ${deviceId}`,
                    null,
                    req
                );

                // Increment failed attempts for the device
                await Device.incrementFailedAttempts(deviceId);

                return res.status(400).json({
                    success: false,
                    error: "Invalid TOTP code",
                    message: "Please check your authenticator app and try again",
                });
            }

            // Activate the device
            await Device.activate(deviceId);

            // Check if this is the first active device
            const userActiveDevices = await Device.getActiveByUserId(device.TwoFactorUserID);
            const isFirstDevice = userActiveDevices.length === 1;

            let responseData = {
                success: true,
                message: "2FA device activated successfully",
                data: {
                    deviceId: deviceId,
                    deviceInfo: device.DeviceInfo,
                    activated: true,
                    activatedAt: new Date().toISOString(),
                    isFirstDevice: isFirstDevice,
                    user: {
                        id: device.TwoFactorUserID,
                        username: user.LoginName,
                        totalActiveDevices: userActiveDevices.length,
                    },
                },
            };

            // If this is the first device, enable 2FA for the user
            if (isFirstDevice) {
                const pool = await databaseConfig.getPool();
                const activationResult = await pool
                    .request()
                    .input("LoginName", sql.NVarChar(500), user.LoginName)
                    .input("ForceNewPassword", sql.Bit, 1)
                    .execute("PRC_ActivateTwoFactor");

                const activateData = activationResult.recordset[0];

                if (activateData.ResultCode === 0) {
                    // Generate JWT token
                    responseData.data.token = jwt.sign(
                        {
                            username: user.LoginName,
                            userId: device.TwoFactorUserID,
                            mitarbeiterID: user.MitarbeiterID,
                            serverLocationID: user.ServerLocationID,
                            mfaVerified: true,
                        },
                        config.jwt.secret,
                        { expiresIn: config.jwt.expiresIn }
                    );

                    responseData.data.dbPassword = activateData.DBPassword;

                    // Create a session
                    const sessionToken = await sessionService.createSession(
                        device.TwoFactorUserID,
                        user.LoginName,
                        device.DeviceInfo,
                        req
                    );

                    responseData.data.sessionToken = sessionToken;
                }
            }

            await User.logAuditEvent(
                user.LoginName,
                "2FA_DEVICE_ACTIVATED",
                true,
                `Device ${deviceId} activated successfully`,
                null,
                req
            );

            res.json(responseData);
        } catch (totpError) {
            if (totpError.message === "Code already used") {
                return res.status(400).json({
                    success: false,
                    error: "Code already used",
                    message: "This code has already been used. Please wait for a new code.",
                });
            }

            await User.logAuditEvent(
                user?.LoginName || "unknown",
                "2FA_VERIFY_ERROR",
                false,
                null,
                totpError.message,
                req
            );

            throw totpError;
        }
    });

    // Get TOTP configuration
    getConfig = asyncHandler(async (req, res) => {
        res.json({
            success: true,
            data: {
                ...totpService.getConfig(),
                features: {
                    totp: true,
                    deviceManagement: true,
                    sessionManagement: true,
                    auditLog: true,
                    rateLimiting: true,
                    backupCodes: false,
                    webauthn: false,
                    emailLinks: false,
                },
                security: {
                    maxFailedAttempts: config.security.maxFailedAttempts,
                    lockoutDuration: config.security.lockoutDuration / 60000, // en minutes
                    maxConcurrentSessions: config.session.maxConcurrentSessions,
                    sessionTimeout: config.session.sessionTimeout / 60000, // en minutes
                },
            },
        });
    });
}

module.exports = new TOTPController();