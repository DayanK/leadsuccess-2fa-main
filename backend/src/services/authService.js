// Backend/src/services/authService.js - Authentication and user management service
const jwt = require("jsonwebtoken");
const { databaseConfig, sql } = require("../config/database");
const User = require("../models/User");
const Device = require("../models/Device");
const config = require("../config/config");

class AuthService {
    constructor() {
        this.config = config;
    }

    // Generate a JWT token
    generateJWT(userData, options = {}) {
        const payload = {
            username: userData.username,
            userId: userData.userId || userData.twoFactorUserID,
            mitarbeiterID: userData.mitarbeiterID,
            serverLocationID: userData.serverLocationID,
            ...options
        };

        return jwt.sign(payload, this.config.jwt.secret, {
            expiresIn: this.config.jwt.expiresIn
        });
    }

    // Check if an account is locked
    async checkAccountLock(user) {
        if (user.AccountLocked && user.LockedUntil && user.LockedUntil > new Date()) {
            return {
                locked: true,
                lockedUntil: user.LockedUntil,
                message: "Account temporarily locked due to multiple failed attempts"
            };
        }
        return { locked: false };
    }

    // Process a direct login (without 2FA)
    async processDirectLogin(user, sessionManager, req) {
        try {
            // Generate JWT token for direct access
            const jwtToken = this.generateJWT({
                username: user.username,
                twoFactorUserID: user.twoFactorUserID,
                mitarbeiterID: user.mitarbeiterID,
                serverLocationID: user.serverLocationID,
                directLogin: true
            });

            // Create a session
            const sessionToken = await sessionManager.createSession(
                user.twoFactorUserID,
                user.username,
                "Direct Login",
                req
            );

            // Reset failed attempt counters
            await User.resetFailedAttempts(user.twoFactorUserID);

            return {
                success: true,
                authenticated: true,
                data: {
                    token: jwtToken,
                    sessionToken: sessionToken,
                    user: {
                        id: user.twoFactorUserID,
                        username: user.username,
                        mitarbeiterID: user.mitarbeiterID,
                        serverLocationID: user.serverLocationID,
                        has2FA: false,
                        deviceCount: 0
                    }
                }
            };
        } catch (error) {
            console.error("❌ Error processing direct login:", error);
            throw error;
        }
    }

    // Process full authentication with 2FA
    async processFullAuthentication(username, totpCode, user, totpService, sessionManager, req) {
        try {
            const activeDevices = await Device.getActiveByUserId(user.twoFactorUserID);

            if (activeDevices.length === 0) {
                throw new Error("No active 2FA devices found. Please contact administrator.");
            }

            // Test TOTP code on all active devices
            let validDevice = null;
            for (const device of activeDevices) {
                if (device.AuthMethod === "TOTP") {
                    try {
                        const verified = await totpService.verifyTOTP(
                            device.SecretData,
                            totpCode,
                            user.twoFactorUserID
                        );

                        if (verified) {
                            validDevice = device;
                            break;
                        }
                    } catch (verifyError) {
                        if (verifyError.message === "Code already used") {
                            throw verifyError;
                        }
                        // Continue with other devices
                    }
                }
            }

            if (!validDevice) {
                // Increment failed attempts for all devices
                await Device.incrementFailedAttemptsForUser(user.twoFactorUserID);
                throw new Error("Invalid 2FA code");
            }

            // Activate 2FA and generate new DB password
            const pool = await databaseConfig.getPool();
            const activateResult = await pool
                .request()
                .input("LoginName", sql.NVarChar(500), username)
                .input("ForceNewPassword", sql.Bit, 1)
                .execute("PRC_ActivateTwoFactor");

            const activateData = activateResult.recordset[0];

            if (activateData.ResultCode !== 0) {
                throw new Error(activateData.ErrorMessage || "Failed to activate 2FA");
            }

            // Reset failed attempt counters
            await User.resetFailedAttempts(user.twoFactorUserID);

            // Update the device used
            await Device.updateLastUsed(validDevice.TwoFactorDeviceID);

            // Generate JWT token
            const jwtToken = this.generateJWT({
                username: username,
                twoFactorUserID: user.twoFactorUserID,
                mitarbeiterID: user.mitarbeiterID,
                serverLocationID: user.serverLocationID,
                mfaVerified: true,
                deviceId: validDevice.TwoFactorDeviceID
            });

            // Create a session
            const sessionToken = await sessionManager.createSession(
                user.twoFactorUserID,
                username,
                validDevice.DeviceInfo,
                req
            );

            return {
                success: true,
                authenticated: true,
                data: {
                    token: jwtToken,
                    sessionToken: sessionToken,
                    dbPassword: activateData.DBPassword,
                    user: {
                        id: user.twoFactorUserID,
                        username: username,
                        mitarbeiterID: user.mitarbeiterID,
                        serverLocationID: user.serverLocationID,
                        has2FA: true,
                        deviceCount: activeDevices.length
                    },
                    deviceUsed: {
                        id: validDevice.TwoFactorDeviceID,
                        authMethod: validDevice.AuthMethod,
                        deviceInfo: validDevice.DeviceInfo
                    }
                }
            };
        } catch (error) {
            console.error("❌ Error processing full authentication:", error);
            throw error;
        }
    }

    // Disable 2FA for a user
    async disable2FA(username, password, totpCode, totpService, sessionManager, req) {
        try {
            // Verify password directly using passport
            const passport = require("passport");
            
            const authResult = await new Promise((resolve, reject) => {
                req.body = { ...req.body, username, password };
                
                passport.authenticate('local', { session: false }, (err, user, info) => {
                    if (err) return reject(err);
                    if (!user) return reject(new Error("Invalid password"));
                    resolve(user);
                })(req, null, () => {});
            });

            // Verify TOTP code
            const activeDevices = await Device.getActiveByUserId(authResult.twoFactorUserID);
            let totpValid = false;
            let usedDevice = null;

            for (const device of activeDevices) {
                if (device.AuthMethod === "TOTP") {
                    try {
                        const verified = await totpService.verifyTOTP(
                            device.SecretData,
                            totpCode,
                            authResult.twoFactorUserID
                        );
                        if (verified) {
                            totpValid = true;
                            usedDevice = device;
                            break;
                        }
                    } catch (e) {
                        if (e.message === "Code already used") {
                            throw e;
                        }
                    }
                }
            }

            if (!totpValid) {
                throw new Error("Invalid 2FA code");
            }

            // Delete all devices
            await Device.deleteAllByUserId(authResult.twoFactorUserID);

            // Disable 2FA for the user
            await User.disable2FA(authResult.twoFactorUserID);

            // Call the disable procedure if it exists
            try {
                const { databaseConfig, sql } = require("../config/database");
                const pool = await databaseConfig.getPool();
                await pool
                    .request()
                    .input("LoginName", sql.NVarChar(500), username)
                    .execute("PRC_Disable2FADevice");
            } catch (e) {
                // Procedure not found, continue
            }

            // Terminate all sessions except the current one
            const currentSessionToken = req.headers["x-session-token"];
            await sessionManager.terminateAllUserSessions(
                authResult.twoFactorUserID,
                currentSessionToken
            );

            return {
                success: true,
                message: "Two-factor authentication has been disabled successfully",
                data: {
                    username: username,
                    devicesDisabled: activeDevices.length,
                    sessionsTerminated: true
                }
            };
        } catch (error) {
            console.error("❌ Error disabling 2FA:", error);
            throw error;
        }
    }
}

module.exports = new AuthService();