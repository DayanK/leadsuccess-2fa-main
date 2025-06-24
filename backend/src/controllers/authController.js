 // Backend/src/controllers/authController.js - Authentication Controller
const passport = require("passport");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const Device = require("../models/Device");
const authService = require("../services/authService");
const sessionService = require("../services/sessionService");
const totpService = require("../services/totpService");
const { asyncHandler } = require("../middleware/errorHandler");
const config = require("../config/config");

class AuthController {
    // Login with username and password
    login = asyncHandler(async (req, res) => {
        const { username, password } = req.body;

        passport.authenticate("local", { session: false }, async (err, user, info) => {
            if (err) {
                await User.logAuditEvent(username, "LOGIN_ERROR", false, null, err.message, req);
                return res.status(500).json({
                    success: false,
                    message: "Authentication error",
                });
            }

            if (!user) {
                await User.logAuditEvent(username, "LOGIN_FAILED", false, "Invalid credentials", null, req);
                
                // Increment failed attempts
                await User.incrementFailedAttempts(
                    username, 
                    config.security.maxFailedAttempts, 
                    config.security.lockoutDuration
                );

                return res.status(401).json({
                    success: false,
                    message: "Invalid username or password",
                });
            }

            // Check if the account is locked
            const lockCheck = await authService.checkAccountLock(user);
            if (lockCheck.locked) {
                await User.logAuditEvent(username, "LOGIN_LOCKED", false, "Account locked", null, req);
                return res.status(423).json({
                    success: false,
                    message: lockCheck.message,
                    lockedUntil: lockCheck.lockedUntil,
                });
            }

            // If no 2FA configured, direct login
            if (!user.has2FA || user.activeDeviceCount === 0) {
                const result = await authService.processDirectLogin(user, sessionService, req);
                
                await User.logAuditEvent(username, "LOGIN_SUCCESS_DIRECT", true, "Direct login without 2FA", null, req);
                
                return res.json({
                    success: true,
                    message: "Login successful",
                    authenticated: true,
                    data: result.data,
                });
            }

            // If 2FA is configured, request the code
            const tempToken = jwt.sign(
                {
                    userId: user.twoFactorUserID,
                    username: username,
                    needsVerification: true,
                },
                config.jwt.secret,
                { expiresIn: "10m" }
            );

            await User.logAuditEvent(username, "LOGIN_NEEDS_2FA", true, "User needs 2FA verification", null, req);

            res.json({
                success: true,
                needs2FA: true,
                tempToken: tempToken,
                user: {
                    id: user.twoFactorUserID,
                    username: username,
                    deviceCount: user.activeDeviceCount,
                },
            });
        })(req, res);
    });

    // Full authentication with 2FA
    authenticate = asyncHandler(async (req, res) => {
        const { username, password, totpCode } = req.body;

        passport.authenticate("local", { session: false }, async (err, user, info) => {
            if (err || !user) {
                await User.logAuditEvent(username, "AUTH_FAILED_PASSWORD", false, "Invalid password", null, req);
                return res.status(401).json({
                    success: false,
                    message: "Invalid credentials",
                });
            }

            try {
                const result = await authService.processFullAuthentication(
                    username, 
                    totpCode, 
                    user, 
                    totpService, 
                    sessionService, 
                    req
                );

                await User.logAuditEvent(username, "AUTH_SUCCESS", true, "Full 2FA authentication successful", null, req);

                res.json({
                    success: true,
                    message: "Authentication successful",
                    data: result.data,
                });
            } catch (error) {
                if (error.message === "Code already used") {
                    return res.status(400).json({
                        success: false,
                        error: "Code already used",
                        message: "This code has already been used. Please wait for a new code.",
                    });
                }

                await User.logAuditEvent(username, "AUTH_FAILED_2FA", false, "Invalid TOTP code", null, req);

                // Nettoyer les codes TOTP récents pour cet utilisateur
                totpService.clearUserCodes(user.twoFactorUserID);

                return res.status(401).json({
                    success: false,
                    message: error.message || "Authentication failed",
                });
            }
        })(req, res);
    });

    // Get current user information
    getCurrentUser = asyncHandler(async (req, res) => {
        const user = await User.getById(req.user.twoFactorUserID);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found",
            });
        }

        const activeDevices = await Device.getActiveByUserId(req.user.twoFactorUserID);

        res.json({
            success: true,
            user: {
                id: req.user.twoFactorUserID,
                username: user.LoginName,
                mitarbeiterId: user.MitarbeiterID,
                serverLocationId: user.ServerLocationID,
                has2FA: activeDevices.length > 0 && !user.Disable2FA,
                deviceCount: activeDevices.length,
                lastLogin: user.LastLogin,
                accountLocked: user.AccountLocked,
                failedAttempts: user.FailedLoginAttempts,
                createdAt: user.CreatedAt,
            },
        });
    });

    // Logout
    logout = asyncHandler(async (req, res) => {
        const sessionToken = req.headers["x-session-token"];
        if (sessionToken) {
            await sessionService.terminateSession(sessionToken);
        }

        await User.logAuditEvent(req.user.username, "LOGOUT", true, "User logged out", null, req);

        res.json({
            success: true,
            message: "Logged out successfully",
        });
    });

    // Disable 2FA
    disable2FA = asyncHandler(async (req, res) => {
        const { password, totpCode } = req.body;
        const username = req.user.username;

        try {
            const result = await authService.disable2FA(
                username,
                password,
                totpCode,
                totpService,
                sessionService,
                req
            );

            await User.logAuditEvent(username, "2FA_DISABLED", true, "2FA disabled completely", null, req);

            res.json(result);
        } catch (error) {
            if (error.message === "Code already used") {
                return res.status(400).json({
                    success: false,
                    error: "Code already used",
                    message: "This code has already been used. Please wait for a new code.",
                });
            }

            await User.logAuditEvent(username, "DISABLE_2FA_ERROR", false, null, error.message, req);

            return res.status(error.message === "Invalid password" ? 401 : 500).json({
                success: false,
                error: error.message === "Invalid password" ? "Invalid password" : "Failed to disable 2FA",
                message: error.message,
            });
        }
    });
}

module.exports = new AuthController();