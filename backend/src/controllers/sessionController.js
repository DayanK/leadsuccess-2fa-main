 // Backend/src/controllers/sessionController.js - Controller for managing user sessions
const User = require("../models/User");
const sessionService = require("../services/sessionService");
const { asyncHandler } = require("../middleware/errorHandler");

class SessionController {
    // Get all active sessions of the user
    getSessions = asyncHandler(async (req, res) => {
        const sessions = await sessionService.getUserSessions(req.user.twoFactorUserID);
        const currentSessionToken = req.headers["x-session-token"];

        res.json({
            success: true,
            sessions: sessions.map((session) => {
                const info = JSON.parse(session.SessionInfo);
                return {
                    id: session.SessionID,
                    deviceInfo: info.deviceInfo || "Unknown Device",
                    ipAddress: session.IPAddress,
                    userAgent: session.UserAgent,
                    createdAt: session.CreatedAt,
                    lastUsed: session.LastUsedTS,
                    expiresAt: session.ExpiresAt,
                    isCurrent: currentSessionToken === session.SessionToken,
                };
            }),
        });
    });

    // Logout all other sessions
    logoutAllSessions = asyncHandler(async (req, res) => {
        const currentSession = req.headers["x-session-token"];
        const sessions = await sessionService.getUserSessions(req.user.twoFactorUserID);

        let terminatedCount = 0;
        for (const session of sessions) {
            if (session.SessionToken !== currentSession) {
                await sessionService.terminateSession(session.SessionToken);
                terminatedCount++;
            }
        }

        await User.logAuditEvent(
            req.user.username,
            "LOGOUT_ALL",
            true,
            `${terminatedCount} sessions terminated`,
            null,
            req
        );

        res.json({
            success: true,
            message: "All other sessions terminated successfully",
            data: {
                terminatedSessions: terminatedCount,
                currentSessionMaintained: true,
            },
        });
    });
}

module.exports = new SessionController();