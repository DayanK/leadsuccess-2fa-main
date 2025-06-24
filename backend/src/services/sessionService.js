// Backend/src/services/sessionService.js - User session management service
const crypto = require("crypto");
const Session = require("../models/Session");
const config = require("../config/config");

class SessionService {
    constructor() {
        this.activeSessions = new Map();
        this.config = config.session;
    }

    // Create a new session
    async createSession(userId, username, deviceInfo, req) {
        const sessionToken = crypto.randomBytes(64).toString("hex");
        const sessionData = {
            userId,
            username,
            deviceInfo: deviceInfo || "Unknown Device",
            ipAddress: req.ip || req.connection?.remoteAddress || "127.0.0.1",
            userAgent: req.get("User-Agent") || "Unknown",
            createdAt: new Date(),
            lastActivity: new Date(),
            expiresAt: new Date(Date.now() + this.config.sessionTimeout),
        };

        try {
            await Session.create(
                sessionToken,
                userId,
                username,
                sessionData,
                sessionData.expiresAt,
                sessionData.ipAddress,
                sessionData.userAgent
            );

            this.activeSessions.set(sessionToken, sessionData);

            // Clean up expired sessions and apply limit
            await this.cleanupAndEnforceLimit(userId);

            return sessionToken;
        } catch (error) {
            console.error("❌ Error creating session:", error);
            throw error;
        }
    }

    // Validate a session
    async validateSession(sessionToken) {
        try {
            const session = await Session.validateByToken(sessionToken);
            return session;
        } catch (error) {
            console.error("❌ Error validating session:", error);
            return null;
        }
    }

    // Clean up and enforce session limits
    async cleanupAndEnforceLimit(userId) {
        try {
            await Session.cleanupAndEnforceLimit(userId, this.config.maxConcurrentSessions);
        } catch (error) {
            console.error("❌ Error in cleanup and enforce limit:", error);
        }
    }

    // Terminate a session
    async terminateSession(sessionToken) {
        try {
            await Session.deleteByToken(sessionToken);
            this.activeSessions.delete(sessionToken);
        } catch (error) {
            console.error("❌ Error terminating session:", error);
            throw error;
        }
    }

    // Retrieve user sessions
    async getUserSessions(userId) {
        try {
            return await Session.getByUserId(userId);
        } catch (error) {
            console.error("❌ Error getting user sessions:", error);
            return [];
        }
    }

    // Terminate all user sessions except the current one
    async terminateAllUserSessions(userId, currentSessionToken = null) {
        try {
            await Session.deleteAllByUserIdExcept(userId, currentSessionToken);
        } catch (error) {
            console.error("❌ Error terminating all sessions:", error);
            throw error;
        }
    }

    // Clean up expired sessions (maintenance)
    async cleanupExpiredSessions() {
        try {
            return await Session.cleanupExpired();
        } catch (error) {
            console.error("❌ Error cleaning up expired sessions:", error);
            return 0;
        }
    }
}

module.exports = new SessionService();