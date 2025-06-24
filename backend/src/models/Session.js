// Backend/src/models/Session.js - Model for user session management
const { databaseConfig, sql } = require("../config/database");

class Session {
    constructor() {
        this.pool = null;
    }

    async getPool() {
        if (!this.pool || !databaseConfig.isHealthy()) {
            this.pool = await databaseConfig.getPool();
        }
        return this.pool;
    }

    // Create a new session
    async create(sessionToken, twoFactorUserID, loginName, sessionData, expiresAt, ipAddress, userAgent) {
        try {
            const pool = await this.getPool();
            await pool
                .request()
                .input("SessionToken", sql.NVarChar(128), sessionToken)
                .input("TwoFactorUserID", sql.Int, twoFactorUserID)
                .input("LoginName", sql.NVarChar(500), loginName)
                .input("SessionInfo", sql.NVarChar(sql.MAX), JSON.stringify(sessionData))
                .input("ExpiresAt", sql.DateTime2, expiresAt)
                .input("IPAddress", sql.NVarChar(45), ipAddress)
                .input("UserAgent", sql.NVarChar(500), userAgent)
                .query(`
                    INSERT INTO TwoFactorSession 
                    (SessionToken, TwoFactorUserID, LoginName, SessionInfo, ExpiresAt, IPAddress, UserAgent)
                    VALUES (@SessionToken, @TwoFactorUserID, @LoginName, @SessionInfo, @ExpiresAt, @IPAddress, @UserAgent)
                `);
        } catch (error) {
            console.error("❌ Error creating session:", error);
            throw error;
        }
    }

    // Validate a session by token
    async validateByToken(sessionToken) {
        try {
            const pool = await this.getPool();
            const result = await pool
                .request()
                .input("SessionToken", sql.NVarChar(128), sessionToken)
                .query(`
                    SELECT * FROM TwoFactorSession 
                    WHERE SessionToken = @SessionToken AND ExpiresAt > GETUTCDATE()
                `);

            const session = result.recordset[0];
            if (!session) return null;

            // Update last activity
            await pool
                .request()
                .input("SessionToken", sql.NVarChar(128), sessionToken)
                .query("UPDATE TwoFactorSession SET LastUsedTS = GETUTCDATE() WHERE SessionToken = @SessionToken");

            return JSON.parse(session.SessionInfo);
        } catch (error) {
            console.error("❌ Error validating session:", error);
            return null;
        }
    }

    // Get all sessions for a user
    async getByUserId(userId) {
        try {
            const pool = await this.getPool();
            const result = await pool
                .request()
                .input("UserID", sql.Int, userId)
                .query(`
                    SELECT * FROM TwoFactorSession 
                    WHERE TwoFactorUserID = @UserID AND ExpiresAt > GETUTCDATE()
                    ORDER BY CreatedAt DESC
                `);

            return result.recordset;
        } catch (error) {
            console.error("❌ Error getting user sessions:", error);
            return [];
        }
    }

    // Delete a session by token
    async deleteByToken(sessionToken) {
        try {
            const pool = await this.getPool();
            await pool
                .request()
                .input("SessionToken", sql.NVarChar(128), sessionToken)
                .query("DELETE FROM TwoFactorSession WHERE SessionToken = @SessionToken");
        } catch (error) {
            console.error("❌ Error deleting session:", error);
            throw error;
        }
    }

    // Delete all sessions for a user except the current one
    async deleteAllByUserIdExcept(userId, currentSessionToken = null) {
        try {
            const pool = await this.getPool();

            if (currentSessionToken) {
                await pool
                    .request()
                    .input("UserID", sql.Int, userId)
                    .input("CurrentSession", sql.NVarChar(128), currentSessionToken)
                    .query(`
                        DELETE FROM TwoFactorSession 
                        WHERE TwoFactorUserID = @UserID AND SessionToken != @CurrentSession
                    `);
            } else {
                await pool
                    .request()
                    .input("UserID", sql.Int, userId)
                    .input("TwoFactorUserID", sql.Int, userId) // Added for consistency with the query
                    .query("DELETE FROM TwoFactorSession WHERE TwoFactorUserID = @TwoFactorUserID");
            }
        } catch (error) {
            console.error("❌ Error deleting all user sessions:", error);
            throw error;
        }
    }

    // Clean up expired sessions and enforce limit
    async cleanupAndEnforceLimit(userId, maxSessions) {
        try {
            const pool = await this.getPool();

            // Delete expired sessions
            await pool
                .request()
                .query("DELETE FROM TwoFactorSession WHERE ExpiresAt < GETUTCDATE()");

            // Get active sessions for this user
            const result = await pool
                .request()
                .input("UserID", sql.Int, userId)
                .query(`
                    SELECT SessionID, SessionToken, CreatedAt 
                    FROM TwoFactorSession 
                    WHERE TwoFactorUserID = @UserID AND ExpiresAt > GETUTCDATE()
                    ORDER BY CreatedAt DESC
                `);

            const sessions = result.recordset;
            if (sessions.length > maxSessions) {
                // Delete the oldest sessions
                const sessionsToRemove = sessions.slice(maxSessions);

                for (const session of sessionsToRemove) {
                    await this.deleteByToken(session.SessionToken);
                }
            }
        } catch (error) {
            console.error("❌ Error in cleanup and enforce limit:", error);
        }
    }

    // Clean up expired sessions (maintenance)
    async cleanupExpired() {
        try {
            const pool = await this.getPool();
            const result = await pool
                .request()
                .query("DELETE FROM TwoFactorSession WHERE ExpiresAt < GETUTCDATE()");

            return result.rowsAffected[0] || 0;
        } catch (error) {
            console.error("❌ Error cleaning up expired sessions:", error);
            return 0;
        }
    }
}

module.exports = new Session();