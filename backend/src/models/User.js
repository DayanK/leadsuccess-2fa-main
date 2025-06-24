// Backend/src/models/User.js - Model for 2FA user management
const { databaseConfig, sql } = require("../config/database");

class User {
    constructor() {
        this.pool = null;
    }

    async getPool() {
        if (!this.pool || !databaseConfig.isHealthy()) {
            this.pool = await databaseConfig.getPool();
        }
        return this.pool;
    }

    // Create or retrieve a 2FA user
    async ensureTwoFactorUser(username, mitarbeiterID = null, serverLocationID = null) {
        try {
            const pool = await this.getPool();

            let result = await pool
                .request()
                .input("LoginName", sql.NVarChar(500), username)
                .query("SELECT * FROM TwoFactorUser WHERE LoginName = @LoginName");

            let user = result.recordset[0];

            if (!user) {
                await pool
                    .request()
                    .input("LoginName", sql.NVarChar(500), username)
                    .input("MitarbeiterID", sql.Int, mitarbeiterID)
                    .input("ServerLocationID", sql.Int, serverLocationID)
                    .query(`
                        INSERT INTO TwoFactorUser (LoginName, MitarbeiterID, ServerLocationID, Disable2FA)
                        VALUES (@LoginName, @MitarbeiterID, @ServerLocationID, 1)
                    `);

                result = await pool
                    .request()
                    .input("LoginName", sql.NVarChar(500), username)
                    .query("SELECT * FROM TwoFactorUser WHERE LoginName = @LoginName");

                user = result.recordset[0];
            }

            return user;
        } catch (error) {
            console.error("❌ Error ensuring TwoFactorUser:", error);
            throw error;
        }
    }

    // Get a user by username
    async getByUsername(username) {
        try {
            const pool = await this.getPool();
            const result = await pool
                .request()
                .input("LoginName", sql.NVarChar(500), username)
                .query("SELECT * FROM TwoFactorUser WHERE LoginName = @LoginName");

            return result.recordset[0];
        } catch (error) {
            console.error("❌ Error getting user by username:", error);
            throw error;
        }
    }

    // Get a user by ID
    async getById(userId) {
        try {
            const pool = await this.getPool();
            const result = await pool
                .request()
                .input("UserID", sql.Int, userId)
                .query("SELECT * FROM TwoFactorUser WHERE TwoFactorUserID = @UserID");

            return result.recordset[0];
        } catch (error) {
            console.error("❌ Error getting user by ID:", error);
            throw error;
        }
    }

    // Update account lock status
    async updateLockStatus(userId, locked, lockedUntil = null, failedAttempts = 0) {
        try {
            const pool = await this.getPool();
            await pool
                .request()
                .input("UserID", sql.Int, userId)
                .input("AccountLocked", sql.Bit, locked)
                .input("LockedUntil", sql.DateTime2, lockedUntil)
                .input("FailedLoginAttempts", sql.Int, failedAttempts)
                .query(`
                    UPDATE TwoFactorUser 
                    SET AccountLocked = @AccountLocked,
                        LockedUntil = @LockedUntil,
                        FailedLoginAttempts = @FailedLoginAttempts,
                        UpdatedAt = GETUTCDATE()
                    WHERE TwoFactorUserID = @UserID
                `);
        } catch (error) {
            console.error("❌ Error updating lock status:", error);
            throw error;
        }
    }

    // Increment failed attempts
    async incrementFailedAttempts(username, maxAttempts, lockoutDuration) {
        try {
            const pool = await this.getPool();
            await pool
                .request()
                .input("LoginName", sql.NVarChar(500), username)
                .input("MaxAttempts", sql.Int, maxAttempts)
                .input("LockoutMinutes", sql.Int, lockoutDuration / 60000)
                .query(`
                    UPDATE TwoFactorUser 
                    SET FailedLoginAttempts = FailedLoginAttempts + 1,
                        LastFailedLogin = GETUTCDATE(),
                        AccountLocked = CASE 
                            WHEN FailedLoginAttempts >= @MaxAttempts - 1 THEN 1 
                            ELSE 0 
                        END,
                        LockedUntil = CASE 
                            WHEN FailedLoginAttempts >= @MaxAttempts - 1 
                            THEN DATEADD(MINUTE, @LockoutMinutes, GETUTCDATE())
                            ELSE LockedUntil
                        END
                    WHERE LoginName = @LoginName
                `);
        } catch (error) {
            console.error("❌ Error incrementing failed attempts:", error);
            throw error;
        }
    }

    // Reset failed attempt counters
    async resetFailedAttempts(userId) {
        try {
            const pool = await this.getPool();
            await pool
                .request()
                .input("UserID", sql.Int, userId)
                .query(`
                    UPDATE TwoFactorUser 
                    SET FailedLoginAttempts = 0, 
                        AccountLocked = 0,
                        LockedUntil = NULL,
                        LastLogin = GETUTCDATE()
                    WHERE TwoFactorUserID = @UserID
                `);
        } catch (error) {
            console.error("❌ Error resetting failed attempts:", error);
            throw error;
        }
    }

    // Disable 2FA for a user
    async disable2FA(userId) {
        try {
            const pool = await this.getPool();
            await pool
                .request()
                .input("UserID", sql.Int, userId)
                .query(`
                    UPDATE TwoFactorUser 
                    SET Disable2FA = 1,
                        DBPassword = NULL,
                        ValidUntilUTC = NULL,
                        UpdatedAt = GETUTCDATE()
                    WHERE TwoFactorUserID = @UserID
                `);
        } catch (error) {
            console.error("❌ Error disabling 2FA:", error);
            throw error;
        }
    }

    // Log an audit event
    async logAuditEvent(loginName, action, success, details = null, error = null, req = null) {
        try {
            const pool = await this.getPool();
            await pool
                .request()
                .input("LoginName", sql.NVarChar(500), loginName || "system")
                .input("Action", sql.NVarChar(100), action)
                .input("Success", sql.Bit, success)
                .input("ActionDetails", sql.NVarChar(1000), details)
                .input("ErrorMessage", sql.NVarChar(1000), error)
                .input("IPAddress", sql.NVarChar(45), req?.ip || req?.connection?.remoteAddress || "localhost")
                .input("UserAgent", sql.NVarChar(500), req?.get("User-Agent") || "Unknown")
                .query(`
                    INSERT INTO TwoFactorAuditLog (LoginName, Action, Success, ActionDetails, ErrorMessage, IPAddress, UserAgent)
                    VALUES (@LoginName, @Action, @Success, @ActionDetails, @ErrorMessage, @IPAddress, @UserAgent)
                `);
        } catch (err) {
            console.error("❌ Audit log error:", err);
        }
    }
}

module.exports = new User();