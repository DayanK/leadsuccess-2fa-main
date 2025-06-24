// Backend/src/models/Device.js - Model for 2FA device management
const { databaseConfig, sql } = require("../config/database");

class Device {
    constructor() {
        this.pool = null;
    }

    async getPool() {
        if (!this.pool || !databaseConfig.isHealthy()) {
            this.pool = await databaseConfig.getPool();
        }
        return this.pool;
    }

    // Create a new device
    async create(twoFactorUserID, authMethod, deviceInfo, secretData, inactive = true) {
        try {
            const pool = await this.getPool();
            const result = await pool
                .request()
                .input("TwoFactorUserID", sql.Int, twoFactorUserID)
                .input("AuthMethod", sql.NVarChar(30), authMethod)
                .input("DeviceInfo", sql.NVarChar(1000), deviceInfo)
                .input("SecretData", sql.NVarChar(4000), secretData)
                .input("Inactive", sql.Bit, inactive)
                .query(`
                    INSERT INTO TwoFactorDevice (TwoFactorUserID, AuthMethod, DeviceInfo, SecretData, Inactive)
                    VALUES (@TwoFactorUserID, @AuthMethod, @DeviceInfo, @SecretData, @Inactive);
                    SELECT SCOPE_IDENTITY() as DeviceID;
                `);

            return result.recordset[0].DeviceID;
        } catch (error) {
            console.error("❌ Error creating device:", error);
            throw error;
        }
    }

    // Get a device by ID
    async getById(deviceId) {
        try {
            const pool = await this.getPool();
            const result = await pool
                .request()
                .input("DeviceID", sql.Int, deviceId)
                .query("SELECT * FROM TwoFactorDevice WHERE TwoFactorDeviceID = @DeviceID");

            return result.recordset[0];
        } catch (error) {
            console.error("❌ Error getting device by ID:", error);
            throw error;
        }
    }

    // Get active devices for a user
    async getActiveByUserId(twoFactorUserID) {
        try {
            const pool = await this.getPool();
            const result = await pool
                .request()
                .input("TwoFactorUserID", sql.Int, twoFactorUserID)
                .query(`
                    SELECT * FROM TwoFactorDevice 
                    WHERE TwoFactorUserID = @TwoFactorUserID AND Inactive = 0
                    ORDER BY CreatedAt DESC
                `);

            return result.recordset || [];
        } catch (error) {
            console.error("❌ Error getting active devices:", error);
            return [];
        }
    }

    // Activate a device
    async activate(deviceId) {
        try {
            const pool = await this.getPool();
            await pool
                .request()
                .input("DeviceID", sql.Int, deviceId)
                .query(`
                    UPDATE TwoFactorDevice 
                    SET Inactive = 0, 
                        UpdatedAt = GETUTCDATE(), 
                        LastUsed = GETUTCDATE(),
                        FailedAttempts = 0
                    WHERE TwoFactorDeviceID = @DeviceID
                `);
        } catch (error) {
            console.error("❌ Error activating device:", error);
            throw error;
        }
    }

    // Deactivate a device
    async deactivate(deviceId) {
        try {
            const pool = await this.getPool();
            await pool
                .request()
                .input("DeviceID", sql.Int, deviceId)
                .query(`
                    UPDATE TwoFactorDevice 
                    SET Inactive = 1, 
                        UpdatedAt = GETUTCDATE() 
                    WHERE TwoFactorDeviceID = @DeviceID
                `);
        } catch (error) {
            console.error("❌ Error deactivating device:", error);
            throw error;
        }
    }

    // Delete all devices for a user
    async deleteAllByUserId(twoFactorUserID) {
        try {
            const pool = await this.getPool();
            await pool
                .request()
                .input("UserID", sql.Int, twoFactorUserID)
                .query("DELETE FROM TwoFactorDevice WHERE TwoFactorUserID = @UserID");
        } catch (error) {
            console.error("❌ Error deleting all devices:", error);
            throw error;
        }
    }

    // Update the last used timestamp for a device
    async updateLastUsed(deviceId) {
        try {
            const pool = await this.getPool();
            await pool
                .request()
                .input("DeviceID", sql.Int, deviceId)
                .query(`
                    UPDATE TwoFactorDevice 
                    SET LastUsed = GETUTCDATE(), 
                        FailedAttempts = 0
                    WHERE TwoFactorDeviceID = @DeviceID
                `);
        } catch (error) {
            console.error("❌ Error updating last used:", error);
            throw error;
        }
    }

    // Increment failed attempts for a device
    async incrementFailedAttempts(deviceId) {
        try {
            const pool = await this.getPool();
            await pool
                .request()
                .input("DeviceID", sql.Int, deviceId)
                .query(`
                    UPDATE TwoFactorDevice 
                    SET FailedAttempts = FailedAttempts + 1,
                        LastFailedAttempt = GETUTCDATE()
                    WHERE TwoFactorDeviceID = @DeviceID
                `);
        } catch (error) {
            console.error("❌ Error incrementing failed attempts:", error);
            throw error;
        }
    }

    // Increment failed attempts for all devices of a user
    async incrementFailedAttemptsForUser(twoFactorUserID) {
        try {
            const pool = await this.getPool();
            await pool
                .request()
                .input("UserID", sql.Int, twoFactorUserID)
                .query(`
                    UPDATE TwoFactorDevice 
                    SET FailedAttempts = FailedAttempts + 1,
                        LastFailedAttempt = GETUTCDATE()
                    WHERE TwoFactorUserID = @UserID AND Inactive = 0
                `);
        } catch (error) {
            console.error("❌ Error incrementing failed attempts for user:", error);
            throw error;
        }
    }
}

module.exports = new Device();