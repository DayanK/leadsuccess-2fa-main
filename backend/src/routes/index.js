// Backend/src/routes/index.js - Entry point for main routes
const express = require("express");
const { databaseConfig } = require("../config/database");
const { rateLimiters } = require("../middleware/validation");
const { asyncHandler } = require("../middleware/errorHandler");

//  Import specialized routes
const authRoutes = require("./authRoutes");
const deviceRoutes = require("./deviceRoutes");
const sessionRoutes = require("./sessionRoutes");

const router = express.Router();

//  Apply general rate limiting
router.use("/", rateLimiters.general);

// Health check complet
router.get("/health", asyncHandler(async (req, res) => {
    try {
        const dbHealth = await databaseConfig.healthCheck();
        res.json({
            success: true,
            message: "LeadSuccess 2FA API is running",
            timestamp: new Date().toISOString(),
            version: "3.0.0",
            database: dbHealth,
            features: {
                totp: true,
                sessions: true,
                deviceManagement: true,
                auditLog: true,
                rateLimiting: true,
                backupCodes: false,
                webauthn: false,
                emailLinks: false,
            },
            endpoints: {
                authentication: [
                    "POST /api/v1/auth/login",
                    "POST /api/v1/auth/authenticate",
                    "POST /api/v1/auth/logout",
                    "GET  /api/v1/auth/me",
                ],
                twoFactor: [
                    "POST /api/v1/auth/setup/2fa",
                    "POST /api/v1/auth/setup/verify",
                    "POST /api/v1/auth/disable-2fa",
                    "GET  /api/v1/auth/setup/config",
                ],
                deviceManagement: [
                    "GET    /api/v1/devices",
                    "DELETE /api/v1/devices/:deviceId",
                ],
                sessionManagement: [
                    "GET  /api/v1/sessions",
                    "POST /api/v1/sessions/logout-all",
                ],
            },
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Health check failed",
            error: error.message,
        });
    }
}));

// Administrative maintenance route
router.post("/admin/maintenance", asyncHandler(async (req, res) => {
    try {
        const pool = await databaseConfig.getPool();
        const result = await pool.request().execute("PRC_MaintenanceJob");
        const maintenanceResult = result.recordset[0];

        res.json({
            success: maintenanceResult.Success === 1,
            message: maintenanceResult.Message,
            timestamp: new Date().toISOString(),
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: "Maintenance job failed",
            message: error.message,
        });
    }
}));

// routes
router.use("/auth", authRoutes);
router.use("/devices", deviceRoutes);
router.use("/sessions", sessionRoutes);

module.exports = router;