// Backend/src/middleware/validation.js - Middleware de validation des données d'entrée
const { body, validationResult } = require("express-validator");
const rateLimit = require("express-rate-limit");
const config = require("../config/config");
const User = require("../models/User");

// Middleware de validation générale
function validateRequest(req, res, next) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            message: "Validation failed",
            errors: errors.array(),
        });
    }
    next();
}

// Schémas de validation
const validationSchemas = {
    // Validation pour la connexion
    login: [
        body("username")
            .trim()
            .isLength({ min: 3, max: 50 })
            .matches(/^[a-zA-Z0-9._-]+$/)
            .withMessage("Username contains invalid characters"),
        body("password")
            .isLength({ min: 1, max: 100 })
            .withMessage("Password is required"),
    ],

    // Validation pour l'authentification complète
    authenticate: [
        body("username")
            .trim()
            .isLength({ min: 3, max: 50 })
            .matches(/^[a-zA-Z0-9._-]+$/)
            .withMessage("Username contains invalid characters"),
        body("password")
            .isLength({ min: 1, max: 100 })
            .withMessage("Password is required"),
        body("totpCode")
            .isLength({ min: 6, max: 6 })
            .isNumeric()
            .withMessage("TOTP code must be exactly 6 digits"),
    ],

    // Validation pour le code TOTP
    totpCode: [
        body("totpCode")
            .isLength({ min: 6, max: 6 })
            .isNumeric()
            .withMessage("TOTP code must be exactly 6 digits"),
    ],

    // Validation pour la configuration 2FA
    deviceSetup: [
        body("username").trim().isLength({ min: 1 }),
        body("deviceInfo").optional().trim().isLength({ max: 200 }),
    ],

    // Validation pour la vérification de setup
    setupVerify: [
        body("deviceId").isNumeric(),
        body("totpCode").isLength({ min: 6, max: 6 }).isNumeric(),
    ],

    // Validation pour la désactivation 2FA
    disable2FA: [
        body("password").isLength({ min: 1 }),
        body("totpCode").isLength({ min: 6, max: 6 }).isNumeric(),
    ],
};

// Créateur de limiteurs de débit
function createRateLimiter(options) {
    return rateLimit({
        windowMs: options.windowMs || config.rateLimiting.windowMs,
        max: options.max || config.rateLimiting.general.max,
        skipSuccessfulRequests: options.skipSuccessfulRequests || false,
        standardHeaders: true,
        legacyHeaders: false,
        handler: async (req, res) => {
            await User.logAuditEvent(
                req.body?.username || "unknown",
                "RATE_LIMIT_EXCEEDED",
                false,
                `Rate limit exceeded for ${req.path}`,
                null,
                req
            );
            res.status(429).json({
                success: false,
                error: "Too many requests",
                message: "Please wait before trying again",
                retryAfter: Math.ceil(options.windowMs / 1000),
            });
        },
    });
}

// Limiteurs de débit spécifiques
const rateLimiters = {
    general: createRateLimiter({ max: config.rateLimiting.general.max }),
    auth: createRateLimiter({ 
        windowMs: config.rateLimiting.windowMs, 
        max: config.rateLimiting.auth.max 
    }),
    totp: createRateLimiter({ 
        windowMs: config.rateLimiting.totp.windowMs, 
        max: config.rateLimiting.totp.max 
    }),
};

module.exports = {
    validateRequest,
    validationSchemas,
    rateLimiters,
    createRateLimiter
};