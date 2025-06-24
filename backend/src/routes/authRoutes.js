 // Backend/src/routes/authRoutes.js - Authentication routes
const express = require("express");
const authController = require("../controllers/authController");
const totpController = require("../controllers/totpController");
const { requireAuth, requireSession } = require("../middleware/authMiddleware");
const { validateRequest, validationSchemas, rateLimiters } = require("../middleware/validation");

const router = express.Router();

 // Authentication routes
router.post(
    "/login",
    rateLimiters.auth,
    validationSchemas.login,
    validateRequest,
    authController.login
);

router.post(
    "/authenticate",
    rateLimiters.auth,
    validationSchemas.authenticate,
    validateRequest,
    authController.authenticate
);

router.get(
    "/me",
    requireAuth,
    authController.getCurrentUser
);

router.post(
    "/logout",
    requireSession,
    authController.logout
);

router.post(
    "/disable-2fa",
    requireAuth,
    rateLimiters.auth,
    validationSchemas.disable2FA,
    validateRequest,
    authController.disable2FA
);

 // 2FA setup routes
router.post(
    "/setup/2fa",
    rateLimiters.auth,
    validationSchemas.deviceSetup,
    validateRequest,
    totpController.setup2FA
);

router.post(
    "/setup/verify",
    rateLimiters.totp,
    validationSchemas.setupVerify,
    validateRequest,
    totpController.verifySetup
);

router.get(
    "/setup/config",
    totpController.getConfig
);

module.exports = router;