 // Backend/src/middleware/authMiddleware.js - Authentication and authorization middleware
const passport = require("passport");
const sessionService = require("../services/sessionService");

 // Middleware for JWT authentication
function requireAuth(req, res, next) {
    passport.authenticate("jwt", { session: false }, (err, user, info) => {
        if (err) {
            return res.status(500).json({
                success: false,
                message: "Authentication error",
            });
        }

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "Unauthorized - Invalid or expired token",
            });
        }

        req.user = user;
        next();
    })(req, res, next);
}

 // Middleware to verify the session
async function requireSession(req, res, next) {
    const sessionToken = req.headers["x-session-token"];

    if (!sessionToken) {
        return res.status(401).json({
            success: false,
            message: "Session token required",
        });
    }

    const session = await sessionService.validateSession(sessionToken);

    if (!session) {
        return res.status(401).json({
            success: false,
            message: "Invalid or expired session",
        });
    }

    req.session = session;
    req.user = {
        username: session.username,
        twoFactorUserID: session.userId,
    };

    next();
}

 // Middleware to verify user role (future extension)
function requireRole(role) {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: "Authentication required",
            });
        }

        // Future implementation for role-based access
        if (req.user.role && req.user.role !== role) {
            return res.status(403).json({
                success: false,
                message: "Insufficient permissions",
            });
        }

        next();
    };
}

 // Middleware to verify ownership of a resource
function requireOwnership(resourceIdParam = 'id', userIdField = 'twoFactorUserID') {
    return (req, res, next) => {
        const resourceId = req.params[resourceIdParam];
        const userId = req.user[userIdField];

        // This logic will depend on your data model
        // For now, just proceed to the next middleware
        next();
    };
}

module.exports = {
    requireAuth,
    requireSession,
    requireRole,
    requireOwnership
};