 // Backend/src/middleware/errorHandler.js - Global error handling middleware
const User = require("../models/User");

 // Middleware for not found routes
function notFoundHandler(req, res) {
    res.status(404).json({
        success: false,
        message: "API endpoint not found",
        requestedUrl: req.url,
        method: req.method,
        availableEndpoints: {
            authentication: [
                "POST /api/v1/auth/login",
                "POST /api/v1/auth/authenticate",
                "POST /api/v1/auth/logout",
                "GET  /api/v1/auth/me",
            ],
            twoFactor: [
                "POST /api/v1/setup/2fa",
                "POST /api/v1/setup/verify",
                "POST /api/v1/auth/disable-2fa",
                "GET  /api/v1/setup/config",
            ],
            deviceManagement: [
                "GET    /api/v1/devices",
                "DELETE /api/v1/devices/:deviceId",
            ],
            sessionManagement: [
                "GET  /api/v1/sessions",
                "POST /api/v1/sessions/logout-all",
            ],
            system: [
                "GET  /api/v1/health", 
                "POST /api/v1/admin/maintenance"
            ],
        },
    });
}

 // Global error handling middleware
function errorHandler(err, req, res, next) {
    console.error("❌ Global error:", err);

    // Log the error in the audit log if possible
    if (req.user?.username || req.body?.username) {
        User.logAuditEvent(
            req.user?.username || req.body?.username,
            "SYSTEM_ERROR",
            false,
            null,
            err.message,
            req
        ).catch(logError => {
            console.error("❌ Failed to log error to audit:", logError);
        });
    }

    const isDevelopment = process.env.NODE_ENV !== "production";

    // Specific error handling
    let statusCode = 500;
    let message = "Internal server error";

    if (err.name === "ValidationError") {
        statusCode = 400;
        message = "Validation error";
    } else if (err.name === "UnauthorizedError") {
        statusCode = 401;
        message = "Unauthorized";
    } else if (err.name === "ForbiddenError") {
        statusCode = 403;
        message = "Forbidden";
    } else if (err.name === "NotFoundError") {
        statusCode = 404;
        message = "Resource not found";
    } else if (err.name === "ConflictError") {
        statusCode = 409;
        message = "Conflict";
    } else if (err.name === "TooManyRequestsError") {
        statusCode = 429;
        message = "Too many requests";
    }

    const errorResponse = {
        success: false,
        message: message,
        timestamp: new Date().toISOString(),
    };

    // Add error details in development mode
    if (isDevelopment) {
        errorResponse.error = err.message;
        errorResponse.stack = err.stack;
    }

    res.status(statusCode).json(errorResponse);
}

 // Middleware to catch asynchronous errors
function asyncHandler(fn) {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
}

 // Custom error classes
class AppError extends Error {
    constructor(message, statusCode) {
        super(message);
        this.statusCode = statusCode;
        this.isOperational = true;

        Error.captureStackTrace(this, this.constructor);
    }
}

 // Specific errors
class ValidationError extends AppError {
    constructor(message = "Validation failed") {
        super(message, 400);
        this.name = "ValidationError";
    }
}

class UnauthorizedError extends AppError {
    constructor(message = "Unauthorized") {
        super(message, 401);
        this.name = "UnauthorizedError";
    }
}

class ForbiddenError extends AppError {
    constructor(message = "Forbidden") {
        super(message, 403);
        this.name = "ForbiddenError";
    }
}

class NotFoundError extends AppError {
    constructor(message = "Resource not found") {
        super(message, 404);
        this.name = "NotFoundError";
    }
}

class ConflictError extends AppError {
    constructor(message = "Conflict") {
        super(message, 409);
        this.name = "ConflictError";
    }
}

class TooManyRequestsError extends AppError {
    constructor(message = "Too many requests") {
        super(message, 429);
        this.name = "TooManyRequestsError";
    }
}

module.exports = {
    notFoundHandler,
    errorHandler,
    asyncHandler,
    AppError,
    ValidationError,
    UnauthorizedError,
    ForbiddenError,
    NotFoundError,
    ConflictError,
    TooManyRequestsError
};