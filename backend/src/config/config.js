 // Backend/src/config/config.js - Centralized application configuration
module.exports = {
    server: {
        port: process.env.PORT || 4001,
        host: process.env.HOST || "localhost",
    },
    
    jwt: {
        secret: process.env.JWT_SECRET || "your-super-secret-jwt-key-change-in-production",
        expiresIn: process.env.JWT_EXPIRES || "24h",
        refreshExpiresIn: "7d",
    },
    
    totp: {
        window: 4,
        step: 30,
        digits: 6,
        issuer: "LeadSuccess",
        serviceName: "LeadSuccess Portal",
    },
    
    session: {
        maxConcurrentSessions: 5,
        sessionTimeout: 24 * 60 * 60 * 1000, // 24 hours
    },
    
    security: {
        maxFailedAttempts: 5,
        lockoutDuration: 30 * 60 * 1000, // 30 minutes
    },
    
    cors: {
        origin: (origin, callback) => {
            const allowedOrigins = [
                "http://localhost:3000",
                "http://localhost:4001",
                "http://localhost:5504",
                "http://localhost:5505",
                "http://localhost:5506",
                "http://localhost:5507",
                "http://localhost:5508",
                "http://127.0.0.1:5504",
                "http://127.0.0.1:5505",
                "http://127.0.0.1:3000",
                "http://127.0.0.1:4001",
                "http://127.0.0.1:5507",
                "http://127.0.0.1:5508",
            ];

            if (!origin || allowedOrigins.includes(origin)) {
                callback(null, true);
            } else {
                callback(new Error("Not allowed by CORS"));
            }
        },
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        credentials: true,
        optionsSuccessStatus: 200,
    },
    
    rateLimiting: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        general: { max: 200 },
        auth: { max: 20 },
        totp: { windowMs: 5 * 60 * 1000, max: 10 },
    }
};