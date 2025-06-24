// Backend/src/utils/logger.js - Système de logging centralisé
const winston = require("winston");
const path = require("path");

// Configuration des formats de log
const logFormat = winston.format.combine(
    winston.format.timestamp({
        format: "YYYY-MM-DD HH:mm:ss"
    }),
    winston.format.errors({ stack: true }),
    winston.format.json()
);

const consoleFormat = winston.format.combine(
    winston.format.colorize(),
    winston.format.timestamp({
        format: "YYYY-MM-DD HH:mm:ss"
    }),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
        let msg = `${timestamp} [${level}]: ${message}`;
        if (Object.keys(meta).length > 0) {
            msg += ` ${JSON.stringify(meta)}`;
        }
        return msg;
    })
);

// Configuration du logger principal
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || "info",
    format: logFormat,
    defaultMeta: { service: "leadsuccess-2fa-api" },
    transports: [
        // Log des erreurs dans un fichier séparé
        new winston.transports.File({
            filename: path.join(__dirname, "../../../logs/error.log"),
            level: "error",
            maxsize: 5242880, // 5MB
            maxFiles: 5,
        }),
        // Log général
        new winston.transports.File({
            filename: path.join(__dirname, "../../../logs/combined.log"),
            maxsize: 5242880, // 5MB
            maxFiles: 5,
        }),
    ],
});

// Ajouter la console en mode développement
if (process.env.NODE_ENV !== "production") {
    logger.add(new winston.transports.Console({
        format: consoleFormat
    }));
}

// Logger spécialisé pour l'audit
const auditLogger = winston.createLogger({
    level: "info",
    format: logFormat,
    defaultMeta: { service: "leadsuccess-2fa-audit" },
    transports: [
        new winston.transports.File({
            filename: path.join(__dirname, "../../../logs/audit.log"),
            maxsize: 10485760, // 10MB
            maxFiles: 10,
        }),
    ],
});

// Logger spécialisé pour la sécurité
const securityLogger = winston.createLogger({
    level: "warn",
    format: logFormat,
    defaultMeta: { service: "leadsuccess-2fa-security" },
    transports: [
        new winston.transports.File({
            filename: path.join(__dirname, "../../../logs/security.log"),
            maxsize: 10485760, // 10MB
            maxFiles: 10,
        }),
    ],
});

// Fonctions utilitaires pour le logging
const loggers = {
    // Logger général
    info: (message, meta = {}) => logger.info(message, meta),
    warn: (message, meta = {}) => logger.warn(message, meta),
    error: (message, meta = {}) => logger.error(message, meta),
    debug: (message, meta = {}) => logger.debug(message, meta),

    // Audit logging
    auditLog: (action, userId, success, details = {}) => {
        auditLogger.info("Audit Event", {
            action,
            userId,
            success,
            timestamp: new Date().toISOString(),
            ...details
        });
    },

    // Security logging
    securityLog: (event, details = {}) => {
        securityLogger.warn("Security Event", {
            event,
            timestamp: new Date().toISOString(),
            ...details
        });
    },

    // Performance logging
    performanceLog: (operation, duration, details = {}) => {
        logger.info("Performance Metric", {
            operation,
            duration: `${duration}ms`,
            timestamp: new Date().toISOString(),
            ...details
        });
    },

    // Request logging middleware
    requestLogger: (req, res, next) => {
        const start = Date.now();
        
        // Log de la requête entrante
        logger.info("Incoming Request", {
            method: req.method,
            url: req.url,
            ip: req.ip,
            userAgent: req.get("User-Agent"),
            timestamp: new Date().toISOString()
        });

        // Override de res.end pour logger la réponse
        const originalEnd = res.end;
        res.end = function(...args) {
            const duration = Date.now() - start;
            
            logger.info("Request Completed", {
                method: req.method,
                url: req.url,
                statusCode: res.statusCode,
                duration: `${duration}ms`,
                timestamp: new Date().toISOString()
            });

            originalEnd.apply(this, args);
        };

        next();
    },

    // Error logging middleware
    errorLogger: (err, req, res, next) => {
        logger.error("Request Error", {
            error: err.message,
            stack: err.stack,
            method: req.method,
            url: req.url,
            ip: req.ip,
            userAgent: req.get("User-Agent"),
            timestamp: new Date().toISOString()
        });

        next(err);
    }
};

// Créer le dossier de logs s'il n'existe pas
const fs = require("fs");
const logsDir = path.join(__dirname, "../../../logs");
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

module.exports = loggers;