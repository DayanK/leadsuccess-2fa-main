// Backend/src/utils/helpers.js - Fonctions utilitaires générales
const crypto = require("crypto");

/**
 * Générer un token sécurisé aléatoire
 * @param {number} length - Longueur en bytes
 * @returns {string} Token hexadécimal
 */
function generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString("hex");
}

/**
 * Obtenir des informations sur l'appareil depuis l'User-Agent
 * @param {string} userAgent 
 * @param {string} platform 
 * @returns {string} Description de l'appareil
 */
function getDeviceInfo(userAgent, platform) {
    if (!userAgent) return "Unknown Device";
    
    let browser = "Unknown";
    let version = "";
    
    if (userAgent.indexOf("Firefox") > -1) {
        browser = "Firefox";
        const match = userAgent.match(/Firefox\/(\d+\.\d+)/);
        version = match ? match[1] : "";
    } else if (userAgent.indexOf("Chrome") > -1) {
        browser = "Chrome";
        const match = userAgent.match(/Chrome\/(\d+\.\d+)/);
        version = match ? match[1] : "";
    } else if (userAgent.indexOf("Safari") > -1) {
        browser = "Safari";
        const match = userAgent.match(/Version\/(\d+\.\d+)/);
        version = match ? match[1] : "";
    } else if (userAgent.indexOf("Edge") > -1) {
        browser = "Edge";
        const match = userAgent.match(/Edge\/(\d+\.\d+)/);
        version = match ? match[1] : "";
    }
    
    return `${browser}${version ? " " + version : ""} on ${platform || "Unknown OS"}`;
}

/**
 * Valider un format d'email
 * @param {string} email 
 * @returns {boolean}
 */
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

/**
 * Valider un code TOTP
 * @param {string} code 
 * @returns {boolean}
 */
function isValidTOTPCode(code) {
    return /^\d{6}$/.test(code);
}

/**
 * Obtenir l'adresse IP du client
 * @param {Object} req - Objet request Express
 * @returns {string}
 */
function getClientIP(req) {
    return req.ip || 
           req.connection?.remoteAddress || 
           req.socket?.remoteAddress || 
           (req.connection?.socket ? req.connection.socket.remoteAddress : null) ||
           "localhost";
}

/**
 * Sanitiser une chaîne pour éviter les injections
 * @param {string} str 
 * @returns {string}
 */
function sanitizeString(str) {
    if (typeof str !== "string") return "";
    return str.replace(/[<>\"'&]/g, "");
}

/**
 * Formater une durée en millisecondes en format lisible
 * @param {number} ms 
 * @returns {string}
 */
function formatDuration(ms) {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) return `${days} day${days > 1 ? "s" : ""}`;
    if (hours > 0) return `${hours} hour${hours > 1 ? "s" : ""}`;
    if (minutes > 0) return `${minutes} minute${minutes > 1 ? "s" : ""}`;
    return `${seconds} second${seconds > 1 ? "s" : ""}`;
}

/**
 * Créer une réponse API standardisée
 * @param {boolean} success 
 * @param {string} message 
 * @param {Object} data 
 * @param {Object} error 
 * @returns {Object}
 */
function createApiResponse(success, message, data = null, error = null) {
    const response = {
        success,
        message,
        timestamp: new Date().toISOString(),
    };

    if (data !== null) {
        response.data = data;
    }

    if (error !== null) {
        response.error = error;
    }

    return response;
}

/**
 * Délai asynchrone
 * @param {number} ms 
 * @returns {Promise}
 */
function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Tronquer un texte à une longueur donnée
 * @param {string} text 
 * @param {number} maxLength 
 * @returns {string}
 */
function truncateText(text, maxLength = 100) {
    if (!text || text.length <= maxLength) return text;
    return text.substring(0, maxLength - 3) + "...";
}

/**
 * Vérifier si une chaîne est un JSON valide
 * @param {string} str 
 * @returns {boolean}
 */
function isValidJSON(str) {
    try {
        JSON.parse(str);
        return true;
    } catch (e) {
        return false;
    }
}

module.exports = {
    generateSecureToken,
    getDeviceInfo,
    isValidEmail,
    isValidTOTPCode,
    getClientIP,
    sanitizeString,
    formatDuration,
    createApiResponse,
    delay,
    truncateText,
    isValidJSON,
};