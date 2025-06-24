// Backend/src/services/totpService.js - TOTP (Time-based One-Time Password) management service
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const config = require("../config/config");

class TOTPService {
    constructor() {
        this.recentCodes = new Map();
        this.cleanupInterval = setInterval(() => this.cleanupOldCodes(), 60000);
        this.config = config.totp;
    }

    // Clean up a user's recent codes
    clearUserCodes(userId) {
        const keysToDelete = [];
        for (const key of this.recentCodes.keys()) {
            if (key.startsWith(`${userId}:`)) {
                keysToDelete.push(key);
            }
        }
        keysToDelete.forEach((key) => this.recentCodes.delete(key));
    }

    // Generate a TOTP secret
    generateSecret() {
        return speakeasy.generateSecret({
            name: this.config.serviceName,
            issuer: this.config.issuer,
            length: 32,
        });
    }

    // Generate a QR Code URL
    async generateQRCode(secret, username) {
        const timestamp = Date.now();
        const otpAuthUrl = `otpauth://totp/${encodeURIComponent(this.config.issuer)}:${encodeURIComponent(username)}?secret=${secret}&issuer=${encodeURIComponent(this.config.issuer)}&algorithm=SHA1&digits=6&period=30&timestamp=${timestamp}`;

        const qrCodeBase64 = await QRCode.toDataURL(otpAuthUrl, {
            errorCorrectionLevel: "M",
            type: "image/png",
            quality: 0.92,
            margin: 1,
            width: 256,
            color: {
                dark: "#000000",
                light: "#FFFFFF",
            },
        });

        return {
            qrCode: qrCodeBase64,
            uri: otpAuthUrl
        };
    }

    // Verify a TOTP code
    async verifyTOTP(secret, token, userId) {
        // Check code format
        if (!/^\d{6}$/.test(token)) {
            throw new Error("Invalid code format");
        }

        const codeKey = `${userId}:${token}`;

        // Check if the code has already been used recently
        if (this.recentCodes.has(codeKey)) {
            throw new Error("Code already used");
        }

        const verified = speakeasy.totp.verify({
            secret,
            encoding: "base32",
            token,
            window: this.config.window,
            algorithm: "sha1",
            digits: this.config.digits,
            step: this.config.step,
        });

        if (verified) {
            // Mark the code as used
            this.recentCodes.set(codeKey, Date.now());
        }

        return verified;
    }

    // Clean up old codes
    cleanupOldCodes() {
        const now = Date.now();
        const ttl = 5 * 60 * 1000; // 5 minutes

        for (const [key, timestamp] of this.recentCodes) {
            if (now - timestamp > ttl) {
                this.recentCodes.delete(key);
            }
        }
    }

    // Get TOTP configuration
    getConfig() {
        return {
            issuer: this.config.issuer,
            serviceName: this.config.serviceName,
            algorithm: "SHA1",
            digits: this.config.digits,
            period: this.config.step,
            window: this.config.window,
            supportedAlgorithms: ["SHA1", "SHA256", "SHA512"],
            supportedDigits: [6, 8],
            compatibleApps: [
                "Google Authenticator",
                "Microsoft Authenticator",
                "Authy",
                "1Password",
                "LastPass Authenticator",
                "Bitwarden Authenticator",
                "AndOTP",
                "FreeOTP",
            ]
        };
    }

    // Destroy the service (cleanup)
    destroy() {
        clearInterval(this.cleanupInterval);
    }
}

module.exports = new TOTPService();