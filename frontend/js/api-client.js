// Frontend/js/api-client.js - Client API pour communication avec le backend
class ApiClient {
    constructor(config = {}) {
        this.baseUrl = config.baseUrl || window.AppConfig.api.baseUrl;
        this.timeout = config.timeout || window.AppConfig.api.timeout;
        this.retryAttempts = config.retryAttempts || window.AppConfig.api.retryAttempts;
        
        this.token = this.getStoredToken();
        this.sessionToken = this.getStoredSessionToken();
    }

    // Storage methods
    getStoredToken() {
        return localStorage.getItem(window.AppConfig.storage.tokenKey);
    }

    getStoredSessionToken() {
        return sessionStorage.getItem(window.AppConfig.storage.sessionKey);
    }

    setStoredToken(token) {
        if (token) {
            localStorage.setItem(window.AppConfig.storage.tokenKey, token);
            this.token = token;
        } else {
            localStorage.removeItem(window.AppConfig.storage.tokenKey);
            this.token = null;
        }
    }

    setStoredSessionToken(sessionToken) {
        if (sessionToken) {
            sessionStorage.setItem(window.AppConfig.storage.sessionKey, sessionToken);
            this.sessionToken = sessionToken;
        } else {
            sessionStorage.removeItem(window.AppConfig.storage.sessionKey);
            this.sessionToken = null;
        }
    }

    // HTTP request method
    async request(method, endpoint, data = null, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const requestOptions = {
            method,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            credentials: 'include',
        };

        // Add authentication headers
        if (this.token && options.requiresAuth !== false) {
            requestOptions.headers['Authorization'] = `Bearer ${this.token}`;
        }

        if (this.sessionToken) {
            requestOptions.headers['X-Session-Token'] = this.sessionToken;
        }

        // Add request body for non-GET requests
        if (data && method !== 'GET') {
            requestOptions.body = JSON.stringify(data);
        }

        try {
            const response = await fetch(url, requestOptions);
            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.message || result.error || `Request failed with status ${response.status}`);
            }

            return result;
        } catch (error) {
            if (window.AppConfig.debug) {
                console.error(`API Error [${method} ${endpoint}]:`, error);
            }
            throw error;
        }
    }

    // Authentication methods
    async login(username, password) {
        const response = await this.request('POST', '/auth/login', {
            username,
            password
        });

        if (response.success && response.authenticated) {
            this.setStoredToken(response.data.token);
            this.setStoredSessionToken(response.data.sessionToken);
        }

        return response;
    }

    async authenticate(username, password, totpCode) {
        const response = await this.request('POST', '/auth/authenticate', {
            username,
            password,
            totpCode
        });

        if (response.success && response.data) {
            this.setStoredToken(response.data.token);
            this.setStoredSessionToken(response.data.sessionToken);
        }

        return response;
    }

    async getCurrentUser() {
        return await this.request('GET', '/auth/me');
    }

    async logout() {
        try {
            await this.request('POST', '/auth/logout');
        } finally {
            this.clearAuth();
        }
    }

    async disable2FA(password, totpCode) {
        return await this.request('POST', '/auth/disable-2fa', {
            password,
            totpCode
        });
    }

    // 2FA setup methods
    async setup2FA(username, deviceInfo = null) {
        return await this.request('POST', '/auth/setup/2fa', {
            username,
            deviceInfo
        });
    }

    async verify2FASetup(deviceId, totpCode) {
        const response = await this.request('POST', '/auth/setup/verify', {
            deviceId,
            totpCode
        });

        if (response.success && response.data && response.data.token) {
            this.setStoredToken(response.data.token);
            this.setStoredSessionToken(response.data.sessionToken);
        }

        return response;
    }

    async getConfig() {
        return await this.request('GET', '/auth/setup/config', null, { requiresAuth: false });
    }

    // Device management methods
    async getDevices() {
        const response = await this.request('GET', '/devices');
        return response.devices || [];
    }

    async removeDevice(deviceId) {
        return await this.request('DELETE', `/devices/${deviceId}`);
    }

    // Session management methods
    async getSessions() {
        const response = await this.request('GET', '/sessions');
        return response.sessions || [];
    }

    async logoutAllSessions() {
        return await this.request('POST', '/sessions/logout-all');
    }

    // System methods
    async getHealth() {
        return await this.request('GET', '/health', null, { requiresAuth: false });
    }

    // Utility methods
    isAuthenticated() {
        if (!this.token) return false;
        
        try {
            const payload = this.parseJWT(this.token);
            return payload && payload.exp * 1000 > Date.now();
        } catch (e) {
            return false;
        }
    }

    parseJWT(token) {
        try {
            const base64Url = token.split('.')[1];
            const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));
            
            return JSON.parse(jsonPayload);
        } catch (e) {
            return null;
        }
    }

    clearAuth() {
        this.setStoredToken(null);
        this.setStoredSessionToken(null);
        localStorage.removeItem(window.AppConfig.storage.userKey);
    }

    getDeviceInfo() {
        const userAgent = navigator.userAgent;
        const platform = navigator.platform;
        
        let browser = 'Unknown';
        let version = '';
        
        if (userAgent.indexOf('Firefox') > -1) {
            browser = 'Firefox';
            const match = userAgent.match(/Firefox\/(\d+\.\d+)/);
            version = match ? match[1] : '';
        } else if (userAgent.indexOf('Chrome') > -1) {
            browser = 'Chrome';
            const match = userAgent.match(/Chrome\/(\d+\.\d+)/);
            version = match ? match[1] : '';
        } else if (userAgent.indexOf('Safari') > -1) {
            browser = 'Safari';
            const match = userAgent.match(/Version\/(\d+\.\d+)/);
            version = match ? match[1] : '';
        } else if (userAgent.indexOf('Edge') > -1) {
            browser = 'Edge';
            const match = userAgent.match(/Edge\/(\d+\.\d+)/);
            version = match ? match[1] : '';
        }
        
        return `${browser}${version ? ' ' + version : ''} on ${platform}`;
    }
}

// Export class for initialization in app.js
window.ApiClient = ApiClient;