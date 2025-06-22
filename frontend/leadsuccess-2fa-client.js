// leadsuccess-2fa-client.js - Version Améliorée
// Client Library for LeadSuccess 2FA Integration

(function(window) {
  'use strict';

  /**
   * LeadSuccess 2FA Client Library
   * Provides complete integration for Two-Factor Authentication
   * @class LeadSuccess2FA
   */
  class LeadSuccess2FA {
    constructor(config = {}) {
      this.config = {
        apiUrl: config.apiUrl || 'http://localhost:4001/api/v1',
        tokenKey: config.tokenKey || 'ls_auth_token',
        sessionKey: config.sessionKey || 'ls_session_token',
        onAuthSuccess: config.onAuthSuccess || null,
        onAuthFailure: config.onAuthFailure || null,
        onSessionExpired: config.onSessionExpired || null,
        debug: config.debug || false,
        autoRefresh: config.autoRefresh || true,
        retryAttempts: config.retryAttempts || 3,
        timeout: config.timeout || 30000
      };

      this.token = null;
      this.sessionToken = null;
      this.user = null;
      this.dbPassword = null;
      this.isInitialized = false;
      
      this._initializeFromStorage();
      this._setupInterceptors();
      this.isInitialized = true;
    }

    // ===========================
    // INITIALIZATION METHODS
    // ===========================

    _initializeFromStorage() {
      try {
        this.token = localStorage.getItem(this.config.tokenKey);
        this.sessionToken = sessionStorage.getItem(this.config.sessionKey);
        
        if (this.token) {
          this._decodeToken();
        }

        this._log('Initialized from storage', { 
          hasToken: !!this.token, 
          hasSession: !!this.sessionToken 
        });
      } catch (error) {
        this._log('Error initializing from storage:', error);
      }
    }

    _setupInterceptors() {
      if (this.config.autoRefresh && this.token) {
        const tokenData = this._parseJWT(this.token);
        if (tokenData && tokenData.exp) {
          const expirationTime = tokenData.exp * 1000;
          const currentTime = Date.now();
          const timeUntilExpiry = expirationTime - currentTime;
          
          if (timeUntilExpiry > 0) {
            // Refresh token 5 minutes before expiry
            const refreshTime = timeUntilExpiry - (5 * 60 * 1000);
            if (refreshTime > 0) {
              setTimeout(() => this._refreshToken(), refreshTime);
            }
          }
        }
      }
    }

    _parseJWT(token) {
      try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
          return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
        
        return JSON.parse(jsonPayload);
      } catch (e) {
        this._log('Failed to parse JWT:', e);
        return null;
      }
    }

    _decodeToken() {
      const decoded = this._parseJWT(this.token);
      if (decoded) {
        this.user = {
          id: decoded.userId || decoded.twoFactorUserID,
          username: decoded.username,
          mitarbeiterID: decoded.mitarbeiterID,
          serverLocationID: decoded.serverLocationID,
          mfaVerified: decoded.mfaVerified || false
        };
      }
    }

    _log(message, data = null) {
      if (this.config.debug) {
        console.log(`[LeadSuccess2FA] ${message}`, data || '');
      }
    }

    // ===========================
    // API REQUEST METHODS
    // ===========================

    async _request(method, endpoint, data = null, requiresAuth = false, retryCount = 0) {
      const url = `${this.config.apiUrl}${endpoint}`;
      const options = {
        method,
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include',
        timeout: this.config.timeout
      };

      if (requiresAuth && this.token) {
        options.headers['Authorization'] = `Bearer ${this.token}`;
      }

      if (this.sessionToken) {
        options.headers['X-Session-Token'] = this.sessionToken;
      }

      if (data && method !== 'GET') {
        options.body = JSON.stringify(data);
      }

      try {
        this._log(`Making ${method} request to ${endpoint}`, data);
        
        const response = await fetch(url, options);
        const result = await response.json();

        if (!response.ok) {
          // Handle specific error cases
          if (response.status === 401) {
            throw new Error(result.message || 'Authentication required');
          } else if (response.status === 423) {
            throw new Error(result.message || 'Account locked');
          } else if (response.status === 429) {
            throw new Error(result.message || 'Too many requests');
          }
          
          throw new Error(result.message || result.error || `Request failed with status ${response.status}`);
        }

        this._log(`${method} ${endpoint} successful`, result);
        return result;

      } catch (error) {
        this._log(`Request error for ${method} ${endpoint}:`, error);
        
        // Retry logic for network errors
        if (retryCount < this.config.retryAttempts && this._isRetryableError(error)) {
          this._log(`Retrying request (attempt ${retryCount + 1}/${this.config.retryAttempts})`);
          await this._delay(1000 * (retryCount + 1)); // Exponential backoff
          return this._request(method, endpoint, data, requiresAuth, retryCount + 1);
        }
        
        throw error;
      }
    }

    _isRetryableError(error) {
      // Retry on network errors, not on business logic errors
      return error.name === 'TypeError' || 
             error.message.includes('fetch') || 
             error.message.includes('network');
    }

    _delay(ms) {
      return new Promise(resolve => setTimeout(resolve, ms));
    }

    _handleUnauthorized() {
      if (this.config.onSessionExpired) {
        this.config.onSessionExpired();
      }
      this.clearAuth();
    }

    // ===========================
    // AUTHENTICATION METHODS
    // ===========================

    /**
     * Login with username and password
     * @param {string} username 
     * @param {string} password 
     * @returns {Promise<Object>}
     */
    async login(username, password) {
      try {
        this._log('Attempting login', { username });

        const response = await this._request('POST', '/auth/login', {
          username,
          password
        });

        if (response.success) {
          if (response.authenticated) {
            // Direct login successful
            this.token = response.data.token;
            this.sessionToken = response.data.sessionToken;
            this.dbPassword = response.data.dbPassword;
            this.user = response.data.user;

            // Store tokens
            localStorage.setItem(this.config.tokenKey, this.token);
            if (this.sessionToken) {
              sessionStorage.setItem(this.config.sessionKey, this.sessionToken);
            }

            // Setup token refresh
            this._setupInterceptors();

            if (this.config.onAuthSuccess) {
              this.config.onAuthSuccess({
                user: this.user,
                dbPassword: this.dbPassword
              });
            }

            return {
              success: true,
              authenticated: true,
              user: this.user,
              dbPassword: this.dbPassword
            };
          } else if (response.needs2FA) {
            // 2FA verification required
            return {
              success: true,
              needs2FA: true,
              tempToken: response.tempToken,
              user: response.user
            };
          }
        }

        return response;
      } catch (error) {
        this._log('Login error:', error);
        if (this.config.onAuthFailure) {
          this.config.onAuthFailure(error);
        }
        throw error;
      }
    }

    /**
     * Complete authentication with 2FA code
     * @param {string} username 
     * @param {string} password 
     * @param {string} totpCode 
     * @returns {Promise<Object>}
     */
    async authenticate(username, password, totpCode) {
      try {
        this._log('Attempting full authentication', { username });

        const response = await this._request('POST', '/auth/authenticate', {
          username,
          password,
          totpCode
        });

        if (response.success && response.data) {
          this.token = response.data.token;
          this.sessionToken = response.data.sessionToken;
          this.dbPassword = response.data.dbPassword;
          this.user = response.data.user;

          // Store tokens
          localStorage.setItem(this.config.tokenKey, this.token);
          if (this.sessionToken) {
            sessionStorage.setItem(this.config.sessionKey, this.sessionToken);
          }

          // Setup token refresh
          this._setupInterceptors();

          if (this.config.onAuthSuccess) {
            this.config.onAuthSuccess({
              user: this.user,
              dbPassword: this.dbPassword
            });
          }

          return {
            success: true,
            authenticated: true,
            user: this.user,
            dbPassword: this.dbPassword,
            deviceUsed: response.data.deviceUsed
          };
        }

        return response;
      } catch (error) {
        this._log('Authentication error:', error);
        if (this.config.onAuthFailure) {
          this.config.onAuthFailure(error);
        }
        throw error;
      }
    }

    /**
     * Logout current session
     * @returns {Promise<Object>}
     */
    async logout() {
      try {
        if (this.sessionToken) {
          await this._request('POST', '/auth/logout', null, false);
        }

        // Clear all authentication data
        this.clearAuth();

        return { success: true, message: 'Logged out successfully' };
      } catch (error) {
        this._log('Logout error:', error);
        // Clear local data even if request fails
        this.clearAuth();
        throw error;
      }
    }

    // ===========================
    // 2FA SETUP METHODS
    // ===========================

    /**
     * Initialize 2FA setup
     * @param {string} username 
     * @param {string} deviceInfo 
     * @returns {Promise<Object>}
     */
    async setup2FA(username, deviceInfo = null) {
      try {
        this._log('Setting up 2FA', { username, deviceInfo });

        const response = await this._request('POST', '/setup/2fa', {
          username,
          deviceInfo: deviceInfo || this._getDeviceInfo()
        });

        if (response.success) {
          return {
            success: true,
            deviceId: response.data.deviceId,
            qrCode: response.data.qrCode,
            secret: response.data.secret,
            uri: response.data.uri,
            manualEntry: response.data.manualEntry,
            instructions: response.data.instructions
          };
        }

        return response;
      } catch (error) {
        this._log('2FA setup error:', error);
        throw error;
      }
    }

    /**
     * Verify 2FA setup with TOTP code
     * @param {number} deviceId 
     * @param {string} totpCode 
     * @returns {Promise<Object>}
     */
    async verify2FASetup(deviceId, totpCode) {
      try {
        this._log('Verifying 2FA setup', { deviceId });

        const response = await this._request('POST', '/setup/verify', {
          deviceId,
          totpCode
        });

        if (response.success && response.data) {
          if (response.data.token) {
            this.token = response.data.token;
            this.dbPassword = response.data.dbPassword;
            this.sessionToken = response.data.sessionToken;
            
            localStorage.setItem(this.config.tokenKey, this.token);
            if (this.sessionToken) {
              sessionStorage.setItem(this.config.sessionKey, this.sessionToken);
            }
            
            this._decodeToken();
          }

          return {
            success: true,
            activated: true,
            isFirstDevice: response.data.isFirstDevice,
            user: response.data.user,
            dbPassword: this.dbPassword
          };
        }

        return response;
      } catch (error) {
        this._log('2FA verify error:', error);
        throw error;
      }
    }

    /**
     * Disable 2FA completely
     * @param {string} password 
     * @param {string} totpCode 
     * @returns {Promise<Object>}
     */
    async disable2FA(password, totpCode) {
      try {
        this._log('Disabling 2FA');

        const response = await this._request('POST', '/auth/disable-2fa', {
          password,
          totpCode
        }, true);

        if (response.success) {
          // Update user state
          if (this.user) {
            this.user.has2FA = false;
            this.user.deviceCount = 0;
          }
        }

        return response;
      } catch (error) {
        this._log('Disable 2FA error:', error);
        throw error;
      }
    }

    // ===========================
    // DEVICE MANAGEMENT METHODS
    // ===========================

    /**
     * Get all devices for current user
     * @returns {Promise<Array>}
     */
    async getDevices() {
      try {
        const response = await this._request('GET', '/devices', null, true);
        return response.devices || [];
      } catch (error) {
        this._log('Get devices error:', error);
        throw error;
      }
    }

    /**
     * Remove a device
     * @param {number} deviceId 
     * @returns {Promise<Object>}
     */
    async removeDevice(deviceId) {
      try {
        this._log('Removing device', { deviceId });

        const response = await this._request('DELETE', `/devices/${deviceId}`, null, true);
        
        if (response.success) {
          // Update user device count
          if (this.user && this.user.deviceCount > 0) {
            this.user.deviceCount--;
          }
        }

        return response;
      } catch (error) {
        this._log('Remove device error:', error);
        throw error;
      }
    }

    // ===========================
    // SESSION MANAGEMENT METHODS
    // ===========================

    /**
     * Get all active sessions
     * @returns {Promise<Array>}
     */
    async getSessions() {
      try {
        const response = await this._request('GET', '/sessions', null, true);
        return response.sessions || [];
      } catch (error) {
        this._log('Get sessions error:', error);
        throw error;
      }
    }

    /**
     * Logout all other sessions
     * @returns {Promise<Object>}
     */
    async logoutAllSessions() {
      try {
        this._log('Logging out all other sessions');

        const response = await this._request('POST', '/sessions/logout-all', null, true);
        return response;
      } catch (error) {
        this._log('Logout all sessions error:', error);
        throw error;
      }
    }

    // ===========================
    // USER INFORMATION METHODS
    // ===========================

    /**
     * Get current user information
     * @returns {Promise<Object>}
     */
    async getCurrentUser() {
      try {
        const response = await this._request('GET', '/auth/me', null, true);
        if (response.success) {
          this.user = response.user;
        }
        return response;
      } catch (error) {
        this._log('Get current user error:', error);
        throw error;
      }
    }

    /**
     * Get system configuration
     * @returns {Promise<Object>}
     */
    async getConfig() {
      try {
        const response = await this._request('GET', '/setup/config');
        return response.data || {};
      } catch (error) {
        this._log('Get config error:', error);
        throw error;
      }
    }

    /**
     * Get system health status
     * @returns {Promise<Object>}
     */
    async getHealth() {
      try {
        const response = await this._request('GET', '/health');
        return response;
      } catch (error) {
        this._log('Get health error:', error);
        throw error;
      }
    }

    

    // ===========================
    // UTILITY METHODS
    // ===========================

    /**
     * Check if user is authenticated
     * @returns {boolean}
     */
    isAuthenticated() {
      if (!this.token) return false;
      
      const tokenData = this._parseJWT(this.token);
      if (!tokenData || !tokenData.exp) return false;
      
      return tokenData.exp * 1000 > Date.now();
    }

    /**
     * Check if user has 2FA enabled
     * @returns {boolean}
     */
    has2FA() {
      return this.user && this.user.has2FA === true;
    }

    /**
     * Get stored database password
     * @returns {string|null}
     */
    getDBPassword() {
      return this.dbPassword;
    }

    /**
     * Get current user information
     * @returns {Object|null}
     */
    getUser() {
      return this.user;
    }

    /**
     * Clear all authentication data
     */
    clearAuth() {
      this.token = null;
      this.sessionToken = null;
      this.user = null;
      this.dbPassword = null;
      
      localStorage.removeItem(this.config.tokenKey);
      sessionStorage.removeItem(this.config.sessionKey);
      
      this._log('Authentication data cleared');
    }

    /**
     * Get device information for current browser/device
     * @private
     * @returns {string}
     */
    _getDeviceInfo() {
      const userAgent = navigator.userAgent;
      const platform = navigator.platform;
      
      // Parse browser info
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
      
      const deviceInfo = `${browser}${version ? ' ' + version : ''} on ${platform}`;
      return deviceInfo;
    }

    /**
     * Refresh authentication token (future implementation)
     * @private
     */
    async _refreshToken() {
      this._log('Token refresh not yet implemented');
      // Future implementation for refresh tokens
    }

    /**
     * Generate TOTP URL for manual entry
     * @param {string} secret 
     * @param {string} username 
     * @param {string} issuer
     * @returns {string}
     */
    generateTOTPUrl(secret, username, issuer = 'LeadSuccess') {
      const algorithm = 'SHA1';
      const digits = 6;
      const period = 30;
      
      return `otpauth://totp/${issuer}:${username}?secret=${secret}&issuer=${issuer}&algorithm=${algorithm}&digits=${digits}&period=${period}`;
    }

    /**
     * Validate TOTP code format
     * @param {string} code 
     * @returns {boolean}
     */
    isValidTOTPCode(code) {
      return /^\d{6}$/.test(code);
    }

    /**
     * Get library version and info
     * @returns {Object}
     */
    getVersion() {
      return {
        version: '3.0.0',
        name: 'LeadSuccess 2FA Client',
        features: [
          'Authentication',
          '2FA Setup & Verification', 
          'Device Management',
          'Session Management',
          'Auto Token Refresh',
          'Error Handling & Retry',
          'Debug Logging'
        ],
        compatibleWith: 'LeadSuccess 2FA API v3.0+'
      };
    }
  }

  // ===========================
  // UI HELPER CLASS
  // ===========================

  /**
   * UI Helper for quick integration
   * @class LeadSuccess2FAUIHelper
   */
  class LeadSuccess2FAUIHelper {
    constructor(client) {
      this.client = client;
      this.currentModal = null;
    }

    /**
     * Create complete login interface
     * @param {HTMLElement} container 
     * @param {Object} options
     */
    createLoginInterface(container, options = {}) {
      const config = {
        showPrivacyConsent: true,
        companyName: 'LeadSuccess',
        logoUrl: null,
        theme: 'light',
        ...options
      };

      const html = `
        <div class="ls-login-container ${config.theme}">
          ${config.logoUrl ? `<img src="${config.logoUrl}" alt="${config.companyName}" class="ls-logo">` : ''}
          <h1 class="ls-title">${config.companyName} Portal</h1>
          <p class="ls-subtitle">Secure access to your account</p>
          
          <form id="ls-login-form" class="ls-form">
            <div class="ls-field">
              <label for="ls-username">Username</label>
              <input type="text" id="ls-username" name="username" required>
            </div>
            
            <div class="ls-field">
              <label for="ls-password">Password</label>
              <input type="password" id="ls-password" name="password" required>
            </div>
            
            ${config.showPrivacyConsent ? `
              <div class="ls-field ls-checkbox-field">
                <input type="checkbox" id="ls-privacy" required>
                <label for="ls-privacy">
                  I agree to the <a href="#" target="_blank">Privacy Policy</a> 
                  and consent to data processing.
                </label>
              </div>
            ` : ''}
            
            <button type="submit" id="ls-login-btn" ${config.showPrivacyConsent ? 'disabled' : ''}>
              <span>Sign In</span>
              <div class="ls-spinner" style="display: none;"></div>
            </button>
          </form>
          
          <div class="ls-links">
            <a href="#" class="ls-forgot-password">Forgot your password?</a>
          </div>
          
          <div id="ls-error" class="ls-error" style="display: none;"></div>
        </div>
      `;

      container.innerHTML = html;
      this._attachLoginHandlers(container, config);
      this._addStyles();
    }

    /**
     * Create 2FA setup modal
     * @param {Object} setupData 
     * @returns {HTMLElement}
     */
    create2FASetupModal(setupData) {
      const modal = document.createElement('div');
      modal.className = 'ls-modal-overlay';
      modal.innerHTML = `
        <div class="ls-modal">
          <div class="ls-modal-header">
            <h3>Setup Two-Factor Authentication</h3>
            <button class="ls-modal-close">&times;</button>
          </div>
          
          <div class="ls-modal-body">
            <div class="ls-qr-section">
              <img src="${setupData.qrCode}" alt="QR Code" class="ls-qr-code">
              <div class="ls-manual-entry">
                <p>Manual entry key:</p>
                <code>${setupData.secret}</code>
              </div>
            </div>
            
            <div class="ls-instructions">
              <h4>Instructions:</h4>
              <ol>
                ${setupData.instructions.map(instruction => `<li>${instruction}</li>`).join('')}
              </ol>
            </div>
            
            <form id="ls-setup-form" class="ls-form">
              <div class="ls-field">
                <label for="ls-setup-code">Verification Code</label>
                <input type="text" id="ls-setup-code" maxlength="6" pattern="[0-9]{6}" required
                       placeholder="000000" class="ls-code-input">
              </div>
              
              <button type="submit">Enable 2FA</button>
            </form>
            
            <div id="ls-setup-error" class="ls-error" style="display: none;"></div>
          </div>
        </div>
      `;

      document.body.appendChild(modal);
      this.currentModal = modal;
      
      this._attach2FASetupHandlers(modal, setupData);
      return modal;
    }

    /**
     * Create 2FA verification modal
     * @param {Object} userData
     * @returns {HTMLElement}
     */
    create2FAVerificationModal(userData) {
      const modal = document.createElement('div');
      modal.className = 'ls-modal-overlay';
      modal.innerHTML = `
        <div class="ls-modal ls-modal-compact">
          <div class="ls-modal-header">
            <h3>Two-Factor Authentication</h3>
          </div>
          
          <div class="ls-modal-body">
            <p>Enter the 6-digit code from your authenticator app</p>
            
            <form id="ls-verify-form" class="ls-form">
              <div class="ls-field">
                <input type="text" id="ls-verify-code" maxlength="6" pattern="[0-9]{6}" required
                       placeholder="000000" class="ls-code-input" autofocus>
              </div>
              
              <button type="submit">Verify</button>
            </form>
            
            <div id="ls-verify-error" class="ls-error" style="display: none;"></div>
          </div>
        </div>
      `;

      document.body.appendChild(modal);
      this.currentModal = modal;
      
      this._attach2FAVerifyHandlers(modal, userData);
      return modal;
    }

    /**
     * Show success message
     * @param {string} title 
     * @param {string} message 
     * @param {Function} callback
     */
    showSuccess(title, message, callback = null) {
      const modal = document.createElement('div');
      modal.className = 'ls-modal-overlay';
      modal.innerHTML = `
        <div class="ls-modal ls-modal-success">
          <div class="ls-modal-body text-center">
            <div class="ls-success-icon">✓</div>
            <h3>${title}</h3>
            <p>${message}</p>
            <button class="ls-btn-success" onclick="this.closest('.ls-modal-overlay').remove()${callback ? '; (' + callback + ')()' : ''}">
              OK
            </button>
          </div>
        </div>
      `;

      document.body.appendChild(modal);
      setTimeout(() => modal.remove(), 5000); // Auto-remove after 5 seconds
    }

    /**
     * Show error message
     * @param {string} title 
     * @param {string} message 
     */
    showError(title, message) {
      const modal = document.createElement('div');
      modal.className = 'ls-modal-overlay';
      modal.innerHTML = `
        <div class="ls-modal ls-modal-error">
          <div class="ls-modal-body text-center">
            <div class="ls-error-icon">✕</div>
            <h3>${title}</h3>
            <p>${message}</p>
            <button class="ls-btn-error" onclick="this.closest('.ls-modal-overlay').remove()">
              OK
            </button>
          </div>
        </div>
      `;

      document.body.appendChild(modal);
    }

    /**
     * Close current modal
     */
    closeModal() {
      if (this.currentModal) {
        this.currentModal.remove();
        this.currentModal = null;
      }
    }

    // Private helper methods
    _attachLoginHandlers(container, config) {
      const form = container.querySelector('#ls-login-form');
      const privacyCheckbox = container.querySelector('#ls-privacy');
      const loginBtn = container.querySelector('#ls-login-btn');

      if (privacyCheckbox) {
        privacyCheckbox.addEventListener('change', () => {
          loginBtn.disabled = !privacyCheckbox.checked;
        });
      }

      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(form);
        const username = formData.get('username');
        const password = formData.get('password');

        this._setButtonLoading(loginBtn, true);
        this._hideError(container);

        try {
          const result = await this.client.login(username, password);
          
          if (result.authenticated) {
            // Direct login successful
            this.showSuccess('Welcome!', 'You have been logged in successfully.');
          } else if (result.needs2FA) {
            // Show 2FA verification
            this.create2FAVerificationModal({ username, password });
          }
        } catch (error) {
          this._showError(container, error.message);
        } finally {
          this._setButtonLoading(loginBtn, false);
        }
      });
    }

    _attach2FASetupHandlers(modal, setupData) {
      const form = modal.querySelector('#ls-setup-form');
      const closeBtn = modal.querySelector('.ls-modal-close');

      closeBtn.addEventListener('click', () => {
        modal.remove();
        this.currentModal = null;
      });

      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const code = form.querySelector('#ls-setup-code').value;

        this._setButtonLoading(form.querySelector('button'), true);
        this._hideError(modal);

        try {
          const result = await this.client.verify2FASetup(setupData.deviceId, code);
          
          if (result.success) {
            modal.remove();
            this.currentModal = null;
            this.showSuccess('2FA Enabled!', '2FA has been successfully enabled for your account.');
          }
        } catch (error) {
          this._showError(modal, error.message);
        } finally {
          this._setButtonLoading(form.querySelector('button'), false);
        }
      });
    }

    _attach2FAVerifyHandlers(modal, userData) {
      const form = modal.querySelector('#ls-verify-form');
      const codeInput = modal.querySelector('#ls-verify-code');

      // Auto-submit when 6 digits entered
      codeInput.addEventListener('input', () => {
        if (codeInput.value.length === 6) {
          form.dispatchEvent(new Event('submit'));
        }
      });

      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const code = codeInput.value;

        this._setButtonLoading(form.querySelector('button'), true);
        this._hideError(modal);

        try {
          const result = await this.client.authenticate(userData.username, userData.password, code);
          
          if (result.success) {
            modal.remove();
            this.currentModal = null;
            this.showSuccess('Welcome!', 'Authentication successful!');
          }
        } catch (error) {
          this._showError(modal, error.message);
          codeInput.value = '';
          codeInput.focus();
        } finally {
          this._setButtonLoading(form.querySelector('button'), false);
        }
      });
    }

    _setButtonLoading(button, loading) {
      const spinner = button.querySelector('.ls-spinner');
      const text = button.querySelector('span') || button;
      
      if (loading) {
        button.disabled = true;
        if (spinner) spinner.style.display = 'inline-block';
        if (text !== button) text.textContent = 'Loading...';
      } else {
        button.disabled = false;
        if (spinner) spinner.style.display = 'none';
        if (text !== button) text.textContent = button.textContent.includes('Enable') ? 'Enable 2FA' : 'Sign In';
      }
    }

    _showError(container, message) {
      const errorEl = container.querySelector('.ls-error') || container.querySelector('#ls-setup-error') || container.querySelector('#ls-verify-error');
      if (errorEl) {
        errorEl.textContent = message;
        errorEl.style.display = 'block';
      }
    }

    _hideError(container) {
      const errorEl = container.querySelector('.ls-error') || container.querySelector('#ls-setup-error') || container.querySelector('#ls-verify-error');
      if (errorEl) {
        errorEl.style.display = 'none';
      }
    }

    _addStyles() {
      if (document.querySelector('#ls-2fa-styles')) return;

      const styles = document.createElement('style');
      styles.id = 'ls-2fa-styles';
      styles.textContent = `
        .ls-login-container {
          max-width: 400px;
          margin: 0 auto;
          padding: 20px;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
        }
        
        .ls-logo {
          display: block;
          margin: 0 auto 20px;
          max-height: 60px;
        }
        
        .ls-title {
          text-align: center;
          margin-bottom: 8px;
          color: #1f2937;
          font-size: 24px;
        }
        
        .ls-subtitle {
          text-align: center;
          margin-bottom: 30px;
          color: #6b7280;
        }
        
        .ls-form {
          background: white;
          padding: 30px;
          border-radius: 8px;
          box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }
        
        .ls-field {
          margin-bottom: 20px;
        }
        
        .ls-field label {
          display: block;
          margin-bottom: 6px;
          font-weight: 500;
          color: #374151;
        }
        
        .ls-field input {
          width: 100%;
          padding: 12px;
          border: 1px solid #d1d5db;
          border-radius: 4px;
          font-size: 16px;
          box-sizing: border-box;
        }
        
        .ls-field input:focus {
          outline: none;
          border-color: #D86141;
          box-shadow: 0 0 0 3px rgba(216, 97, 65, 0.1);
        }
        
        .ls-checkbox-field {
          display: flex;
          align-items: flex-start;
          gap: 8px;
        }
        
        .ls-checkbox-field input {
          width: auto;
          margin: 0;
        }
        
        .ls-checkbox-field label {
          margin: 0;
          font-size: 14px;
          line-height: 1.4;
        }
        
        .ls-form button {
          width: 100%;
          background: #D86141;
          color: white;
          border: none;
          padding: 12px;
          border-radius: 4px;
          font-size: 16px;
          font-weight: 500;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
        }
        
        .ls-form button:disabled {
          background: #9ca3af;
          cursor: not-allowed;
        }
        
        .ls-form button:not(:disabled):hover {
          background: #b53e20;
        }
        
        .ls-spinner {
          width: 16px;
          height: 16px;
          border: 2px solid #ffffff3d;
          border-top: 2px solid #ffffff;
          border-radius: 50%;
          animation: ls-spin 1s linear infinite;
        }
        
        @keyframes ls-spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        
        .ls-links {
          text-align: center;
          margin-top: 20px;
        }
        
        .ls-forgot-password {
          color: #D86141;
          text-decoration: none;
          font-size: 14px;
        }
        
        .ls-forgot-password:hover {
          text-decoration: underline;
        }
        
        .ls-error {
          background: #fef2f2;
          border: 1px solid #fecaca;
          color: #dc2626;
          padding: 12px;
          border-radius: 4px;
          margin-top: 15px;
        }
        
        .ls-modal-overlay {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: rgba(0, 0, 0, 0.5);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 1000;
          padding: 20px;
        }
        
        .ls-modal {
          background: white;
          border-radius: 8px;
          max-width: 500px;
          width: 100%;
          max-height: 90vh;
          overflow-y: auto;
        }
        
        .ls-modal-compact {
          max-width: 400px;
        }
        
        .ls-modal-header {
          padding: 20px 20px 0;
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        
        .ls-modal-header h3 {
          margin: 0;
          color: #1f2937;
        }
        
        .ls-modal-close {
          background: none;
          border: none;
          font-size: 24px;
          cursor: pointer;
          color: #6b7280;
        }
        
        .ls-modal-body {
          padding: 20px;
        }
        
        .ls-qr-section {
          text-align: center;
          margin-bottom: 20px;
        }
        
        .ls-qr-code {
          max-width: 200px;
          margin-bottom: 15px;
        }
        
        .ls-manual-entry {
          background: #f9fafb;
          padding: 15px;
          border-radius: 4px;
          margin-bottom: 20px;
        }
        
        .ls-manual-entry code {
          display: block;
          background: white;
          padding: 8px;
          border: 1px solid #d1d5db;
          border-radius: 4px;
          font-family: monospace;
          word-break: break-all;
          margin-top: 5px;
        }
        
        .ls-instructions h4 {
          margin-bottom: 10px;
          color: #374151;
        }
        
        .ls-instructions ol {
          padding-left: 20px;
          line-height: 1.6;
        }
        
        .ls-code-input {
          text-align: center;
          font-size: 24px;
          letter-spacing: 4px;
          font-family: monospace;
        }
        
        .ls-modal-success, .ls-modal-error {
          max-width: 400px;
        }
        
        .ls-success-icon {
          width: 60px;
          height: 60px;
          background: #10b981;
          color: white;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 30px;
          margin: 0 auto 20px;
        }
        
        .ls-error-icon {
          width: 60px;
          height: 60px;
          background: #ef4444;
          color: white;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 30px;
          margin: 0 auto 20px;
        }
        
        .ls-btn-success {
          background: #10b981;
          color: white;
          border: none;
          padding: 12px 24px;
          border-radius: 4px;
          cursor: pointer;
          font-weight: 500;
        }
        
        .ls-btn-error {
          background: #ef4444;
          color: white;
          border: none;
          padding: 12px 24px;
          border-radius: 4px;
          cursor: pointer;
          font-weight: 500;
        }
        
        .text-center {
          text-align: center;
        }
      `;
      
      document.head.appendChild(styles);
    }
  }

  // Export to window
  window.LeadSuccess2FA = LeadSuccess2FA;
  window.LeadSuccess2FAUIHelper = LeadSuccess2FAUIHelper;

  // Also provide a simple factory function
  window.createLeadSuccess2FA = function(config) {
    return new LeadSuccess2FA(config);
  };

})(window);