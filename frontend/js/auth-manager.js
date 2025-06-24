// Frontend/js/auth-manager.js - Gestionnaire d'authentification
class AuthManager {
    constructor() {
        this.currentUser = null;
        this.tempToken = null;
        this.currentDeviceId = null;
    }

    // Authentication flow
    async handleLogin(formData) {
        // Check if managers are initialized
        if (!window.uiManager || !window.apiClient) {
            console.error('Managers not initialized');
            return;
        }

        const username = formData.get('username');
        const password = formData.get('password');

        window.uiManager.setLoadingState('loginBtn', true);
        window.uiManager.hideError('loginError');

        try {
            const result = await window.apiClient.login(username, password);

            if (result.needsSetup) {
                this.tempToken = result.tempToken;
                this.currentUser = { username, needsSetup: true };
                this.showDashboard(result);
            } else if (result.needs2FA) {
                this.tempToken = result.tempToken;
                this.currentUser = { username };
                this.showVerify2FA();
            } else if (result.authenticated) {
                this.showDashboard(result);
            }
        } catch (error) {
            window.uiManager.showError('loginError', error.message);
        } finally {
            window.uiManager.setLoadingState('loginBtn', false);
        }
    }

    async handleVerify2FA(code, userData) {
        window.uiManager.setLoadingState('verifyBtn', true);
        window.uiManager.hideError('verifyError');

        try {
            const result = await window.apiClient.authenticate(
                userData.username, 
                userData.password, 
                code
            );

            if (result.success) {
                window.uiManager.closeModal('verify2FAModal');
                window.uiManager.removeModal('verify2FAModal');
                this.showDashboard(result);
            }
        } catch (error) {
            window.uiManager.showError('verifyError', error.message);
            
            // Safely clear and focus the input field
            const verifyCodeElement = document.getElementById('verifyCode');
            if (verifyCodeElement) {
                verifyCodeElement.value = '';
                verifyCodeElement.focus();
            }
        } finally {
            window.uiManager.setLoadingState('verifyBtn', false);
        }
    }

    // 2FA Setup
    async show2FASetup() {
        if (!this.currentUser) return;

        try {
            const result = await window.apiClient.setup2FA(
                this.currentUser.username,
                window.apiClient.getDeviceInfo()
            );

            if (result.success) {
                this.currentDeviceId = result.data.deviceId;
                this.create2FASetupModal(result.data);
            }
        } catch (error) {
            window.uiManager.showError('setupError', error.message);
        }
    }

    create2FASetupModal(setupData) {
        const modalContent = `
            <div class="bg-white rounded-lg max-w-md w-full max-h-[90vh] overflow-y-auto fade-in">
                <div class="p-6">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-lg font-semibold text-gray-900">Setup Two-Factor Authentication</h3>
                        <button onclick="window.uiManager.closeModal('setup2FAModal')" class="text-gray-400 hover:text-gray-600">
                            <i class="fas fa-times text-xl"></i>
                        </button>
                    </div>

                    <div class="space-y-4">
                        <div class="text-center">
                            <div class="mb-4">
                                <img src="${setupData.qrCode}" alt="QR Code" class="mx-auto w-48 h-48 border rounded">
                            </div>

                            <div class="bg-gray-50 p-3 rounded text-sm">
                                <p class="text-gray-600 mb-2">Manual entry key:</p>
                                <code class="block bg-white p-2 rounded border font-mono text-xs break-all">${setupData.secret}</code>
                            </div>
                        </div>

                        <div class="text-sm text-gray-600">
                            <p class="font-medium mb-2">Instructions:</p>
                            <ol pl-4 space-y-1">
                                ${setupData.instructions.map(instruction => `<li>${instruction}</li>`).join('')}
                            </ol>
                        </div>

                        <form id="setup2FAForm" class="space-y-4">
                            <div>
                                <label for="setupCode" class="block text-sm font-medium text-gray-700">Verification Code</label>
                                <input type="text" id="setupCode" maxlength="6" pattern="[0-9]{6}" required
                                    class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md text-center text-lg tracking-widest focus:outline-none focus:ring-primary focus:border-primary">
                            </div>

                            <button type="submit" id="setupBtn"
                                class="w-full bg-primary hover:bg-primary-dark text-white py-2 px-4 rounded-md text-sm font-medium transition-colors">
                                <span id="setupBtnText">Enable 2FA</span>
                                <div id="setupSpinner" class="spinner ml-2 hidden"></div>
                            </button>
                        </form>

                        <div id="setupError" class="hidden bg-red-50 border border-red-200 text-red-700 px-3 py-2 rounded">
                            <p class="text-sm mb-2" id="setupErrorMessage"></p>
                            <button onclick="TroubleshootModal.show()" 
                                class="text-xs bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded transition-colors">
                                <i class="fas fa-tools mr-1"></i>Troubleshoot
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;

        window.uiManager.createModal('setup2FAModal', modalContent);
        window.uiManager.showModal('setup2FAModal');

        // Attach event listeners
        document.getElementById('setup2FAForm').addEventListener('submit', (e) => {
            e.preventDefault();
            const code = document.getElementById('setupCode').value;
            this.handleSetup2FA(code);
        });

        // Auto-submit when 6 digits entered
        document.getElementById('setupCode').addEventListener('input', (e) => {
            if (e.target.value.length === 6) {
                setTimeout(() => {
                    document.getElementById('setup2FAForm').dispatchEvent(new Event('submit'));
                }, window.AppConfig.ui.autoSubmitDelay);
            }
        });
    }

    async handleSetup2FA(code) {
        window.uiManager.setLoadingState('setupBtn', true);
        window.uiManager.hideError('setupError');

        try {
            const result = await window.apiClient.verify2FASetup(this.currentDeviceId, code);

            if (result.success) {
                window.uiManager.closeModal('setup2FAModal');
                window.uiManager.removeModal('setup2FAModal');

                if (result.data && result.data.dbPassword) {
                    window.uiManager.showDBPassword(result.data.dbPassword);
                }

                window.uiManager.showSuccess('2FA Enabled', '2FA has been successfully enabled for your account!');
                await this.loadCurrentUser();
                this.loadDevices();
            }
        } catch (error) {
            window.uiManager.showError('setupError', error.message);
            
            // Safely clear and focus the input field
            const setupCodeElement = document.getElementById('setupCode');
            if (setupCodeElement) {
                setupCodeElement.value = '';
                setupCodeElement.focus();
            }
        } finally {
            window.uiManager.setLoadingState('setupBtn', false);
        }
    }

    // 2FA Verification modal
    showVerify2FA() {
        const modalContent = `
            <div class="bg-white rounded-lg max-w-md w-full fade-in">
                <div class="p-6">
                    <div class="text-center mb-6">
                        <h3 class="text-lg font-semibold text-gray-900 mb-2">Two-Factor Authentication</h3>
                        <p class="text-gray-600">Enter the 6-digit code from your authenticator app</p>
                    </div>

                    <form id="verify2FAForm" class="space-y-4">
                        <div>
                            <input type="text" id="verifyCode" maxlength="6" pattern="[0-9]{6}" required
                                placeholder="000000"
                                class="block w-full px-3 py-3 border border-gray-300 rounded-md text-center text-xl tracking-widest focus:outline-none focus:ring-primary focus:border-primary">
                        </div>

                        <button type="submit" id="verifyBtn"
                            class="w-full bg-primary hover:bg-primary-dark text-white py-2 px-4 rounded-md font-medium transition-colors">
                            <span id="verifyBtnText">Verify</span>
                            <div id="verifySpinner" class="spinner ml-2 hidden"></div>
                        </button>
                    </form>

                    <div id="verifyError" class="hidden mt-4 bg-red-50 border border-red-200 text-red-700 px-3 py-2 rounded"></div>
                </div>
            </div>
        `;

        window.uiManager.createModal('verify2FAModal', modalContent);
        window.uiManager.showModal('verify2FAModal');

        // Store password for verification
        const passwordField = document.getElementById('password');
        const userData = {
            username: this.currentUser.username,
            password: passwordField ? passwordField.value : ''
        };

        // Attach event listeners
        document.getElementById('verify2FAForm').addEventListener('submit', (e) => {
            e.preventDefault();
            const code = document.getElementById('verifyCode').value;
            this.handleVerify2FA(code, userData);
        });

        // Auto-submit when 6 digits entered
        document.getElementById('verifyCode').addEventListener('input', (e) => {
            if (e.target.value.length === 6) {
                setTimeout(() => {
                    document.getElementById('verify2FAForm').dispatchEvent(new Event('submit'));
                }, window.AppConfig.ui.autoSubmitDelay);
            }
        });

        document.getElementById('verifyCode').focus();
    }

    // Disable 2FA
    showDisable2FAModal() {
        const modalContent = `
            <div class="bg-white rounded-lg max-w-md w-full fade-in">
                <div class="p-6">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-lg font-semibold text-gray-900">Disable 2FA</h3>
                        <button onclick="window.uiManager.closeModal('disable2FAModal')" class="text-gray-400 hover:text-gray-600">
                            <i class="fas fa-times text-xl"></i>
                        </button>
                    </div>

                    <div class="bg-yellow-50 border-l-4 border-yellow-400 p-4 mb-4">
                        <p class="text-yellow-700 text-sm">This will disable two-factor authentication for your account.</p>
                    </div>

                    <form id="disable2FAForm" class="space-y-4">
                        <div>
                            <label for="disablePassword" class="block text-sm font-medium text-gray-700">Password</label>
                            <input type="password" id="disablePassword" required
                                class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-primary focus:border-primary">
                        </div>

                        <div>
                            <label for="disableCode" class="block text-sm font-medium text-gray-700">2FA Code</label>
                            <input type="text" id="disableCode" maxlength="6" pattern="[0-9]{6}" required
                                class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md text-center tracking-widest focus:outline-none focus:ring-primary focus:border-primary">
                        </div>

                        <div class="flex space-x-3 pt-4">
                            <button type="button" onclick="window.uiManager.closeModal('disable2FAModal')"
                                class="flex-1 bg-gray-200 hover:bg-gray-300 text-gray-700 py-2 px-4 rounded-md font-medium transition-colors">
                                Cancel
                            </button>
                            <button type="submit"
                                class="flex-1 bg-red-600 hover:bg-red-700 text-white py-2 px-4 rounded-md font-medium transition-colors">
                                Disable 2FA
                            </button>
                        </div>
                    </form>

                    <div id="disableError" class="hidden mt-4 bg-red-50 border border-red-200 text-red-700 px-3 py-2 rounded"></div>
                </div>
            </div>
        `;

        window.uiManager.createModal('disable2FAModal', modalContent);
        window.uiManager.showModal('disable2FAModal');

        document.getElementById('disable2FAForm').addEventListener('submit', (e) => {
            e.preventDefault();
            const password = document.getElementById('disablePassword').value;
            const code = document.getElementById('disableCode').value;
            this.handleDisable2FA(password, code);
        });
    }

    async handleDisable2FA(password, code) {
        try {
            const result = await window.apiClient.disable2FA(password, code);

            if (result.success) {
                window.uiManager.closeModal('disable2FAModal');
                window.uiManager.removeModal('disable2FAModal');

                window.uiManager.showSuccess('2FA Disabled', 'Two-factor authentication has been disabled.');
                await this.loadCurrentUser();
                this.loadDevices();
            }
        } catch (error) {
            console.error('Disable 2FA error:', error);
            
            let errorMessage = error.message;
            
            // Handle specific error cases
            if (error.message.includes('Invalid password')) {
                errorMessage = 'The password you entered is incorrect. Please try again.';
            } else if (error.message.includes('Invalid 2FA code')) {
                errorMessage = 'The 2FA code is incorrect or has expired. Please enter a fresh code.';
            } else if (error.message.includes('Code already used')) {
                errorMessage = 'This code has already been used. Please wait for a new code and try again.';
            } else if (error.message.includes('Internal Server Error')) {
                errorMessage = 'Server error occurred. Please try again or contact support.';
            }
            
            window.uiManager.showError('disableError', errorMessage);
        }
    }

    // Data loading
    async loadCurrentUser() {
        try {
            const result = await window.apiClient.getCurrentUser();
            if (result.success) {
                this.currentUser = result.user;
                window.uiManager.updateUserDisplay(this.currentUser);
            }
        } catch (error) {
            console.error('Error loading user:', error);
        }
    }

    async loadDevices() {
        try {
            const devices = await window.apiClient.getDevices();
            window.uiManager.displayDevices(devices);
        } catch (error) {
            console.error('Error loading devices:', error);
        }
    }

    async loadSessions() {
        try {
            const sessions = await window.apiClient.getSessions();
            window.uiManager.displaySessions(sessions);
        } catch (error) {
            console.error('Error loading sessions:', error);
        }
    }

    async removeDevice(deviceId) {
        if (!confirm('Are you sure you want to remove this device?')) return;

        try {
            const result = await window.apiClient.removeDevice(deviceId);
            if (result.success) {
                window.uiManager.showSuccess('Device Removed', 'The device has been successfully removed.');
                this.loadDevices();
                await this.loadCurrentUser();
            }
        } catch (error) {
            window.uiManager.showError('', error.message);
        }
    }

    // Session management
    async logoutAllSessions() {
        if (window.uiManager.otherSessionsCount > 0) {
            this.showLogoutConfirmModal();
        } else {
            window.uiManager.showSuccess('No Other Sessions', 'You have no other active sessions to terminate.');
        }
    }

    showLogoutConfirmModal() {
        const modalContent = `
            <div class="bg-white rounded-lg max-w-md w-full fade-in">
                <div class="p-6">
                    <div class="flex items-center mb-4">
                        <div class="flex-shrink-0">
                            <div class="h-12 w-12 bg-orange-100 rounded-full flex items-center justify-center">
                                <i class="fas fa-sign-out-alt text-orange-600 text-lg"></i>
                            </div>
                        </div>
                        <div class="ml-4">
                            <h3 class="text-lg font-semibold text-gray-900">Logout Other Sessions?</h3>
                        </div>
                    </div>

                    <p class="text-gray-600 mb-6">
                        This will terminate <strong>${window.uiManager.otherSessionsCount}</strong> other active session${window.uiManager.otherSessionsCount > 1 ? 's' : ''} 
                        on different devices or browsers. Your current session will remain active.
                    </p>

                    <div class="bg-blue-50 border-l-4 border-blue-400 p-4 mb-6">
                        <div class="flex">
                            <i class="fas fa-info-circle text-blue-400 mt-0.5 mr-2"></i>
                            <div class="text-sm text-blue-700">
                                <p class="font-medium mb-1">Active sessions will be terminated on:</p>
                                <ul class="list-disc list-inside text-xs">
                                    <li>Other browsers</li>
                                    <li>Other devices</li>
                                    <li>Mobile applications</li>
                                </ul>
                            </div>
                        </div>
                    </div>

                    <div class="flex space-x-3">
                        <button type="button" onclick="window.uiManager.closeModal('logoutConfirmModal')"
                            class="flex-1 bg-gray-200 hover:bg-gray-300 text-gray-700 py-2 px-4 rounded-md font-medium transition-colors">
                            Cancel
                        </button>
                        <button type="button" onclick="window.authManager.confirmLogoutAllSessions()"
                            class="flex-1 bg-orange-600 hover:bg-orange-700 text-white py-2 px-4 rounded-md font-medium transition-colors">
                            <i class="fas fa-sign-out-alt mr-2"></i>Logout Other Sessions
                        </button>
                    </div>
                </div>
            </div>
        `;

        window.uiManager.createModal('logoutConfirmModal', modalContent);
        window.uiManager.showModal('logoutConfirmModal');
    }

    async confirmLogoutAllSessions() {
        window.uiManager.closeModal('logoutConfirmModal');
        window.uiManager.removeModal('logoutConfirmModal');

        window.uiManager.showLoadingModal('Terminating sessions...');

        try {
            const result = await window.apiClient.logoutAllSessions();
            if (result.success) {
                window.uiManager.hideLoadingModal();
                window.uiManager.showSuccess('Sessions Terminated', `Successfully terminated ${result.data?.terminatedSessions || 'all other'} sessions.`);
                this.loadSessions();
            }
        } catch (error) {
            window.uiManager.hideLoadingModal();
            window.uiManager.showError('', error.message);
        }
    }

    // Dashboard and logout
    showDashboard(data) {
        this.currentUser = data.user || data.data?.user || this.currentUser;
        
        if (data.data?.dbPassword || data.dbPassword) {
            window.uiManager.showDBPassword(data.data?.dbPassword || data.dbPassword);
        }

        window.uiManager.updateUserDisplay(this.currentUser);
        window.uiManager.showDashboard();
        this.loadCurrentUser();
    }

    async logout() {
        try {
            await window.apiClient.logout();
            this.currentUser = null;
            this.tempToken = null;

            // Reset form
            const loginForm = document.getElementById('loginForm');
            if (loginForm) {
                loginForm.reset();
                document.getElementById('privacyConsent').checked = false;
                document.getElementById('loginBtn').disabled = true;
            }

            window.uiManager.showLogin();
        } catch (error) {
            console.error('Logout error:', error);
        }
    }
}

// Export class for initialization in app.js
window.AuthManager = AuthManager;