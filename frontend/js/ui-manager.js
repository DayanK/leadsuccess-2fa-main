// Frontend/js/ui-manager.js - Gestionnaire d'interface utilisateur
class UIManager {
    constructor() {
        this.modals = new Map();
        this.currentUser = null;
        this.otherSessionsCount = 0;
    }

    // Modal management
    showModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.remove('hidden');
        }
    }

    closeModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.add('hidden');
        }
    }

    createModal(id, content) {
        const modalContainer = document.getElementById('modalContainer');
        const modal = document.createElement('div');
        modal.id = id;
        modal.className = 'hidden fixed inset-0 bg-black bg-opacity-50 modal-overlay flex items-center justify-center z-50 p-4';
        modal.innerHTML = content;
        modalContainer.appendChild(modal);
        this.modals.set(id, modal);
        return modal;
    }

    removeModal(id) {
        const modal = this.modals.get(id);
        if (modal) {
            modal.remove();
            this.modals.delete(id);
        }
    }

    // Navigation and tabs
    showTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            const isActive = btn.getAttribute('data-tab') === tabName;
            btn.classList.toggle('border-primary', isActive);
            btn.classList.toggle('text-primary', isActive);
            btn.classList.toggle('border-transparent', !isActive);
            btn.classList.toggle('text-gray-500', !isActive);
        });

        // Hide all tab contents
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.add('hidden');
        });

        // Show active tab
        const activeTab = document.getElementById(tabName + 'Tab');
        if (activeTab) {
            activeTab.classList.remove('hidden');
        }

        // Load dynamic content for specific tabs
        if (tabName === 'devices') {
            window.authManager.loadDevices();
        } else if (tabName === 'sessions') {
            window.authManager.loadSessions();
        }
    }

    // User interface updates
    updateUserDisplay(user) {
        this.currentUser = user;
        const userDisplay = document.getElementById('userDisplay');
        if (userDisplay) {
            userDisplay.textContent = user.username;
        }
        this.updateUserInfo();
        this.updateSecurityStatus();
    }

    updateUserInfo() {
        const userInfo = document.getElementById('userInfo');
        if (!userInfo || !this.currentUser) return;

        userInfo.innerHTML = `
            <div class="flex justify-between py-2 border-b">
                <span class="font-medium">Username:</span>
                <span>${this.currentUser.username}</span>
            </div>
            <div class="flex justify-between py-2 border-b">
                <span class="font-medium">Employee ID:</span>
                <span>${this.currentUser.mitarbeiterId || 'N/A'}</span>
            </div>
            <div class="flex justify-between py-2 border-b">
                <span class="font-medium">2FA Status:</span>
                <span class="${this.currentUser.has2FA ? 'text-green-600' : 'text-red-600'}">${this.currentUser.has2FA ? 'Enabled' : 'Disabled'}</span>
            </div>
            <div class="flex justify-between py-2 border-b">
                <span class="font-medium">Active Devices:</span>
                <span>${this.currentUser.deviceCount || 0}</span>
            </div>
            <div class="flex justify-between py-2">
                <span class="font-medium">Last Login:</span>
                <span>${this.currentUser.lastLogin ? new Date(this.currentUser.lastLogin).toLocaleString() : 'Never'}</span>
            </div>
        `;
    }

    updateSecurityStatus() {
        const setupBtn = document.getElementById('setup2FABtn');
        const securityIcon = document.getElementById('securityIcon');
        const securityStatus = document.getElementById('securityStatus');

        if (!this.currentUser) return;

        if (this.currentUser.has2FA) {
            setupBtn?.classList.add('hidden');
            if (securityIcon) securityIcon.textContent = '🔒';
            if (securityStatus) {
                securityStatus.textContent = 'Account Secured';
                securityStatus.className = 'text-sm font-medium text-green-600 bg-green-100 px-3 py-1 rounded-full inline-block';
            }
        } else {
            setupBtn?.classList.remove('hidden');
            if (securityIcon) securityIcon.textContent = '⚠️';
            if (securityStatus) {
                securityStatus.textContent = 'Enable 2FA for Security';
                securityStatus.className = 'text-sm font-medium text-yellow-600 bg-yellow-100 px-3 py-1 rounded-full inline-block';
            }
        }
    }

    // Device display
    displayDevices(devices) {
        const devicesList = document.getElementById('devicesList');
        if (!devicesList) return;

        if (devices.length === 0) {
            devicesList.innerHTML = '<p class="text-gray-500 text-center py-8">No devices configured</p>';
            return;
        }

        devicesList.innerHTML = devices.map(device => `
            <div class="flex items-center justify-between p-4 border rounded-lg">
                <div class="flex items-center space-x-3">
                    <div class="text-2xl">
                        ${this.getDeviceIcon(device.type)}
                    </div>
                    <div>
                        <div class="font-medium">${device.name}</div>
                        <div class="text-sm text-gray-500">
                            ${device.type} • Added ${new Date(device.created).toLocaleDateString()}
                            ${device.lastUsed ? ` • Last used ${new Date(device.lastUsed).toLocaleDateString()}` : ''}
                        </div>
                    </div>
                </div>
                <button onclick="window.authManager.removeDevice(${device.id})" 
                    class="text-red-600 hover:text-red-800 p-2">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        `).join('');
    }

    getDeviceIcon(type) {
        switch (type) {
            case 'TOTP': return '📱';
            case 'BACKUP_CODE': return '🔑';
            default: return '🔐';
        }
    }

    // Session display
    displaySessions(sessions) {
        const sessionsList = document.getElementById('sessionsList');
        if (!sessionsList) return;

        this.otherSessionsCount = sessions.filter(s => !s.isCurrent).length;

        if (sessions.length === 0) {
            sessionsList.innerHTML = '<p class="text-gray-500 text-center py-8">No active sessions</p>';
            return;
        }

        sessionsList.innerHTML = sessions.map(session => `
            <div class="p-4 border rounded-lg ${session.isCurrent ? 'border-primary bg-primary/5' : ''}">
                <div class="flex justify-between items-start">
                    <div>
                        <div class="font-medium flex items-center">
                            ${session.deviceInfo}
                            ${session.isCurrent ? '<span class="ml-2 bg-green-100 text-green-800 text-xs px-2 py-1 rounded">Current</span>' : ''}
                        </div>
                        <div class="text-sm text-gray-500 mt-1">
                            <div>IP: ${session.ipAddress}</div>
                            <div>Started: ${new Date(session.createdAt).toLocaleString()}</div>
                            <div>Last activity: ${new Date(session.lastUsed).toLocaleString()}</div>
                        </div>
                    </div>
                </div>
            </div>
        `).join('');
    }

    // Password display
    showDBPassword(password) {
        const passwordValue = document.getElementById('dbPasswordValue');
        const passwordDisplay = document.getElementById('dbPasswordDisplay');
        
        if (passwordValue && passwordDisplay) {
            passwordValue.textContent = password;
            passwordDisplay.classList.remove('hidden');
        }
    }

    copyDBPassword() {
        const password = document.getElementById('dbPasswordValue')?.textContent;
        if (password) {
            navigator.clipboard.writeText(password).then(() => {
                this.showSuccess('Copied', 'Password copied to clipboard!');
            });
        }
    }

    // Notifications and messages
    showSuccess(title, message, callback = null) {
        this.createModal('successModal', `
            <div class="bg-white rounded-lg max-w-md w-full fade-in">
                <div class="p-6 text-center">
                    <div class="text-green-500 text-4xl mb-4">
                        <i class="fas fa-check-circle"></i>
                    </div>
                    <h3 class="text-lg font-semibold text-gray-900 mb-2">${title}</h3>
                    <p class="text-gray-600 mb-6">${message}</p>
                    <button onclick="window.uiManager.closeModal('successModal')${callback ? '; (' + callback + ')()' : ''}"
                        class="bg-primary hover:bg-primary-dark text-white py-2 px-6 rounded-md font-medium transition-colors">
                        OK
                    </button>
                </div>
            </div>
        `);
        this.showModal('successModal');
    }

    showError(elementId, message) {
        if (elementId) {
            const errorEl = document.getElementById(elementId);
            if (errorEl) {
                errorEl.textContent = message;
                errorEl.classList.remove('hidden');
                setTimeout(() => errorEl.classList.add('hidden'), window.AppConfig.ui.toastDuration);
            }
        }
    }

    hideError(elementId) {
        const errorEl = document.getElementById(elementId);
        if (errorEl) {
            errorEl.classList.add('hidden');
        }
    }

    // Loading states
    setLoadingState(btnId, loading) {
        const btn = document.getElementById(btnId);
        const spinner = document.getElementById(btnId.replace('Btn', 'Spinner'));
        const text = document.getElementById(btnId.replace('Btn', 'BtnText'));

        if (!btn) return;

        if (loading) {
            btn.disabled = true;
            spinner?.classList.remove('hidden');
            if (text) text.textContent = 'Loading...';
        } else {
            btn.disabled = false;
            spinner?.classList.add('hidden');

            // Reset text based on button
            if (text) {
                if (btnId === 'loginBtn') text.textContent = 'Sign In';
                else if (btnId === 'setupBtn') text.textContent = 'Enable 2FA';
                else if (btnId === 'verifyBtn') text.textContent = 'Verify';
            }
        }
    }

    showLoadingModal(text = 'Processing...') {
        this.createModal('loadingModal', `
            <div class="bg-white rounded-lg p-6 fade-in">
                <div class="flex items-center space-x-3">
                    <div class="spinner"></div>
                    <span class="text-gray-700 font-medium">${text}</span>
                </div>
            </div>
        `);
        this.showModal('loadingModal');
    }

    hideLoadingModal() {
        this.closeModal('loadingModal');
        this.removeModal('loadingModal');
    }

    // Layout switching
    showDashboard() {
        document.getElementById('loginContainer')?.classList.add('hidden');
        document.getElementById('dashboardLayout')?.classList.remove('hidden');
        this.showTab('overview');
    }

    showLogin() {
        document.getElementById('dashboardLayout')?.classList.add('hidden');
        document.getElementById('loginContainer')?.classList.remove('hidden');
    }
}

// Export class for initialization in app.js
window.UIManager = UIManager;