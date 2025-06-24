// Frontend/js/app.js - Point d'entrée principal de l'application
class App {
    constructor() {
        this.initialized = false;
    }

    // Initialize application
    async init() {
        if (this.initialized) return;

        try {
            // Initialize managers in correct order
            this.initializeManagers();
            
            this.setupEventListeners();
            this.checkAuthStatus();
            this.initialized = true;

            if (window.AppConfig.debug) {
                console.log('LeadSuccess Portal initialized successfully');
            }
        } catch (error) {
            console.error('Failed to initialize application:', error);
        }
    }

    // Initialize all managers with proper dependencies
    initializeManagers() {
        // Initialize API client first
        window.apiClient = new window.ApiClient();
        
        // Initialize UI manager
        window.uiManager = new window.UIManager();
        
        // Initialize auth manager (depends on apiClient and uiManager)
        window.authManager = new window.AuthManager();
    }

    // Setup all event listeners
    setupEventListeners() {
        // Privacy consent checkbox
        const privacyConsent = document.getElementById('privacyConsent');
        if (privacyConsent) {
            privacyConsent.addEventListener('change', this.handlePrivacyConsentChange);
        }

        // Login form
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', this.handleLoginSubmit);
        }

        // Global error handling
        window.addEventListener('error', this.handleGlobalError);
        window.addEventListener('unhandledrejection', this.handleUnhandledRejection);

        // Setup global functions for inline event handlers
        this.setupGlobalFunctions();
    }

    // Setup global functions accessible from HTML
    setupGlobalFunctions() {
        // Navigation functions
        window.showTab = (tabName) => window.uiManager.showTab(tabName);
        window.logout = () => window.authManager.logout();
        
        // 2FA functions
        window.show2FASetup = () => window.authManager.show2FASetup();
        window.showDisable2FAModal = () => window.authManager.showDisable2FAModal();
        
        // Device management
        window.removeDevice = (deviceId) => window.authManager.removeDevice(deviceId);
        
        // Session management
        window.logoutAllSessions = () => window.authManager.logoutAllSessions();
        
        // Utility functions
        window.copyDBPassword = () => window.uiManager.copyDBPassword();
        window.closeModal = (modalId) => window.uiManager.closeModal(modalId);
    }

    // Check if user is already authenticated
    checkAuthStatus() {
        if (window.apiClient && window.apiClient.isAuthenticated()) {
            window.authManager.loadCurrentUser().then(() => {
                window.uiManager.showDashboard();
            }).catch(error => {
                console.error('Error loading user:', error);
                window.uiManager.showLogin();
            });
        }
    }

    // Event handlers
    handlePrivacyConsentChange(event) {
        const loginBtn = document.getElementById('loginBtn');
        if (!loginBtn) return;

        if (event.target.checked) {
            loginBtn.disabled = false;
            loginBtn.classList.remove('bg-gray-400', 'cursor-not-allowed');
            loginBtn.classList.add('bg-primary', 'hover:bg-primary-dark');
        } else {
            loginBtn.disabled = true;
            loginBtn.classList.add('bg-gray-400', 'cursor-not-allowed');
            loginBtn.classList.remove('bg-primary', 'hover:bg-primary-dark');
        }
    }

    async handleLoginSubmit(event) {
        event.preventDefault();
        const formData = new FormData(event.target);
        await window.authManager.handleLogin(formData);
    }

    handleGlobalError(event) {
        if (window.AppConfig.debug) {
            console.error('Global error:', event.error);
        }
        
        // You could show a global error notification here
        // window.uiManager.showError('', 'An unexpected error occurred');
    }

    handleUnhandledRejection(event) {
        if (window.AppConfig.debug) {
            console.error('Unhandled promise rejection:', event.reason);
        }
        
        // Prevent default behavior (console error)
        event.preventDefault();
    }

    // Utility methods
    getVersion() {
        return {
            app: window.AppConfig.app.version,
            name: window.AppConfig.app.name,
            initialized: this.initialized,
            timestamp: new Date().toISOString()
        };
    }

    // Development helpers
    debug() {
        if (!window.AppConfig.debug) {
            console.warn('Debug mode is disabled');
            return;
        }

        return {
            config: window.AppConfig,
            apiClient: window.apiClient,
            authManager: window.authManager,
            uiManager: window.uiManager,
            app: this,
            version: this.getVersion(),
            storage: {
                token: window.apiClient.getStoredToken(),
                sessionToken: window.apiClient.getStoredSessionToken(),
                isAuthenticated: window.apiClient.isAuthenticated()
            }
        };
    }

    // Clean up resources
    destroy() {
        // Clean up event listeners and resources
        window.removeEventListener('error', this.handleGlobalError);
        window.removeEventListener('unhandledrejection', this.handleUnhandledRejection);
        
        // Clear auth data
        window.apiClient.clearAuth();
        
        this.initialized = false;
    }
}

// Initialize application when DOM is loaded
document.addEventListener('DOMContentLoaded', async () => {
    window.app = new App();
    await window.app.init();
});

// Make debug function available globally in development
if (window.AppConfig.debug) {
    window.debug = () => window.app?.debug();
}

// Export for potential module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = App;
}