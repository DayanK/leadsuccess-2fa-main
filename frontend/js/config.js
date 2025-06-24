// Frontend/js/config.js - Configuration de l'application frontend
window.AppConfig = {
    // API Configuration
    api: {
        baseUrl: 'http://localhost:4001/api/v1',
        timeout: 30000,
        retryAttempts: 3
    },

    // Storage keys
    storage: {
        tokenKey: 'ls_auth_token',
        sessionKey: 'ls_session_token',
        userKey: 'ls_user_data'
    },

    // UI Configuration
    ui: {
        animationDuration: 300,
        toastDuration: 5000,
        autoSubmitDelay: 100
    },

    // Security Configuration
    security: {
        totpCodeLength: 6,
        passwordMinLength: 1,
        maxLoginAttempts: 5
    },

    // Application metadata
    app: {
        name: 'LeadSuccess Portal',
        version: '3.0.0',
        copyright: 'LeadSuccess Team'
    },

    // Debug mode (disable in production)
    debug: true
};