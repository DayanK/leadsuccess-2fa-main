// Frontend/js/troubleshoot-modal.js - Modal de dépannage pour les problèmes TOTP
class TroubleshootModal {
    static show() {
        const modalContent = `
            <div class="bg-white rounded-lg max-w-lg w-full max-h-[90vh] overflow-y-auto fade-in">
                <div class="p-6">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-lg font-semibold text-gray-900">TOTP Troubleshooting</h3>
                        <button onclick="window.uiManager.closeModal('troubleshootModal')" class="text-gray-400 hover:text-gray-600">
                            <i class="fas fa-times text-xl"></i>
                        </button>
                    </div>

                    <div class="space-y-4">
                        <div class="bg-blue-50 border-l-4 border-blue-400 p-4">
                            <h4 class="text-sm font-semibold text-blue-800 mb-2">
                                <i class="fas fa-info-circle mr-2"></i>Common Issues
                            </h4>
                            <ul class="text-xs text-blue-700 space-y-1">
                                <li>• Device clock not synchronized</li>
                                <li>• Code already used (wait for new code)</li>
                                <li>• Authenticator app not configured correctly</li>
                                <li>• Typing code too slowly</li>
                            </ul>
                        </div>

                        <div class="bg-yellow-50 border-l-4 border-yellow-400 p-4">
                            <h4 class="text-sm font-semibold text-yellow-800 mb-2">
                                <i class="fas fa-clock mr-2"></i>Time Synchronization
                            </h4>
                            <p class="text-xs text-yellow-700 mb-2">Server Time: <span id="serverTime">Loading...</span></p>
                            <p class="text-xs text-yellow-700 mb-2">Your Time: <span id="clientTime">${new Date().toLocaleString()}</span></p>
                            <p class="text-xs text-yellow-700">Time Difference: <span id="timeDiff">Calculating...</span></p>
                            <button onclick="TroubleshootModal.checkTimeSync()" 
                                class="mt-2 text-xs bg-yellow-600 hover:bg-yellow-700 text-white px-3 py-1 rounded transition-colors">
                                Check Time Sync
                            </button>
                        </div>

                        <div class="bg-green-50 border-l-4 border-green-400 p-4">
                            <h4 class="text-sm font-semibold text-green-800 mb-2">
                                <i class="fas fa-lightbulb mr-2"></i>Solutions
                            </h4>
                            <ol class="text-xs text-green-700 space-y-1 list-decimal list-inside">
                                <li>Wait for a fresh code (30 seconds cycle)</li>
                                <li>Check your device's date and time settings</li>
                                <li>Enable automatic time synchronization</li>
                                <li>Re-scan the QR code if still failing</li>
                                <li>Try a different authenticator app</li>
                            </ol>
                        </div>

                        <div class="bg-red-50 border-l-4 border-red-400 p-4">
                            <h4 class="text-sm font-semibold text-red-800 mb-2">
                                <i class="fas fa-exclamation-triangle mr-2"></i>Need Help?
                            </h4>
                            <p class="text-xs text-red-700 mb-2">If problems persist, contact your administrator with:</p>
                            <ul class="text-xs text-red-700 space-y-1">
                                <li>• Your username</li>
                                <li>• Time difference (shown above)</li>
                                <li>• Authenticator app name/version</li>
                                <li>• Device type (phone/tablet)</li>
                            </ul>
                        </div>

                        <div class="flex space-x-3 pt-4">
                            <button onclick="window.uiManager.closeModal('troubleshootModal')"
                                class="flex-1 bg-gray-200 hover:bg-gray-300 text-gray-700 py-2 px-4 rounded-md font-medium transition-colors">
                                Close
                            </button>
                            <button onclick="TroubleshootModal.resetSetup()"
                                class="flex-1 bg-primary hover:bg-primary-dark text-white py-2 px-4 rounded-md font-medium transition-colors">
                                Start Over
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;

        window.uiManager.createModal('troubleshootModal', modalContent);
        window.uiManager.showModal('troubleshootModal');
        
        // Auto-check time sync when modal opens
        TroubleshootModal.checkTimeSync();
    }

    static async checkTimeSync() {
        try {
            const response = await fetch(window.AppConfig.api.baseUrl + '/health');
            const serverData = await response.json();
            
            const serverTime = new Date(serverData.timestamp);
            const clientTime = new Date();
            const timeDiff = Math.abs(serverTime.getTime() - clientTime.getTime()) / 1000;

            document.getElementById('serverTime').textContent = serverTime.toLocaleString();
            document.getElementById('clientTime').textContent = clientTime.toLocaleString();
            
            if (timeDiff > 30) {
                document.getElementById('timeDiff').innerHTML = 
                    `<span class="text-red-600 font-semibold">${timeDiff.toFixed(1)}s - Clock sync issue!</span>`;
            } else {
                document.getElementById('timeDiff').innerHTML = 
                    `<span class="text-green-600">${timeDiff.toFixed(1)}s - OK</span>`;
            }
        } catch (error) {
            document.getElementById('timeDiff').innerHTML = 
                '<span class="text-red-600">Error checking server time</span>';
        }
    }

    static resetSetup() {
        window.uiManager.closeModal('troubleshootModal');
        window.uiManager.removeModal('troubleshootModal');
        
        // Close any existing setup modals
        window.uiManager.closeModal('setup2FAModal');
        window.uiManager.removeModal('setup2FAModal');
        
        // Restart 2FA setup
        window.authManager.show2FASetup();
    }
}

// Make available globally
window.TroubleshootModal = TroubleshootModal;