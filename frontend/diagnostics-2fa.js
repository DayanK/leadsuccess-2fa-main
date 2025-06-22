// Script de diagnostic complet
async function runDiagnostics() {
    console.log("🔍 DIAGNOSTIC 2FA - DÉBUT");
    console.log("========================");
    
    // 1. Vérifier l'état actuel
    console.log("\n1️⃣ État actuel de l'utilisateur:");
    try {
        const userInfo = await client2FA.getCurrentUser();
        console.log("User info:", userInfo);
        console.log("- has2FA:", userInfo.user.has2FA);
        console.log("- disable2FA:", userInfo.user.disable2FA);
        console.log("- deviceCount:", userInfo.user.deviceCount);
    } catch (error) {
        console.error("Erreur getCurrentUser:", error);
    }
    
    // 2. Lister les devices
    console.log("\n2️⃣ Devices configurés:");
    try {
        const devices = await client2FA.getDevices();
        console.log("Devices:", devices);
        devices.forEach((device, i) => {
            console.log(`Device ${i+1}:`, {
                id: device.id,
                name: device.name,
                type: device.type,
                isActive: device.isActive
            });
        });
    } catch (error) {
        console.error("Erreur getDevices:", error);
    }
    
    // 3. Tester la connexion
    console.log("\n3️⃣ Test de connexion:");
    try {
        const loginResult = await client2FA.login('testuser', 'password');
        console.log("Login result:", loginResult);
        console.log("- authenticated:", loginResult.authenticated);
        console.log("- needs2FA:", loginResult.needs2FA);
        console.log("- user has2FA:", loginResult.user?.has2FA);
    } catch (error) {
        console.error("Erreur login:", error);
    }
    
    console.log("\n========================");
    console.log("🔍 DIAGNOSTIC TERMINÉ");
}

// Fonction pour configurer et tester le 2FA
async function testSetup2FA() {
    console.log("🔧 TEST SETUP 2FA - DÉBUT");
    console.log("========================");
    
    try {
        // 1. Initier le setup
        console.log("\n1️⃣ Initiation setup 2FA:");
        const setupResult = await client2FA.setup2FA('testuser', 'Test Device from Console');
        console.log("Setup result:", {
            success: setupResult.success,
            deviceId: setupResult.deviceId,
            secret: setupResult.secret
        });
        
        // 2. Afficher le QR code
        console.log("\n2️⃣ QR Code généré - Scannez avec votre app:");
        console.log("Secret key:", setupResult.secret);
        console.log("Device ID:", setupResult.deviceId);
        
        // 3. Instructions pour la vérification
        console.log("\n3️⃣ Pour vérifier, exécutez:");
        console.log(`await testVerify2FA(${setupResult.deviceId}, 'VOTRE_CODE_6_CHIFFRES');`);
        
        return setupResult.deviceId;
    } catch (error) {
        console.error("Erreur setup 2FA:", error);
    }
}

// Fonction pour vérifier le setup
async function testVerify2FA(deviceId, totpCode) {
    console.log("✅ TEST VERIFY 2FA - DÉBUT");
    console.log("========================");
    
    try {
        const verifyResult = await client2FA.verify2FASetup(deviceId, totpCode);
        console.log("Verify result:", verifyResult);
        console.log("- activated:", verifyResult.activated);
        console.log("- isFirstDevice:", verifyResult.isFirstDevice);
        console.log("- user:", verifyResult.user);
        console.log("- dbPassword:", verifyResult.dbPassword);
        
        // Vérifier l'état après activation
        console.log("\n📊 État après activation:");
        await runDiagnostics();
        
    } catch (error) {
        console.error("Erreur verify 2FA:", error);
    }
}

// Fonction pour tester la désactivation
async function testDisable2FA(password, totpCode) {
    console.log("🚫 TEST DISABLE 2FA - DÉBUT");
    console.log("========================");
    
    try {
        const result = await client2FA.disable2FA(password, totpCode);
        console.log("Disable result:", result);
        
        // Vérifier l'état après désactivation
        console.log("\n📊 État après désactivation:");
        await runDiagnostics();
        
    } catch (error) {
        console.error("Erreur disable 2FA:", error);
        console.log("Status:", error.status);
        console.log("Message:", error.message);
    }
}

// Lancer le diagnostic
console.log("🚀 Fonctions de test disponibles:");
console.log("- runDiagnostics() : Diagnostic complet");
console.log("- testSetup2FA() : Configurer le 2FA");
console.log("- testVerify2FA(deviceId, code) : Vérifier le setup");
console.log("- testDisable2FA('password', '123456') : Désactiver le 2FA");
console.log("\nCommencez par: await runDiagnostics()");