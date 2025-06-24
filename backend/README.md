# LeadSuccess 2FA API - Backend

## Description
API backend modulaire pour l'authentification à deux facteurs (2FA) utilisant TOTP, conçue pour l'écosystème LeadSuccess.

## Architecture

```
/backend
├── .env.example              # Variables d'environnement exemple
├── package.json             # Dépendances et scripts npm
├── README.md               # Cette documentation
└── src/
    ├── config/
    │   ├── config.js        # Configuration centralisée
    │   ├── database.js      # Configuration base de données
    │   └── passport.js      # Stratégies d'authentification
    ├── controllers/
    │   ├── authController.js    # Contrôleur d'authentification
    │   ├── deviceController.js  # Gestion des appareils 2FA
    │   ├── sessionController.js # Gestion des sessions
    │   └── totpController.js    # Configuration TOTP
    ├── middleware/
    │   ├── authMiddleware.js    # Middleware d'authentification
    │   ├── errorHandler.js     # Gestion d'erreurs globale
    │   └── validation.js       # Validation des données
    ├── models/
    │   ├── Device.js           # Modèle des appareils
    │   ├── Session.js          # Modèle des sessions
    │   └── User.js             # Modèle des utilisateurs
    ├── routes/
    │   ├── authRoutes.js       # Routes d'authentification
    │   ├── deviceRoutes.js     # Routes des appareils
    │   ├── index.js           # Point d'entrée des routes
    │   └── sessionRoutes.js    # Routes des sessions
    ├── services/
    │   ├── authService.js      # Services d'authentification
    │   ├── sessionService.js   # Services de session
    │   └── totpService.js      # Services TOTP
    ├── utils/
    │   ├── helpers.js          # Fonctions utilitaires
    │   └── logger.js           # Système de logging
    └── server.js              # Point d'entrée principal
```

## Prérequis

- **Node.js** >= 16.0.0
- **npm** >= 8.0.0
- **SQL Server** avec la base de données LeadSuccess2FA
- **Windows Authentication** configurée pour SQL Server

## Installation

1. **Cloner le projet**
   ```bash
   git clone <repository-url>
   cd backend
   ```

2. **Installer les dépendances**
   ```bash
   npm install
   ```

3. **Configuration**
   ```bash
   cp .env.example .env
   # Éditer le fichier .env avec vos paramètres
   ```

4. **Base de données**
   - Exécuter le script `db_script5.sql` pour créer la base de données
   - Vérifier la connectivité avec SQL Server

## Configuration

### Variables d'environnement (.env)

```bash
# Serveur
PORT=4001
HOST=localhost
NODE_ENV=development

# Base de données
DB_SERVER=CONVEYNUC12
DB_DATABASE=LeadSuccess2FA

# JWT
JWT_SECRET=your-super-secret-jwt-key-change-in-production

# Logging
LOG_LEVEL=info
```

### Configuration principale (src/config/config.js)

- **Serveur** : Port, host, CORS
- **JWT** : Secret, expiration
- **TOTP** : Fenêtre de validation, algorithme
- **Sécurité** : Tentatives max, verrouillage
- **Sessions** : Limite concurrent, timeout

## Démarrage

### Mode développement
```bash
npm run dev
```

### Mode production
```bash
npm start
```

### Scripts disponibles
```bash
npm run dev      # Développement avec nodemon
npm run start    # Production
npm run lint     # Vérification du code
npm run format   # Formatage du code
```

## API Endpoints

### Authentification
- `POST /api/v1/auth/login` - Connexion initiale
- `POST /api/v1/auth/authenticate` - Authentification complète avec 2FA
- `GET /api/v1/auth/me` - Informations utilisateur
- `POST /api/v1/auth/logout` - Déconnexion
- `POST /api/v1/auth/disable-2fa` - Désactiver le 2FA

### Configuration 2FA
- `POST /api/v1/auth/setup/2fa` - Initier la configuration 2FA
- `POST /api/v1/auth/setup/verify` - Vérifier la configuration
- `GET /api/v1/auth/setup/config` - Obtenir la configuration TOTP

### Gestion des appareils
- `GET /api/v1/devices` - Lister les appareils
- `DELETE /api/v1/devices/:deviceId` - Supprimer un appareil

### Gestion des sessions
- `GET /api/v1/sessions` - Lister les sessions actives
- `POST /api/v1/sessions/logout-all` - Déconnecter toutes les autres sessions

### Système
- `GET /api/v1/health` - Statut de santé de l'API
- `POST /api/v1/admin/maintenance` - Job de maintenance

## Flux d'authentification

### 1. Connexion simple (sans 2FA)
```
Client -> POST /auth/login -> Connexion directe si pas de 2FA configuré
```

### 2. Première configuration 2FA
```
Client -> POST /setup/2fa -> QR Code généré
Client -> POST /setup/verify -> Appareil activé + 2FA activé
```

### 3. Connexion avec 2FA
```
Client -> POST /auth/login -> needs2FA: true
Client -> POST /auth/authenticate -> Authentification complète
```

## Sécurité

### Mesures implémentées
- **Rate limiting** par endpoint
- **Validation** des données d'entrée
- **JWT** avec expiration
- **Sessions** avec limite et timeout
- **Audit logging** complet
- **Codes TOTP** à usage unique
- **Verrouillage** de compte après échecs

### Protection TOTP
- Fenêtre de tolérance configurable
- Anti-rejeu des codes
- Synchronisation temporelle
- Support des apps standard (Google Authenticator, etc.)

## Base de données

### Tables principales
- `TwoFactorUser` - Utilisateurs 2FA
- `TwoFactorDevice` - Appareils d'authentification
- `TwoFactorSession` - Sessions actives
- `TwoFactorAuditLog` - Journal d'audit

### Procédures stockées
- `PRC_CheckGlobalPassword_Local` - Vérification mot de passe
- `PRC_ActivateTwoFactor` - Activation 2FA
- `PRC_Disable2FADevice` - Désactivation 2FA
- `PRC_MaintenanceJob` - Nettoyage automatique

## Logging

### Niveaux de log
- `error` - Erreurs critiques
- `warn` - Avertissements
- `info` - Informations générales
- `debug` - Débogage (développement)

### Fichiers de log
- `logs/error.log` - Erreurs uniquement
- `logs/combined.log` - Tous les logs
- `logs/audit.log` - Actions utilisateurs
- `logs/security.log` - Événements sécurité

## Développement

### Structure modulaire
- **Controllers** : Logique des endpoints
- **Services** : Logique métier
- **Models** : Accès aux données
- **Middleware** : Traitements transversaux
- **Utils** : Fonctions utilitaires

### Bonnes pratiques
- Code en anglais, commentaires en français
- Gestion d'erreurs centralisée
- Validation systématique des entrées
- Logging structuré
- Tests unitaires (à implémenter)

## Déploiement

### Production
1. Configurer les variables d'environnement
2. Utiliser un gestionnaire de processus (PM2)
3. Configurer le proxy inverse (nginx)
4. Activer HTTPS
5. Configurer la rotation des logs

### Sécurité production
- Changer JWT_SECRET
- Configurer CORS restrictif
- Activer rate limiting strict
- Surveillance des logs
- Backup automatique de la base

## Maintenance

### Jobs automatiques
- Nettoyage des sessions expirées
- Purge des anciens logs d'audit
- Déverrouillage automatique des comptes

### Monitoring
- Surveillance de la base de données
- Métriques d'authentification
- Alertes sur les échecs répétés
- Performance des endpoints

## Support

### Debug
- Activer `LOG_LEVEL=debug`
- Consulter les logs structurés
- Utiliser les endpoints de santé

### Erreurs communes
- **DB Connection** : Vérifier la connectivité SQL Server
- **JWT Invalid** : Vérifier JWT_SECRET
- **CORS Error** : Configurer les origines autorisées
- **Rate Limited** : Ajuster les limites ou attendre

---

**Version:** 3.0.0  
**Maintenu par:** LeadSuccess Team  
**Licence:** MIT