// Backend/server.js - Version Complètement Améliorée
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { body, validationResult } = require("express-validator");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;

// Import database configuration
const { databaseConfig, sql } = require("./src/config/database.js");

// ===========================================
// CONFIGURATION AMÉLIORÉE
// ===========================================

const config = {
  server: {
    port: process.env.PORT || 4001,
    host: process.env.HOST || "localhost",
  },
  jwt: {
    secret:
      process.env.JWT_SECRET ||
      "your-super-secret-jwt-key-change-in-production",
    expiresIn: process.env.JWT_EXPIRES || "24h",
    refreshExpiresIn: "7d",
  },
  totp: {
    window: 4,
    step: 30,
    digits: 6,
    issuer: "LeadSuccess",
    serviceName: "Test LeadSuccess Portal",
  },
  session: {
    maxConcurrentSessions: 5,
    sessionTimeout: 24 * 60 * 60 * 1000, // 24 hours
  },
  security: {
    maxFailedAttempts: 5,
    lockoutDuration: 30 * 60 * 1000, // 30 minutes
  },
  cors: {
    origin: (origin, callback) => {
      console.log("🌐 CORS Origin:", origin || "null");

      const allowedOrigins = [
        "http://localhost:3000",
        "http://localhost:4001",
        "http://localhost:5504",
        "http://localhost:5505",
        "http://127.0.0.1:5504",
        "http://127.0.0.1:5505",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:4001",
      ];

      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        console.log(`❌ CORS: Origin ${origin} not allowed`);
        callback(new Error("Not allowed by CORS"));
      }
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    credentials: true,
    optionsSuccessStatus: 200,
  },
};

// ===========================================
// EXPRESS APP SETUP
// ===========================================

const app = express();

// Security middleware
app.use(
  helmet({
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);

app.use(cors(config.cors));

// Rate limiting amélioré
const createRateLimiter = (options) => {
  return rateLimit({
    windowMs: options.windowMs || 15 * 60 * 1000,
    max: options.max || 100,
    skipSuccessfulRequests: options.skipSuccessfulRequests || false,
    standardHeaders: true,
    legacyHeaders: false,
    handler: async (req, res) => {
      await logAuditEvent(
        req.body?.username || "unknown",
        "RATE_LIMIT_EXCEEDED",
        false,
        `Rate limit exceeded for ${req.path}`,
        null,
        req
      );
      res.status(429).json({
        success: false,
        error: "Too many requests",
        message: "Please wait before trying again",
        retryAfter: Math.ceil(options.windowMs / 1000),
      });
    },
  });
};

// Limiteurs spécifiques
const generalLimiter = createRateLimiter({ max: 200 });
const authLimiter = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 20 });
const totpLimiter = createRateLimiter({ windowMs: 5 * 60 * 1000, max: 10 });

app.use("/api/", generalLimiter);

// Body parsing
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(passport.initialize());

// ===========================================
// FONCTIONS D'AIDE BASE DE DONNÉES
// ===========================================

async function getDbPool() {
  if (!databaseConfig.isHealthy()) {
    await databaseConfig.connect();
  }
  return databaseConfig.getPool();
}

async function logAuditEvent(
  loginName,
  action,
  success,
  details = null,
  error = null,
  req = null
) {
  try {
    const pool = await getDbPool();
    const request = pool.request();

    await request
      .input("LoginName", sql.NVarChar(500), loginName || "system")
      .input("Action", sql.NVarChar(100), action)
      .input("Success", sql.Bit, success)
      .input("ActionDetails", sql.NVarChar(1000), details)
      .input("ErrorMessage", sql.NVarChar(1000), error)
      .input(
        "IPAddress",
        sql.NVarChar(45),
        req?.ip || req?.connection?.remoteAddress || "localhost"
      )
      .input(
        "UserAgent",
        sql.NVarChar(500),
        req?.get("User-Agent") || "Unknown"
      ).query(`
        INSERT INTO TwoFactorAuditLog (LoginName, Action, Success, ActionDetails, ErrorMessage, IPAddress, UserAgent)
        VALUES (@LoginName, @Action, @Success, @ActionDetails, @ErrorMessage, @IPAddress, @UserAgent)
      `);
  } catch (err) {
    console.error("❌ Audit log error:", err);
  }
}

async function ensureTwoFactorUser(
  username,
  mitarbeiterID = null,
  serverLocationID = null
) {
  try {
    const pool = await getDbPool();

    let result = await pool
      .request()
      .input("LoginName", sql.NVarChar(500), username)
      .query("SELECT * FROM TwoFactorUser WHERE LoginName = @LoginName");

    let user = result.recordset[0];

    if (!user) {
      console.log("🆕 Creating new TwoFactorUser:", username);

      await pool
        .request()
        .input("LoginName", sql.NVarChar(500), username)
        .input("MitarbeiterID", sql.Int, mitarbeiterID)
        .input("ServerLocationID", sql.Int, serverLocationID).query(`
          INSERT INTO TwoFactorUser (LoginName, MitarbeiterID, ServerLocationID, Disable2FA)
          VALUES (@LoginName, @MitarbeiterID, @ServerLocationID, 1)
        `);

      result = await pool
        .request()
        .input("LoginName", sql.NVarChar(500), username)
        .query("SELECT * FROM TwoFactorUser WHERE LoginName = @LoginName");

      user = result.recordset[0];
    }

    return user;
  } catch (error) {
    console.error("❌ Error ensuring TwoFactorUser:", error);
    throw error;
  }
}

async function getUserActiveDevices(twoFactorUserID) {
  try {
    const pool = await getDbPool();

    const result = await pool
      .request()
      .input("TwoFactorUserID", sql.Int, twoFactorUserID).query(`
        SELECT * FROM TwoFactorDevice 
        WHERE TwoFactorUserID = @TwoFactorUserID AND Inactive = 0
        ORDER BY CreatedAt DESC
      `);

    console.log(
      "📱 Active devices for user ID",
      twoFactorUserID,
      ":",
      result.recordset.length
    );
    return result.recordset || [];
  } catch (error) {
    console.error("❌ Error getting active devices:", error);
    return [];
  }
}

async function getDeviceById(deviceId) {
  try {
    const pool = await getDbPool();
    const result = await pool
      .request()
      .input("DeviceID", sql.Int, deviceId)
      .query(
        "SELECT * FROM TwoFactorDevice WHERE TwoFactorDeviceID = @DeviceID"
      );

    return result.recordset[0];
  } catch (error) {
    console.error("❌ Error getting device:", error);
    return null;
  }
}

// ===========================================
// GESTION DES SESSIONS AMÉLIORÉE
// ===========================================

class SessionManager {
  constructor() {
    this.activeSessions = new Map();
  }

  async createSession(userId, username, deviceInfo, req) {
    const sessionToken = crypto.randomBytes(64).toString("hex");
    const sessionData = {
      userId,
      username,
      deviceInfo: deviceInfo || "Unknown Device",
      ipAddress: req.ip || req.connection?.remoteAddress || "127.0.0.1",
      userAgent: req.get("User-Agent") || "Unknown",
      createdAt: new Date(),
      lastActivity: new Date(),
      expiresAt: new Date(Date.now() + config.session.sessionTimeout),
    };

    try {
      const pool = await getDbPool();
      await pool
        .request()
        .input("SessionToken", sql.NVarChar(128), sessionToken)
        .input("TwoFactorUserID", sql.Int, userId)
        .input("LoginName", sql.NVarChar(500), username)
        .input(
          "SessionInfo",
          sql.NVarChar(sql.MAX),
          JSON.stringify(sessionData)
        )
        .input("ExpiresAt", sql.DateTime2, sessionData.expiresAt)
        .input("IPAddress", sql.NVarChar(45), sessionData.ipAddress)
        .input("UserAgent", sql.NVarChar(500), sessionData.userAgent).query(`
          INSERT INTO TwoFactorSession 
          (SessionToken, TwoFactorUserID, LoginName, SessionInfo, ExpiresAt, IPAddress, UserAgent)
          VALUES (@SessionToken, @TwoFactorUserID, @LoginName, @SessionInfo, @ExpiresAt, @IPAddress, @UserAgent)
        `);

      this.activeSessions.set(sessionToken, sessionData);

      // Nettoyer les sessions expirées et appliquer la limite
      await this.cleanupAndEnforceLimit(userId);

      return sessionToken;
    } catch (error) {
      console.error("❌ Error creating session:", error);
      throw error;
    }
  }

  async validateSession(sessionToken) {
    try {
      const pool = await getDbPool();
      const result = await pool
        .request()
        .input("SessionToken", sql.NVarChar(128), sessionToken).query(`
          SELECT * FROM TwoFactorSession 
          WHERE SessionToken = @SessionToken AND ExpiresAt > GETUTCDATE()
        `);

      const session = result.recordset[0];
      if (!session) return null;

      // Mettre à jour la dernière activité
      await pool
        .request()
        .input("SessionToken", sql.NVarChar(128), sessionToken)
        .query(
          "UPDATE TwoFactorSession SET LastUsedTS = GETUTCDATE() WHERE SessionToken = @SessionToken"
        );

      return JSON.parse(session.SessionInfo);
    } catch (error) {
      console.error("❌ Error validating session:", error);
      return null;
    }
  }

  async cleanupAndEnforceLimit(userId) {
    try {
      const pool = await getDbPool();

      // D'abord, supprimer les sessions expirées
      await pool
        .request()
        .query("DELETE FROM TwoFactorSession WHERE ExpiresAt < GETUTCDATE()");

      // Ensuite, obtenir les sessions actives pour cet utilisateur
      const result = await pool.request().input("UserID", sql.Int, userId)
        .query(`
          SELECT SessionID, SessionToken, CreatedAt 
          FROM TwoFactorSession 
          WHERE TwoFactorUserID = @UserID AND ExpiresAt > GETUTCDATE()
          ORDER BY CreatedAt DESC
        `);

      const sessions = result.recordset;
      if (sessions.length > config.session.maxConcurrentSessions) {
        // Supprimer les sessions les plus anciennes
        const sessionsToRemove = sessions.slice(
          config.session.maxConcurrentSessions
        );

        for (const session of sessionsToRemove) {
          await this.terminateSession(session.SessionToken);
        }
      }
    } catch (error) {
      console.error("❌ Error in cleanup and enforce limit:", error);
    }
  }

  async terminateSession(sessionToken) {
    try {
      const pool = await getDbPool();
      await pool
        .request()
        .input("SessionToken", sql.NVarChar(128), sessionToken)
        .query(
          "DELETE FROM TwoFactorSession WHERE SessionToken = @SessionToken"
        );

      this.activeSessions.delete(sessionToken);
    } catch (error) {
      console.error("❌ Error terminating session:", error);
    }
  }

  async getUserSessions(userId) {
    try {
      const pool = await getDbPool();
      const result = await pool.request().input("UserID", sql.Int, userId)
        .query(`
          SELECT * FROM TwoFactorSession 
          WHERE TwoFactorUserID = @UserID AND ExpiresAt > GETUTCDATE()
          ORDER BY CreatedAt DESC
        `);

      return result.recordset;
    } catch (error) {
      console.error("❌ Error getting user sessions:", error);
      return [];
    }
  }

  async terminateAllUserSessions(userId, currentSessionToken = null) {
    try {
      const pool = await getDbPool();

      if (currentSessionToken) {
        // Garder la session actuelle
        await pool
          .request()
          .input("UserID", sql.Int, userId)
          .input("CurrentSession", sql.NVarChar(128), currentSessionToken)
          .query(`
            DELETE FROM TwoFactorSession 
            WHERE TwoFactorUserID = @UserID AND SessionToken != @CurrentSession
          `);
      } else {
        // Supprimer toutes les sessions
        await pool
          .request()
          .input("UserID", sql.Int, userId)
          .query(
            "DELETE FROM TwoFactorSession WHERE TwoFactorUserID = @UserID"
          );
      }
    } catch (error) {
      console.error("❌ Error terminating all sessions:", error);
    }
  }
}

const sessionManager = new SessionManager();

// ===========================================
// SERVICE TOTP AMÉLIORÉ
// ===========================================

class TOTPService {
  constructor() {
    this.recentCodes = new Map();
    this.cleanupInterval = setInterval(() => this.cleanupOldCodes(), 60000);
  }

  // Clear recent codes on startup
  clearUserCodes(userId) {
    // Supprimer tous les codes de cet utilisateur
    const keysToDelete = [];
    for (const key of this.recentCodes.keys()) {
      if (key.startsWith(`${userId}:`)) {
        keysToDelete.push(key);
      }
    }
    keysToDelete.forEach((key) => this.recentCodes.delete(key));
    console.log(
      `🧹 Cleared ${keysToDelete.length} TOTP codes for user ${userId}`
    );
  }

  generateSecret() {
    return speakeasy.generateSecret({
      name: config.totp.serviceName,
      issuer: config.totp.issuer,
      length: 32,
    });
  }

  async verifyTOTP(secret, token, userId) {
    // Vérifier le format du code
    if (!/^\d{6}$/.test(token)) {
      console.log("❌ Invalid TOTP format:", token);
      throw new Error("Invalid code format");
    }

    const codeKey = `${userId}:${token}`;

    // Vérifier si le code a déjà été utilisé récemment
    if (this.recentCodes.has(codeKey)) {
      console.log("❌ TOTP code already used:", codeKey);
      throw new Error("Code already used");
    }

    // ✅ Log pour debug
      console.log("🔍 Verifying TOTP:");
      console.log("   User ID:", userId);
      console.log("   Token:", token);
      console.log("   Window:", config.totp.window);


    const verified = speakeasy.totp.verify({
      secret,
      encoding: "base32",
      token,
      window: config.totp.window,
      algorithm: "sha1",
      digits: config.totp.digits,
      step: config.totp.step,
    });

    console.log("   Result:", verified ? "✅ Valid" : "❌ Invalid");


    if (verified) {
      // Marquer le code comme utilisé
      this.recentCodes.set(codeKey, Date.now());
    }

    return verified;
  }

  cleanupOldCodes() {
    const now = Date.now();
    const ttl = 5 * 60 * 1000; // 5 minutes

    for (const [key, timestamp] of this.recentCodes) {
      if (now - timestamp > ttl) {
        this.recentCodes.delete(key);
      }
    }
  }

  destroy() {
    clearInterval(this.cleanupInterval);
  }
}

const totpService = new TOTPService();

// ===========================================
// STRATEGIES PASSPORT
// ===========================================

passport.use(
  new LocalStrategy(
    { usernameField: "username", passwordField: "password" },
    async (username, password, done) => {
      try {
        const pool = await getDbPool();

        // Appeler la procédure de vérification du mot de passe
        const result = await pool
          .request()
          .input("LoginName", sql.NVarChar(500), username)
          .input("Password", sql.NVarChar(100), password)
          .execute("PRC_CheckGlobalPassword_Local");

        const authResult = result.recordset[0];

        if (authResult.ResultCode === 0) {
          console.log("✅ Password verification successful for:", username);

          const userInfo = JSON.parse(authResult.UserInfo || "{}");
          const twoFactorUser = await ensureTwoFactorUser(
            username,
            userInfo.mitarbeiterID,
            userInfo.serverLocationID
          );

          const activeDevices = await getUserActiveDevices(
            twoFactorUser.TwoFactorUserID
          );

          return done(null, {
            username: username,
            mitarbeiterID:
              userInfo.mitarbeiterID || twoFactorUser.MitarbeiterID,
            serverLocationID:
              userInfo.serverLocationID || twoFactorUser.ServerLocationID,
            has2FA:
              activeDevices.length > 0 &&
              (twoFactorUser.Disable2FA === 0 ||
                twoFactorUser.Disable2FA === false),
            disable2FA:
              twoFactorUser.Disable2FA === 1 ||
              twoFactorUser.Disable2FA === true,
            twoFactorUserID: twoFactorUser.TwoFactorUserID,
            activeDeviceCount: activeDevices.length,
          });
        } else {
          console.log("❌ Password verification failed for:", username);
          return done(null, false, { message: "Invalid credentials" });
        }
      } catch (error) {
        console.error("❌ Authentication error:", error);
        return done(error);
      }
    }
  )
);

passport.use(
  new JwtStrategy(
    {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.jwt.secret,
    },
    async (jwtPayload, done) => {
      try {
        const pool = await getDbPool();
        const result = await pool
          .request()
          .input("LoginName", sql.NVarChar(500), jwtPayload.username)
          .query("SELECT * FROM TwoFactorUser WHERE LoginName = @LoginName");

        const user = result.recordset[0];

        if (user && !user.AccountLocked) {
          return done(null, {
            username: jwtPayload.username,
            mitarbeiterID: user.MitarbeiterID,
            serverLocationID: user.ServerLocationID,
            twoFactorUserID: user.TwoFactorUserID,
          });
        } else {
          return done(null, false);
        }
      } catch (error) {
        return done(error, false);
      }
    }
  )
);

// ===========================================
// SCHÉMAS DE VALIDATION
// ===========================================

const validationSchemas = {
  login: [
    body("username")
      .trim()
      .isLength({ min: 3, max: 50 })
      .matches(/^[a-zA-Z0-9._-]+$/)
      .withMessage("Username contains invalid characters"),
    body("password")
      .isLength({ min: 1, max: 100 })
      .withMessage("Password is required"),
  ],

  totpCode: [
    body("totpCode")
      .isLength({ min: 6, max: 6 })
      .isNumeric()
      .withMessage("TOTP code must be exactly 6 digits"),
  ],

  deviceSetup: [
    body("username").trim().isLength({ min: 1 }),
    body("deviceInfo").optional().trim().isLength({ max: 200 }),
  ],
};

// ===========================================
// MIDDLEWARE
// ===========================================

function validateRequest(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: "Validation failed",
      errors: errors.array(),
    });
  }
  next();
}

function requireAuth(req, res, next) {
  passport.authenticate("jwt", { session: false }, (err, user, info) => {
    if (err) {
      return res.status(500).json({
        success: false,
        message: "Authentication error",
      });
    }

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized - Invalid or expired token",
      });
    }

    req.user = user;
    next();
  })(req, res, next);
}

async function requireSession(req, res, next) {
  const sessionToken = req.headers["x-session-token"];

  if (!sessionToken) {
    return res.status(401).json({
      success: false,
      message: "Session token required",
    });
  }

  const session = await sessionManager.validateSession(sessionToken);

  if (!session) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired session",
    });
  }

  req.session = session;
  req.user = {
    username: session.username,
    twoFactorUserID: session.userId,
  };

  next();
}

// ===========================================
// ROUTES API AMÉLIORÉES
// ===========================================

// Health check complet
app.get("/api/v1/health", async (req, res) => {
  try {
    const dbHealth = await databaseConfig.healthCheck();
    res.json({
      success: true,
      message: "LeadSuccess 2FA API is running",
      timestamp: new Date().toISOString(),
      version: "3.0.0",
      database: dbHealth,
      features: {
        totp: true,
        sessions: true,
        deviceManagement: true,
        auditLog: true,
        rateLimiting: true,
        backupCodes: false,
        webauthn: false,
        emailLinks: false,
      },
      endpoints: {
        authentication: [
          "POST /api/v1/auth/login",
          "POST /api/v1/auth/authenticate",
          "POST /api/v1/auth/logout",
          "GET  /api/v1/auth/me",
        ],
        twoFactor: [
          "POST /api/v1/setup/2fa",
          "POST /api/v1/setup/verify",
          "POST /api/v1/auth/disable-2fa",
          "GET  /api/v1/setup/config",
        ],
        deviceManagement: [
          "GET    /api/v1/devices",
          "DELETE /api/v1/devices/:deviceId",
        ],
        sessionManagement: [
          "GET  /api/v1/sessions",
          "POST /api/v1/sessions/logout-all",
        ],
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Health check failed",
      error: error.message,
    });
  }
});

// Login amélioré avec gestion du flux complet
app.post(
  "/api/v1/auth/login",
  authLimiter,
  validationSchemas.login,
  validateRequest,
  async (req, res) => {
    try {
      const { username, password } = req.body;
      console.log("🔐 Login attempt for:", username);

      passport.authenticate(
        "local",
        { session: false },
        async (err, user, info) => {
          if (err) {
            console.error("❌ Passport authentication error:", err);
            await logAuditEvent(
              username,
              "LOGIN_ERROR",
              false,
              null,
              err.message,
              req
            );
            return res.status(500).json({
              success: false,
              message: "Authentication error",
            });
          }

          if (!user) {
            console.log("❌ Invalid credentials for:", username);
            await logAuditEvent(
              username,
              "LOGIN_FAILED",
              false,
              "Invalid credentials",
              null,
              req
            );

            // Incrémenter les tentatives d'échec
            try {
              const pool = await getDbPool();
              await pool
                .request()
                .input("LoginName", sql.NVarChar(500), username).query(`
                UPDATE TwoFactorUser 
                SET FailedLoginAttempts = FailedLoginAttempts + 1,
                    LastFailedLogin = GETUTCDATE(),
                    AccountLocked = CASE 
                      WHEN FailedLoginAttempts >= ${
                        config.security.maxFailedAttempts - 1
                      } THEN 1 
                      ELSE 0 
                    END,
                    LockedUntil = CASE 
                      WHEN FailedLoginAttempts >= ${
                        config.security.maxFailedAttempts - 1
                      } 
                      THEN DATEADD(MINUTE, ${
                        config.security.lockoutDuration / 60000
                      }, GETUTCDATE())
                      ELSE LockedUntil
                    END
                WHERE LoginName = @LoginName
              `);
            } catch (dbError) {
              console.error("Error updating failed attempts:", dbError);
            }

            return res.status(401).json({
              success: false,
              message: "Invalid username or password",
            });
          }

          // Vérifier si le compte est verrouillé
          const pool = await getDbPool();
          const lockCheck = await pool
            .request()
            .input("UserID", sql.Int, user.twoFactorUserID)
            .query(
              "SELECT AccountLocked, LockedUntil FROM TwoFactorUser WHERE TwoFactorUserID = @UserID"
            );

          const lockInfo = lockCheck.recordset[0];

          if (lockInfo?.AccountLocked && lockInfo.LockedUntil > new Date()) {
            await logAuditEvent(
              username,
              "LOGIN_LOCKED",
              false,
              "Account locked",
              null,
              req
            );
            return res.status(423).json({
              success: false,
              message:
                "Account temporarily locked due to multiple failed attempts",
              lockedUntil: lockInfo.LockedUntil,
            });
          }

          console.log("✅ Credentials valid for:", username, {
            has2FA: user.has2FA,
            deviceCount: user.activeDeviceCount,
          });

          // Réinitialiser les tentatives d'échec en cas de succès
          await pool.request().input("UserID", sql.Int, user.twoFactorUserID)
            .query(`
            UPDATE TwoFactorUser 
            SET FailedLoginAttempts = 0, 
                AccountLocked = 0,
                LockedUntil = NULL
            WHERE TwoFactorUserID = @UserID
          `);

          // Nouveau flux : Si pas de 2FA configuré, connexion directe
          if (!user.has2FA || user.activeDeviceCount === 0) {
            console.log("🚪 Direct login (no 2FA configured):", username);

            // Générer token JWT pour accès direct
            const jwtToken = jwt.sign(
              {
                username: username,
                userId: user.twoFactorUserID,
                mitarbeiterID: user.mitarbeiterID,
                serverLocationID: user.serverLocationID,
                directLogin: true,
              },
              config.jwt.secret,
              { expiresIn: config.jwt.expiresIn }
            );

            // Créer une session
            const sessionToken = await sessionManager.createSession(
              user.twoFactorUserID,
              username,
              "Direct Login",
              req
            );

            await logAuditEvent(
              username,
              "LOGIN_SUCCESS_DIRECT",
              true,
              "Direct login without 2FA",
              null,
              req
            );

            return res.json({
              success: true,
              message: "Login successful",
              authenticated: true,
              data: {
                token: jwtToken,
                sessionToken: sessionToken,
                user: {
                  id: user.twoFactorUserID,
                  username: username,
                  mitarbeiterID: user.mitarbeiterID,
                  serverLocationID: user.serverLocationID,
                  has2FA: false,
                  deviceCount: 0,
                },
              },
            });
          }

          // Si 2FA est configuré, demander le code
          const tempToken = jwt.sign(
            {
              userId: user.twoFactorUserID,
              username: username,
              needsVerification: true,
            },
            config.jwt.secret,
            { expiresIn: "10m" }
          );

          await logAuditEvent(
            username,
            "LOGIN_NEEDS_2FA",
            true,
            "User needs 2FA verification",
            null,
            req
          );

          res.json({
            success: true,
            needs2FA: true,
            tempToken: tempToken,
            user: {
              id: user.twoFactorUserID,
              username: username,
              deviceCount: user.activeDeviceCount,
            },
          });
        }
      )(req, res);
    } catch (error) {
      console.error("❌ Login error:", error);
      await logAuditEvent(
        req.body.username,
        "LOGIN_ERROR",
        false,
        null,
        error.message,
        req
      );
      res.status(500).json({
        success: false,
        message: "Internal server error during login",
      });
    }
  }
);

// Configuration 2FA améliorée
app.post(
  "/api/v1/setup/2fa",
  authLimiter,
  validationSchemas.deviceSetup,
  validateRequest,
  async (req, res) => {
    try {
      const { username, deviceInfo } = req.body;
      console.log("📱 Setup 2FA request for:", username);

      const twoFactorUser = await ensureTwoFactorUser(username);
      const secret = totpService.generateSecret();

      console.log("🔐 Generated TOTP secret");

      // Créer l'URL OTP Auth
      const timestamp = Date.now();

      // const otpAuthUrl = `otpauth://totp/${encodeURIComponent(
      //   config.totp.issuer
      // )}:${encodeURIComponent(username)}?secret=${
      //   secret.base32
      // }&issuer=${encodeURIComponent(
      //   config.totp.issuer
      // )}&algorithm=SHA1&digits=6&period=30`;

      const otpAuthUrl = `otpauth://totp/${encodeURIComponent(config.totp.issuer)}:${encodeURIComponent(username)}?secret=${secret.base32}&issuer=${encodeURIComponent(config.totp.issuer)}&algorithm=SHA1&digits=6&period=30&timestamp=${timestamp}`;


      // Générer le QR Code
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

      // Créer le device dans la base (inactif pour l'instant)
      const pool = await getDbPool();
      const deviceResult = await pool
        .request()
        .input("TwoFactorUserID", sql.Int, twoFactorUser.TwoFactorUserID)
        .input("AuthMethod", sql.NVarChar(30), "TOTP")
        .input("DeviceInfo", sql.NVarChar(1000), deviceInfo || "Web Browser")
        .input("SecretData", sql.NVarChar(4000), secret.base32)
        .input("Inactive", sql.Bit, 1) // Inactif jusqu'à vérification
        .query(`
          INSERT INTO TwoFactorDevice (TwoFactorUserID, AuthMethod, DeviceInfo, SecretData, Inactive)
          VALUES (@TwoFactorUserID, @AuthMethod, @DeviceInfo, @SecretData, @Inactive);
          SELECT SCOPE_IDENTITY() as DeviceID;
        `);

      const deviceID = deviceResult.recordset[0].DeviceID;

      await logAuditEvent(
        username,
        "2FA_SETUP_INITIATED",
        true,
        `Setup initiated for device: ${deviceInfo || "Web Browser"}`,
        null,
        req
      );

      console.log("✅ Device created with ID:", deviceID);

      res.json({
        success: true,
        message: "2FA setup initiated successfully",
        data: {
          deviceId: deviceID,
          deviceInfo: deviceInfo || "Web Browser",
          secret: secret.base32,
          qrCode: qrCodeBase64,
          uri: otpAuthUrl,
          manualEntry: {
            account: username,
            key: secret.base32,
            issuer: config.totp.issuer,
          },
          instructions: [
            "1. Open your authenticator app (Google Authenticator, Microsoft Authenticator, Authy, etc.)",
            "2. Scan the QR code or manually enter the key",
            "3. Enter the 6-digit code from your app to verify",
          ],
          config: {
            issuer: config.totp.issuer,
            serviceName: config.totp.serviceName,
            algorithm: "SHA1",
            digits: 6,
            period: 30,
          },

          // ✅ AJOUTER pour debug
    debug: {
      secretLength: secret.base32.length,
      serverTime: new Date().toISOString(),
      testCode: speakeasy.totp({
        secret: secret.base32,
        encoding: 'base32',
        algorithm: 'sha1',
        digits: 6,
        step: 30
      })
    }
        },
      });
    } catch (error) {
      console.error("❌ Setup 2FA error:", error);
      await logAuditEvent(
        req.body.username,
        "2FA_SETUP_ERROR",
        false,
        null,
        error.message,
        req
      );
      res.status(500).json({
        success: false,
        error: "Failed to setup 2FA device",
        message: error.message,
      });
    }
  }
);

// Vérification setup 2FA améliorée
app.post("/api/v1/setup/verify",  totpLimiter,  [
    body("deviceId").isNumeric(),
    body("totpCode").isLength({ min: 6, max: 6 }).isNumeric(),
  ],
  validateRequest,
  async (req, res) => {
    try {
      const { deviceId, totpCode } = req.body;
      console.log("🔍 Verify setup request for device:", deviceId);

      const pool = await getDbPool();

      // Récupérer le device et l'utilisateur
      const deviceResult = await pool
        .request()
        .input("DeviceID", sql.Int, deviceId).query(`
          SELECT d.*, u.LoginName 
          FROM TwoFactorDevice d
          JOIN TwoFactorUser u ON d.TwoFactorUserID = u.TwoFactorUserID
          WHERE d.TwoFactorDeviceID = @DeviceID
        `);

      const device = deviceResult.recordset[0];
      if (!device) {
        return res.status(404).json({
          success: false,
          error: "Device not found",
          message: "The device you're trying to verify doesn't exist",
        });
      }

      // Vérifier le code TOTP
      try {
        console.log("🔐 Attempting TOTP verification:");
        console.log("   Device ID:", deviceId);
        console.log("   User ID:", device.TwoFactorUserID);
        console.log("   Code:", totpCode);
        console.log("   Secret length:", device.SecretData?.length);

        const verified = await totpService.verifyTOTP(
          device.SecretData, 
          totpCode,
          device.TwoFactorUserID
        );

        if (!verified) {
          await logAuditEvent(
            device.LoginName,
            "2FA_VERIFY_FAILED",
            false,
            `Invalid TOTP for device ${deviceId}`,
            null,
            req
          );

          // Incrémenter les tentatives d'échec du device
          await pool.request().input("DeviceID", sql.Int, deviceId).query(`
              UPDATE TwoFactorDevice 
              SET FailedAttempts = FailedAttempts + 1,
                  LastFailedAttempt = GETUTCDATE()
              WHERE TwoFactorDeviceID = @DeviceID
            `);

          return res.status(400).json({
            success: false,
            error: "Invalid TOTP code",
            message: "Please check your authenticator app and try again",
          });
        }

        console.log("✅ TOTP verification successful");

        // Activer le device
        await pool.request().input("DeviceID", sql.Int, deviceId).query(`
            UPDATE TwoFactorDevice 
            SET Inactive = 0, 
                UpdatedAt = GETUTCDATE(), 
                LastUsed = GETUTCDATE(),
                FailedAttempts = 0
            WHERE TwoFactorDeviceID = @DeviceID
          `);

        console.log("✅ Device activated successfully:", deviceId);

        // Vérifier si c'est le premier device actif
        const userActiveDevices = await getUserActiveDevices(
          device.TwoFactorUserID
        );
        const isFirstDevice = userActiveDevices.length === 1;

        let responseData = {
          success: true,
          message: "2FA device activated successfully",
          data: {
            deviceId: deviceId,
            deviceInfo: device.DeviceInfo,
            activated: true,
            activatedAt: new Date().toISOString(),
            isFirstDevice: isFirstDevice,
            user: {
              id: device.TwoFactorUserID,
              username: device.LoginName,
              totalActiveDevices: userActiveDevices.length,
            },
          },
        };

        // Si c'est le premier device, activer 2FA pour l'utilisateur
        if (isFirstDevice) {
          const activationResult = await pool
            .request()
            .input("LoginName", sql.NVarChar(500), device.LoginName)
            .input("ForceNewPassword", sql.Bit, 1)
            .execute("PRC_ActivateTwoFactor");

          const activateData = activationResult.recordset[0];

          if (activateData.ResultCode === 0) {
            // Générer token JWT
            responseData.data.token = jwt.sign(
              {
                username: device.LoginName,
                userId: device.TwoFactorUserID,
                mitarbeiterID: device.MitarbeiterID,
                serverLocationID: device.ServerLocationID,
                mfaVerified: true,
              },
              config.jwt.secret,
              { expiresIn: config.jwt.expiresIn }
            );

            responseData.data.dbPassword = activateData.DBPassword;

            // Créer une session
            const sessionToken = await sessionManager.createSession(
              device.TwoFactorUserID,
              device.LoginName,
              device.DeviceInfo,
              req
            );

            responseData.data.sessionToken = sessionToken;
          }
        }

        await logAuditEvent(
          device.LoginName,
          "2FA_DEVICE_ACTIVATED",
          true,
          `Device ${deviceId} activated successfully`,
          null,
          req
        );

        res.json(responseData);
      } catch (totpError) {
        if (totpError.message === "Code already used") {
          return res.status(400).json({
            success: false,
            error: "Code already used",
            message:
              "This code has already been used. Please wait for a new code.",
          });
        }
        throw totpError;
      }
    } catch (error) {
      console.error("❌ Verify setup error:", error);
      await logAuditEvent(
        "unknown",
        "2FA_VERIFY_ERROR",
        false,
        null,
        error.message,
        req
      );
      res.status(500).json({
        success: false,
        error: "Failed to verify TOTP code",
        message: error.message,
      });
    }
  }
);

// Authentification complète avec 2FA
app.post(
  "/api/v1/auth/authenticate",
  authLimiter,
  [
    body("username").isLength({ min: 1 }).trim(),
    body("password").isLength({ min: 1 }),
    body("totpCode").isLength({ min: 6, max: 6 }).isNumeric(),
  ],
  validateRequest,
  async (req, res) => {
    try {
      const { username, password, totpCode } = req.body;
      console.log("🔐 Full authentication attempt for:", username);

      passport.authenticate(
        "local",
        { session: false },
        async (err, user, info) => {
          if (err || !user) {
            console.log("❌ Password verification failed for:", username);
            await logAuditEvent(
              username,
              "AUTH_FAILED_PASSWORD",
              false,
              "Invalid password",
              null,
              req
            );

            return res.status(401).json({
              success: false,
              message: "Invalid credentials",
            });
          }

          try {
            const pool = await getDbPool();
            const activeDevices = await getUserActiveDevices(
              user.twoFactorUserID
            );

            if (activeDevices.length === 0) {
              console.log("❌ No active 2FA devices found for:", username);
              await logAuditEvent(
                username,
                "AUTH_FAILED_NO_DEVICES",
                false,
                "No active 2FA devices",
                null,
                req
              );
              return res.status(403).json({
                success: false,
                message:
                  "No active 2FA devices found. Please contact administrator.",
              });
            }

            // Tester le code TOTP sur tous les devices actifs
            let validDevice = null;
            for (const device of activeDevices) {
              if (device.AuthMethod === "TOTP") {
                try {
                  const verified = await totpService.verifyTOTP(
                    device.SecretData,
                    totpCode,
                    user.twoFactorUserID
                  );

                  if (verified) {
                    validDevice = device;
                    break;
                  }
                } catch (verifyError) {
                  if (verifyError.message === "Code already used") {
                    return res.status(400).json({
                      success: false,
                      error: "Code already used",
                      message:
                        "This code has already been used. Please wait for a new code.",
                    });
                  }
                  // Continue with other devices
                  console.log(
                    "TOTP verification failed for device:",
                    device.TwoFactorDeviceID
                  );
                }
              }
            }

            if (!validDevice) {
              console.log("❌ Invalid TOTP code for:", username);
              await logAuditEvent(
                username,
                "AUTH_FAILED_2FA",
                false,
                "Invalid TOTP code",
                null,
                req
              );

              // Incrémenter les tentatives d'échec pour tous les devices
              await pool
                .request()
                .input("UserID", sql.Int, user.twoFactorUserID).query(`
                UPDATE TwoFactorDevice 
                SET FailedAttempts = FailedAttempts + 1,
                    LastFailedAttempt = GETUTCDATE()
                WHERE TwoFactorUserID = @UserID AND Inactive = 0
              `);

              // ✅ Nettoyer les codes TOTP récents pour cet utilisateur
              totpService.clearUserCodes(req.user.twoFactorUserID);

              return res.status(401).json({
                success: false,
                message: "Invalid 2FA code",
              });
            }

            console.log("✅ 2FA verification successful for:", username);

            // Activer 2FA et générer nouveau mot de passe DB
            const activateResult = await pool
              .request()
              .input("LoginName", sql.NVarChar(500), username)
              .input("ForceNewPassword", sql.Bit, 1)
              .execute("PRC_ActivateTwoFactor");

            const activateData = activateResult.recordset[0];

            if (activateData.ResultCode !== 0) {
              console.error("❌ PRC_ActivateTwoFactor failed:", activateData);
              throw new Error(
                activateData.ErrorMessage || "Failed to activate 2FA"
              );
            }

            // Réinitialiser les compteurs d'échec
            await pool.request().input("UserID", sql.Int, user.twoFactorUserID)
              .query(`
              UPDATE TwoFactorUser 
              SET FailedLoginAttempts = 0, 
                  LastLogin = GETUTCDATE(),
                  AccountLocked = 0,
                  LockedUntil = NULL
              WHERE TwoFactorUserID = @UserID
            `);

            // Mettre à jour le device utilisé
            await pool
              .request()
              .input("DeviceID", sql.Int, validDevice.TwoFactorDeviceID).query(`
              UPDATE TwoFactorDevice 
              SET LastUsed = GETUTCDATE(), 
                  FailedAttempts = 0
              WHERE TwoFactorDeviceID = @DeviceID
            `);

            // Générer JWT token
            const jwtToken = jwt.sign(
              {
                username: username,
                userId: user.twoFactorUserID,
                mitarbeiterID: user.mitarbeiterID,
                serverLocationID: user.serverLocationID,
                mfaVerified: true,
                deviceId: validDevice.TwoFactorDeviceID,
              },
              config.jwt.secret,
              { expiresIn: config.jwt.expiresIn }
            );

            // Créer une session
            const sessionToken = await sessionManager.createSession(
              user.twoFactorUserID,
              username,
              validDevice.DeviceInfo,
              req
            );

            await logAuditEvent(
              username,
              "AUTH_SUCCESS",
              true,
              "Full 2FA authentication successful",
              null,
              req
            );

            res.json({
              success: true,
              message: "Authentication successful",
              data: {
                authenticated: true,
                token: jwtToken,
                sessionToken: sessionToken,
                dbPassword: activateData.DBPassword,
                expiresAt: new Date(
                  Date.now() + 24 * 60 * 60 * 1000
                ).toISOString(),
                user: {
                  id: user.twoFactorUserID,
                  username: username,
                  mitarbeiterID: user.mitarbeiterID,
                  serverLocationID: user.serverLocationID,
                  has2FA: true,
                  deviceCount: activeDevices.length,
                },
                deviceUsed: {
                  id: validDevice.TwoFactorDeviceID,
                  authMethod: validDevice.AuthMethod,
                  deviceInfo: validDevice.DeviceInfo,
                },
              },
            });
          } catch (dbError) {
            console.error("❌ Database error during authentication:", dbError);
            await logAuditEvent(
              username,
              "AUTH_ERROR",
              false,
              null,
              dbError.message,
              req
            );
            res.status(500).json({
              success: false,
              message: "Authentication failed due to server error",
            });
          }
        }
      )(req, res);
    } catch (error) {
      console.error("❌ Authentication error:", error);
      await logAuditEvent(
        req.body.username,
        "AUTH_ERROR",
        false,
        null,
        error.message,
        req
      );
      res.status(500).json({
        success: false,
        message: "Internal server error during authentication",
      });
    }
  }
);

// Informations utilisateur améliorées
app.get("/api/v1/auth/me", requireAuth, async (req, res) => {
  try {
    const pool = await getDbPool();
    const userResult = await pool
      .request()
      .input("UserID", sql.Int, req.user.twoFactorUserID).query(`
        SELECT LoginName, MitarbeiterID, ServerLocationID, Disable2FA, 
               CreatedAt, LastLogin, AccountLocked, FailedLoginAttempts
        FROM TwoFactorUser 
        WHERE TwoFactorUserID = @UserID
      `);

    const user = userResult.recordset[0];
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    const activeDevices = await getUserActiveDevices(req.user.twoFactorUserID);
    const has2FA = activeDevices.length > 0 && user.Disable2FA === false;
    console.log("has2FA?", has2FA, "Disable2FA=", user.Disable2FA);

    const has2FA1 = activeDevices.length > 0 && !user.Disable2FA;
    console.log("has2FA1?", has2FA1, "Disable2FA1=", !user.Disable2FA);

    res.json({
      success: true,
      user: {
        id: req.user.twoFactorUserID,
        username: user.LoginName,
        mitarbeiterId: user.MitarbeiterID,
        serverLocationId: user.ServerLocationID,
        has2FA: activeDevices.length > 0 && !user.Disable2FA,
        deviceCount: activeDevices.length,
        lastLogin: user.LastLogin,
        accountLocked: user.AccountLocked,
        failedAttempts: user.FailedLoginAttempts,
        createdAt: user.CreatedAt,
      },
    });
  } catch (error) {
    console.error("❌ Error getting user info:", error);
    res.status(500).json({
      success: false,
      error: "Failed to get user information",
    });
  }
});

// Gestion des devices améliorée
app.get("/api/v1/devices", requireAuth, async (req, res) => {
  try {
    const activeDevices = await getUserActiveDevices(req.user.twoFactorUserID);

    res.json({
      success: true,
      devices: activeDevices.map((device) => ({
        id: device.TwoFactorDeviceID,
        name: device.DeviceInfo,
        type: device.AuthMethod,
        created: device.CreatedAt,
        lastUsed: device.LastUsed,
        isActive: device.Inactive === 0,
        failedAttempts: device.FailedAttempts,
        lastFailedAttempt: device.LastFailedAttempt,
      })),
    });
  } catch (error) {
    console.error("❌ Error fetching devices:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch devices",
    });
  }
});

// Suppression de device corrigée
app.delete("/api/v1/devices/:deviceId", requireAuth, async (req, res) => {
  try {
    const { deviceId } = req.params;
    const userId = req.user.twoFactorUserID;

    // Vérifier que le device appartient à l'utilisateur
    const device = await getDeviceById(deviceId);
    if (!device || device.TwoFactorUserID !== userId) {
      return res.status(403).json({
        success: false,
        error: "Access denied - Device not found or not owned by user",
      });
    }

    // Vérifier qu'il ne s'agit pas du dernier device actif
    const activeDevices = await getUserActiveDevices(userId);
    if (activeDevices.length <= 1) {
      return res.status(400).json({
        success: false,
        error:
          "Cannot remove the last active device. Add another device first.",
        message: "You must have at least one active 2FA device",
      });
    }

    // Désactiver le device
    const pool = await getDbPool();
    await pool.request().input("DeviceID", sql.Int, deviceId).query(`
        UPDATE TwoFactorDevice 
        SET Inactive = 1, UpdatedAt = GETUTCDATE() 
        WHERE TwoFactorDeviceID = @DeviceID
      `);

    await logAuditEvent(
      req.user.username,
      "DEVICE_REMOVED",
      true,
      `Device ${deviceId} (${device.DeviceInfo}) removed`,
      null,
      req
    );

    res.json({
      success: true,
      message: "Device removed successfully",
      removedDevice: {
        id: deviceId,
        name: device.DeviceInfo,
        type: device.AuthMethod,
      },
    });
  } catch (error) {
    console.error("❌ Error removing device:", error);
    await logAuditEvent(
      req.user?.username || "unknown",
      "DEVICE_REMOVE_ERROR",
      false,
      null,
      error.message,
      req
    );
    res.status(500).json({
      success: false,
      error: "Failed to remove device",
      message: error.message,
    });
  }
});

// Désactivation 2FA corrigée
app.post(
  "/api/v1/auth/disable-2fa",
  requireAuth,
  authLimiter,
  [
    body("password").isLength({ min: 1 }),
    body("totpCode").isLength({ min: 6, max: 6 }).isNumeric(),
  ],
  validateRequest,
  async (req, res) => {
    console.log("🔐 [POST] /auth/disable-2fa → headers:", req.headers);
    console.log("🔐 Body:", req.body);

    try {
      const { password, totpCode } = req.body;
      const username = req.user.username;
      const userId = req.user?.twoFactorUserID;

      console.log("🔐 User ID from token:", userId);
      console.log("🚫 Disable 2FA request for:", username);

      req.body.username = username;

      // Vérifier le mot de passe
      passport.authenticate(
        "local",
        { session: false },
        async (err, user, info) => {
          if (err || !user) {
            await logAuditEvent(
              username,
              "DISABLE_2FA_FAILED_PASSWORD",
              false,
              "Invalid password",
              null,
              req
            );
            return res.status(401).json({
              success: false,
              error: "Invalid password",
              message: "Please enter your correct password",
            });
          }

          try {
            // Vérifier le code TOTP
            const activeDevices = await getUserActiveDevices(
              req.user.twoFactorUserID
            );
            let totpValid = false;
            let usedDevice = null;

            for (const device of activeDevices) {
              if (device.AuthMethod === "TOTP") {
                try {
                  const verified = await totpService.verifyTOTP(
                    device.SecretData,
                    totpCode,
                    req.user.twoFactorUserID
                  );
                  if (verified) {
                    totpValid = true;
                    usedDevice = device;
                    break;
                  }
                } catch (e) {
                  if (e.message === "Code already used") {
                    return res.status(400).json({
                      success: false,
                      error: "Code already used",
                      message:
                        "This code has already been used. Please wait for a new code.",
                    });
                  }
                }
              }
            }

            if (!totpValid) {
              await logAuditEvent(
                username,
                "DISABLE_2FA_FAILED_TOTP",
                false,
                "Invalid 2FA code",
                null,
                req
              );
              return res.status(401).json({
                success: false,
                error: "Invalid 2FA code",
                message:
                  "Please enter the correct code from your authenticator app",
              });
            }

            const pool = await getDbPool();

            // Désactiver tous les devices
            // await pool
            //   .request()
            //   .input("UserID", sql.Int, req.user.twoFactorUserID).query(`
            //   UPDATE TwoFactorDevice 
            //   SET Inactive = 1, UpdatedAt = GETUTCDATE()
            //   WHERE TwoFactorUserID = @UserID
            // `);

            await pool
            .request()
            .input("UserID", sql.Int, req.user.twoFactorUserID)
            .query(`
              DELETE FROM TwoFactorDevice 
              WHERE TwoFactorUserID = @UserID
            `);

            // Désactiver 2FA pour l'utilisateur
            await pool
              .request()
              .input("UserID", sql.Int, req.user.twoFactorUserID).query(`
              UPDATE TwoFactorUser 
              SET Disable2FA = 1, 
                  DBPassword = NULL,
                  ValidUntilUTC = NULL,
                  UpdatedAt = GETUTCDATE()
              WHERE TwoFactorUserID = @UserID
            `);

            // Appeler la procédure de désactivation si elle existe
            try {
              await pool
                .request()
                .input("LoginName", sql.NVarChar(500), username)
                .execute("PRC_Disable2FADevice");
            } catch (e) {
              console.log(
                "PRC_Disable2FADevice not found or failed, continuing..."
              );
            }

            // Terminer toutes les sessions sauf la courante
            const currentSessionToken = req.headers["x-session-token"];
            await sessionManager.terminateAllUserSessions(
              req.user.twoFactorUserID,
              currentSessionToken
            );

            await logAuditEvent(
              username,
              "2FA_DISABLED",
              true,
              "2FA disabled completely",
              null,
              req
            );

            res.json({
              success: true,
              message:
                "Two-factor authentication has been disabled successfully",
              data: {
                username: username,
                devicesDisabled: activeDevices.length,
                sessionsTerminated: true,
              },
            });
          } catch (dbError) {
            console.error("❌ Database error disabling 2FA:", dbError);
            await logAuditEvent(
              username,
              "DISABLE_2FA_ERROR",
              false,
              null,
              dbError.message,
              req
            );
            res.status(500).json({
              success: false,
              error: "Failed to disable 2FA due to server error",
              message: dbError.message,
            });
          }
        }
      )(req, res);
    } catch (error) {
      console.error("❌ Error disabling 2FA:", error);
      await logAuditEvent(
        req.user?.username,
        "DISABLE_2FA_ERROR",
        false,
        null,
        error.message,
        req
      );
      res.status(500).json({
        success: false,
        error: "Failed to disable 2FA",
        message: error.message,
      });
    }
  }
);

// Gestion des sessions améliorée
app.get("/api/v1/sessions", requireAuth, async (req, res) => {
  try {
    const sessions = await sessionManager.getUserSessions(
      req.user.twoFactorUserID
    );
    const currentSessionToken = req.headers["x-session-token"];

    res.json({
      success: true,
      sessions: sessions.map((session) => {
        const info = JSON.parse(session.SessionInfo);
        return {
          id: session.SessionID,
          deviceInfo: info.deviceInfo || "Unknown Device",
          ipAddress: session.IPAddress,
          userAgent: session.UserAgent,
          createdAt: session.CreatedAt,
          lastUsed: session.LastUsedTS,
          expiresAt: session.ExpiresAt,
          isCurrent: currentSessionToken === session.SessionToken,
        };
      }),
    });
  } catch (error) {
    console.error("❌ Error fetching sessions:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch sessions",
    });
  }
});

// Logout corrigé
app.post("/api/v1/auth/logout", requireSession, async (req, res) => {
  try {
    const sessionToken = req.headers["x-session-token"];
    await sessionManager.terminateSession(sessionToken);

    await logAuditEvent(
      req.user.username,
      "LOGOUT",
      true,
      "User logged out",
      null,
      req
    );

    res.json({
      success: true,
      message: "Logged out successfully",
    });
  } catch (error) {
    console.error("❌ Error during logout:", error);
    res.status(500).json({
      success: false,
      error: "Failed to logout",
      message: error.message,
    });
  }
});

// Logout de toutes les autres sessions corrigé
app.post("/api/v1/sessions/logout-all", requireAuth, async (req, res) => {
  try {
    const currentSession = req.headers["x-session-token"];
    const sessions = await sessionManager.getUserSessions(
      req.user.twoFactorUserID
    );

    let terminatedCount = 0;
    for (const session of sessions) {
      if (session.SessionToken !== currentSession) {
        await sessionManager.terminateSession(session.SessionToken);
        terminatedCount++;
      }
    }

    await logAuditEvent(
      req.user.username,
      "LOGOUT_ALL",
      true,
      `${terminatedCount} sessions terminated`,
      null,
      req
    );

    res.json({
      success: true,
      message: "All other sessions terminated successfully",
      data: {
        terminatedSessions: terminatedCount,
        currentSessionMaintained: true,
      },
    });
  } catch (error) {
    console.error("❌ Error terminating sessions:", error);
    await logAuditEvent(
      req.user?.username,
      "LOGOUT_ALL_ERROR",
      false,
      null,
      error.message,
      req
    );
    res.status(500).json({
      success: false,
      error: "Failed to terminate sessions",
      message: error.message,
    });
  }
});

// Configuration endpoint amélioré
app.get("/api/v1/setup/config", (req, res) => {
  res.json({
    success: true,
    data: {
      issuer: config.totp.issuer,
      serviceName: config.totp.serviceName,
      algorithm: "SHA1",
      digits: config.totp.digits,
      period: config.totp.step,
      window: config.totp.window,
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
      ],
      features: {
        totp: true,
        deviceManagement: true,
        sessionManagement: true,
        auditLog: true,
        rateLimiting: true,
        backupCodes: false,
        webauthn: false,
        emailLinks: false,
      },
      security: {
        maxFailedAttempts: config.security.maxFailedAttempts,
        lockoutDuration: config.security.lockoutDuration / 60000, // en minutes
        maxConcurrentSessions: config.session.maxConcurrentSessions,
        sessionTimeout: config.session.sessionTimeout / 60000, // en minutes
      },
    },
  });
});

// Route pour le nettoyage de maintenance
app.post("/api/v1/admin/maintenance", async (req, res) => {
  try {
    const pool = await getDbPool();

    // Exécuter le job de maintenance
    const result = await pool.request().execute("PRC_MaintenanceJob");
    const maintenanceResult = result.recordset[0];

    res.json({
      success: maintenanceResult.Success === 1,
      message: maintenanceResult.Message,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error("❌ Maintenance job error:", error);
    res.status(500).json({
      success: false,
      error: "Maintenance job failed",
      message: error.message,
    });
  }
});

// Ajouter après les autres routes (vers ligne 1300)
app.get("/api/v1/time-check", (req, res) => {
  const serverTime = new Date();
  const serverTimeUTC = new Date().toISOString();
  const serverTimestamp = Math.floor(Date.now() / 1000);
  
  res.json({
    serverTime: serverTime.toString(),
    serverTimeUTC: serverTimeUTC,
    serverTimestamp: serverTimestamp,
    serverTimeFormatted: new Date().toLocaleString()
  });
});

// Route de test pour vérifier manuellement un code TOTP
app.post("/api/v1/test-totp", requireAuth, async (req, res) => {
  try {
    const { deviceId, totpCode } = req.body;
    const pool = await getDbPool();
    
    const result = await pool.request()
      .input('DeviceID', sql.Int, deviceId)
      .query('SELECT * FROM TwoFactorDevice WHERE TwoFactorDeviceID = @DeviceID');
    
    const device = result.recordset[0];
    if (!device) {
      return res.status(404).json({ error: 'Device not found' });
    }
    
    // Générer plusieurs codes valides pour debug
    const validCodes = [];
    for (let i = -config.totp.window; i <= config.totp.window; i++) {
      const code = speakeasy.totp({
        secret: device.SecretData,
        encoding: 'base32',
        algorithm: 'sha1',
        digits: 6,
        step: 30,
        counter: Math.floor(Date.now() / 1000 / 30) + i
      });
      validCodes.push({ offset: i, code: code });
    }
    
    const verified = await totpService.verifyTOTP(device.SecretData, totpCode, device.TwoFactorUserID);
    
    res.json({
      deviceId: deviceId,
      secret: device.SecretData,
      providedCode: totpCode,
      verified: verified,
      validCodes: validCodes,
      currentTime: new Date().toISOString(),
      serverTimestamp: Math.floor(Date.now() / 1000)
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===========================================
// GESTION D'ERREURS
// ===========================================

app.use((req, res) => {
  console.log(`❌ 404 - Endpoint not found: ${req.method} ${req.url}`);
  res.status(404).json({
    success: false,
    message: "API endpoint not found",
    requestedUrl: req.url,
    method: req.method,
    availableEndpoints: {
      authentication: [
        "POST /api/v1/auth/login",
        "POST /api/v1/auth/authenticate",
        "POST /api/v1/auth/logout",
        "GET  /api/v1/auth/me",
      ],
      twoFactor: [
        "POST /api/v1/setup/2fa",
        "POST /api/v1/setup/verify",
        "POST /api/v1/auth/disable-2fa",
        "GET  /api/v1/setup/config",
      ],
      deviceManagement: [
        "GET    /api/v1/devices",
        "DELETE /api/v1/devices/:deviceId",
      ],
      sessionManagement: [
        "GET  /api/v1/sessions",
        "POST /api/v1/sessions/logout-all",
      ],
      system: ["GET  /api/v1/health", "POST /api/v1/admin/maintenance"],
    },
  });
});

app.use((err, req, res, next) => {
  console.error("❌ Global error:", err);

  const isDevelopment = process.env.NODE_ENV !== "production";

  res.status(500).json({
    success: false,
    message: "Internal server error",
    timestamp: new Date().toISOString(),
    ...(isDevelopment && {
      error: err.message,
      stack: err.stack,
    }),
  });
});

// ===========================================
// DÉMARRAGE DU SERVEUR
// ===========================================

async function startServer() {
  try {
    // Connexion à la base de données
    await databaseConfig.connect();
    console.log("✅ Database connection established");

    // Démarrer le serveur
    const server = app.listen(config.server.port, config.server.host, () => {
      console.log(
        "\n🚀 ═══════════════════════════════════════════════════════════"
      );
      console.log("🚀 LeadSuccess 2FA API Server Started - v3.0 ENHANCED");
      console.log(
        "🚀 ═══════════════════════════════════════════════════════════"
      );
      console.log(
        `📍 Server: http://${config.server.host}:${config.server.port}`
      );
      console.log(
        `🗄️  Database: ${databaseConfig.config.server}/${databaseConfig.config.database}`
      );
      console.log("✅ Ready to accept connections");
      console.log("\n📋 API Documentation:");
      console.log(
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      );
      console.log("🔐 AUTHENTICATION:");
      console.log(
        `   POST ${config.server.host}:${config.server.port}/api/v1/auth/login`
      );
      console.log(
        `   POST ${config.server.host}:${config.server.port}/api/v1/auth/authenticate`
      );
      console.log(
        `   POST ${config.server.host}:${config.server.port}/api/v1/auth/logout`
      );
      console.log(
        `   GET  ${config.server.host}:${config.server.port}/api/v1/auth/me`
      );
      console.log("\n📱 2FA SETUP:");
      console.log(`   POST ${config.server.host}:${config.server.port}/api/v1/setup/2fa`
      );
      console.log(
        `   POST ${config.server.host}:${config.server.port}/api/v1/setup/verify`
      );
      console.log(
        `   POST ${config.server.host}:${config.server.port}/api/v1/auth/disable-2fa`
      );
      console.log(
        `   GET  ${config.server.host}:${config.server.port}/api/v1/setup/config`
      );
      console.log("\n🔧 DEVICE MANAGEMENT:");
      console.log(
        `   GET    ${config.server.host}:${config.server.port}/api/v1/devices`
      );
      console.log(
        `   DELETE ${config.server.host}:${config.server.port}/api/v1/devices/:deviceId`
      );
      console.log("\n💻 SESSION MANAGEMENT:");
      console.log(
        `   GET  ${config.server.host}:${config.server.port}/api/v1/sessions`
      );
      console.log(
        `   POST ${config.server.host}:${config.server.port}/api/v1/sessions/logout-all`
      );
      console.log("\n⚡ SYSTEM:");
      console.log(
        `   GET  ${config.server.host}:${config.server.port}/api/v1/health`
      );
      console.log(
        `   POST ${config.server.host}:${config.server.port}/api/v1/admin/maintenance`
      );
      console.log(
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      );
      console.log("\n🧪 Test avec Postman:");
      console.log("1. Import Collection: Utilisez les URLs ci-dessus");
      console.log("2. Variables d'environnement:");
      console.log(
        `   - baseUrl: http://${config.server.host}:${config.server.port}/api/v1`
      );
      console.log("   - token: {{token}} (sera défini automatiquement)");
      console.log(
        "   - sessionToken: {{sessionToken}} (sera défini automatiquement)"
      );
      console.log("\n💡 Flux de test recommandé:");
      console.log(
        "   1. POST /auth/login (username: lstestmaximadmin, password: test123)"
      );
      console.log("   2. POST /setup/2fa (si pas encore configuré)");
      console.log("   3. POST /setup/verify (avec le code TOTP)");
      console.log("   4. POST /auth/authenticate (login complet avec 2FA)");
      console.log("   5. GET /auth/me (vérifier les infos utilisateur)");
      console.log("   6. GET /devices (lister les appareils)");
      console.log("   7. GET /sessions (lister les sessions actives)");
      console.log(
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      );
    });

    // Nettoyage automatique toutes les heures
    setInterval(async () => {
      try {
        const pool = await getDbPool();
        await pool.request().execute("PRC_MaintenanceJob");
        console.log("🧹 Automatic maintenance completed");
      } catch (error) {
        console.error("❌ Automatic maintenance failed:", error);
      }
    }, 60 * 60 * 1000); // 1 heure

    return server;
  } catch (error) {
    console.error("❌ Failed to start server:", error);
    process.exit(1);
  }
}

// Gestion gracieuse de l'arrêt
process.on("SIGINT", async () => {
  console.log("\n🛑 Received SIGINT, shutting down gracefully...");
  try {
    totpService.destroy();
    await databaseConfig.disconnect();
    console.log("✅ Database connection closed");
  } catch (error) {
    console.error("❌ Error during shutdown:", error);
  }
  console.log("✅ Server shutdown complete");
  process.exit(0);
});

process.on("SIGTERM", async () => {
  console.log("\n🛑 Received SIGTERM, shutting down gracefully...");
  try {
    totpService.destroy();
    await databaseConfig.disconnect();
    console.log("✅ Database connection closed");
  } catch (error) {
    console.error("❌ Error during shutdown:", error);
  }
  console.log("✅ Server shutdown complete");
  process.exit(0);
});

// Gestion des erreurs non capturées
process.on("uncaughtException", (error) => {
  console.error("❌ Uncaught Exception:", error);
  process.exit(1);
});

process.on("unhandledRejection", (reason, promise) => {
  console.error("❌ Unhandled Rejection at:", promise, "reason:", reason);
  process.exit(1);
});

// Démarrer le serveur si ce fichier est exécuté directement
if (require.main === module) {
  startServer();
}

module.exports = app;
