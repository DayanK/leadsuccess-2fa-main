
// ===================================================
// src/config/passport.js - FIXED Authentication Strategies
// ===================================================
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;

const { databaseConfig, sql } = require("./database");
const config = require("./config");

function setupPassportStrategies() {
    console.log("🔧 Configuring Passport strategies...");

    // Local Strategy for password authentication
    passport.use(
        new LocalStrategy(
            { usernameField: "username", passwordField: "password" },
            async (username, password, done) => {
                try {
                    console.log(`🔍 Authenticating user: ${username}`);
                    
                    // Use getPool() with auto-reconnect
                    const pool = await databaseConfig.getPool();

                    const result = await pool
                        .request()
                        .input("LoginName", sql.NVarChar(500), username)
                        .input("Password", sql.NVarChar(100), password)
                        .execute("PRC_CheckGlobalPassword_Local");

                    const authResult = result.recordset[0];

                    if (authResult.ResultCode === 0) {
                        const userInfo = JSON.parse(authResult.UserInfo || "{}");

                        const userResult = await pool
                            .request()
                            .input("LoginName", sql.NVarChar(500), username)
                            .query("SELECT * FROM TwoFactorUser WHERE LoginName = @LoginName");

                        let twoFactorUser = userResult.recordset[0];

                        if (!twoFactorUser) {
                            await pool
                                .request()
                                .input("LoginName", sql.NVarChar(500), username)
                                .input("MitarbeiterID", sql.Int, userInfo.mitarbeiterID)
                                .input("ServerLocationID", sql.Int, userInfo.serverLocationID)
                                .query(`
                                    INSERT INTO TwoFactorUser (LoginName, MitarbeiterID, ServerLocationID, Disable2FA)
                                    VALUES (@LoginName, @MitarbeiterID, @ServerLocationID, 1)
                                `);

                            const newUserResult = await pool
                                .request()
                                .input("LoginName", sql.NVarChar(500), username)
                                .query("SELECT * FROM TwoFactorUser WHERE LoginName = @LoginName");

                            twoFactorUser = newUserResult.recordset[0];
                        }

                        const devicesResult = await pool
                            .request()
                            .input("TwoFactorUserID", sql.Int, twoFactorUser.TwoFactorUserID)
                            .query(`
                                SELECT * FROM TwoFactorDevice 
                                WHERE TwoFactorUserID = @TwoFactorUserID AND Inactive = 0
                                ORDER BY CreatedAt DESC
                            `);

                        const activeDevices = devicesResult.recordset || [];

                        console.log(`✅ User authenticated: ${username}`);
                        
                        return done(null, {
                            username: username,
                            mitarbeiterID: userInfo.mitarbeiterID || twoFactorUser.MitarbeiterID,
                            serverLocationID: userInfo.serverLocationID || twoFactorUser.ServerLocationID,
                            has2FA: activeDevices.length > 0 && !twoFactorUser.Disable2FA,
                            disable2FA: twoFactorUser.Disable2FA,
                            twoFactorUserID: twoFactorUser.TwoFactorUserID,
                            activeDeviceCount: activeDevices.length,
                        });
                    } else {
                        console.log(`❌ Authentication failed for user: ${username}`);
                        return done(null, false, { message: "Invalid credentials" });
                    }
                } catch (error) {
                    console.error("❌ Authentication error:", error);
                    return done(error);
                }
            }
        )
    );

    // JWT Strategy for authenticated requests
    passport.use(
        new JwtStrategy(
            {
                jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
                secretOrKey: config.jwt.secret,
            },
            async (jwtPayload, done) => {
                try {
                    const pool = await databaseConfig.getPool();
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
                    console.error("❌ JWT verification error:", error);
                    return done(error, false);
                }
            }
        )
    );

    console.log("✅ Passport strategies configured successfully");
}

module.exports = setupPassportStrategies;