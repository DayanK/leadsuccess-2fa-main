// Backend/src/server.js - Main entry point
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const passport = require("passport");

const { databaseConfig } = require("./config/database");
const setupPassportStrategies = require("./config/passport");
const routes = require("./routes");
const { errorHandler, notFoundHandler } = require("./middleware/errorHandler");
const config = require("./config/config");

const app = express();

// Security middleware
app.use(helmet({
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
}));

app.use(cors(config.cors));

// Body parsing
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// Passport configuration
app.use(passport.initialize());
setupPassportStrategies();

// Routes
app.use("/api/v1", routes);

// Error handling
app.use(notFoundHandler);
app.use(errorHandler);

// Server startup
async function startServer() {
    try {
        // Database connection
        await databaseConfig.connect();
        console.log("✅ Database connection established");

        // Start server
        const server = app.listen(config.server.port, config.server.host, () => {
            console.log(`🚀 LeadSuccess 2FA API Server Started`);
            console.log(`📍 Server: http://${config.server.host}:${config.server.port}`);
            console.log(`🗄️  Database: ${databaseConfig.config.server}/${databaseConfig.config.database}`);
            console.log("✅ Ready to accept connections");
        });

        // Automatic maintenance every hour
        setInterval(async () => {
            try {
                const pool = await databaseConfig.getPool();
                await pool.request().execute("PRC_MaintenanceJob");
            } catch (error) {
                console.error("❌ Automatic maintenance failed:", error);
            }
        }, 60 * 60 * 1000);

        return server;
    } catch (error) {
        console.error("❌ Failed to start server:", error);
        process.exit(1);
    }
}

// Graceful shutdown
process.on("SIGINT", async () => {
    console.log("\n🛑 Received SIGINT, shutting down gracefully...");
    try {
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
        await databaseConfig.disconnect();
        console.log("✅ Database connection closed");
    } catch (error) {
        console.error("❌ Error during shutdown:", error);
    }
    console.log("✅ Server shutdown complete");
    process.exit(0);
});

// Start server if run directly
if (require.main === module) {
    startServer();
}

module.exports = app;