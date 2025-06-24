// Backend\src\config\database.js



const sql = require('mssql/msnodesqlv8');



class DatabaseConfig {

    constructor() {

        this.pool = null;

        this.isConnected = false;

       

        // Configuration optimisée pour votre environnement

        this.config = {

            server: process.env.DB_SERVER || 'CONVEYNUC12',

            port: parseInt(process.env.DB_PORT) || 1433,

            database: process.env.DB_DATABASE || 'LeadSuccess2FA',

            driver: "msnodesqlv8", // Requis pour Windows Authentication

            options: {

                trustedConnection: true, // Windows Authentication

                trustServerCertificate: true,

                enableArithAbort: true,

                useUTC: true,

                connectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT) || 30000,

                requestTimeout: parseInt(process.env.DB_REQUEST_TIMEOUT) || 30000,

            },

            pool: {

                min: parseInt(process.env.DB_POOL_MIN) || 2,

                max: parseInt(process.env.DB_POOL_MAX) || 10,

                idleTimeoutMillis: 30000,

                createTimeoutMillis: 30000,

                acquireTimeoutMillis: 30000,

                createRetryIntervalMillis: 200,

            }

        };

    }



    // Connexion à la base de données

    async connect() {

        try {

            if (this.isConnected && this.pool) {

                return this.pool;

            }



            console.log('🔗 Connecting to SQL Server...', {

                server: this.config.server,

                database: this.config.database

            });



            this.pool = new sql.ConnectionPool(this.config);

           

            // Event listeners pour monitoring

            this.pool.on('connect', () => {

                console.log('✅ Database pool connected successfully');

            });



            this.pool.on('close', () => {

                console.log('⚠️ Database pool closed');

                this.isConnected = false;

            });



            this.pool.on('error', (err) => {

                console.error('❌ Database pool error:', err);

                this.isConnected = false;

            });



            await this.pool.connect();

            this.isConnected = true;



            // Test de connexion

            await this.testConnection();

           

            return this.pool;



        } catch (error) {

            console.error('❌ Database connection failed:', error);

            this.isConnected = false;

            throw new Error(`Database connection failed: ${error.message}`);

        }

    }



    // Test de connexion

    async testConnection() {

        try {

            const request = this.pool.request();

            const result = await request.query(`

                SELECT

                    GETUTCDATE() as CurrentTime,

                    @@VERSION as SQLVersion,

                    DB_NAME() as DatabaseName,

                    USER_NAME() as CurrentUser

            `);

           

            console.log('✅ Database test successful:', {

                currentTime: result.recordset[0].CurrentTime,

                database: result.recordset[0].DatabaseName,

                user: result.recordset[0].CurrentUser

            });



            return true;

        } catch (error) {

            console.error('❌ Database test failed:', error);

            throw error;

        }

    }



    // Obtenir le pool de connexions

    getPool() {

        if (!this.isConnected || !this.pool) {

            throw new Error('Database not connected. Call connect() first.');

        }

        return this.pool;

    }



    // Fermeture propre de la connexion

    async disconnect() {

        try {

            if (this.pool && this.isConnected) {

                await this.pool.close();

                this.pool = null;

                this.isConnected = false;

                console.log('✅ Database connection closed successfully');

            }

        } catch (error) {

            console.error('❌ Error closing database connection:', error);

            throw error;

        }

    }



    // Vérifier le statut de connexion

    isHealthy() {

        return this.isConnected && this.pool && this.pool.connected;

    }



    // Obtenir les statistiques de connexion

    getConnectionStats() {

        if (!this.pool) {

            return { connected: false };

        }



        return {

            connected: this.isConnected,

            poolSize: this.pool.size,

            availableConnections: this.pool.available,

            pendingRequests: this.pool.pending,

            config: {

                server: this.config.server,

                database: this.config.database,

                poolMin: this.config.pool.min,

                poolMax: this.config.pool.max

            }

        };

    }



    // Health check complet

    async healthCheck() {

        try {

            if (!this.isHealthy()) {

                return {

                    healthy: false,

                    error: 'Database connection not available'

                };

            }



            // Test simple de requête

            const request = this.pool.request();

            await request.query('SELECT 1 as HealthCheck');



            return {

                healthy: true,

                stats: this.getConnectionStats(),

                timestamp: new Date().toISOString()

            };



        } catch (error) {

            return {

                healthy: false,

                error: error.message,

                timestamp: new Date().toISOString()

            };

        }

    }

}



// Export singleton instance

const databaseConfig = new DatabaseConfig();



module.exports = {
    databaseConfig,
    sql
};