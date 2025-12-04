const sql = require('mssql');
require('dotenv').config();

const dbConfig = {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    server: process.env.DB_SERVER,
    port: parseInt(process.env.DB_PORT, 10),
    database: process.env.DB_DATABASE,
    options: {
        encrypt: true, // This must be true for Azure SQL connections
        trustServerCertificate: true, // For self-signed certificates in some environments
        enableArithAbort: true
    }
};

const poolPromise = new sql.ConnectionPool(dbConfig)
    .connect()
    .then(pool => {
        console.log('Successfully connected to the database!');
        return pool;
    })
    .catch(err => {
        console.error('FATAL: Database connection failed on startup:', err);
        process.exit(1);
    });

module.exports = {
    sql,
    poolPromise
};
