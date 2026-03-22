const express = require('express');
const mysql = require('mysql2/promise');
const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('./swagger.json');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

// MySQL Connection Pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Initialize Database Tables
async function initDB() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS api_keys (
                id INT AUTO_INCREMENT PRIMARY KEY,
                api_key VARCHAR(255) UNIQUE NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                analysis_mode VARCHAR(50),
                ai_provider VARCHAR(50),
                phishing_detected BOOLEAN,
                raw_data JSON,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log("Database initialized successfully.");
    } catch (error) {
        console.error("Database initialization failed. Retrying in 5 seconds...", error.message);
        setTimeout(initDB, 5000); 
    }
}
initDB();

// Swagger Configuration
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Security Middleware
const authenticate = async (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) return res.status(401).json({ error: "Unauthorized: Missing API Key" });

    try {
        const [rows] = await pool.query('SELECT id FROM api_keys WHERE api_key = ? AND is_active = TRUE', [apiKey]);
        if (rows.length === 0) {
            return res.status(401).json({ error: "Unauthorized: Invalid or inactive API Key" });
        }
        next();
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Internal Server Error during authentication" });
    }
};

// Endpoints

app.post('/api/logs', authenticate, async (req, res) => {
    const { analysis_mode, ai_provider, phishing_detected, raw_data } = req.body;
    try {
        const [result] = await pool.query(
            'INSERT INTO logs (analysis_mode, ai_provider, phishing_detected, raw_data) VALUES (?, ?, ?, ?)',
            [analysis_mode, ai_provider, phishing_detected, JSON.stringify(raw_data)]
        );
        res.status(201).json({ success: true, log_id: result.insertId });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Failed to store log" });
    }
});

app.get('/api/logs', authenticate, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM logs ORDER BY timestamp DESC');
        res.status(200).json(rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Failed to retrieve logs" });
    }
});

app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
    console.log(`Swagger Docs available at http://localhost:${PORT}/api-docs`);
});