const express = require('express');
const cors = require('cors');
require('dotenv').config();
const routes = require('./routes');
const { poolPromise } = require('./db'); // Import to ensure DB connection starts before server

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// API Routes
app.use('/api', routes);

// Start the server only after the database is connected
poolPromise.then(() => {
    app.listen(PORT, () => {
        console.log(`Backend server is running on http://localhost:${PORT}`);
    });
}).catch(err => {
    console.error("Failed to start server due to DB connection error:", err);
});

