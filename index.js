const express = require('express');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const validator = require('validator');
const fs = require('fs');
const https = require('https');
const csrf = require('csurf');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const morgan = require('morgan');
const sqlite3 = require('sqlite3').verbose(); // Persistent SQLite Database

// Create the express app
const app = express();
app.use(express.json()); // Handle JSON requests
app.use(helmet()); // Enforce security headers
app.use(morgan('combined')); // Log incoming requests

// CORS setup: Restrict domains
const corsOptions = {
    origin: ['https://localhost:3000', 'https://your-production-domain.com'],
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// CSRF protection: apply on non-API routes
const csrfProtection = csrf({ cookie: true });

// Apply CSRF protection only on non-API routes
app.use((req, res, next) => {
    if (req.path === '/register' || req.path === '/login' || req.path.startsWith('/2fa') || req.path === '/users' || req.path.startsWith('/users/')) {
        next(); // Skip CSRF protection for API routes like registration, login, 2FA, and user management routes
    } else {
        csrfProtection(req, res, next); // Apply CSRF protection for non-API routes
    }
});




// Rate limiting: Prevent brute-force or DDoS attacks
const limiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 50,
    message: 'Too many requests from this IP, please try again later.',
    headers: true,
});
app.use(limiter);

// SQLite Database Setup
const db = new sqlite3.Database('./users.db', (err) => {
    if (err) {
        console.error('Error opening the database:', err.message);
    } else {
        console.log('Connected to SQLite database.');
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        `);
    }
});

// Username and Password Validation Patterns
const usernamePattern = /^[a-zA-Z0-9]{4,20}$/; // Username: 4-20 chars, alphanumeric
const passwordPattern = /^[a-zA-Z0-9@#$%^&*]{8,}$/; // Password: 8+ chars, with special symbols

/**
 * User Registration Route
 * Validate input, hash the password, and save the user to the database.
 */
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // Input validation
    if (!validator.isAlphanumeric(username) || !usernamePattern.test(username)) {
        return res.status(400).json({ message: 'Username must be alphanumeric and 4-20 characters.' });
    }

    if (!passwordPattern.test(password) || !validator.isStrongPassword(password, { minSymbols: 1 })) {
        return res.status(400).json({ message: 'Password must contain at least 8 characters, a mix of uppercase, lowercase, numbers, and symbols.' });
    }

    try {
        // Hash the password using Argon2
        const hashedPassword = await argon2.hash(password, { timeCost: 4, memoryCost: 2 ** 16, parallelism: 2 });

        // Store user in SQLite database
        db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], function (err) {
            if (err) {
                return res.status(400).json({ message: 'Username already exists.' });
            }
            res.status(201).json({ message: 'Registration successful!' });
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Internal server error during registration. Please try again later.' });
    }
});

/**
 * User Login Route
 * Validate credentials and issue a JWT token.
 */
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!usernamePattern.test(username)) {
        return res.status(400).json({ message: 'Invalid username format.' });
    }

    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err || !user) {
            return res.status(400).json({ message: 'Invalid username or password.' });
        }

        try {
            // Verify password using Argon2
            const passwordMatch = await argon2.verify(user.password, password);
            if (!passwordMatch) {
                return res.status(400).json({ message: 'Invalid username or password.' });
            }

            // Issue JWT token
            const token = jwt.sign({ username: user.username }, 'super_secret_key', {
                expiresIn: '1h',
                algorithm: 'HS256'
            });
            res.status(200).json({ message: 'Login successful!', token });
        } catch (error) {
            console.error('Login error:', error);
            res.status(500).json({ message: 'Internal server error during login.' });
        }
    });
});

/**
 * View All Users (Admin function)
 * Fetch and display all users in the system.
 */
app.get('/users', (req, res) => {
    db.all(`SELECT username FROM users`, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ message: 'Unable to retrieve users.' });
        }
        res.status(200).json({ users: rows });
    });
});

/**
 * Remove a User
 * Remove a user from the database using their username.
 */
app.delete('/users/:username', (req, res) => {
    const { username } = req.params;

    db.run(`DELETE FROM users WHERE username = ?`, [username], function (err) {
        if (err) {
            return res.status(500).json({ message: 'Failed to delete the user.' });
        }
        if (this.changes === 0) {
            return res.status(400).json({ message: 'User not found.' });
        }
        res.status(200).json({ message: `User '${username}' has been removed.` });
    });
});

/**
 * 2FA Setup Route
 * Generate a 2FA secret and return a QR code for the user to scan.
 */
app.post('/2fa/setup', (req, res) => {
    const secret = speakeasy.generateSecret();
    qrcode.toDataURL(secret.otpauth_url, (err, data) => {
        if (err) {
            console.error('Error generating 2FA QR code:', err);
            return res.status(500).json({ message: 'Unable to generate 2FA QR code.' });
        }
        res.status(200).json({ secret: secret.base32, qrCode: data });
    });
});

/**
 * 2FA Verification Route
 * Verify the TOTP code provided by the user.
 */
app.post('/2fa/verify', (req, res) => {
    const { token, secret } = req.body;

    const verified = speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token,
    });

    if (verified) {
        res.status(200).json({ message: '2FA verification successful.' });
    } else {
        res.status(400).json({ message: 'Invalid 2FA code. Please try again.' });
    }
});

// SSL configuration
const sslOptions = {
    key: fs.readFileSync('./key.pem'),
    cert: fs.readFileSync('./cert.pem')
};

// Global error handling middleware
app.use((err, req, res, next) => {
    console.error('Unexpected error:', err);
    res.status(500).json({ message: 'Internal server error. Please contact support.' });
});

// Start the HTTPS server
https.createServer(sslOptions, app).listen(5000, () => {
    console.log('Secure server is running on port 5000.');
});
