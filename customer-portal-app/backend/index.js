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
const speakeasy = require('speakeasy'); // For 2FA (Two-Factor Authentication)
const qrcode = require('qrcode'); // To generate QR codes for 2FA setup
const morgan = require('morgan'); // Logging middleware for better monitoring

const app = express();
app.use(express.json()); // Handle JSON request bodies
app.use(helmet()); // Secure HTTP headers to mitigate common attacks
app.use(morgan('combined')); // Log all incoming requests for debugging

// Limit CORS origins to only specific trusted domains
const corsOptions = {
    origin: ['https://localhost:3000', 'https://your-production-domain.com'], // Replace with your actual domains
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions)); // Enable restricted cross-origin requests

// Enhanced CSRF protection middleware (for non-API routes)
const csrfProtection = csrf({ cookie: true });

// Apply CSRF protection only on non-API routes
app.use((req, res, next) => {
    if (req.path === '/register' || req.path === '/login' || req.path.startsWith('/2fa')) {
        next(); // Skip CSRF for these API routes
    } else {
        csrfProtection(req, res, next); // Apply CSRF for non-API routes
    }
});

// Advanced Rate Limiting to prevent DDoS attacks
const limiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 50, // Max 50 requests per windowMs
    message: 'Too many requests from this IP, please try again after 10 minutes.',
    headers: true,
});
app.use(limiter);

// Simulated In-Memory Database (For testing purposes only)
const users = [];

// RegEx patterns for validation
const usernamePattern = /^[a-zA-Z0-9]+$/; // Only alphanumeric
const passwordPattern = /^[a-zA-Z0-9@#$%^&*]+$/; // Only alphanumeric and special characters

/**
 * User Registration Route
 */
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // Input Validation
    if (!usernamePattern.test(username)) {
        return res.status(400).json({ message: 'Username must be alphanumeric.' });
    }

    if (!passwordPattern.test(password) || !validator.isStrongPassword(password, { minSymbols: 1 })) {
        return res.status(400).json({ message: 'Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and one special character.' });
    }

    // Check if username is already registered
    const existingUser = users.find(u => u.username === username);
    if (existingUser) {
        return res.status(400).json({ message: 'Username is already taken.' });
    }

    // Hash the password using Argon2 with enhanced security settings
    try {
        const hashedPassword = await argon2.hash(password, { timeCost: 4, memoryCost: 2 ** 16, parallelism: 2 });
        users.push({ username, password: hashedPassword });
        res.status(201).json({ message: 'User registered successfully.' });
    } catch (error) {
        console.error('Error during registration:', error); // Log error for debugging
        res.status(500).json({ message: 'Server error during registration. Please try again later.' });
    }
});

/**
 * User Login Route
 */
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Input Validation
    if (!usernamePattern.test(username)) {
        return res.status(400).json({ message: 'Invalid username.' });
    }

    const user = users.find(u => u.username === username);

    if (!user) {
        return res.status(400).json({ message: 'Invalid username or password.' });
    }

    try {
        const isMatch = await argon2.verify(user.password, password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid username or password.' });
        }

        // Sign JWT token with enhanced security
        const token = jwt.sign({ username: user.username }, 'super_secret_key', {
            expiresIn: '1h',
            algorithm: 'HS256'
        });
        res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
        console.error('Error during login:', error); // Log error for debugging
        res.status(500).json({ message: 'Server error during login. Please try again later.' });
    }
});

/**
 * 2FA Setup Route
 */
app.post('/2fa/setup', (req, res) => {
    const secret = speakeasy.generateSecret();
    qrcode.toDataURL(secret.otpauth_url, (err, data) => {
        if (err) {
            console.error('Error generating QR code:', err); // Log error for debugging
            return res.status(500).json({ message: 'Error setting up 2FA. Please try again later.' });
        }
        res.json({ secret: secret.base32, qrCode: data });
    });
});

/**
 * 2FA Verification Route
 */
app.post('/2fa/verify', (req, res) => {
    const { token, secret } = req.body;
    const verified = speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token,
    });

    if (verified) {
        res.json({ message: '2FA success' });
    } else {
        res.status(400).json({ message: '2FA verification failed. Please try again.' });
    }
});

// SSL setup using cert.pem and key.pem
const sslOptions = {
    key: fs.readFileSync('./key.pem'),
    cert: fs.readFileSync('./cert.pem')
};

// Global Error Handling Middleware for unexpected errors
app.use((err, req, res, next) => {
    console.error('Unexpected Error:', err);
    res.status(500).json({ message: 'Unexpected server error. Please try again later.' });
});

// Start the app over HTTPS with SSL
https.createServer(sslOptions, app).listen(5000, () => {
    console.log('Secure server running on port 5000 with SSL');
});
