const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { addRedirect, getRedirect } = require('./db'); // Import DB functions

const app = express();
const PORT = process.env.PORT || 3000;

// Config
const JWT_SECRET = 'your_strong_secret_key'; // Replace with a strong secret key

// Middleware
app.use(express.static('public'));
app.use(express.json());

// Rate limiting: Protect endpoints from abuse
const limiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1-minute window
    max: 10,
    message: 'Too many requests. Please try again later.',
});
app.use(limiter);

// Helper functions
function generateUniqueKey() {
    return crypto.randomBytes(8).toString('hex');
}

function generateToken(key) {
    return jwt.sign({ key }, JWT_SECRET); // No expiration for now
}

// Routes

// Add a new redirect
app.post('/add-redirect', (req, res) => {
    const { destination } = req.body;

    if (!destination || !/^https?:\/\//.test(destination)) {
        return res.status(400).json({ message: 'Invalid destination URL.' });
    }

    const key = generateUniqueKey();
    const token = generateToken(key);

    addRedirect(key, destination, token);

    const baseUrl = req.protocol + '://' + req.get('host');

    res.json({
        message: 'Redirect added successfully!',
        redirectUrl: `${baseUrl}/${key}?token=${token}`,
        pathRedirectUrl: `${baseUrl}/${key}/${token}`,
    });
});

// Handle redirects with optional email param
app.get('/:key/:token/:email?', (req, res) => {
    const { key, token, email: emailFromPath } = req.params;
    const emailFromQuery = req.query.email;

    let email = emailFromPath || emailFromQuery;

    if (email) {
        try {
            email = decodeURIComponent(email);
        } catch (err) {
            return res.status(400).send('Invalid email encoding.');
        }
    }

    const userAgent = req.headers['user-agent'] || '';
    if (/bot|crawl|spider|preview/i.test(userAgent)) {
        return res.status(403).send('Access denied.');
    }

    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).send('Invalid email format.');
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.key !== key) {
            return res.status(403).send('Invalid token.');
        }

        const redirectData = getRedirect(key);

        if (redirectData && redirectData.token === token) {
            let destination = redirectData.destination;

            if (email) {
                destination = destination.endsWith('/') ? destination + email : destination + '/' + email;
            }

            return res.redirect(destination);
        } else {
            return res.status(404).send('Redirect not found.');
        }
    } catch {
        return res.status(403).send('Invalid or expired token.');
    }
});

// Handle redirects without email param
app.get('/:key/:token', (req, res) => {
    const { key, token } = req.params;

    const userAgent = req.headers['user-agent'] || '';
    if (/bot|crawl|spider|preview/i.test(userAgent)) {
        return res.status(403).send('Access denied.');
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.key !== key) {
            return res.status(403).send('Invalid token.');
        }

        const redirectData = getRedirect(key);

        if (redirectData && redirectData.token === token) {
            return res.redirect(redirectData.destination);
        } else {
            return res.status(404).send('Redirect not found.');
        }
    } catch {
        return res.status(403).send('Invalid or expired token.');
    }
});

// Fallback for invalid routes
app.use((req, res) => {
    res.status(404).send('Error: Invalid request.');
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
