const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const db = require('./db'); // Use SQLite DB

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration
const JWT_SECRET = 'your_strong_secret_key';
const ENCRYPTION_KEY = crypto.createHash('sha256').update(JWT_SECRET).digest();
const IV_LENGTH = 16;

// Middleware
app.use(express.static('public'));
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    message: 'Too many requests. Please try again later.',
});
app.use(limiter);

// Helper functions
function generateUniqueKey() {
    return crypto.randomBytes(8).toString('hex');
}

function generateToken(key) {
    return jwt.sign({ key }, JWT_SECRET);
}

// POST /add-redirect (use SQLite)
app.post('/add-redirect', (req, res) => {
    const { destination } = req.body;

    if (!destination || !/^https?:\/\//.test(destination)) {
        return res.status(400).json({ message: 'Invalid destination URL.' });
    }

    const key = generateUniqueKey();
    const token = generateToken(key);

    db.addRedirect(key, destination, token, (err) => {
        if (err) {
            console.error('DB error:', err);
            return res.status(500).json({ message: 'Failed to save redirect.' });
        }

        const baseUrl = req.protocol + '://' + req.get('host');
        res.json({
            message: 'Redirect added successfully!',
            redirectUrl: `${baseUrl}/${key}?token=${token}`,
            pathRedirectUrl: `${baseUrl}/${key}/${token}`,
        });
    });
});

// GET /:key/:token (use SQLite)
app.get('/:key/:token', (req, res) => {
    const { key, token } = req.params;
    const email = req.query.email || null;

    const userAgent = req.headers['user-agent'] || '';
    if (/bot|crawl|spider|preview/i.test(userAgent)) {
        return res.status(403).send('Access denied.');
    }

    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).send('Invalid email format.');
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        db.getRedirect(key, (err, row) => {
            if (err || !row) {
                return res.status(404).send('Redirect not found.');
            }

            if (row.token !== token) {
                return res.status(403).send('Invalid token.');
            }

            let destination = row.destination;
            if (email) {
                destination = destination.endsWith('/') ? destination + email : `${destination}/${email}`;
            }

            res.redirect(destination);
        });
    } catch (err) {
        res.status(403).send('Invalid or expired token.');
    }
});

// 404 fallback
app.use((req, res) => {
    res.status(404).send('Error: Invalid request.');
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
