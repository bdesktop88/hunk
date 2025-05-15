const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET = 'cf5d34c7c72c8c773a68bee7957d40d32c00251531287419530d586cd5a39708';
const ENCRYPTION_SECRET = 'b394935aba846242ecf504683c2ebdf34e175e22993fb3e27f8866a4bb51eb85';
const ENCRYPTION_KEY = crypto.createHash('sha256').update(ENCRYPTION_SECRET).digest();
const IV_LENGTH = 16;

app.use(express.static('public'));
app.use(express.json());

const limiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 10,
    message: 'Too many requests. Please try again later.',
});

app.use(limiter);

function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return `${iv.toString('hex')}:${encrypted}`;
}

function decrypt(encryptedText) {
    const [ivHex, encryptedData] = encryptedText.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

function loadRedirects() {
    try {
        if (!fs.existsSync('redirects.json')) {
            fs.writeFileSync('redirects.json', '{}');
        }
        const data = fs.readFileSync('redirects.json');
        const redirects = JSON.parse(data);
        for (const key in redirects) {
            redirects[key] = decrypt(redirects[key]);
        }
        return redirects;
    } catch (err) {
        console.error('Error loading redirects:', err);
        return {};
    }
}

function saveRedirects(redirects) {
    const encryptedRedirects = {};
    for (const key in redirects) {
        encryptedRedirects[key] = encrypt(redirects[key]);
    }
    fs.writeFileSync('redirects.json', JSON.stringify(encryptedRedirects, null, 2));
}

function generateUniqueKey() {
    return crypto.randomBytes(16).toString('hex');
}

function generateToken(key) {
    return jwt.sign({ key }, JWT_SECRET, { expiresIn: '30d' });
}

app.post('/add-redirect', (req, res) => {
    const { destination } = req.body;

    if (!destination || !/^https?:\/\//.test(destination)) {
        return res.status(400).json({ message: 'Invalid destination URL.' });
    }

    const key = generateUniqueKey();
    const token = generateToken(key);

    const redirects = loadRedirects();
    redirects[key] = destination;
    saveRedirects(redirects);

    const baseUrl = req.protocol + '://' + req.get('host');

    res.json({
        message: 'Redirect added successfully!',
        redirectUrl: `${baseUrl}/${key}?token=${token}`,
        pathRedirectUrl: `${baseUrl}/${key}/${token}`,
    });
});

function isBot(userAgent) {
    const bots = /bot|crawl|spider|preview/i;
    return bots.test(userAgent);
}

app.get('/:key/:token/:email?', (req, res) => {
    const { key, token, email: emailFromPath } = req.params;
    const emailFromQuery = req.query.email;
    let email = emailFromPath || emailFromQuery;

    if (email) {
        try {
            email = decodeURIComponent(email);
        } catch (err) {
            console.error('Error decoding email:', err);
            return res.status(400).send('Invalid email encoding.');
        }
    }

    const userAgent = req.headers['user-agent'] || '';
    if (isBot(userAgent)) {
        return res.status(403).send('Access denied. Bots are not allowed.');
    }

    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).send('Invalid email format.');
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const redirects = loadRedirects();

        if (redirects[key] && decoded.key === key) {
            let destination = redirects[key];

            // ✅ Email appended as query parameter instead of path
            if (email) {
                const separator = destination.includes('?') ? '&' : '?';
                destination += `${separator}email=${encodeURIComponent(email)}`;
            }

            res.redirect(destination);
        } else {
            res.status(404).send('Invalid or expired redirect.');
        }
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            console.error('JWT Token Expired:', err);
            return res.status(403).send('Token has expired.');
        }

        console.error('Error during redirection:', err);
        res.status(403).send('Invalid or expired token.');
    }
});

app.get('/:key/:token', (req, res) => {
    const { key, token } = req.params;

    const userAgent = req.headers['user-agent'] || '';
    if (isBot(userAgent)) {
        return res.status(403).send('Access denied. Bots are not allowed.');
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const redirects = loadRedirects();

        if (redirects[key] && decoded.key === key) {
            res.redirect(redirects[key]);
        } else {
            res.status(404).send('Invalid or expired redirect.');
        }
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            console.error('JWT Token Expired:', err);
            return res.status(403).send('Token has expired.');
        }

        console.error('Error during redirection:', err);
        res.status(403).send('Invalid or expired token.');
    }
});

app.use((req, res) => {
    res.status(404).send('Error: Invalid request.');
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
