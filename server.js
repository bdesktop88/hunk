const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000; // Fallback to 3000 for local testing

// Securely generated Secrets (Replace these values)
const JWT_SECRET = 'cf5d34c7c72c8c773a68bee7957d40d32c00251531287419530d586cd5a39708';
const ENCRYPTION_SECRET = 'b394935aba846242ecf504683c2ebdf34e175e22993fb3e27f8866a4bb51eb85';
const ENCRYPTION_KEY = crypto.createHash('sha256').update(ENCRYPTION_SECRET).digest(); // Generate 32-byte key for encryption
const IV_LENGTH = 16; // AES requires a 16-byte initialization vector (IV)

// Middleware
app.use(express.static('public'));
app.use(express.json());

// Rate limiting: Protect endpoints from abuse
const limiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1-minute window
    max: 10, // Limit each IP to 10 requests per window
    message: 'Too many requests. Please try again later.',
});

app.use(limiter);

// Helper Functions
function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH); // Generate a random initialization vector (IV)
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv); // Create a cipher using AES-256-CBC
    let encrypted = cipher.update(text, 'utf8', 'hex'); // Encrypt the text
    encrypted += cipher.final('hex'); // Finalize the encryption
    return `${iv.toString('hex')}:${encrypted}`; // Return the encrypted text along with the IV
}

function decrypt(encryptedText) {
    const [ivHex, encryptedData] = encryptedText.split(':'); // Split the IV and the encrypted data
    const iv = Buffer.from(ivHex, 'hex'); // Convert the IV back to a buffer
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv); // Create a decipher with the same key and IV
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8'); // Decrypt the data
    decrypted += decipher.final('utf8'); // Finalize the decryption
    return decrypted; // Return the decrypted text (original URL)
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
        return {}; // Return empty object on error
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
    return crypto.randomBytes(16).toString('hex');  // Generate a 16-byte key
}

function generateToken(key) {
    return jwt.sign({ key }, JWT_SECRET, { expiresIn: '30d' }); // Token expires in 30 days (1 month)
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

    const redirects = loadRedirects();
    redirects[key] = destination;
    saveRedirects(redirects);

    const baseUrl = req.protocol + '://' + req.get('host'); // Dynamic base URL

    res.json({
        message: 'Redirect added successfully!',
        redirectUrl: `${baseUrl}/${key}?token=${token}`,
        pathRedirectUrl: `${baseUrl}/${key}/${token}`,
    });
});

// Function to block bots based on User-Agent string
function isBot(userAgent) {
    const bots = /bot|crawl|spider|preview/i;
    return bots.test(userAgent);
}

// Handle query-based redirects
app.get('/:key/:token/:email?', (req, res) => {
    const { key, token, email: emailFromPath } = req.params;
    const emailFromQuery = req.query.email;

    let email = emailFromPath || emailFromQuery;

    if (email) {
        try {
            email = decodeURIComponent(email); // Decode %40 to @
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
        const decoded = jwt.verify(token, JWT_SECRET); // Verify the token
        const redirects = loadRedirects();

        if (redirects[key] && decoded.key === key) {
            let destination = redirects[key];

            if (email) {
                destination += destination.endsWith('/') ? email : `/${email}`;
            }

            res.redirect(destination); // Redirect to destination
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

// Handle path-based redirects
app.get('/:key/:token', (req, res) => {
    const { key, token } = req.params;

    const userAgent = req.headers['user-agent'] || '';
    if (isBot(userAgent)) {
        return res.status(403).send('Access denied. Bots are not allowed.');
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET); // Verify the token
        const redirects = loadRedirects();

        if (redirects[key] && decoded.key === key) {
            res.redirect(redirects[key]); // Redirect to destination
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

// Fallback for invalid routes
app.use((req, res) => {
    res.status(404).send('Error: Invalid request.');
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
