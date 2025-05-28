// server.js
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { addRedirect, getRedirect } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration
const JWT_SECRET = 'your_strong_secret_key'; // Replace with secure secret
const ENCRYPTION_KEY = crypto.createHash('sha256').update(JWT_SECRET).digest();
const IV_LENGTH = 16;

// Middleware
app.use(express.static('public'));
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 10,
  message: 'Too many requests. Please try again later.',
});

app.use(limiter);

// Helper Functions
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

function generateUniqueKey() {
  return crypto.randomBytes(8).toString('hex');
}

function generateToken(key) {
  return jwt.sign({ key }, JWT_SECRET); // No expiration
}

// Routes

// Add new redirect
app.post('/add-redirect', (req, res) => {
  const { destination } = req.body;

  if (!destination || !/^https?:\/\//.test(destination)) {
    return res.status(400).json({ message: 'Invalid destination URL.' });
  }

  const key = generateUniqueKey();
  const token = generateToken(key);

  addRedirect(key, destination, token, (err) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ message: 'Database error.' });
    }

    const baseUrl = req.protocol + '://' + req.get('host');

    res.json({
      message: 'Redirect added successfully!',
      redirectUrl: `${baseUrl}/${key}?token=${token}`,
      pathRedirectUrl: `${baseUrl}/${key}/${token}`,
    });
  });
});

// Handle redirects
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

    getRedirect(key, (err, row) => {
      if (err || !row || row.token !== token || decoded.key !== key) {
        return res.status(404).send('Invalid or expired redirect.');
      }

      let destination = row.destination;
      if (email) {
        destination += destination.endsWith('/') ? email : `/${email}`;
      }

      return res.redirect(destination);
    });
  } catch (err) {
    return res.status(403).send('Invalid or expired token.');
  }
});

// Fallback
app.use((req, res) => {
  res.status(404).send('Error: Invalid request.');
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at https://localhost:${PORT}`);
});
