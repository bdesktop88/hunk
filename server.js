const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const ENCRYPTION_SECRET = 'b394935aba846242ecf504683c2ebdf34e175e22993fb3e27f8866a4bb51eb85';
const ENCRYPTION_KEY = crypto.createHash('sha256').update(ENCRYPTION_SECRET).digest();
const IV_LENGTH = 16;

const RECAPTCHA_SECRET = '6LcBjT4rAAAAANCGmLJtAqAiWaK2mxTENg93TI86'; // 🔐 Replace with your actual secret

app.use(express.static('public'));
app.use(express.json());

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: 'Too many requests. Please try again later.',
});
app.use(limiter);

// Encryption
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

// Redirects file
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
  const encrypted = {};
  for (const key in redirects) {
    encrypted[key] = encrypt(redirects[key]);
  }
  fs.writeFileSync('redirects.json', JSON.stringify(encrypted, null, 2));
}

function generateUniqueKey() {
  return crypto.randomBytes(16).toString('hex');
}

app.post('/add-redirect', (req, res) => {
  const { destination } = req.body;
  if (!destination || !/^https?:\/\//.test(destination)) {
    return res.status(400).json({ message: 'Invalid destination URL.' });
  }

  const key = generateUniqueKey();
  const redirects = loadRedirects();
  redirects[key] = destination;
  saveRedirects(redirects);

  const baseUrl = req.protocol + '://' + req.get('host');
  res.json({
    message: 'Redirect added successfully!',
    redirectUrl: `${baseUrl}/${key}`,
  });
});

app.get('/:key', (req, res) => {
  const { key } = req.params;
  const redirects = loadRedirects();
  if (!redirects[key]) return res.status(404).send('Redirect not found.');

  res.sendFile(path.join(__dirname, 'public', 'redirect.html'));
});

app.get('/verify-redirect', async (req, res) => {
  const { key, token, email } = req.query;
  const redirects = loadRedirects();

  if (!redirects[key] || !token) return res.status(400).send('Invalid request.');

  try {
    const response = await axios.post(`https://www.google.com/recaptcha/api/siteverify`, null, {
      params: {
        secret: RECAPTCHA_SECRET,
        response: token,
      },
    });

    const data = response.data;
    if (!data.success || data.score < 0.5 || data.action !== 'redirect') {
      return res.status(403).send('reCAPTCHA verification failed.');
    }

    let destination = redirects[key];
    if (email && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      const separator = destination.includes('?') ? '&' : '?';
      destination += `${separator}email=${encodeURIComponent(email)}`;
    }

    res.redirect(destination);
  } catch (error) {
    console.error('reCAPTCHA error:', error.message);
    res.status(500).send('Server error during verification.');
  }
});

app.use((req, res) => {
  res.status(404).send('Error: Invalid request.');
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
