const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const path = require('path');
const initRedirects = () => {
  const source = path.join(__dirname, 'redirects.json');
  const destination = path.join('/tmp', 'redirects.json');
  if (fs.existsSync(source) && !fs.existsSync(destination)) {
    fs.copyFileSync(source, destination);
  }
};
initRedirects();
const app = express();
const PORT = process.env.PORT || 3000;

// Replace this with your actual reCAPTCHA secret key
const RECAPTCHA_SECRET = '6LcBjT4rAAAAANCGmLJtAqAiWaK2mxTENg93TI86';

app.use(express.static('public'));
app.use(express.json());

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: 'Too many requests. Please try again later.',
});
app.use(limiter);

// File operations
function loadRedirects() {
  try {
    const redirectsFilePath = path.join('/tmp', 'redirects.json');
    if (!fs.existsSync(redirectsFilePath)) {
      fs.writeFileSync(redirectsFilePath, '{}');
    }
    const data = fs.readFileSync(redirectsFilePath, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    console.error('Error loading redirects:', err);
    return {};
  }
}

function saveRedirects(redirects) {
  try {
    const redirectsFilePath = path.join('/tmp', 'redirects.json');
    fs.writeFileSync(redirectsFilePath, JSON.stringify(redirects, null, 2));
  } catch (err) {
    console.error('Error saving redirects:', err);
  }
}

function generateUniqueKey() {
  return crypto.randomBytes(16).toString('hex');
}

// Create new redirect
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

// Serve reCAPTCHA page
app.get('/:key', (req, res) => {
  const { key } = req.params;
  const redirects = loadRedirects();
  console.log('Trying redirect key:', key);
  console.log('Redirects keys:', Object.keys(redirects));
  if (!redirects[key]) return res.status(404).send('Redirect not found.');

  res.sendFile(path.join(__dirname, 'public', 'redirect.html'));
});



// Verify reCAPTCHA and redirect
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
