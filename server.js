const express = require('express');
const bodyParser = require('body-parser');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { addRedirect, getRedirect } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// Secret key for JWT token generation
const JWT_SECRET = process.env.JWT_SECRET || 'your-very-secure-secret';

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Rate limit
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
});
app.use(limiter);

// Serve homepage
app.get('/', (req, res) => {
  res.send('Redirect service running.');
});

// Generate token
function generateToken(key) {
  return jwt.sign({ key }, JWT_SECRET, { expiresIn: '1d' });
}

function generateUniqueKey() {
  return uuidv4().split('-')[0];
}

// Add redirect
app.post('/add-redirect', (req, res) => {
  const { destination } = req.body;

  if (!destination || !/^https?:\/\//.test(destination)) {
    return res.status(400).json({ message: 'Invalid destination URL.' });
  }

  const key = generateUniqueKey();
  const token = generateToken(key);

  addRedirect(key, destination, token, (err) => {
    if (err) {
      console.error('DB insert error:', err);
      return res.status(500).json({ message: 'Internal error storing redirect.' });
    }

    const baseUrl = req.protocol + '://' + req.get('host');

    res.json({
      message: 'Redirect added successfully!',
      redirectUrl: `${baseUrl}/${key}?token=${token}`,
      pathRedirectUrl: `${baseUrl}/${key}/${token}`,
    });
  });
});

// Redirect handler (query token)
app.get('/:key', (req, res) => {
  const { key } = req.params;
  const { token, email } = req.query;

  if (!token) return res.status(400).send('Token required.');

  try {
    jwt.verify(token, JWT_SECRET);

    getRedirect(key, (err, redirectData) => {
      if (err || !redirectData) return res.status(404).send('Redirect not found.');
      if (redirectData.token !== token) return res.status(403).send('Invalid token.');

      let destination = redirectData.destination;
      if (email) {
        destination = destination.endsWith('/')
          ? destination + email
          : destination + '/' + email;
      }

      return res.redirect(destination);
    });
  } catch (err) {
    return res.status(403).send('Invalid or expired token.');
  }
});

// Redirect handler (path token)
app.get('/:key/:token', (req, res) => {
  const { key, token } = req.params;
  const { email } = req.query;

  try {
    jwt.verify(token, JWT_SECRET);

    getRedirect(key, (err, redirectData) => {
      if (err || !redirectData) return res.status(404).send('Redirect not found.');
      if (redirectData.token !== token) return res.status(403).send('Invalid token.');

      let destination = redirectData.destination;
      if (email) {
        destination = destination.endsWith('/')
          ? destination + email
          : destination + '/' + email;
      }

      return res.redirect(destination);
    });
  } catch (err) {
    return res.status(403).send('Invalid or expired token.');
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
