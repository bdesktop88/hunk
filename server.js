const express = require('express');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const app = express();
const PORT = process.env.PORT || 3000;

app.get('/verify-redirect', async (req, res) => {
  const key = req.query.key;
  const token = req.query.token;

  console.log('Trying redirect key:', key);

  const redirects = loadRedirects();
  console.log('Redirects keys:', Object.keys(redirects));

  if (!redirects[key]) {
    console.log('Redirect key NOT found!');
    return res.status(404).send('Redirect not found.');
  }

  try {
    const secretKey = process.env.RECAPTCHA_SECRET_KEY || '6LcBjT4rAAAAANCGmLJtAqAiWaK2mxTENg93TI86';
    const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${token}`;
    const response = await axios.post(verifyUrl);

    if (response.data.success && response.data.score >= 0.5) {
      res.redirect(redirects[key]);
    } else {
      res.status(403).send('reCAPTCHA verification failed');
    }
  } catch (error) {
    console.error('reCAPTCHA verification error:', error);
    res.status(500).send('Internal Server Error');
  }
});

function loadRedirects() {
  try {
    const redirectsFilePath = path.join(__dirname, 'redirects.json');
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

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
