const sqlite3 = require('sqlite3').verbose();
const path = '/tmp/redirects.db'; // Use /tmp for Render compatibility

console.log('Opening SQLite DB at:', path);
const db = new sqlite3.Database(path, (err) => {
  if (err) {
    console.error('Failed to open DB:', err);
  } else {
    console.log('SQLite DB opened successfully.');
  }
});

// Create table on startup
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS redirects (
      key TEXT PRIMARY KEY,
      destination TEXT NOT NULL,
      token TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err) {
      console.error('Failed to create table:', err);
    } else {
      console.log('Table redirects ready');
    }
  });
});

function addRedirect(key, destination, token, callback) {
  const stmt = db.prepare('INSERT INTO redirects (key, destination, token) VALUES (?, ?, ?)');
  stmt.run(key, destination, token, function(err) {
    if (err) {
      console.error('SQLite INSERT error:', err);
    } else {
      console.log(`Inserted redirect: key=${key}, destination=${destination}`);
    }
    if (callback) callback(err);
  });
  stmt.finalize();
}

function getRedirect(key, callback) {
  db.get('SELECT * FROM redirects WHERE key = ?', [key], (err, row) => {
    if (err) {
      console.error('SQLite SELECT error:', err);
    }
    callback(err, row);
  });
}

module.exports = { addRedirect, getRedirect };
