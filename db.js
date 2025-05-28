// db.js
const sqlite3 = require('sqlite3').verbose();
const path = '/tmp/redirects.db'; // Use /tmp for Render compatibility

const db = new sqlite3.Database(path);

// Create table on startup
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS redirects (
      key TEXT PRIMARY KEY,
      destination TEXT NOT NULL,
      token TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

function addRedirect(key, destination, token, callback) {
  const stmt = db.prepare('INSERT INTO redirects (key, destination, token) VALUES (?, ?, ?)');
  stmt.run(key, destination, token, callback);
  stmt.finalize();
}

function getRedirect(key, callback) {
  db.get('SELECT * FROM redirects WHERE key = ?', [key], callback);
}

module.exports = { addRedirect, getRedirect };
