const Database = require('better-sqlite3');
const path = '/tmp/redirects.db'; // Writable path on Render

const db = new Database(path);

// Create table if it doesn't exist
db.exec(`
  CREATE TABLE IF NOT EXISTS redirects (
    key TEXT PRIMARY KEY,
    destination TEXT NOT NULL,
    token TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

/**
 * Add a new redirect record
 * @param {string} key - unique redirect key
 * @param {string} destination - URL to redirect to
 * @param {string} token - JWT token associated with this redirect
 */
function addRedirect(key, destination, token) {
  const stmt = db.prepare('INSERT INTO redirects (key, destination, token) VALUES (?, ?, ?)');
  stmt.run(key, destination, token);
}

/**
 * Retrieve redirect info by key
 * @param {string} key
 * @returns {object|null} redirect row or null if not found
 */
function getRedirect(key) {
  const stmt = db.prepare('SELECT * FROM redirects WHERE key = ?');
  return stmt.get(key);
}

module.exports = { addRedirect, getRedirect };
