const sqlite3 = require('sqlite3').verbose();
const path = '/tmp/redirects.db'; // Use /tmp for Render compatibility

const db = new sqlite3.Database(path, (err) => {
  if (err) {
    console.error('Failed to open database:', err);
  } else {
    console.log('Connected to SQLite database at', path);
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
      console.log('Redirects table ready');
    }
  });
});

function addRedirect(key, destination, token, callback) {
  const stmt = db.prepare('INSERT INTO redirects (key, destination, token) VALUES (?, ?, ?)');
  stmt.run(key, destination, token, function(err) {
    if (err) {
      console.error('Insert error:', err);
    } else {
      console.log('Redirect saved:', { key, destination, token });
    }
    callback(err);
  });
  stmt.finalize();
}

function getRedirect(key, callback) {
  db.get('SELECT * FROM redirects WHERE key = ?', [key], callback);
}

module.exports = { addRedirect, getRedirect };
