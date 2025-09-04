const path = require('path');
const Database = require('better-sqlite3');

const db = new Database(path.join(__dirname, 'data.sqlite'));
db.pragma('journal_mode = WAL');

// Create tables
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT DEFAULT 'user',
  active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vouchers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  company TEXT NOT NULL,
  pay_to TEXT NOT NULL,
  date TEXT NOT NULL,          -- ISO YYYY-MM-DD
  total REAL NOT NULL,
  created_by INTEGER,
  deleted INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS voucher_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  voucher_id INTEGER NOT NULL,
  category TEXT NOT NULL,
  description TEXT NOT NULL,
  amount REAL NOT NULL,
  FOREIGN KEY(voucher_id) REFERENCES vouchers(id)
);

-- Companies master
CREATE TABLE IF NOT EXISTS companies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  logo_name TEXT,                         -- e.g. "Nana.png"
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_companies_name ON companies(name);


-- Activity log for dashboard
CREATE TABLE IF NOT EXISTS activity_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT NOT NULL,             -- 'create' | 'delete' | 'hard_delete'
  voucher_id INTEGER,
  note TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(voucher_id) REFERENCES vouchers(id)
);
`);

// Migration for older DBs (add deleted if missing)
const cols = db.prepare("PRAGMA table_info('vouchers')").all();
if (!cols.some(c => c.name === 'deleted')) {
  db.prepare('ALTER TABLE vouchers ADD COLUMN deleted INTEGER DEFAULT 0').run();
  console.log('DB migration: added vouchers.deleted column');
}

// Ensure users.avatar_name exists
const userCols = db.prepare("PRAGMA table_info('users')").all();
if (!userCols.some(c => c.name === 'avatar_name')) {
  db.prepare('ALTER TABLE users ADD COLUMN avatar_name TEXT').run();
  console.log('DB migration: added users.avatar_name column');
}

// Indexes
db.exec(`
CREATE INDEX IF NOT EXISTS idx_vouchers_cb  ON vouchers(created_by);
CREATE INDEX IF NOT EXISTS idx_vouchers_del ON vouchers(deleted);
CREATE INDEX IF NOT EXISTS idx_companies_name ON companies(name);
CREATE INDEX IF NOT EXISTS idx_log_time ON activity_log(created_at);
`);

module.exports = db;