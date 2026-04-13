const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'app.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    color TEXT DEFAULT '#1a4a7a',
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS lists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category_id INTEGER REFERENCES categories(id),
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    event_date TEXT NOT NULL,
    slots INTEGER NOT NULL DEFAULT 10,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS signups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    list_id INTEGER NOT NULL REFERENCES lists(id),
    slot_number INTEGER NOT NULL,
    nickname TEXT NOT NULL,
    signed_at TEXT DEFAULT (datetime('now')),
    UNIQUE(list_id, slot_number)
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

db.prepare("DELETE FROM sessions WHERE created_at < datetime('now', '-24 hours')").run();

app.use(express.json());

// ── Auth ───────────────────────────────────────────────────────────────────

function getToken(req) {
  const cookie = req.headers.cookie || '';
  const m = cookie.match(/(?:^|;\s*)auth_token=([^;]+)/);
  return m ? m[1] : null;
}
function isAuthenticated(req) {
  const token = getToken(req);
  if (!token) return false;
  return !!db.prepare('SELECT token FROM sessions WHERE token = ?').get(token);
}
function requireAuth(req, res, next) {
  if (!isAuthenticated(req)) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

app.get('/api/auth/status', (req, res) => res.json({ authenticated: isAuthenticated(req) }));

app.post('/api/auth/login', (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'No password provided' });
  const given = crypto.createHash('sha256').update(password).digest('hex');
  const expected = crypto.createHash('sha256').update(ADMIN_PASSWORD).digest('hex');
  if (given !== expected) return res.status(401).json({ error: 'Wrong password' });
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions (token) VALUES (?)').run(token);
  res.setHeader('Set-Cookie', `auth_token=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400`);
  res.json({ ok: true });
});

app.post('/api/auth/logout', (req, res) => {
  const token = getToken(req);
  if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  res.setHeader('Set-Cookie', 'auth_token=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  res.json({ ok: true });
});

// ── Static ─────────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ── Categories ─────────────────────────────────────────────────────────────

app.get('/api/categories', (_req, res) => {
  const cats = db.prepare(`
    SELECT c.*,
      COUNT(DISTINCT l.id) AS list_count,
      COALESCE(SUM(s.cnt),0) AS total_signups,
      COALESCE(SUM(l.slots),0) AS total_slots
    FROM categories c
    LEFT JOIN lists l ON l.category_id = c.id
    LEFT JOIN (SELECT list_id, COUNT(*) AS cnt FROM signups GROUP BY list_id) s ON s.list_id = l.id
    GROUP BY c.id
    ORDER BY c.created_at ASC
  `).all();
  res.json(cats);
});

app.get('/api/categories/:id', (req, res) => {
  const cat = db.prepare('SELECT * FROM categories WHERE id = ?').get(req.params.id);
  if (!cat) return res.status(404).json({ error: 'Not found' });
  const lists = db.prepare(`
    SELECT l.*, COUNT(s.id) AS filled
    FROM lists l LEFT JOIN signups s ON s.list_id = l.id
    WHERE l.category_id = ?
    GROUP BY l.id ORDER BY l.event_date ASC
  `).all(req.params.id);
  res.json({ ...cat, lists });
});

app.post('/api/categories', requireAuth, (req, res) => {
  const { name, description, color } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Name required' });
  const r = db.prepare('INSERT INTO categories (name, description, color) VALUES (?,?,?)')
    .run(name.trim(), description?.trim() || '', color || '#1a4a7a');
  res.json({ id: r.lastInsertRowid });
});

app.put('/api/categories/:id', requireAuth, (req, res) => {
  const { name, description, color } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Name required' });
  db.prepare('UPDATE categories SET name=?, description=?, color=? WHERE id=?')
    .run(name.trim(), description?.trim() || '', color || '#1a4a7a', req.params.id);
  res.json({ ok: true });
});

app.delete('/api/categories/:id', requireAuth, (req, res) => {
  // cascade: delete signups → lists → category
  const lists = db.prepare('SELECT id FROM lists WHERE category_id = ?').all(req.params.id);
  for (const l of lists) {
    db.prepare('DELETE FROM signups WHERE list_id = ?').run(l.id);
  }
  db.prepare('DELETE FROM lists WHERE category_id = ?').run(req.params.id);
  db.prepare('DELETE FROM categories WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ── Lists ──────────────────────────────────────────────────────────────────

app.get('/api/lists/:id', (req, res) => {
  const list = db.prepare('SELECT * FROM lists WHERE id = ?').get(req.params.id);
  if (!list) return res.status(404).json({ error: 'Not found' });
  const signups = db.prepare('SELECT * FROM signups WHERE list_id = ? ORDER BY slot_number').all(req.params.id);
  res.json({ ...list, signups });
});

app.post('/api/lists', requireAuth, (req, res) => {
  const { category_id, title, description, event_date, slots } = req.body;
  if (!title?.trim() || !event_date || !slots || !category_id)
    return res.status(400).json({ error: 'Missing fields' });
  const n = Math.min(Math.max(parseInt(slots) || 1, 1), 500);
  const r = db.prepare('INSERT INTO lists (category_id, title, description, event_date, slots) VALUES (?,?,?,?,?)')
    .run(category_id, title.trim(), description?.trim() || '', event_date, n);
  res.json({ id: r.lastInsertRowid });
});

app.delete('/api/lists/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM signups WHERE list_id = ?').run(req.params.id);
  db.prepare('DELETE FROM lists WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ── Signups ────────────────────────────────────────────────────────────────

app.post('/api/lists/:id/signup', (req, res) => {
  const { slot_number, nickname } = req.body;
  if (!nickname?.trim() || slot_number == null) return res.status(400).json({ error: 'Missing fields' });
  const list = db.prepare('SELECT * FROM lists WHERE id = ?').get(req.params.id);
  if (!list) return res.status(404).json({ error: 'List not found' });
  if (slot_number < 1 || slot_number > list.slots) return res.status(400).json({ error: 'Invalid slot' });
  try {
    db.prepare('INSERT INTO signups (list_id, slot_number, nickname) VALUES (?,?,?)')
      .run(req.params.id, slot_number, nickname.trim());
    res.json({ ok: true });
  } catch {
    res.status(409).json({ error: 'Slot already taken' });
  }
});

app.delete('/api/lists/:id/signup/:slot', requireAuth, (req, res) => {
  db.prepare('DELETE FROM signups WHERE list_id = ? AND slot_number = ?').run(req.params.id, req.params.slot);
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`✔ Listify running on port ${PORT}`));
