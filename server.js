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
    event_time TEXT DEFAULT '',
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
  CREATE TABLE IF NOT EXISTS delete_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    list_id INTEGER NOT NULL REFERENCES lists(id),
    slot_number INTEGER NOT NULL,
    nickname TEXT NOT NULL,
    reason TEXT DEFAULT '',
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS marketplace_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nickname TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    image_data TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

// Migrations for existing DBs
try { db.prepare("ALTER TABLE lists ADD COLUMN event_time TEXT DEFAULT ''").run(); } catch(e) {}
try { db.prepare("ALTER TABLE lists ADD COLUMN channel INTEGER DEFAULT 1").run(); } catch(e) {}
try { db.prepare("ALTER TABLE marketplace_items ADD COLUMN image_data TEXT DEFAULT ''").run(); } catch(e) {}

db.prepare("DELETE FROM sessions WHERE created_at < datetime('now', '-24 hours')").run();

// Increase JSON body limit for base64 image uploads (up to 8MB)
app.use(express.json({ limit: '8mb' }));

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
    GROUP BY l.id ORDER BY l.event_date ASC, l.event_time ASC
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
  const lists = db.prepare('SELECT id FROM lists WHERE category_id = ?').all(req.params.id);
  for (const l of lists) {
    db.prepare('DELETE FROM signups WHERE list_id = ?').run(l.id);
  }
  db.prepare('DELETE FROM lists WHERE category_id = ?').run(req.params.id);
  db.prepare('DELETE FROM categories WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ── Lists ──────────────────────────────────────────────────────────────────

app.get('/api/lists/upcoming', (_req, res) => {
  const lists = db.prepare(`
    SELECT l.*, c.name as category_name, c.color as category_color,
      COUNT(s.id) AS filled
    FROM lists l
    JOIN categories c ON c.id = l.category_id
    LEFT JOIN signups s ON s.list_id = l.id
    WHERE l.event_date >= date('now')
    GROUP BY l.id
    ORDER BY l.event_date ASC, COALESCE(NULLIF(l.event_time,''), '99:99') ASC
    LIMIT 20
  `).all();

  const result = lists.map(l => {
    const signups = db.prepare('SELECT * FROM signups WHERE list_id = ? ORDER BY slot_number').all(l.id);
    return { ...l, signups };
  });

  res.json(result);
});

app.get('/api/lists/:id', (req, res) => {
  const list = db.prepare('SELECT * FROM lists WHERE id = ?').get(req.params.id);
  if (!list) return res.status(404).json({ error: 'Not found' });
  const signups = db.prepare('SELECT * FROM signups WHERE list_id = ? ORDER BY slot_number').all(req.params.id);
  res.json({ ...list, signups });
});

app.post('/api/lists', (req, res) => {
  const { category_id, title, description, event_date, event_time, slots, channel } = req.body;
  if (!title?.trim() || !event_date || !slots || !category_id)
    return res.status(400).json({ error: 'Missing fields' });
  const n = Math.min(Math.max(parseInt(slots) || 1, 1), 500);
  const ch = Math.min(Math.max(parseInt(channel) || 1, 1), 7);
  const r = db.prepare('INSERT INTO lists (category_id, title, description, event_date, event_time, slots, channel) VALUES (?,?,?,?,?,?,?)')
    .run(category_id, title.trim(), description?.trim() || '', event_date, event_time?.trim() || '', n, ch);
  res.json({ id: r.lastInsertRowid });
});

app.put('/api/lists/:id', (req, res) => {
  const { title, description, event_date, event_time, slots, channel } = req.body;
  if (!title?.trim() || !event_date || !slots)
    return res.status(400).json({ error: 'Missing fields' });
  const n = Math.min(Math.max(parseInt(slots) || 1, 1), 500);
  const ch = Math.min(Math.max(parseInt(channel) || 1, 1), 7);
  db.prepare('UPDATE lists SET title=?, description=?, event_date=?, event_time=?, slots=?, channel=? WHERE id=?')
    .run(title.trim(), description?.trim() || '', event_date, event_time?.trim() || '', n, ch, req.params.id);
  res.json({ ok: true });
});

app.delete('/api/lists/:id', (req, res) => {
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
  db.prepare('DELETE FROM delete_requests WHERE list_id = ? AND slot_number = ? AND status = ?').run(req.params.id, req.params.slot, 'pending');
  res.json({ ok: true });
});

// ── Delete Requests ────────────────────────────────────────────────────────

app.get('/api/delete-requests', requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT dr.*, l.title as list_title, l.event_date
    FROM delete_requests dr
    JOIN lists l ON l.id = dr.list_id
    WHERE dr.status = 'pending'
    ORDER BY dr.created_at ASC
  `).all();
  res.json(rows);
});

app.get('/api/delete-requests/count', (req, res) => {
  const row = db.prepare("SELECT COUNT(*) as count FROM delete_requests WHERE status = 'pending'").get();
  res.json({ count: row.count });
});

app.post('/api/lists/:id/signup/:slot/request-delete', (req, res) => {
  const { nickname, reason } = req.body;
  if (!nickname?.trim()) return res.status(400).json({ error: 'Nickname required' });
  const signup = db.prepare('SELECT * FROM signups WHERE list_id = ? AND slot_number = ?').get(req.params.id, req.params.slot);
  if (!signup) return res.status(404).json({ error: 'Slot not found' });
  if (signup.nickname !== nickname.trim()) return res.status(403).json({ error: 'Name does not match the slot' });
  const existing = db.prepare("SELECT id FROM delete_requests WHERE list_id = ? AND slot_number = ? AND status = 'pending'").get(req.params.id, req.params.slot);
  if (existing) return res.status(409).json({ error: 'A request is already pending for this slot' });
  db.prepare('INSERT INTO delete_requests (list_id, slot_number, nickname, reason) VALUES (?,?,?,?)')
    .run(req.params.id, req.params.slot, nickname.trim(), reason?.trim() || '');
  res.json({ ok: true });
});

app.post('/api/delete-requests/:id/accept', requireAuth, (req, res) => {
  const req2 = db.prepare('SELECT * FROM delete_requests WHERE id = ?').get(req.params.id);
  if (!req2) return res.status(404).json({ error: 'Request not found' });
  db.prepare('DELETE FROM signups WHERE list_id = ? AND slot_number = ?').run(req2.list_id, req2.slot_number);
  db.prepare("UPDATE delete_requests SET status = 'accepted' WHERE id = ?").run(req.params.id);
  res.json({ ok: true });
});

app.post('/api/delete-requests/:id/deny', requireAuth, (req, res) => {
  db.prepare("UPDATE delete_requests SET status = 'denied' WHERE id = ?").run(req.params.id);
  res.json({ ok: true });
});

// ── Marketplace ────────────────────────────────────────────────────────────

// Get all marketplace items (no image data in list, for performance)
app.get('/api/marketplace', (_req, res) => {
  const items = db.prepare('SELECT id, nickname, title, description, created_at FROM marketplace_items ORDER BY created_at DESC').all();
  res.json(items);
});

// Get single marketplace item with image
app.get('/api/marketplace/:id', (req, res) => {
  const item = db.prepare('SELECT * FROM marketplace_items WHERE id = ?').get(req.params.id);
  if (!item) return res.status(404).json({ error: 'Not found' });
  res.json(item);
});

// Create marketplace item (anyone)
app.post('/api/marketplace', (req, res) => {
  const { nickname, title, description, image_data } = req.body;
  if (!nickname?.trim() || !title?.trim() || !description?.trim())
    return res.status(400).json({ error: 'Nickname, title and description are required' });
  const r = db.prepare('INSERT INTO marketplace_items (nickname, title, description, image_data) VALUES (?,?,?,?)')
    .run(nickname.trim(), title.trim(), description.trim(), image_data?.trim() || '');
  res.json({ id: r.lastInsertRowid });
});

// Delete marketplace item (admin only)
app.delete('/api/marketplace/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM marketplace_items WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`✔ Chronomancer's Book running on port ${PORT}`));