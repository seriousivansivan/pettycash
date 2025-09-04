const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const ejs = require('ejs');
const puppeteer = require('puppeteer');
const bcrypt = require('bcryptjs');
const db = require('./db');
const multer = require('multer');
const app = express();
const PORT = process.env.PORT || 3000;

// ---------- helpers ----------
const TH_TZ = 'Asia/Bangkok';

function iso(date) {
  if (!date) return new Date().toISOString().slice(0, 10);
  const d = new Date(date);
  return new Date(d.getTime() - (d.getTimezoneOffset() * 60000)).toISOString().slice(0, 10);
}
function displayDate(isoStr) {
  const d = new Date(isoStr);
  return d.toLocaleDateString('en-GB', { timeZone: TH_TZ });
}
function toBangkokDateTime(utcSqlDateTime) {
  const iso = utcSqlDateTime ? utcSqlDateTime.replace(' ', 'T') + 'Z' : new Date().toISOString();
  return new Date(iso).toLocaleString('en-GB', { timeZone: TH_TZ });
}
// additional 
function fileNameForCompany(name) {
  const base = String(name || '').trim().replace(/[\\/:*?"<>|]/g, '_');
  return `${base}.png`;
}
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, path.join(__dirname, 'logos')),
    filename: (req, file, cb) => cb(null, fileNameForCompany(req.body.name || 'company'))
  }),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    if (file.mimetype !== 'image/png') return cb(new Error('PNG only'));
    cb(null, true);
  }
});



app.get('/profile', requireAuth, (req, res) => {
  const row = db.prepare('SELECT username, role, avatar_name FROM users WHERE id = ?').get(req.session.user.id);
  const u = {
    id: req.session.user.id,
    name: row?.username || req.session.user.name,
    role: row?.role || req.session.user.role,
    avatar_name: row?.avatar_name || null
  };
  res.render('profile', { user: u, error: req.query.e || null, message: req.query.m || null });
});


// 
function getLogoDataUrl(company) {
  const p = path.join(__dirname, 'logos', `${company}.png`);
  if (fs.existsSync(p)) {
    const data = fs.readFileSync(p);
    return `data:image/png;base64,${data.toString('base64')}`;
  }
  return null;
}



// ---------- auth + middleware ---------- Body parsers
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Const Upload Avatar_DIR (Profile)
const AVATAR_DIR = path.join(__dirname, 'avatars');
if (!fs.existsSync(AVATAR_DIR)) fs.mkdirSync(AVATAR_DIR, { recursive: true });
app.use('/avatars', express.static(AVATAR_DIR));
function avatarFilename(req) {
  const id = req.session.user.id;
  const ext = path.extname((req.file?.originalname || '')).toLowerCase();
  const allowedExt = ['.png', '.jpg', '.jpeg', '.webp'];
  const finalExt = allowedExt.includes(ext) ? ext : '.png';
  return `user-${id}${finalExt}`;
}
const uploadAvatar = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, AVATAR_DIR),
    filename: (req, file, cb) => cb(null, `user-${req.session.user.id}${path.extname(file.originalname).toLowerCase() || '.png'}`)
  }),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const ok = ['image/png', 'image/jpeg', 'image/webp'].includes(file.mimetype);
    cb(ok ? null : new Error('Only PNG/JPG/WebP allowed'));
  }
});
// End of Const Upload Avatar

// trust proxy if you’re behind nginx/Cloudflare later
app.set('trust proxy', 1);

// single session middleware
app.use(session({
  name: 'pc.sid',
  secret: process.env.SESSION_SECRET || 'change-this-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,           // keep false on http://localhost, set true only when you serve HTTPS
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  }
}));

app.use(
  session({
    secret: 'change-this-secret',
    resave: false,
    saveUninitialized: false
  })
);

// static after session is fine
app.use(express.static(path.join(__dirname, 'public')));
app.use('/logos', express.static(path.join(__dirname, 'logos')));
app.use('/avatars', express.static(path.join(__dirname, 'avatars')));

// view engine (if not already set)
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// make user available to all views/partials
app.use((req, res, next) => {
  res.locals.user = req.session?.user || null;
  next();
});

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.redirect('/login');
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.user && req.session.user.role === 'admin') return next();
  return res.status(403).send('Admins only');
}

// Ensure admin user exists
(function ensureAdmin() {
  const row = db.prepare('SELECT COUNT(*) AS c FROM users').get();
  if (row.c === 0) {
    const username = process.env.APP_USER || 'admin';
    const pass = process.env.APP_PASS || '1234';
    const hash = bcrypt.hashSync(pass, 10);
    db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)').run(username, hash, 'admin');
    console.log(`Created default admin: ${username} / ${pass}`);
  }
})();

// ---------- routes ----------
app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', (req, res) => res.render('login', { error: null }));
// Login Loop
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ? AND active = 1').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.render('login', { error: 'Invalid username or password' });
  }

  // regenerate then save
  req.session.regenerate(err => {
    if (err) return res.render('login', { error: 'Session error' });
    req.session.user = { id: user.id, name: user.username, role: user.role, avatar_name: user.avatar_name || null };
    req.session.save(() => {
      res.redirect(user.role === 'admin' ? '/dashboard' : '/form');
    });
  });
});
// Logout
app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

//Avatar upload and remove
app.post('/profile/avatar', requireAuth, uploadAvatar.single('avatar'), (req, res) => {
  try {
    if (!req.file) return res.redirect('/profile?e=' + encodeURIComponent('No file uploaded'));
    const newName = req.file.filename;
    const prev = db.prepare('SELECT avatar_name FROM users WHERE id = ?').get(req.session.user.id);
    if (prev && prev.avatar_name && prev.avatar_name !== newName) {
      const oldP = path.join(AVATAR_DIR, prev.avatar_name);
      if (fs.existsSync(oldP)) { try { fs.unlinkSync(oldP); } catch { } }
    }
    db.prepare('UPDATE users SET avatar_name = ? WHERE id = ?').run(newName, req.session.user.id);
    res.redirect('/profile?m=' + encodeURIComponent('Profile image updated'));
  } catch (e) {
    console.error(e);
    res.redirect('/profile?e=' + encodeURIComponent(e.message));
  }
});

app.post('/profile/avatar/delete', requireAuth, (req, res) => {
  try {
    const prev = db.prepare('SELECT avatar_name FROM users WHERE id = ?').get(req.session.user.id);
    if (prev && prev.avatar_name) {
      const p = path.join(AVATAR_DIR, prev.avatar_name);
      if (fs.existsSync(p)) { try { fs.unlinkSync(p); } catch { } }
      db.prepare('UPDATE users SET avatar_name = NULL WHERE id = ?').run(req.session.user.id);
    }
    res.redirect('/profile?m=' + encodeURIComponent('Profile image removed'));
  } catch (e) {
    console.error(e);
    res.redirect('/profile?e=' + encodeURIComponent(e.message));
  }
});
// End of Avatar

// Dashboard (admin)
app.get('/dashboard', requireAuth, requireAdmin, (req, res) => {
  const usersCount = db.prepare('SELECT COUNT(*) AS c FROM users WHERE active = 1').get().c;
  const historiesCount = db.prepare('SELECT COUNT(*) AS c FROM vouchers WHERE deleted = 0').get().c;
  const companiesCount = db.prepare('SELECT COUNT(*) AS c FROM companies').get().c;
  const deletedHistoriesCount = db.prepare('SELECT COUNT(*) AS c FROM vouchers WHERE deleted = 1').get().c;

  const recentRaw = db.prepare(`
    SELECT a.*, u.username AS actor,
           v.id AS v_id, v.company, v.pay_to, v.date, v.total, v.deleted AS v_deleted
    FROM activity_log a
    LEFT JOIN users u ON u.id = a.user_id
    LEFT JOIN vouchers v ON v.id = a.voucher_id
    ORDER BY a.id DESC
    LIMIT 15
  `).all();

  const recent = recentRaw.map(r => {
    let noteObj = null;
    try { noteObj = r.note ? JSON.parse(r.note) : null; } catch { }
    return {
      ...r,
      created_at_th: toBangkokDateTime(r.created_at),
      date_display: r.date ? displayDate(r.date) : (noteObj?.date ? displayDate(noteObj.date) : ''),
      noteObj
    };
  });

  res.render('dashboard', {
    user: req.session.user,
    usersCount,
    historiesCount,
    companiesCount,
    deletedHistoriesCount,
    recent
  });
});

// Companies list + add (admin)
app.get('/companies', requireAuth, requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT c.*,
           (SELECT COUNT(*) FROM vouchers v WHERE v.company = c.name AND v.deleted = 0) AS voucher_count
    FROM companies c
    ORDER BY c.name
  `).all();
  res.render('companies', {
    user: req.session.user,
    rows,
    error: req.query.e || null,
    message: req.query.m || null
  });
});


//Companies Edit
app.get('/companies/:id/edit', requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const row = db.prepare('SELECT * FROM companies WHERE id = ?').get(id);
  if (!row) return res.redirect('/companies?e=' + encodeURIComponent('Company not found'));
  res.render('company_edit', { user: req.session.user, company: row, error: null, message: null });
});

app.post('/companies/:id/edit', requireAuth, requireAdmin, upload.single('logo'), (req, res) => {
  const id = Number(req.params.id);
  const row = db.prepare('SELECT * FROM companies WHERE id = ?').get(id);
  if (!row) return res.redirect('/companies?e=' + encodeURIComponent('Company not found'));

  const oldName = row.name;
  const newName = (req.body.name || '').trim();
  if (!newName) {
    return res.redirect(`/companies/${id}/edit?e=` + encodeURIComponent('Name is required'));
  }

  const dupe = db.prepare('SELECT id FROM companies WHERE name = ? AND id != ?').get(newName, id);
  if (dupe) {
    return res.redirect(`/companies/${id}/edit?e=` + encodeURIComponent('That name already exists'));
  }

  const logosDir = path.join(__dirname, 'logos');
  const oldLogoName = row.logo_name || fileNameForCompany(oldName);
  const newLogoName = fileNameForCompany(newName);
  const oldPath = path.join(logosDir, oldLogoName);
  const newPath = path.join(logosDir, newLogoName);

  try {
    if (req.file) {
      // New PNG uploaded; multer already saved it using newName
      if (oldName !== newName && fs.existsSync(oldPath) && oldPath !== newPath) {
        try { fs.unlinkSync(oldPath); } catch { }
      }
      db.prepare('UPDATE companies SET name = ?, logo_name = ? WHERE id = ?').run(newName, newLogoName, id);
    } else {
      // No new file; if name changed, rename logo file if it exists
      if (oldName !== newName && fs.existsSync(oldPath) && oldPath !== newPath) {
        try { fs.renameSync(oldPath, newPath); } catch { }
      }
      db.prepare('UPDATE companies SET name = ?, logo_name = ? WHERE id = ?').run(newName, newLogoName, id);
    }

    if (oldName !== newName) {
      // Update existing vouchers to the new company name
      db.prepare('UPDATE vouchers SET company = ? WHERE company = ?').run(newName, oldName);
    }

    return res.redirect('/companies?m=' + encodeURIComponent('Company updated'));
  } catch (e) {
    console.error(e);
    return res.redirect(`/companies/${id}/edit?e=` + encodeURIComponent(e.message));
  }
});

// Tweak Delete 

app.post('/companies/:id/delete', requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const row = db.prepare('SELECT * FROM companies WHERE id = ?').get(id);
  if (!row) return res.redirect('/companies?e=' + encodeURIComponent('Company not found'));
  const vc = db.prepare('SELECT COUNT(*) AS c FROM vouchers WHERE company = ?').get(row.name).c;
  if (vc > 0) return res.redirect('/companies?e=' + encodeURIComponent('Company has vouchers; cannot delete'));

  const p = path.join(__dirname, 'logos', row.logo_name || fileNameForCompany(row.name));
  if (fs.existsSync(p)) { try { fs.unlinkSync(p); } catch { } }
  db.prepare('DELETE FROM companies WHERE id = ?').run(id);
  res.redirect('/companies?m=' + encodeURIComponent('Company deleted'));
});


// Add or update logo
app.post('/companies', requireAuth, requireAdmin, upload.single('logo'), (req, res) => {
  try {
    const name = (req.body.name || '').trim();
    if (!name) return res.redirect('/companies?e=' + encodeURIComponent('Company name is required'));
    if (!req.file) return res.redirect('/companies?e=' + encodeURIComponent('PNG logo is required (max 10MB)'));

    const logoName = fileNameForCompany(name); // saved by multer
    const exists = db.prepare('SELECT id FROM companies WHERE name = ?').get(name);
    if (exists) {
      db.prepare('UPDATE companies SET logo_name = ? WHERE id = ?').run(logoName, exists.id);
      return res.redirect('/companies?m=' + encodeURIComponent('Logo updated for ' + name));
    } else {
      db.prepare('INSERT INTO companies (name, logo_name) VALUES (?, ?)').run(name, logoName);
      return res.redirect('/companies?m=' + encodeURIComponent('Company added'));
    }
  } catch (e) {
    console.error(e);
    return res.redirect('/companies?e=' + encodeURIComponent(e.message));
  }
});

// Delete company (only if no vouchers use it)
app.post('/companies/:id/delete', requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const row = db.prepare('SELECT * FROM companies WHERE id = ?').get(id);
  if (!row) return res.redirect('/companies?e=' + encodeURIComponent('Company not found'));
  const vc = db.prepare('SELECT COUNT(*) AS c FROM vouchers WHERE company = ?').get(row.name).c;
  if (vc > 0) return res.redirect('/companies?e=' + encodeURIComponent('Company has vouchers; cannot delete'));

  // remove logo file
  const p = path.join(__dirname, 'logos', row.logo_name || fileNameForCompany(row.name));
  if (fs.existsSync(p)) try { fs.unlinkSync(p); } catch { }
  db.prepare('DELETE FROM companies WHERE id = ?').run(id);
  res.redirect('/companies?m=' + encodeURIComponent('Company deleted'));
});

// Edit Company routes


// API for dropdown list
app.get('/api/companies', requireAuth, (req, res) => {
  const names = db.prepare('SELECT name FROM companies ORDER BY name').all().map(r => r.name);
  res.json({ names });
});

// Form (users create vouchers)
app.get('/form', requireAuth, (req, res) => {
  if (req.session.user.role === 'admin') return res.redirect('/dashboard');
  res.render('app', { user: req.session.user });
});

// History (privacy: users see only their own; admin sees all)
app.get('/history', requireAuth, (req, res) => {
  const isAdmin = req.session.user.role === 'admin';
  let rows;
  if (isAdmin) {
    rows = db.prepare(`
      SELECT v.*, u.username AS created_by_name
      FROM vouchers v
      LEFT JOIN users u ON u.id = v.created_by
      WHERE v.deleted = 0
      ORDER BY v.id DESC
      LIMIT 500
    `).all();
  } else {
    rows = db.prepare(`
      SELECT v.*, u.username AS created_by_name
      FROM vouchers v
      LEFT JOIN users u ON u.id = v.created_by
      WHERE v.deleted = 0 AND v.created_by = ?
      ORDER BY v.id DESC
      LIMIT 500
    `).all(req.session.user.id);
  }
  rows = rows.map(r => ({ ...r, created_at_th: toBangkokDateTime(r.created_at) }));
  res.render('history', { user: req.session.user, rows, isAdmin });
});

// Users (admin)
app.get('/users', requireAuth, requireAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT u.id, u.username, u.role, u.active, u.created_at,
           (SELECT COUNT(*) FROM vouchers v WHERE v.created_by = u.id) AS voucher_count
    FROM users u
    ORDER BY u.id
  `).all();
  res.render('users', {
    user: req.session.user,
    users,
    error: req.query.e || null,
    message: req.query.m || null
  });
});
app.post('/users', requireAuth, requireAdmin, (req, res) => {
  const { username, password, role } = req.body;
  try {
    if (!password || password.length < 6) {
      return res.redirect('/users?e=' + encodeURIComponent('Password must be at least 6 characters'));
    }
    const hash = bcrypt.hashSync(password, 10);
    db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)').run(username, hash, role || 'user');
    res.redirect('/users?m=' + encodeURIComponent('User created'));
  } catch {
    res.redirect('/users?e=' + encodeURIComponent('Username already exists'));
  }
});
app.post('/users/:id/toggle-active', requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const u = db.prepare('SELECT id, username, role, active FROM users WHERE id = ?').get(id);
  if (!u) return res.redirect('/users?e=' + encodeURIComponent('User not found'));
  if (u.role === 'admin' && u.active === 1) {
    const c = db.prepare('SELECT COUNT(*) AS c FROM users WHERE role = "admin" AND active = 1').get().c;
    if (c <= 1) return res.redirect('/users?e=' + encodeURIComponent('Cannot deactivate the last active admin'));
  }
  if (u.id === req.session.user.id) {
    return res.redirect('/users?e=' + encodeURIComponent('You cannot deactivate your own account'));
  }
  const to = u.active ? 0 : 1;
  db.prepare('UPDATE users SET active = ? WHERE id = ?').run(to, id);
  res.redirect('/users?m=' + encodeURIComponent(`${u.username} ${to ? 'reactivated' : 'deactivated'}`));
});
app.post('/users/:id/reset-password', requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const { newPassword } = req.body;
  const u = db.prepare('SELECT id, username FROM users WHERE id = ?').get(id);
  if (!u) return res.redirect('/users?e=' + encodeURIComponent('User not found'));
  if (!newPassword || newPassword.length < 6) {
    return res.redirect('/users?e=' + encodeURIComponent('New password must be at least 6 characters'));
  }
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, id);
  res.redirect('/users?m=' + encodeURIComponent(`Password updated for ${u.username}`));
});
app.post('/users/:id/hard-delete', requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const u = db.prepare('SELECT id, username, role FROM users WHERE id = ?').get(id);
  if (!u) return res.redirect('/users?e=' + encodeURIComponent('User not found'));
  if (u.id === req.session.user.id) return res.redirect('/users?e=' + encodeURIComponent('You cannot delete your own account'));
  if (u.role === 'admin') {
    const c = db.prepare('SELECT COUNT(*) AS c FROM users WHERE role = "admin" AND active = 1 AND id != ?').get(id).c;
    if (c === 0) return res.redirect('/users?e=' + encodeURIComponent('Cannot delete the last admin'));
  }
  const vc = db.prepare('SELECT COUNT(*) AS c FROM vouchers WHERE created_by = ?').get(id).c;
  if (vc > 0) return res.redirect('/users?e=' + encodeURIComponent('User has vouchers. Deactivate instead.'));
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  res.redirect('/users?m=' + encodeURIComponent(`User ${u.username} deleted`));
});

// Profile (self password change)
app.get('/profile', requireAuth, (req, res) => res.render('profile', { user: req.session.user, error: null, message: null }));
app.post('/profile/password', requireAuth, (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;
  const u = db.prepare('SELECT id, password_hash FROM users WHERE id = ?').get(req.session.user.id);
  if (!bcrypt.compareSync(currentPassword || '', u.password_hash)) {
    return res.render('profile', { user: req.session.user, error: 'Current password is incorrect', message: null });
  }
  if (!newPassword || newPassword.length < 6) {
    return res.render('profile', { user: req.session.user, error: 'New password must be at least 6 characters', message: null });
  }
  if (newPassword !== confirmPassword) {
    return res.render('profile', { user: req.session.user, error: 'Passwords do not match', message: null });
  }
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.session.user.id);
  res.render('profile', { user: req.session.user, error: null, message: 'Password updated' });
});



// PDF rendering
async function renderGroupsToPDF(groups) {
  const html = await ejs.renderFile(path.join(__dirname, 'views', 'voucherBatch.ejs'), { groups });
  const browser = await puppeteer.launch({ args: ['--no-sandbox'], headless: 'new' });
  const page = await browser.newPage();
  await page.setContent(html, { waitUntil: 'networkidle0' });
  const buffer = await page.pdf({
    format: 'A5',
    landscape: true,
    printBackground: true,
    preferCSSPageSize: true,
    margin: { top: '8mm', bottom: '8mm', left: '8mm', right: '8mm' }
  });
  await browser.close();
  return buffer;
}

// Generate vouchers (saves + logs)
app.post('/generate', requireAuth, async (req, res) => {
  try {
    const { rows } = req.body;
    if (!Array.isArray(rows) || rows.length === 0) return res.status(400).send('No rows submitted');

    const parsed = rows
      .map(r => ({
        company: (r.company || '').trim(),
        category: (r.category || '').trim(),
        description: (r.description || '').trim(),
        amount: parseFloat(String(r.amount).replace(/,/g, '')) || 0,
        payTo: (r.payTo || '').trim(),
        dateISO: iso(r.date),
        separate: !!r.separate
      }))
      .filter(r => r.company && r.category && r.description && r.payTo && r.dateISO);

    const map = new Map();
    const groups = [];
    for (const row of parsed) {
      if (row.separate) {
        groups.push({
          company: row.company, payTo: row.payTo,
          dateISO: row.dateISO, dateStr: displayDate(row.dateISO),
          logoDataUrl: getLogoDataUrl(row.company),
          entries: [row]
        });
      } else {
        const key = `${row.company}|${row.payTo}|${row.dateISO}`;
        if (!map.has(key)) {
          map.set(key, {
            company: row.company, payTo: row.payTo,
            dateISO: row.dateISO, dateStr: displayDate(row.dateISO),
            logoDataUrl: getLogoDataUrl(row.company),
            entries: []
          });
        }
        map.get(key).entries.push(row);
      }
    }
    for (const g of map.values()) groups.push(g);

    // Save + log
    const insV = db.prepare('INSERT INTO vouchers (company, pay_to, date, total, created_by) VALUES (?, ?, ?, ?, ?)');
    const insI = db.prepare('INSERT INTO voucher_items (voucher_id, category, description, amount) VALUES (?, ?, ?, ?)');
    const insLog = db.prepare('INSERT INTO activity_log (user_id, action, voucher_id, note) VALUES (?, ?, ?, ?)');

    for (const g of groups) {
      const total = g.entries.reduce((s, e) => s + (e.amount || 0), 0);
      const v = insV.run(g.company, g.payTo, g.dateISO, total, req.session.user.id);
      for (const e of g.entries) insI.run(v.lastInsertRowid, e.category, e.description, e.amount);
      insLog.run(req.session.user.id, 'create', v.lastInsertRowid, null);
    }

    const buffer = await renderGroupsToPDF(groups);
    const filename = `pettycash-${new Date().toISOString().slice(0, 10)}.pdf`;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(buffer);
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to generate PDF');
  }
});

// PDF for one voucher (permission checked)
app.get('/voucher/:id/pdf', requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  const isAdmin = req.session.user.role === 'admin';
  const v = db.prepare('SELECT * FROM vouchers WHERE id = ?').get(id);
  if (!v) return res.status(404).send('Not found');
  if (!isAdmin && v.deleted) return res.status(404).send('Not found');
  if (!isAdmin && v.created_by !== req.session.user.id) return res.status(403).send('Forbidden');

  const items = db.prepare('SELECT category, description, amount FROM voucher_items WHERE voucher_id = ? ORDER BY id').all(id);
  const group = {
    company: v.company,
    payTo: v.pay_to,
    dateISO: v.date,
    dateStr: displayDate(v.date),
    logoDataUrl: getLogoDataUrl(v.company),
    entries: items
  };
  const buffer = await renderGroupsToPDF([group]);
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="voucher-${id}.pdf"`);
  res.send(buffer);
});

// Soft delete (owner/admin) + log
app.post('/voucher/:id/delete', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const v = db.prepare('SELECT id, created_by FROM vouchers WHERE id = ? AND deleted = 0').get(id);
  if (!v) return res.status(404).send('Not found');
  const isAdmin = req.session.user.role === 'admin';
  if (!isAdmin && v.created_by !== req.session.user.id) return res.status(403).send('Forbidden');

  db.prepare('UPDATE vouchers SET deleted = 1 WHERE id = ?').run(id);
  db.prepare('INSERT INTO activity_log (user_id, action, voucher_id) VALUES (?, ?, ?)').run(req.session.user.id, 'delete', id);
  res.redirect('/history');
});

// Hard delete (admin) + log
app.post('/voucher/:id/hard-delete', requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const v = db.prepare('SELECT id, company, pay_to, date, total FROM vouchers WHERE id = ?').get(id);

  const nullLog = db.prepare('UPDATE activity_log SET voucher_id = NULL WHERE voucher_id = ?');
  const delItems = db.prepare('DELETE FROM voucher_items WHERE voucher_id = ?');
  const delVoucher = db.prepare('DELETE FROM vouchers WHERE id = ?');
  const deletedHistoriesCount = db.prepare('SELECT COUNT(*) AS c FROM vouchers WHERE deleted = 1').get().c;
  res.render('dashboard', { user: req.session.user, usersCount, historiesCount, companiesCount, deletedHistoriesCount, recent });

  const tx = db.transaction(vid => {
    nullLog.run(vid);
    delItems.run(vid);
    delVoucher.run(vid);
  });
  tx(id);

  const meta = JSON.stringify({ voucherId: id, company: v?.company || null, pay_to: v?.pay_to || null, date: v?.date || null, total: v?.total || null });
  db.prepare('INSERT INTO activity_log (user_id, action, voucher_id, note) VALUES (?, ?, ?, ?)').run(req.session.user.id, 'hard_delete', null, meta);

  res.redirect('/history/deleted');
});

app.post('/vouchers/bulk-hard-delete', requireAuth, requireAdmin, (req, res) => {
  let ids = req.body.ids;
  if (!ids) return res.redirect('/history/deleted');
  if (!Array.isArray(ids)) ids = [ids];

  const details = ids
    .map(s => Number(s))
    .filter(Number.isFinite)
    .map(id => db.prepare('SELECT id, company, pay_to, date, total FROM vouchers WHERE id = ?').get(id))
    .filter(Boolean);

  const nullLog = db.prepare('UPDATE activity_log SET voucher_id = NULL WHERE voucher_id = ?');
  const delItems = db.prepare('DELETE FROM voucher_items WHERE voucher_id = ?');
  const delVoucher = db.prepare('DELETE FROM vouchers WHERE id = ?');

  const tx = db.transaction(list => {
    for (const row of list) {
      nullLog.run(row.id);
      delItems.run(row.id);
      delVoucher.run(row.id);
    }
  });
  tx(details);

  const insLog = db.prepare('INSERT INTO activity_log (user_id, action, voucher_id, note) VALUES (?, ?, ?, ?)');
  for (const row of details) {
    insLog.run(req.session.user.id, 'hard_delete', null, JSON.stringify({
      voucherId: row.id, company: row.company, pay_to: row.pay_to, date: row.date, total: row.total
    }));
  }
  res.redirect('/history/deleted');
});

// Bulk soft delete (owner/admin) + log
app.post('/vouchers/bulk-delete', requireAuth, (req, res) => {
  let ids = req.body.ids;
  if (!ids) return res.redirect('/history');
  if (!Array.isArray(ids)) ids = [ids];

  const isAdmin = req.session.user.role === 'admin';
  const fetch = db.prepare('SELECT id, created_by FROM vouchers WHERE id = ? AND deleted = 0');
  const soft = db.prepare('UPDATE vouchers SET deleted = 1 WHERE id = ?');
  const log = db.prepare('INSERT INTO activity_log (user_id, action, voucher_id) VALUES (?, ?, ?)');

  const tx = db.transaction((list) => {
    for (const idStr of list) {
      const id = Number(idStr);
      if (!Number.isFinite(id)) continue;
      const v = fetch.get(id);
      if (!v) continue;
      if (isAdmin || v.created_by === req.session.user.id) {
        soft.run(id);
        log.run(req.session.user.id, 'delete', id);
      }
    }
  });
  tx(ids);

  res.redirect('/history');
});



// Trash Page
app.get('/history/deleted', requireAuth, requireAdmin, (req, res) => {
  let rows = db.prepare(`
    SELECT v.*, u.username AS created_by_name
    FROM vouchers v
    LEFT JOIN users u ON u.id = v.created_by
    WHERE v.deleted = 1
    ORDER BY v.id DESC
    LIMIT 1000
  `).all();
  rows = rows.map(r => ({ ...r, created_at_th: toBangkokDateTime(r.created_at) }));
  res.render('history_deleted', { user: req.session.user, rows });
});

//Restore Route
app.post('/voucher/:id/restore', requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const v = db.prepare('SELECT id FROM vouchers WHERE id = ? AND deleted = 1').get(id);
  if (!v) return res.redirect('/history/deleted');
  db.prepare('UPDATE vouchers SET deleted = 0 WHERE id = ?').run(id);
  db.prepare('INSERT INTO activity_log (user_id, action, voucher_id) VALUES (?, ?, ?)').run(req.session.user.id, 'restore', id);
  res.redirect('/history/deleted');
});

app.post('/vouchers/bulk-restore', requireAuth, requireAdmin, (req, res) => {
  let ids = req.body.ids;
  if (!ids) return res.redirect('/history/deleted');
  if (!Array.isArray(ids)) ids = [ids];

  const upd = db.prepare('UPDATE vouchers SET deleted = 0 WHERE id = ?');
  const log = db.prepare('INSERT INTO activity_log (user_id, action, voucher_id) VALUES (?, ?, ?)');

  const tx = db.transaction(list => {
    for (const s of list) {
      const id = Number(s);
      if (!Number.isFinite(id)) continue;
      upd.run(id);
      log.run(req.session.user.id, 'restore', id);
    }
  });
  tx(ids);

  res.redirect('/history/deleted');
});

app.listen(PORT, () => console.log(`Petty Cash running at http://localhost:${PORT}`));