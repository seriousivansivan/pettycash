const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const ejs = require('ejs');
const puppeteer = require('puppeteer');

const app = express();
const PORT = process.env.PORT || 3000;

// middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/logos', express.static(path.join(__dirname, 'logos')));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(
  session({
    secret: 'change-this-secret',
    resave: false,
    saveUninitialized: false
  })
);

function requireAuth(req, res, next) {
  if (req.session.user) return next();
  res.redirect('/login');
}

// auth routes
app.get('/login', (req, res) => res.render('login', { error: null }));

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const USER = process.env.APP_USER || 'admin';
  const PASS = process.env.APP_PASS || '1234';

  if (username === USER && password === PASS) {
    req.session.user = { name: username };
    res.redirect('/form');
  } else {
    res.render('login', { error: 'Invalid username or password' });
  }
});

app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

// app routes
app.get('/', (req, res) => res.redirect('/form'));
app.get('/form', requireAuth, (req, res) => res.render('app', { user: req.session.user }));

function getLogoDataUrl(company) {
  const p = path.join(__dirname, 'logos', `${company}.png`);
  if (fs.existsSync(p)) {
    const data = fs.readFileSync(p);
    return `data:image/png;base64,${data.toString('base64')}`;
  }
  return null; // no logo
}

app.post('/generate', requireAuth, async (req, res) => {
  try {
    const { rows } = req.body;
    if (!Array.isArray(rows) || rows.length === 0) {
      return res.status(400).send('No rows submitted');
    }

    // sanitize + parse
    const parsed = rows
      .map(r => ({
        company: (r.company || '').trim(),
        category: (r.category || '').trim(),
        description: (r.description || '').trim(),
        amount: parseFloat(String(r.amount).replace(/,/g, '')) || 0,
        payTo: (r.payTo || '').trim(),
        date: r.date ? new Date(r.date) : new Date(),
        separate: !!r.separate
      }))
      .filter(r => r.company && r.category && r.description && r.payTo && r.date);

    // group by (company|payTo|date) unless "separate" is checked
    const map = new Map();
    const groups = [];

    for (const row of parsed) {
      if (row.separate) {
        groups.push({
          company: row.company,
          payTo: row.payTo,
          dateStr: row.date.toLocaleDateString(),
          logoDataUrl: getLogoDataUrl(row.company),
          entries: [row]
        });
      } else {
        const dateKey = row.date.toISOString().slice(0, 10);
        const key = `${row.company}|${row.payTo}|${dateKey}`;
        if (!map.has(key)) {
          map.set(key, {
            company: row.company,
            payTo: row.payTo,
            dateStr: row.date.toLocaleDateString(),
            logoDataUrl: getLogoDataUrl(row.company),
            entries: []
          });
        }
        map.get(key).entries.push(row);
      }
    }
    for (const g of map.values()) groups.push(g);

    // render vouchers HTML
    const html = await ejs.renderFile(path.join(__dirname, 'views', 'voucherBatch.ejs'), { groups });

    // print to A5 PDF (landscape)
    const browser = await puppeteer.launch({ args: ['--no-sandbox'], headless: 'new' });
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'networkidle0' });
    const buffer = await page.pdf({
      format: 'A5',
      landscape: true,
      printBackground: true,
      preferCSSPageSize: true,
      margin: { top: '10mm', bottom: '10mm', left: '10mm', right: '10mm' }
    });
    await browser.close();

    const filename = `pettycash-${new Date().toISOString().slice(0, 10)}.pdf`;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(buffer);
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to generate PDF');
  }
});

app.listen(PORT, () => console.log(`Petty Cash running at http://localhost:${PORT}`));