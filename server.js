const express = require('express'), bcrypt = require('bcrypt'), jwt = require('jsonwebtoken'), helmet = require('helmet'),
  rateLimit = require('express-rate-limit'), speakeasy = require('speakeasy'), crypto = require('crypto'),
  fs = require('fs'), https = require('https');
const { db, enc, dec } = require('./lib');
const VULN = process.env.VULNERABLE === '1'; // LAB ONLY: switches on an insecure search for "before" evidence
const KEYS = { v2: process.env.JWT_KEY_V2, v1: process.env.JWT_KEY_V1 }, CURRENT = 'v2'; // key rotation: v1 tokens still verify

const log = (event, d = {}) => fs.appendFileSync('security.log', JSON.stringify({ t: new Date().toISOString(), event, ...d }) + '\n');
const app = express();
app.use(helmet()); // secure headers + CSP
app.use(express.json({ limit: '10kb', verify: (req, _res, buf) => { req.raw = buf; } }));
app.use(express.static('public'));

// ---- Login: password + MFA code -> short-lived signed JWT ----
app.post('/api/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 5, handler: (req, res) => { log('RATE_LIMITED', { ip: req.ip }); res.sendStatus(429); } }),
  async (req, res) => {
    const { index_no, password, otp } = req.body || {};
    const u = db.prepare('SELECT * FROM users WHERE index_no = ?').get(String(index_no)); // parameterized
    const ok = u && await bcrypt.compare(String(password), u.hash) &&
      speakeasy.totp.verify({ secret: dec(u.mfa_secret), encoding: 'base32', token: String(otp), window: 1 });
    if (!ok) { log('LOGIN_FAIL', { index_no, ip: req.ip }); return res.status(401).json({ error: 'Invalid login' }); }
    log('LOGIN_OK', { index_no });
    const token = jwt.sign({ sub: u.index_no, role: u.role }, KEYS[CURRENT], { expiresIn: '15m', keyid: CURRENT });
    res.json({ token, role: u.role });
  });

// ---- IAM/RBAC middleware ----
const auth = (roles = []) => (req, res, next) => {
  try {
    const t = (req.headers.authorization || '').split(' ')[1];
    const kid = jwt.decode(t, { complete: true })?.header.kid;
    if (!KEYS[kid]) throw new Error('bad kid');
    const p = jwt.verify(t, KEYS[kid], { algorithms: ['HS256'] });
    if (roles.length && !roles.includes(p.role)) { log('FORBIDDEN', { user: p.sub, path: req.path }); return res.sendStatus(403); }
    req.user = p; next();
  } catch { log('BAD_TOKEN', { ip: req.ip, path: req.path }); res.sendStatus(401); }
};

app.get('/api/grades', auth(['student']), (req, res) =>
  res.json(db.prepare('SELECT course, score FROM grades WHERE index_no = ?').all(req.user.sub))); // only MY grades
app.post('/api/grades', auth(['lecturer']), (req, res) => {
  const { index_no, course, score } = req.body;
  if (!Number.isInteger(score) || score < 0 || score > 100) return res.status(400).json({ error: 'Score 0-100' });
  db.prepare('INSERT INTO grades(index_no,course,score) VALUES(?,?,?)').run(String(index_no), String(course), score);
  log('GRADE_ADDED', { by: req.user.sub, index_no, course }); res.sendStatus(201);
});

// ---- Public course search (the SQL injection target) ----
app.get('/api/courses', (req, res) => {
  const q = String(req.query.q || '');
  try {
    const rows = VULN ? db.prepare(`SELECT code, title FROM courses WHERE title LIKE '%${q}%'`).all() // INSECURE
                      : db.prepare('SELECT code, title FROM courses WHERE title LIKE ?').all(`%${q}%`); // SAFE
    res.json(rows);
  } catch { res.sendStatus(400); }
});

// ---- Webhook: payment gateway tells us fees are paid; verify HMAC signature ----
app.post('/api/webhook/fees', (req, res) => {
  const good = crypto.createHmac('sha256', process.env.WEBHOOK_SECRET).update(req.raw || '').digest('hex');
  const got = String(req.headers['x-signature'] || '');
  if (got.length !== good.length || !crypto.timingSafeEqual(Buffer.from(got), Buffer.from(good))) {
    log('WEBHOOK_REJECTED', { ip: req.ip }); return res.sendStatus(401);
  }
  db.prepare('UPDATE users SET fees_paid = 1 WHERE index_no = ?').run(String(req.body.index_no));
  log('WEBHOOK_OK', { index_no: req.body.index_no }); res.sendStatus(200);
});

// ---- TLS (HTTPS) if certs exist ----
const port = process.env.PORT || 3443;
if (fs.existsSync('certs/key.pem')) https.createServer({ key: fs.readFileSync('certs/key.pem'), cert: fs.readFileSync('certs/cert.pem') }, app).listen(port, () => console.log('HTTPS on', port, VULN ? '(VULNERABLE MODE)' : ''));
else app.listen(port, () => console.log('HTTP (no certs) on', port, VULN ? '(VULNERABLE MODE)' : ''));
