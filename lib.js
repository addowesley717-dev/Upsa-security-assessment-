const Database = require('better-sqlite3'), crypto = require('crypto');
const db = new Database('portal.db');
db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, index_no TEXT UNIQUE, hash TEXT, role TEXT, mfa_secret TEXT, phone_enc TEXT, fees_paid INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS grades(id INTEGER PRIMARY KEY, index_no TEXT, course TEXT, score INTEGER);
CREATE TABLE IF NOT EXISTS courses(code TEXT, title TEXT);`);
const KEY = Buffer.from(process.env.DATA_KEY || '', 'hex'); // 32 bytes = AES-256
// Encryption at rest: AES-256-GCM (scrambles AND detects tampering)
const enc = t => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const d = Buffer.concat([c.update(t, 'utf8'), c.final()]); return Buffer.concat([iv, c.getAuthTag(), d]).toString('base64'); };
const dec = s => { const b = Buffer.from(s, 'base64'), d = crypto.createDecipheriv('aes-256-gcm', KEY, b.subarray(0, 12));
  d.setAuthTag(b.subarray(12, 28)); return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8'); };
// Strong password policy: 10+ chars, upper, lower, digit, symbol
const strong = p => /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*\W).{10,}$/.test(p || '');
module.exports = { db, enc, dec, strong };
