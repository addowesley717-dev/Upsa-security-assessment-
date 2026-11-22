// Attack test plan. Run once against `npm run vuln` (BEFORE) and once against `npm start` (AFTER).
// Usage: BASE=https://localhost:3443 NODE_TLS_REJECT_UNAUTHORIZED=0 npm run attack
const crypto = require('crypto'), jwt = require('jsonwebtoken');
const BASE = process.env.BASE || 'https://localhost:3443';
const r = async (p, o = {}) => fetch(BASE + p, o);
const show = (n, pass, note) => console.log(`${pass ? 'BLOCKED ' : 'SUCCEEDED'} | ${n} | ${note}`);
(async () => {
  // 1. SQL injection: UNION to steal password hashes
  const q = encodeURIComponent("zzz' UNION SELECT index_no, hash FROM users--");
  const t = await (await r('/api/courses?q=' + q)).text();
  show('SQL injection', !t.includes('$2b$'), t.includes('$2b$') ? 'password hashes leaked' : 'no data leaked');
  // 2. Brute force: 8 wrong logins
  let blocked = 0;
  for (let i = 0; i < 8; i++) { const x = await r('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ index_no: '10230001', password: 'guess' + i, otp: '000000' }) }); if (x.status === 429) blocked++; }
  show('Brute force', blocked > 0, `${blocked}/8 attempts rate-limited`);
  // 3. No token
  show('No token access', (await r('/api/grades')).status === 401, 'expect 401');
  // 4. Forged JWT (signed with attacker key)
  const forged = jwt.sign({ sub: 'LEC001', role: 'lecturer' }, 'attacker-key', { keyid: 'v2' });
  show('Forged JWT', (await r('/api/grades', { headers: { Authorization: 'Bearer ' + forged } })).status === 401, 'expect 401');
  // 5. Fake payment webhook
  const body = JSON.stringify({ index_no: '10230001' });
  const w = await r('/api/webhook/fees', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-signature': 'deadbeef' }, body });
  show('Fake webhook', w.status === 401, 'status ' + w.status);
})();
