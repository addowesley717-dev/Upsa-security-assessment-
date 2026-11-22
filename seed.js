const bcrypt = require('bcrypt'), speakeasy = require('speakeasy');
const { db, enc, strong } = require('./lib');
const users = [['10230001', 'Kwame#Mensah2026', 'student', '0241234567'],
               ['10230002', 'Abena#Owusu2026', 'student', '0201234567'],
               ['LEC001', 'Dr#Addo2026Pass', 'lecturer', '0551234567']];
for (const [i, p, role, phone] of users) {
  if (!strong(p)) throw new Error('Weak password for ' + i);
  const s = speakeasy.generateSecret({ length: 20 });
  db.prepare('INSERT OR IGNORE INTO users(index_no,hash,role,mfa_secret,phone_enc) VALUES(?,?,?,?,?)')
    .run(i, bcrypt.hashSync(p, 12), role, enc(s.base32), enc(phone));
  console.log(i, role, 'MFA key (add to Google Authenticator):', s.base32);
}
db.exec(`INSERT INTO courses SELECT 'BSIT301','Programming' WHERE NOT EXISTS(SELECT 1 FROM courses);
INSERT INTO courses SELECT 'BSIT309','IT Security' WHERE (SELECT COUNT(*) FROM courses)<2;`);
db.prepare('INSERT INTO grades(index_no,course,score) VALUES(?,?,?)').run('10230001', 'BSIT301', 78);
db.prepare('INSERT INTO grades(index_no,course,score) VALUES(?,?,?)').run('10230002', 'BSIT309', 85);
