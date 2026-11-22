# UPSA Student Portal - BSIT 309 Secure Architecture Project
Domain: **Systems/Applications**. Stack: Node.js 20+, Express, SQLite.

## Build (reproducible)
```
npm install
cp .env.example .env      # then put real random values in .env (openssl rand -hex 32)
sh gen-cert.sh            # lab TLS certificate
npm run seed              # creates 3 users, prints each MFA key for Google Authenticator
npm start                 # https://localhost:3443
```
Demo logins (lab only): 10230001 / Kwame#Mensah2026, 10230002 / Abena#Owusu2026, LEC001 / Dr#Addo2026Pass

## (i) Architecture and threat model
Zones: Browser (untrusted) -> [TLS boundary] -> Express API (DMZ/app tier) -> [internal boundary] -> SQLite (data tier).
Data flow: login (password+OTP) -> JWT -> API checks role -> DB query.
| Threat (STRIDE) | Example | Control |
|---|---|---|
| Spoofing | stolen password, phishing | MFA (TOTP), bcrypt, rate limit |
| Tampering | forged JWT, SQL injection | JWT signature, parameterized SQL |
| Repudiation | lecturer denies editing grade | security.log |
| Info disclosure | sniffing Wi-Fi, DB theft | TLS, AES-256-GCM, bcrypt |
| DoS | registration-week flood | rate limiting (+ firewall/CDN in production) |
| Elevation | student edits grades | RBAC middleware |

## (iii) Where each control lives
MFA/password policy/JWT/RBAC/rate limit/logging/webhook: `server.js`, `lib.js`, `seed.js`. TLS: `gen-cert.sh`.
Encryption at rest: phone and MFA secret encrypted (AES-256-GCM); for whole-database encryption in production use SQLCipher or PostgreSQL with disk encryption.
JWT rotation: tokens carry `kid`; sign with v2, still accept v1 until old tokens expire (15 min), then delete v1.
Kerberos: not coded here. Lab step: Windows Server VM with Active Directory, join a Windows client, show a Kerberos ticket with `klist`; document it as the staff single sign-on option.
Perimeter (Ubuntu): `ufw default deny incoming && ufw allow 3443/tcp`

## (iv) Attack test plan
`npm run vuln` then `npm run attack` (BEFORE), then `npm start` and `npm run attack` (AFTER). Screenshot both. Add Wireshark captures for man-in-the-middle (HTTP vs HTTPS) and a phishing demo showing a stolen password fails without the OTP.
Residual risk: a user can type a live OTP into a fake site (real-time phishing); a real DDoS needs network-level protection; a stolen unexpired JWT works for up to 15 minutes; self-signed cert needs a real CA in production.

## (v) Production-readiness
- [ ] Real CA certificate, HTTP redirected to HTTPS  - [ ] Secrets in a vault, not .env
- [ ] VULNERABLE mode removed  - [ ] DB on a separate server, backups encrypted
- [ ] Logs shipped to a monitored server with alerts on LOGIN_FAIL/RATE_LIMITED spikes
- [ ] `npm audit` clean, dependencies updated  - [ ] Firewall, OS patched, non-root service user
Incident response: detect (log alert) -> contain (disable account, rotate JWT key) -> eradicate -> recover from backup -> review.
Framework mapping: OWASP Top 10 (A01 RBAC, A02 crypto, A03 injection, A07 auth); NIST CSF (Protect: PR.AA, PR.DS; Detect: DE.CM); ISO 27001 Annex A (access control, cryptography, logging).
