// Local dev server: http://localhost:8080 — same backend logic as AWS, with real email + password sign-in
// emulated locally (passwords hashed with scrypt, reset codes printed in this terminal). Data in dev/data.json.
// Run: OWNER_EMAIL=you@company.com [OWNER_PASSWORD=...] [ANTHROPIC_API_KEY=...] node dev/server.mjs
import http from 'node:http';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, extname, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, scryptSync, timingSafeEqual, createHmac, createHash } from 'node:crypto';
import { makeCore, tenantOf } from '../backend/core.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const WEB = join(ROOT, 'web'), DATA = join(ROOT, 'dev', 'data.json'), BLOBS = join(ROOT, 'dev', 'blobs');
const PORT = +process.env.PORT || 8080, OWNER = (process.env.OWNER_EMAIL || 'owner@example.com').toLowerCase();
mkdirSync(BLOBS, { recursive: true });
let DB = existsSync(DATA) ? JSON.parse(readFileSync(DATA, 'utf8')) : existsSync(join(ROOT, 'seed', 'seed.json')) ? JSON.parse(readFileSync(join(ROOT, 'seed', 'seed.json'), 'utf8')) : {};
let saveT; const save = () => { clearTimeout(saveT); saveT = setTimeout(() => writeFileSync(DATA, JSON.stringify(DB)), 200); };
const T = k => (DB[k] = DB[k] || {});
const store = {
  async get(pk, sk) { const v = (DB[pk] || {})[sk]; return v === undefined ? null : JSON.parse(JSON.stringify(v)); },
  async put(pk, sk, d) { T(pk)[sk] = JSON.parse(JSON.stringify(d)); save(); },
  async del(pk, sk) { if (DB[pk]) delete DB[pk][sk]; save(); },
  async list(pk) { return Object.entries(DB[pk] || {}).map(([id, data]) => ({ id, data })); },
  // versioned records (same semantics as the DynamoDB transactions in backend/index.mjs)
  async items(pk) { return Object.entries(DB['~' + pk] || {}).map(([sk, x]) => Object.assign({ sk }, JSON.parse(JSON.stringify(x)))); },
  async txn(ops) {
    for (const op of ops) { const k = op.put || op.del, cur = (DB['~' + k.pk] || {})[k.sk];
      if (op.cond === null ? !!cur : !cur || cur.v !== op.cond) throw Object.assign(new Error('conflict'), { code: 'conflict' }); }
    for (const op of ops) { if (op.put) { const x = op.put; T('~' + x.pk)[x.sk] = { data: JSON.parse(JSON.stringify(x.data)), v: x.v, o: x.o || 0, by: x.by || '' }; } else delete DB['~' + op.del.pk][op.del.sk]; }
    save();
  }
};
const blobs = {
  async put(key, buf, ct) { const f = join(BLOBS, key.replace(/\//g, '__')); writeFileSync(f, buf); writeFileSync(f + '.ct', ct); },
  async get(key) { const f = join(BLOBS, key.replace(/\//g, '__')); return existsSync(f) ? { buf: readFileSync(f), ct: readFileSync(f + '.ct', 'utf8') } : null; }
};

/* ---------- user directory + passwords (stands in for Cognito) ---------- */
const subOf = email => 'dev_' + Buffer.from(email.toLowerCase()).toString('hex').slice(0, 20);
const hash = pw => { const salt = randomBytes(16).toString('hex'); return { salt, hash: scryptSync(pw, salt, 32).toString('hex') }; };
const check = (rec, pw) => { if (!rec) return false; const h = scryptSync(String(pw), rec.salt, 32); return timingSafeEqual(h, Buffer.from(rec.hash, 'hex')); };
const dir = () => T('_dir');
function setPw(email, pw, temp) { const u = Object.values(dir()).find(x => x.email === email); if (!u) throw Object.assign(new Error('no user'), { code: 'not_found' });
  Object.assign(u, hash(pw), { status: temp ? 'FORCE_CHANGE_PASSWORD' : 'CONFIRMED' }); save(); }
if (!dir()[subOf(OWNER)]) { const pw = process.env.OWNER_PASSWORD || 'owner1234'; dir()[subOf(OWNER)] = { sub: subOf(OWNER), email: OWNER, name: 'Owner', enabled: true, created: new Date().toISOString() }; setPw(OWNER, pw, true);
  console.log(`[dev] owner account ${OWNER} — temporary password: ${pw}`); }
const users = {
  async create({ email, name, password, temporary }) { const sub = subOf(email); dir()[sub] = Object.assign(dir()[sub] || {}, { sub, email, name, enabled: true, created: new Date().toISOString() }); setPw(email, password, temporary); return sub; },
  async list() { return Object.values(dir()).map(({ sub, email, name, enabled, status, created, totp }) => ({ sub, email, name, enabled, status, created, mfa: !!totp })); },
  async setEnabled(sub, on) { if (dir()[sub]) { dir()[sub].enabled = on; save(); } },
  async setPassword(sub, pw, temp) { if (dir()[sub]) setPw(dir()[sub].email, pw, temp); },
  async mfaOff(sub) { if (dir()[sub]) { delete dir()[sub].totp; save(); } },
  async reset(sub) { const u = dir()[sub]; if (!u) return; u.status = 'RESET_REQUIRED'; const c = String(Math.floor(100000 + Math.random() * 900000)); T('_codes')[u.email] = c; save(); console.log(`[dev] reset code for ${u.email}: ${c}`); }
};
const issue = email => { const access = 'dev_' + randomBytes(24).toString('hex'), refresh = 'devr_' + randomBytes(24).toString('hex');
  T('_sess')[access] = { email, exp: Date.now() + 3600e3 }; T('_ref')[refresh] = email; save(); return { AccessToken: access, RefreshToken: refresh, ExpiresIn: 3600, email }; };
const fail = (code, message = '') => ({ status: 400, body: { code, message } });
const pwOk = p => typeof p === 'string' && p.length >= 8 && /\d/.test(p) && /[a-z]/.test(p);
// TOTP (RFC 6238) so the local server works with a real authenticator app
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const b32dec = s => { let bits = ''; for (const ch of s.replace(/=+$/, '').toUpperCase()) bits += B32.indexOf(ch).toString(2).padStart(5, '0'); const out = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(out); };
const totp = (secret, step) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(step)); const h = createHmac('sha1', b32dec(secret)).update(b).digest(); const o = h[19] & 15;
  return String(((h.readUInt32BE(o) & 0x7fffffff) % 1e6)).padStart(6, '0'); };
const totpOk = (secret, code) => { const st = Math.floor(Date.now() / 30000); return [-1, 0, 1].some(d => totp(secret, st + d) === String(code)); };
const userOfToken = t => { const s = T('_sess')[t]; return s && s.exp > Date.now() ? dir()[subOf(s.email)] : null; };
const AUTH_OPS = {
  'mfa-signin'({ email, session, code }) { email = String(email || '').toLowerCase(); if (T('_mfa')[session] !== email) return fail('NotAuthorizedException', 'Invalid session');
    const u = dir()[subOf(email)]; if (!u || !u.totp || !totpOk(u.totp, code)) return fail('CodeMismatchException'); delete DB._mfa[session]; save(); return { body: issue(email) }; },
  'mfa-status'({ token }) { const u = userOfToken(token); return u ? { body: { enabled: !!u.totp } } : fail('NotAuthorizedException'); },
  'mfa-assoc'({ token }) { const u = userOfToken(token); if (!u) return fail('NotAuthorizedException'); const sec = [...randomBytes(20)].map(x => B32[x % 32]).join(''); u.totpPending = sec; save(); return { body: { secret: sec } }; },
  'mfa-verify'({ token, code }) { const u = userOfToken(token); if (!u || !u.totpPending) return fail('NotAuthorizedException'); if (!totpOk(u.totpPending, code)) return fail('EnableSoftwareTokenMFAException');
    u.totp = u.totpPending; delete u.totpPending; save(); return { body: { ok: true } }; },
  'mfa-off'({ token }) { const u = userOfToken(token); if (!u) return fail('NotAuthorizedException'); delete u.totp; save(); return { body: { ok: true } }; },
  signin({ email, password }) { email = String(email || '').toLowerCase(); const u = dir()[subOf(email)];
    if (!u || !check(u, password)) return fail('NotAuthorizedException', 'Incorrect username or password.');
    if (!u.enabled) return fail('NotAuthorizedException', 'User is disabled.');
    if (u.status === 'RESET_REQUIRED') return fail('PasswordResetRequiredException');
    if (u.status === 'FORCE_CHANGE_PASSWORD') { const s = randomBytes(16).toString('hex'); T('_chal')[s] = email; save(); return { body: { challenge: 'NEW_PASSWORD', session: s } }; }
    if (u.totp) { const s = randomBytes(16).toString('hex'); T('_mfa')[s] = email; save(); return { body: { challenge: 'MFA', session: s } }; }
    return { body: issue(email) }; },
  newpw({ email, session, password }) { if (T('_chal')[session] !== String(email).toLowerCase()) return fail('NotAuthorizedException', 'Invalid session');
    if (!pwOk(password)) return fail('InvalidPasswordException'); delete DB._chal[session]; setPw(email.toLowerCase(), password, false); return { body: issue(email.toLowerCase()) }; },
  forgot({ email }) { email = String(email || '').toLowerCase(); const u = dir()[subOf(email)];
    if (u && u.status === 'FORCE_CHANGE_PASSWORD') return fail('InvalidParameterException');
    if (u && u.enabled) { const c = String(Math.floor(100000 + Math.random() * 900000)); T('_codes')[email] = c; save(); console.log(`[dev] password reset code for ${email}: ${c}`); }
    return { body: { ok: true } }; },
  confirm({ email, code, password }) { email = String(email || '').toLowerCase(); if (!T('_codes')[email] || T('_codes')[email] !== String(code)) return fail('CodeMismatchException');
    if (!pwOk(password)) return fail('InvalidPasswordException'); delete DB._codes[email]; setPw(email, password, false); return { body: { ok: true } }; },
  change({ token, old, password }) { const s = T('_sess')[token]; if (!s) return fail('NotAuthorizedException'); const u = dir()[subOf(s.email)];
    if (!check(u, old)) return fail('NotAuthorizedException', 'Incorrect password.'); if (!pwOk(password)) return fail('InvalidPasswordException'); setPw(s.email, password, false); return { body: { ok: true } }; },
  refresh({ refresh }) { const email = T('_ref')[refresh]; const u = email && dir()[subOf(email)]; if (!u || !u.enabled) return fail('NotAuthorizedException');
    const t = issue(email); delete t.RefreshToken; return { body: t }; }
};
const auth = async h => { const s = T('_sess')[h['x-bannaa-token'] || '']; if (!s || s.exp < Date.now()) return null; const u = dir()[subOf(s.email)];
  if (!u || !u.enabled) return null; return { id: 'u_' + u.sub, email: u.email, name: u.name || '' }; };
// photo protection: the browser gets an HttpOnly cookie on sign-in; /_blob/* is served only with a valid one
const cookies = async (u, h, tid) => [`bn_blob=${h['x-bannaa-token']}; Path=/_blob/; HttpOnly; SameSite=Lax; Max-Age=43200`];

/* ---------- live updates: a minimal WebSocket server (stands in for API Gateway WebSockets) ---------- */
const sockets = new Set();
function wsSend(sock, obj) { const p = Buffer.from(JSON.stringify(obj)); const h = p.length < 126 ? Buffer.from([0x81, p.length]) : Buffer.from([0x81, 126, p.length >> 8, p.length & 255]); try { sock.write(Buffer.concat([h, p])); } catch (e) {} }
const broadcast = async (tid, path) => { for (const c of sockets) if (c.tid === tid) wsSend(c.sock, { type: 'changed', path }); };
// presigned upload emulation: the browser PUTs the file to /api/upload/<key>?sig=…
const SIGS = new Map();
const presign = async (key, ct) => { const sig = randomBytes(16).toString('hex'); SIGS.set(sig, { key, exp: Date.now() + 900e3 }); return { uploadUrl: `/api/upload?sig=${sig}`, method: 'PUT', headers: { 'content-type': ct } }; };
const mail = async m => console.log('\n[mail] to', m.to.join(','), '—', m.subject, '\n' + m.text + '\n');
let core;
core = makeCore({ store, blobs, auth, mail, users, cookies, broadcast, presign, ownerEmail: OWNER,
  startJob: async job => { setTimeout(() => core.runJob(job, { getKey: async () => process.env.ANTHROPIC_API_KEY || '', model: process.env.MODEL || 'claude-sonnet-4-5', modelComplex: process.env.MODEL_COMPLEX || 'claude-sonnet-4-5' }), 0); } });

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg' };
http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const chunks = []; for await (const c of req) chunks.push(c);
  if (url.pathname === '/api/upload' && req.method === 'PUT') {
    const s = SIGS.get(url.searchParams.get('sig')); if (!s || s.exp < Date.now()) { res.writeHead(403); return res.end(); }
    SIGS.delete(url.searchParams.get('sig')); await blobs.put(s.key, Buffer.concat(chunks), req.headers['content-type'] || 'application/octet-stream'); res.writeHead(200); return res.end();
  }
  if (url.pathname.startsWith('/api/auth/') && req.method === 'POST') {
    const op = AUTH_OPS[url.pathname.slice(10)]; let body = {}; try { body = JSON.parse(Buffer.concat(chunks).toString() || '{}'); } catch (e) {}
    const r = op ? op(body) : fail('NotFound'); res.writeHead(r.status || 200, { 'content-type': 'application/json' }); return res.end(JSON.stringify(r.body));
  }
  if (url.pathname.startsWith('/api/')) {
    const ev = { requestContext: { http: { method: req.method } }, rawPath: url.pathname, queryStringParameters: Object.fromEntries(url.searchParams), headers: req.headers, body: Buffer.concat(chunks).toString('base64'), isBase64Encoded: true };
    const r = await core.handler(ev); const hd = Object.assign({}, r.headers); if (r.cookies) hd['set-cookie'] = r.cookies; res.writeHead(r.statusCode, hd); return res.end(r.body);
  }
  if (url.pathname.startsWith('/_blob/')) {
    const ck = Object.fromEntries(String(req.headers.cookie || '').split(/;\s*/).filter(Boolean).map(x => x.split('=')));
    const bu = await auth({ 'x-bannaa-token': ck.bn_blob || '' });
    if (!bu || url.pathname.split('/')[2] !== await tenantOf(store, bu, OWNER)) { res.writeHead(403); return res.end('sign in required'); }   // files of your own company only
    const o = await blobs.get(url.pathname.slice(1)); if (!o) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'content-type': o.ct }); return res.end(o.buf); }
  if (url.pathname === '/config.js') { res.writeHead(200, { 'content-type': TYPES['.js'] }); return res.end(`window.BANNAA_CONFIG={dev:true,wsUrl:'ws://'+location.host+'/ws'};`); }
  const f = join(WEB, url.pathname === '/' ? 'index.html' : url.pathname.replace(/\.\./g, ''));
  if (!existsSync(f)) { res.writeHead(404); return res.end('not found'); }
  res.writeHead(200, { 'content-type': TYPES[extname(f)] || 'application/octet-stream' }); res.end(readFileSync(f));
}).on('upgrade', async (req, sock) => {
  const url = new URL(req.url, 'http://x'); const u = await auth({ 'x-bannaa-token': url.searchParams.get('t') || '' });
  if (url.pathname !== '/ws' || !u) { sock.end('HTTP/1.1 401 Unauthorized\r\n\r\n'); return; }
  const acc = createHash('sha1').update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  sock.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${acc}\r\n\r\n`);
  const c = { sock, tid: await tenantOf(store, u, OWNER) }; sockets.add(c);
  sock.on('data', b => { if ((b[0] & 15) === 8) sock.end(); }); sock.on('close', () => sockets.delete(c)); sock.on('error', () => sockets.delete(c));
}).listen(PORT, () => console.log(`Bannaa dev server: http://localhost:${PORT}  (owner: ${OWNER})`));
