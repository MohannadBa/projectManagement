// Local dev server: http://localhost:8080 — same backend logic as AWS, data kept in dev/data.json.
// Run: OWNER_EMAIL=you@company.com [ANTHROPIC_API_KEY=...] node dev/server.mjs
import http from 'node:http';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, extname, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeCore } from '../backend/core.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const WEB = join(ROOT, 'web'), DATA = join(ROOT, 'dev', 'data.json'), BLOBS = join(ROOT, 'dev', 'blobs');
const PORT = +process.env.PORT || 8080, OWNER = process.env.OWNER_EMAIL || 'owner@example.com';
mkdirSync(BLOBS, { recursive: true });
let DB = existsSync(DATA) ? JSON.parse(readFileSync(DATA, 'utf8')) : {};
if (!existsSync(DATA) && existsSync(join(ROOT, 'seed', 'seed.json'))) DB = JSON.parse(readFileSync(join(ROOT, 'seed', 'seed.json'), 'utf8'));
let saveT; const save = () => { clearTimeout(saveT); saveT = setTimeout(() => writeFileSync(DATA, JSON.stringify(DB)), 200); };
const store = {
  async get(pk, sk) { const v = (DB[pk] || {})[sk]; return v === undefined ? null : JSON.parse(JSON.stringify(v)); },
  async put(pk, sk, d) { (DB[pk] = DB[pk] || {})[sk] = JSON.parse(JSON.stringify(d)); save(); },
  async del(pk, sk) { if (DB[pk]) delete DB[pk][sk]; save(); },
  async list(pk) { return Object.entries(DB[pk] || {}).map(([id, data]) => ({ id, data })); }
};
const blobs = {
  async put(key, buf, ct) { const f = join(BLOBS, key.replace(/\//g, '__')); writeFileSync(f, buf); writeFileSync(f + '.ct', ct); },
  async get(key) { const f = join(BLOBS, key.replace(/\//g, '__')); return existsSync(f) ? { buf: readFileSync(f), ct: readFileSync(f + '.ct', 'utf8') } : null; }
};
// dev tokens look like "dev:email:name" — the sign-in form in claude-shim.js creates them
const auth = async h => { const t = h['x-bannaa-token'] || ''; if (!t.startsWith('dev:')) return null; const [, email, name] = t.split(':');
  if (!email) return null; const sub = 'dev_' + Buffer.from(email.toLowerCase()).toString('hex').slice(0, 20); const d = (DB._dir || {})[sub];
  if (d && !d.enabled) return null;
  return { id: 'u_' + sub, email: email.toLowerCase(), name: decodeURIComponent(name || '') || (d && d.name) || '' }; };
const mail = async m => console.log('\n[mail] to', m.to.join(','), '—', m.subject, '\n' + m.text + '\n');
// dev user directory (stands in for Cognito)
const users = {
  async create({ email, name }) { const sub = 'dev_' + Buffer.from(email).toString('hex').slice(0, 20); (DB._dir = DB._dir || {})[sub] = { sub, email, name, enabled: true, status: 'CONFIRMED', created: new Date().toISOString() }; save(); return sub; },
  async list() { const d = Object.values(DB._dir || {}); if (!d.some(x => x.email === OWNER.toLowerCase())) d.push({ sub: 'dev_' + Buffer.from(OWNER.toLowerCase()).toString('hex').slice(0, 20), email: OWNER.toLowerCase(), name: 'Owner', enabled: true, status: 'CONFIRMED' }); return d; },
  async setEnabled(sub, on) { if (DB._dir && DB._dir[sub]) { DB._dir[sub].enabled = on; save(); } },
  async reset(sub) { if (DB._dir && DB._dir[sub]) { DB._dir[sub].status = 'RESET_REQUIRED'; save(); } console.log('[reset password]', sub); }
};
let core;
core = makeCore({ store, blobs, auth, mail, users, ownerEmail: OWNER,
  startJob: async job => { setTimeout(() => core.runJob(job, { getKey: async () => process.env.ANTHROPIC_API_KEY || '', model: process.env.MODEL || 'claude-sonnet-4-5', modelComplex: process.env.MODEL_COMPLEX || 'claude-sonnet-4-5' }), 0); } });

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg' };
http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname.startsWith('/api/')) {
    const chunks = []; for await (const c of req) chunks.push(c);
    const ev = { requestContext: { http: { method: req.method } }, rawPath: url.pathname, queryStringParameters: Object.fromEntries(url.searchParams), headers: req.headers, body: Buffer.concat(chunks).toString('base64'), isBase64Encoded: true };
    const r = await core.handler(ev); res.writeHead(r.statusCode, r.headers); return res.end(r.body);
  }
  if (url.pathname.startsWith('/_blob/')) { const o = await blobs.get(url.pathname.slice(1)); if (!o) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'content-type': o.ct }); return res.end(o.buf); }
  if (url.pathname === '/config.js') { res.writeHead(200, TYPES['.js']); return res.end('window.BANNAA_CONFIG={dev:true};'); }
  const f = join(WEB, url.pathname === '/' ? 'index.html' : url.pathname.replace(/\.\./g, ''));
  if (!existsSync(f)) { res.writeHead(404); return res.end('not found'); }
  res.writeHead(200, { 'content-type': TYPES[extname(f)] || 'application/octet-stream' }); res.end(readFileSync(f));
}).listen(PORT, () => console.log(`Bannaa dev server: http://localhost:${PORT}  (owner: ${OWNER})`));
