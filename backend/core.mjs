// Bannaa backend core — storage/auth/mail/AI are injected so the same logic runs on AWS Lambda and on the local dev server.
import { randomBytes } from 'node:crypto';

const lc = s => String(s || '').trim().toLowerCase();
const J = (code, obj) => ({ statusCode: code, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }, body: JSON.stringify(obj) });
const PATH_RE = /^[A-Za-z0-9_\-.~:@+]+(\/[A-Za-z0-9_\-.~:@+]+)*$/;
const domOk = (t, e) => (t.domains || []).map(lc).includes(lc(e).split('@')[1] || '');

// '__owner' = the platform owner (OWNER_EMAIL). Member roles: pm, eng, owner (the client), acc, admin (user management only).
export const ROLES = ['pm', 'eng', 'owner', 'acc', 'admin'];
const RN = { pm: 'مدير المشروع', eng: 'مهندس الموقع', owner: 'مالك المشروع', acc: 'المحاسب', admin: 'مدير النظام' };
export function roleOf(u, t, ownerEmail) {
  if (u.email && u.email === lc(ownerEmail)) return '__owner';
  const m = (t.members || {})[u.id]; if (m) return m.role;
  const inv = (t.invites || {})[u.email]; if (inv && inv.status !== 'revoked' && domOk(t, u.email)) return inv.role;
  if (t.autoJoin && t.autoJoin.on && domOk(t, u.email)) return t.autoJoin.role;
  return null;
}
const isMgr = r => r === '__owner' || r === 'admin';      // may add users, change roles, edit team settings
const isMember = r => !!r && r !== 'admin';                // may read and write project data

export function makeCore({ store, blobs, auth, mail, startJob, ownerEmail, users }) {
  const team = async () => (await store.get('team', 'members')) || {};

  async function handler(ev) {
    const method = ev.requestContext.http.method;
    const path = ev.rawPath.replace(/^\/api/, '') || '/';
    const q = ev.queryStringParameters || {};
    const headers = Object.fromEntries(Object.entries(ev.headers || {}).map(([k, v]) => [k.toLowerCase(), v]));
    const raw = () => { const b = ev.body || ''; return ev.isBase64Encoded ? Buffer.from(b, 'base64') : Buffer.from(b); };
    const json = () => { const t = raw().toString('utf8'); return t ? JSON.parse(t) : {}; };

    const u = await auth(headers);
    if (!u) return J(401, { code: 'unauthorized' });
    const t = await team();
    const role = roleOf(u, t, ownerEmail);
    const member = isMember(role);
    const log = async text => { const tt = await team(); tt.log = (tt.log || []).concat([{ at: new Date().toISOString(), by: u.email, text }]).slice(-300); await store.put('team', 'members', tt); };

    try {
      if (path === '/me') {
        await store.put('_users', u.id, { id: u.id, email: u.email, name: u.name, lastLogin: new Date().toISOString() });
        return J(200, { id: u.id, email: u.email, name: u.name, role, isOwner: role === '__owner', canEdit: isMgr(role) });
      }

      if (path === '/db') {
        const p = String(q.path || q.col || '');
        if (!PATH_RE.test(p) || p.startsWith('_') || p.split('/').length > 15) return J(400, { code: 'bad_path' });
        const segs = p.split('/'), top = segs[0];
        const openRead = top === 'team' || top === 'requests';
        if (method === 'GET') {
          if (!openRead && !member) return J(403, { code: 'not_member' });
          if (q.col) return J(200, { docs: await store.list(p) });
          const sk = segs.pop(); const d = await store.get(segs.join('/'), sk);
          return J(200, { exists: d != null, data: d });
        }
        const sk = segs[segs.length - 1], pk = segs.slice(0, -1).join('/');
        if (!pk) return J(400, { code: 'bad_path' });
        let ok = false;
        if (top === 'team') ok = isMgr(role);
        else if (top === 'requests') ok = sk === u.id || isMgr(role);
        else ok = member;
        if (!ok) return J(403, { code: 'permission_denied' });
        if (method === 'PUT') { await store.put(pk, sk, json()); return J(200, { ok: true }); }
        if (method === 'DELETE') { await store.del(pk, sk); return J(200, { ok: true }); }
        return J(405, { code: 'method' });
      }

      if (path === '/profiles' && method === 'POST') {
        const { ids = [] } = json(); const out = {};
        for (const id of [].concat(ids).slice(0, 200)) out[id] = (await store.get('_users', String(id))) || null;
        return J(200, out);
      }
      if (path === '/search') {
        if (!member) return J(200, []);
        const s = lc(q.q); const all = (await store.list('_users')).map(x => x.data);
        return J(200, all.filter(x => !s || lc(x.name).includes(s) || lc(x.email).includes(s)).slice(0, 8));
      }

      if (path === '/assets' && method === 'POST') {
        if (!member) return J(403, { code: 'not_granted' });
        const b = raw(); const ct = headers['content-type'] || 'application/octet-stream';
        if (b.length > 15e6) return J(413, { code: 'too_large' });
        if (!/^(image\/(jpeg|png|webp|gif)|application\/pdf)/.test(ct)) return J(415, { code: 'unsupported_type' });
        const id = randomBytes(16).toString('hex');
        await blobs.put((q.tmp ? '_tmp/' : '_blob/') + id, b, ct);
        return J(200, { id, url: '/_blob/' + id, sizeBytes: b.length, contentType: ct });
      }

      if (path === '/ai' && method === 'POST') {
        if (!member) return J(403, { code: 'not_granted' });
        const { prompt, images = [], tier } = json();
        if (!prompt) return J(400, { code: 'bad_request' });
        const id = randomBytes(12).toString('hex');
        await store.put('_jobs', id, { status: 'running', uid: u.id }, Math.floor(Date.now() / 1000) + 86400);
        await startJob({ id, uid: u.id, prompt: String(prompt), images: images.slice(0, 20), tier });
        return J(200, { job: id });
      }
      if (path === '/ai' && method === 'GET') {
        const d = await store.get('_jobs', String(q.job || ''));
        if (!d || d.uid !== u.id) return J(404, { code: 'not_found' });
        return J(200, d);
      }

      if (path === '/mail' && method === 'POST') {
        if (!isMgr(role)) return J(403, { code: 'not_granted' });
        const { to, subject, body, html } = json();
        const list = [].concat(to || []).map(lc).filter(e => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)).slice(0, 5);
        if (!list.length) return J(400, { code: 'bad_request' });
        await mail({ to: list, subject: String(subject || ''), text: String(body || ''), html: html ? String(html) : '' });
        return J(200, { ok: true });
      }

      /* ---------- user management: platform owner and the admin role ---------- */
      if (path.startsWith('/users')) {
        if (!isMgr(role)) return J(403, { code: 'permission_denied' });
        const tt = await team(); tt.members = tt.members || {};
        if (path === '/users' && method === 'GET') {
          const dir = await users.list(), seen = await store.list('_users'), last = Object.fromEntries(seen.map(x => [x.id, x.data.lastLogin]));
          return J(200, dir.map(d => { const id = 'u_' + d.sub, m = tt.members[id] || {}, own = d.email === lc(ownerEmail);
            const status = !d.enabled ? 'disabled' : d.status === 'RESET_REQUIRED' ? 'reset' : !last[id] ? 'never' : 'active';
            return { id, email: d.email, name: d.name || m.name || '', role: own ? 'pm' : m.role || null, isOwner: own, status, lastLogin: last[id] || null, created: d.created }; }));
        }
        if (path === '/users' && method === 'POST') {
          const b = json(); const email = lc(b.email), name = String(b.name || '').slice(0, 80);
          if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || !ROLES.includes(b.role)) return J(400, { code: 'bad_request' });
          if ((tt.domains || []).length && !domOk(tt, email)) return J(400, { code: 'domain_not_allowed' });
          if (email === lc(ownerEmail)) return J(400, { code: 'exists' });
          const sub = await users.create({ email, name });
          tt.members['u_' + sub] = { role: b.role, email, name, added: new Date().toISOString().slice(0, 10), via: 'مدير النظام' };
          tt.log = (tt.log || []).concat([{ at: new Date().toISOString(), by: u.email, text: `إضافة ${email} بدور ${RN[b.role]}` }]).slice(-300);
          await store.put('team', 'members', tt);
          let sent = false;
          try { const link = (headers.origin || '').replace(/\/$/, '') + '/';
            await mail({ to: [email], subject: 'حسابك في منصة بنّاء — Bannaa account', text:
              `مرحباً ${name},\n\nأُنشئ لك حساب في منصة بنّاء لإدارة المشاريع الإنشائية.\n\nطريقة الدخول أول مرة:\n1) افتح الرابط: ${link}\n2) اضغط "Forgot your password?"\n3) اكتب بريدك: ${email}\n4) سيصلك رمز على بريدك — أدخله واختر كلمة المرور الخاصة بك\n5) ادخل بالبريد وكلمة المرور الجديدة\n\nWelcome to Bannaa. First sign-in: open ${link}, click "Forgot your password?", enter ${email}, and set your own password with the code you receive.`,
              html: `<div dir="rtl" style="font-family:Tahoma,Arial,sans-serif;font-size:15px;line-height:1.8;color:#1C1A16;max-width:560px"><div style="background:#14110C;color:#C9983F;padding:16px 20px;border-radius:10px 10px 0 0;font-size:20px;font-weight:bold">بنّاء</div><div style="border:1px solid #E6E2DA;border-top:0;padding:20px;border-radius:0 0 10px 10px"><p>مرحباً ${name.replace(/[<>&]/g, '')}،</p><p>أُنشئ لك حساب في منصة بنّاء لإدارة المشاريع الإنشائية.</p><p style="text-align:center;margin:22px 0"><a href="${link}" style="background:#94701F;color:#fff;padding:12px 26px;border-radius:8px;text-decoration:none;font-weight:bold">فتح المنصة</a></p><ol><li>اضغط <b dir="ltr">Forgot your password?</b></li><li>اكتب بريدك: <b dir="ltr">${email}</b></li><li>أدخل الرمز الذي يصلك واختر كلمة المرور</li><li>ادخل بالبريد وكلمة المرور الجديدة</li></ol></div></div>` });
            sent = true; } catch (e) { console.error('welcome mail', e); }
          return J(200, { id: 'u_' + sub, mail: sent });
        }
        if (path === '/users' && method === 'PATCH') {
          const { id, role: nr } = json();
          if (!tt.members[id] || !ROLES.includes(nr)) return J(400, { code: 'bad_request' });
          const old = tt.members[id].role; tt.members[id].role = nr; await store.put('team', 'members', tt);
          await log(`تغيير دور ${tt.members[id].email}: ${RN[old] || old} ← ${RN[nr]}`); return J(200, { ok: true });
        }
        if (path === '/users/status' && method === 'POST') {
          const { id, on } = json(); const m = tt.members[id]; if (!m || id === u.id) return J(400, { code: 'bad_request' });
          await users.setEnabled(String(id).replace(/^u_/, ''), !!on); await log(`${on ? 'تفعيل' : 'إيقاف'} حساب ${m.email}`); return J(200, { ok: true });
        }
        if (path === '/users/reset' && method === 'POST') {
          const { id } = json(); const m = tt.members[id]; if (!m) return J(400, { code: 'bad_request' });
          await users.reset(String(id).replace(/^u_/, '')); await log(`إعادة تعيين كلمة مرور ${m.email}`); return J(200, { ok: true });
        }
        if (path === '/users/domains' && method === 'POST') {
          if (role !== '__owner') return J(403, { code: 'permission_denied' });
          const ds = [...new Set([].concat(json().domains || []).map(lc).filter(x => /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(x)))];
          tt.domains = ds; await store.put('team', 'members', tt); await log(`نطاق البريد: ${ds.join(', ') || 'أي نطاق'}`); return J(200, { ok: true });
        }
        return J(404, { code: 'not_found' });
      }

      return J(404, { code: 'not_found' });
    } catch (e) {
      console.error(e);
      return J(500, { code: e.code || 'server_error', message: String(e.message || e) });
    }
  }

  async function runJob(j, { getKey, model, modelComplex }) {
    const ttl = Math.floor(Date.now() / 1000) + 86400;
    try {
      const key = await getKey();
      if (!key) { await store.put('_jobs', j.id, { status: 'error', code: 'sampling_disabled', uid: j.uid }, ttl); return; }
      const content = [];
      for (const id of j.images || []) {
        if (!/^[a-f0-9]{32}$/.test(id)) continue;
        const o = await blobs.get('_tmp/' + id); if (!o) continue;
        content.push({ type: 'image', source: { type: 'base64', media_type: o.ct || 'image/jpeg', data: o.buf.toString('base64') } });
      }
      content.push({ type: 'text', text: j.prompt });
      const res = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
        body: JSON.stringify({ model: j.tier === 'complex' ? modelComplex : model, max_tokens: 8192, system: 'Reply with valid JSON only — no prose, no code fences.', messages: [{ role: 'user', content }] })
      });
      const d = await res.json().catch(() => ({}));
      if (!res.ok) {
        const code = res.status === 429 || res.status === 529 ? 'rate_limited' : res.status === 413 ? 'prompt_too_large' : res.status === 401 ? 'sampling_disabled' : 'upstream_error';
        await store.put('_jobs', j.id, { status: 'error', code, message: (d.error && d.error.message) || String(res.status), uid: j.uid }, ttl); return;
      }
      const text = (d.content || []).filter(c => c.type === 'text').map(c => c.text).join('');
      await store.put('_jobs', j.id, { status: 'done', text, uid: j.uid }, ttl);
    } catch (e) {
      await store.put('_jobs', j.id, { status: 'error', code: 'upstream_error', message: String(e.message || e), uid: j.uid }, ttl);
    }
  }

  return { handler, runJob };
}
