// Bannaa backend core — storage/auth/mail/AI are injected so the same logic runs on AWS Lambda and on the local dev server.
import { randomBytes } from 'node:crypto';
import { makeDocs, STRUCT } from './docs.mjs';

const lc = s => String(s || '').trim().toLowerCase();
const J = (code, obj, cookies) => Object.assign({ statusCode: code, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }, body: JSON.stringify(obj) }, cookies && cookies.length ? { cookies } : {});
const PATH_RE = /^[A-Za-z0-9_\-.~:@+]+(\/[A-Za-z0-9_\-.~:@+]+)*$/;
const domOk = (t, e) => (t.domains || []).map(lc).includes(lc(e).split('@')[1] || '');

// '__owner' = the platform owner (OWNER_EMAIL). Member roles: pm, eng, owner (the client), acc, admin (user management only).
export const ROLES = ['pm', 'eng', 'owner', 'acc', 'admin'];
const RN = { pm: 'مدير المشروع', eng: 'مهندس الموقع', owner: 'مالك المشروع', acc: 'المحاسب', admin: 'مدير النظام' };
export function roleOf(u, t, operator) {
  if (operator) return '__owner';
  const m = (t.members || {})[u.id]; if (m) return m.super ? '__owner' : m.role;
  const inv = (t.invites || {})[u.email]; if (inv && inv.status !== 'revoked' && domOk(t, u.email)) return inv.role;
  if (t.autoJoin && t.autoJoin.on && domOk(t, u.email)) return t.autoJoin.role;
  return null;
}
const pwOk = p => typeof p === 'string' && p.length >= 8 && p.length <= 128 && /\d/.test(p) && /[a-z]/.test(p);
const isMgr = r => r === '__owner' || r === 'admin';      // may add users, change roles, edit team settings
const isMember = r => !!r && r !== 'admin' && r !== '__platform';               // may read and write project data

// which projects a user may open: platform owner → all; admin → none; others → their assigned list ('*' = all)
export function projectAccess(u, role, t) {
  if (role === '__owner') return '*';
  if (!role || role === 'admin') return [];
  const m = (t.members || {})[u.id];
  if (!m || m.projects === undefined || m.projects === '*') return '*';
  return Array.isArray(m.projects) ? m.projects : [];
}
const canOpen = (acc, pid) => acc === '*' || acc.includes(pid);

// Multi-company: every company (tenant) has its own team, settings, projects and files. The first company ('t1')
// keeps un-prefixed keys so existing data needs no migration; other companies' keys are prefixed with T#<id>|.
export const DEFAULT_TENANT = 't1';
const DEFAULT_NAME = process.env.COMPANY_NAME || 'الراسيات';
const TID_RE = /^[a-z][a-z0-9-]{1,30}$/;
export function scoped(gstore, tid) {
  const pre = tid === DEFAULT_TENANT ? '' : `T#${tid}|`, k = pk => pre + pk;
  return {
    get: (pk, sk) => gstore.get(k(pk), sk), put: (pk, sk, d, ttl) => gstore.put(k(pk), sk, d, ttl), del: (pk, sk) => gstore.del(k(pk), sk),
    list: pk => gstore.list(k(pk)), items: pk => gstore.items(k(pk)),
    txn: ops => gstore.txn(ops.map(op => op.put ? Object.assign({}, op, { put: Object.assign({}, op.put, { pk: k(op.put.pk) }) }) : Object.assign({}, op, { del: Object.assign({}, op.del, { pk: k(op.del.pk) }) })))
  };
}
// platform administrators (OWNER_EMAIL + any added later) belong to no company and see no project data
export const PLATFORM = '__platform';
export async function tenantOf(gstore, u, ownerEmail) {
  if (ownerEmail && u.email === lc(ownerEmail)) return PLATFORM;
  const m = await gstore.get('_tenantOf', u.id);
  return (m && m.tid) || DEFAULT_TENANT;
}
const HEX_RE = /^#[0-9a-fA-F]{6}$/;
const LOGO_RE = /^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/;
// name, main colour, secondary colour and logo (small data URL, so it shows without signed cookies)
function brandFields(cur, b) {
  if (b.name !== undefined) { const n = String(b.name).trim().slice(0, 120); if (n) cur.name = n; }
  if (b.color1 !== undefined) cur.color1 = HEX_RE.test(b.color1) ? b.color1 : null;
  if (b.color2 !== undefined) cur.color2 = HEX_RE.test(b.color2) ? b.color2 : null;
  if (b.logo !== undefined) { if (b.logo && (!LOGO_RE.test(b.logo) || b.logo.length > 200000)) { const e = new Error('الشعار: صورة PNG/JPEG/WebP أصغر من 150 كيلوبايت'); e.code = 'bad_request'; throw e; } cur.logo = b.logo || null; }
  return cur;
}
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

export function makeCore({ store: gstore, blobs, auth, mail, startJob, ownerEmail, users, cookies, broadcast = async () => {}, presign }) {
  async function welcome({ email, name, password, temporary, sendPassword, origin, company, roleName }) {
    const link = (origin || '').replace(/\/$/, '') + '/', esc = x => String(x).replace(/[<>&"]/g, '');
    const pwLine = sendPassword ? `كلمة المرور${temporary ? ' المؤقتة' : ''}: ${password}` : 'كلمة المرور: يزوّدك بها مدير النظام';
    const intro = `أُنشئ لك حساب في منصة بنّاء لإدارة المشاريع الإنشائية${company ? ` — ${company}` : ''}${roleName ? ` بدور ${roleName}` : ''}.`;
    await mail({ to: [email], subject: 'حسابك في منصة بنّاء — Bannaa account', text:
      `مرحباً ${name},\n\n${intro}\n\nالرابط: ${link}\nالبريد: ${email}\n${pwLine}\n${temporary ? 'سيُطلب منك اختيار كلمة مرور جديدة عند أول دخول.\n' : ''}نسيت كلمة المرور؟ اضغط "نسيت كلمة المرور؟" في صفحة الدخول.\n\nBannaa account created for ${email}. Sign in at ${link}`,
      html: `<div dir="rtl" style="font-family:Tahoma,Arial,sans-serif;font-size:15px;line-height:1.8;color:#1C1A16;max-width:560px"><div style="background:#14110C;color:#C9983F;padding:16px 20px;border-radius:10px 10px 0 0;font-size:20px;font-weight:bold">بنّاء</div><div style="border:1px solid #E6E2DA;border-top:0;padding:20px;border-radius:0 0 10px 10px"><p>مرحباً ${esc(name)}،</p><p>${esc(intro)}</p><p>البريد: <b dir="ltr">${esc(email)}</b><br>${esc(pwLine).replace(/: (.*)$/, ': <b dir="ltr">$1</b>')}</p>${temporary ? '<p>سيُطلب منك اختيار كلمة مرور جديدة عند أول دخول.</p>' : ''}<p style="text-align:center;margin:22px 0"><a href="${esc(link)}" style="background:#94701F;color:#fff;padding:12px 26px;border-radius:8px;text-decoration:none;font-weight:bold">تسجيل الدخول</a></p><p style="color:#6E685E;font-size:13px">نسيت كلمة المرور؟ اضغط «نسيت كلمة المرور؟» في صفحة الدخول.</p></div></div>` });
  }
  const safeWelcome = async o => { try { await welcome(o); return true; } catch (e) { console.error('welcome mail', e); return false; } };
  const userStatus = (d, last) => !d.enabled ? 'disabled' : d.status === 'RESET_REQUIRED' ? 'reset' : d.status === 'FORCE_CHANGE_PASSWORD' ? 'temp' : !last ? 'never' : 'active';

  async function handler(ev) {
    const method = ev.requestContext.http.method;
    const path = ev.rawPath.replace(/^\/api/, '') || '/';
    const q = ev.queryStringParameters || {};
    const headers = Object.fromEntries(Object.entries(ev.headers || {}).map(([k, v]) => [k.toLowerCase(), v]));
    const raw = () => { const b = ev.body || ''; return ev.isBase64Encoded ? Buffer.from(b, 'base64') : Buffer.from(b); };
    const json = () => { const t = raw().toString('utf8'); return t ? JSON.parse(t) : {}; };

    const u = await auth(headers);
    if (!u) return J(401, { code: 'unauthorized' });
    const tid = await tenantOf(gstore, u, ownerEmail);
    const operator = tid === PLATFORM, primary = u.email === lc(ownerEmail);
    const tenant = operator ? { id: PLATFORM, name: 'إدارة المنصة', active: true } : (await gstore.get('TENANTS', tid)) || { id: tid, name: tid === DEFAULT_TENANT ? DEFAULT_NAME : tid, active: true };
    if (tenant.active === false && !operator) return J(403, { code: 'tenant_suspended', message: 'حساب الشركة موقوف — تواصل مع مزوّد المنصة' });
    const store = scoped(gstore, tid), docs = makeDocs(store);
    const team = async () => (await store.get('team', 'members')) || {};
    const changed = path => broadcast(tid, path).catch(e => console.error('broadcast', e));
    const t = await team();
    const role = operator ? '__platform' : roleOf(u, t, false);
    const member = isMember(role);
    const log = async text => { const tt = await team(); tt.log = (tt.log || []).concat([{ at: new Date().toISOString(), by: u.email, text }]).slice(-300); await store.put('team', 'members', tt); changed('team/members'); };

    try {
      if (path === '/me') {
        if (operator) await gstore.put('_platformSeen', u.id, { at: new Date().toISOString() });
        else await store.put('_users', u.id, { id: u.id, email: u.email, name: u.name, lastLogin: new Date().toISOString() });
        return J(200, { id: u.id, email: u.email, name: u.name, role, isOwner: role === '__owner', canEdit: isMgr(role), isOperator: operator, isPrimary: primary,
          tenant: { id: tid, name: tenant.name, logo: tenant.logo || null, color1: tenant.color1 || null, color2: tenant.color2 || null } }, member || isMgr(role) ? await cookies(u, headers, tid) : []);
      }
      // refreshes the signed cookie that lets the browser load this company's protected files (/_blob/<company>/*)
      if (path === '/blobcookie') return J(200, { ok: member }, member || isMgr(role) ? await cookies(u, headers, tid) : []);

      /* ---------- platform administration: companies and platform admins ---------- */
      if (operator) {
        const tmapP = async () => Object.fromEntries((await gstore.list('_tenantOf')).map(x => [x.id, x.data.tid]));
        const tidOfUser = (tm, d) => d.email === lc(ownerEmail) ? PLATFORM : tm['u_' + d.sub] || DEFAULT_TENANT;
        const getT = async id => (await gstore.get('TENANTS', id)) || (id === DEFAULT_TENANT ? { name: DEFAULT_NAME, active: true } : null);
        const b = method === 'GET' ? {} : json();
        if (path === '/tenants' && method === 'GET') {
          const list = await gstore.list('TENANTS'), all = list.some(x => x.id === DEFAULT_TENANT) ? list : [{ id: DEFAULT_TENANT, data: { name: DEFAULT_NAME, active: true } }].concat(list);
          const tm = await tmapP(), dir = await users.list(), out = [];
          for (const x of all) {
            const sc = scoped(gstore, x.id), mem = ((await sc.get('team', 'members')) || {}).members || {};
            const inT = dir.filter(d => tidOfUser(tm, d) === x.id);
            out.push(Object.assign({ id: x.id, users: inT.length, admins: inT.filter(d => { const m = mem['u_' + d.sub]; return m && (m.role === 'admin' || m.super); }).length,
              projects: (await sc.list('PRJIDX')).length + (await sc.list('projects')).length }, x.data));
          }
          return J(200, out);
        }
        if (path === '/tenants' && method === 'POST') {
          const id = lc(b.id), a = b.admin || {}, email = lc(a.email), name = String(b.name || '').trim().slice(0, 120);
          if (!TID_RE.test(id) || id === DEFAULT_TENANT || !name) return J(400, { code: 'bad_request', message: 'اسم الشركة مطلوب، والرمز حروف إنجليزية صغيرة وأرقام وشرطة (2–31)' });
          if (await gstore.get('TENANTS', id)) return J(400, { code: 'exists', message: 'رمز الشركة مستخدم' });
          if (!EMAIL_RE.test(email) || !pwOk(a.password)) return J(400, { code: 'bad_request', message: 'تحقق من بريد وكلمة مرور مدير نظام الشركة' });
          if (email === lc(ownerEmail) || (await users.list()).some(x => x.email === email)) return J(400, { code: 'exists', message: 'هذا البريد مسجّل مسبقاً على المنصة' });
          const rec = brandFields({ name, active: true, created: new Date().toISOString(), by: u.email }, b);
          await gstore.put('TENANTS', id, rec);
          const temporary = a.temporary !== false, aname = String(a.name || '').slice(0, 80);
          const sub = await users.create({ email, name: aname, password: a.password, temporary });
          await gstore.put('_tenantOf', 'u_' + sub, { tid: id });
          const now = new Date().toISOString();
          await scoped(gstore, id).put('team', 'members', { members: { ['u_' + sub]: { role: 'admin', email, name: aname, added: now.slice(0, 10), via: 'إدارة المنصة', projects: [] } },
            domains: b.domain ? [lc(b.domain)].filter(x => /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(x)) : [], log: [{ at: now, by: u.email, text: `إنشاء الشركة ومدير النظام ${email}` }] });
          const mailed = a.sendEmail === false ? false : await safeWelcome({ email, name: aname, password: a.password, temporary, sendPassword: !!a.sendPassword, origin: headers.origin, company: name, roleName: 'مدير النظام' });
          return J(200, { ok: true, id, mail: mailed });
        }
        if (path === '/tenants' && method === 'PATCH') {
          const id = lc(b.id), cur = await getT(id);
          if (!cur) return J(404, { code: 'not_found' });
          brandFields(cur, b);
          if (b.active !== undefined && id !== DEFAULT_TENANT) cur.active = !!b.active;
          await gstore.put('TENANTS', id, cur); return J(200, { ok: true });
        }
        // a company's system admins (the platform adds the first one; they manage everyone else)
        if (path.startsWith('/tenants/admins')) {
          const id = lc(q.id || b.id), cur = await getT(id);
          if (!cur) return J(404, { code: 'not_found' });
          const sc = scoped(gstore, id), tt = (await sc.get('team', 'members')) || {}; tt.members = tt.members || {};
          const tm = await tmapP(), dir = (await users.list()).filter(d => tidOfUser(tm, d) === id);
          const tlog = async text => { tt.log = (tt.log || []).concat([{ at: new Date().toISOString(), by: u.email, text }]).slice(-300); await sc.put('team', 'members', tt); broadcast(id, 'team/members').catch(() => {}); };
          if (method === 'GET') {
            const last = Object.fromEntries((await sc.list('_users')).map(x => [x.id, x.data.lastLogin]));
            return J(200, dir.filter(d => { const m = tt.members['u_' + d.sub]; return m && (m.role === 'admin' || m.super); })
              .map(d => ({ id: 'u_' + d.sub, email: d.email, name: d.name || tt.members['u_' + d.sub].name || '', status: userStatus(d, last['u_' + d.sub]), mfa: !!d.mfa, lastLogin: last['u_' + d.sub] || null })));
          }
          if (path === '/tenants/admins' && method === 'POST') {
            const email = lc(b.email), name = String(b.name || '').slice(0, 80), temporary = b.temporary !== false;
            if (!EMAIL_RE.test(email) || !pwOk(b.password)) return J(400, { code: 'bad_request', message: 'تحقق من البريد وكلمة المرور' });
            const ex = (await users.list()).find(x => x.email === email);
            if (email === lc(ownerEmail) || ex && !dir.includes(ex)) return J(400, { code: 'exists', message: 'هذا البريد مسجّل في شركة أخرى على المنصة' });
            let sub;
            if (ex) { sub = ex.sub; await users.setPassword(sub, b.password, temporary); }
            else { sub = await users.create({ email, name, password: b.password, temporary }); if (id !== DEFAULT_TENANT) await gstore.put('_tenantOf', 'u_' + sub, { tid: id }); }
            const m = tt.members['u_' + sub] || { email, name, added: new Date().toISOString().slice(0, 10), via: 'إدارة المنصة', projects: [] };
            if (!m.super) m.role = 'admin'; tt.members['u_' + sub] = m;
            await tlog(`إدارة المنصة: تعيين ${email} مديراً للنظام`);
            const mailed = b.sendEmail === false ? false : await safeWelcome({ email, name, password: b.password, temporary, sendPassword: !!b.sendPassword, origin: headers.origin, company: cur.name, roleName: 'مدير النظام' });
            return J(200, { ok: true, id: 'u_' + sub, mail: mailed });
          }
          const m = tt.members[b.uid], d = dir.find(x => 'u_' + x.sub === b.uid);
          if (!m || !d) return J(400, { code: 'bad_request' });
          if (path === '/tenants/admins/password' && method === 'POST') {
            if (!pwOk(b.password)) return J(400, { code: 'weak_password' });
            await users.setPassword(d.sub, b.password, b.temporary !== false); await tlog(`إدارة المنصة: كلمة مرور جديدة لـ ${d.email}`); return J(200, { ok: true });
          }
          if (path === '/tenants/admins/status' && method === 'POST') { await users.setEnabled(d.sub, !!b.on); await tlog(`إدارة المنصة: ${b.on ? 'تفعيل' : 'إيقاف'} ${d.email}`); return J(200, { ok: true }); }
          if (path === '/tenants/admins/mfa-off' && method === 'POST') { await users.mfaOff(d.sub); await tlog(`إدارة المنصة: إلغاء التحقق الثنائي لـ ${d.email}`); return J(200, { ok: true }); }
          return J(404, { code: 'not_found' });
        }
        // platform administrators
        if (path.startsWith('/platform/admins')) {
          const tm = await tmapP(), dir = (await users.list()).filter(d => tidOfUser(tm, d) === PLATFORM), seen = Object.fromEntries((await gstore.list('_platformSeen')).map(x => [x.id, x.data.at]));
          if (method === 'GET') return J(200, dir.map(d => ({ id: 'u_' + d.sub, email: d.email, name: d.name || '', primary: d.email === lc(ownerEmail), self: d.email === u.email, status: userStatus(d, seen['u_' + d.sub]), mfa: !!d.mfa })));
          if (path === '/platform/admins' && method === 'POST') {
            const email = lc(b.email), name = String(b.name || '').slice(0, 80), temporary = b.temporary !== false;
            if (!EMAIL_RE.test(email) || !pwOk(b.password)) return J(400, { code: 'bad_request', message: 'تحقق من البريد وكلمة المرور' });
            if ((await users.list()).some(x => x.email === email)) return J(400, { code: 'exists', message: 'هذا البريد مسجّل مسبقاً على المنصة' });
            const sub = await users.create({ email, name, password: b.password, temporary });
            await gstore.put('_tenantOf', 'u_' + sub, { tid: PLATFORM });
            const mailed = b.sendEmail === false ? false : await safeWelcome({ email, name, password: b.password, temporary, sendPassword: !!b.sendPassword, origin: headers.origin, company: 'إدارة المنصة', roleName: 'مدير المنصة' });
            return J(200, { ok: true, id: 'u_' + sub, mail: mailed });
          }
          const d = dir.find(x => 'u_' + x.sub === b.uid);
          if (!d || d.email === lc(ownerEmail) || d.email === u.email) return J(400, { code: 'bad_request', message: 'لا يمكن تعديل المدير الرئيسي أو حسابك' });
          if (path === '/platform/admins/status' && method === 'POST') { await users.setEnabled(d.sub, !!b.on); return J(200, { ok: true }); }
          if (path === '/platform/admins/password' && method === 'POST') { if (!pwOk(b.password)) return J(400, { code: 'weak_password' }); await users.setPassword(d.sub, b.password, b.temporary !== false); return J(200, { ok: true }); }
          return J(404, { code: 'not_found' });
        }
        // the platform console has no company data: empty reads keep the page quiet, everything else is refused
        if (path === '/db' && method === 'GET') return J(200, q.col ? { docs: [] } : { exists: false, data: null });
        if (path === '/profiles' && method === 'POST') return J(200, {});
        if (path === '/search') return J(200, []);
        if (path === '/blobcookie') return J(200, { ok: false });
        return J(403, { code: 'permission_denied', message: 'حساب إدارة المنصة لا يصل إلى بيانات الشركات' });
      }
      if (path.startsWith('/tenants') || path.startsWith('/platform')) return J(403, { code: 'permission_denied' });

      // company branding — the company's system admin (or legacy company owner)
      if (path === '/branding' && method === 'POST') {
        if (!isMgr(role)) return J(403, { code: 'permission_denied' });
        const cur = Object.assign({ active: true }, tenant); delete cur.id;
        brandFields(cur, json()); await gstore.put('TENANTS', tid, cur); changed('team/members'); return J(200, { ok: true });
      }

      const acc = projectAccess(u, role, t);
      const limits = async () => { const s = await docs.read('settings/prices'); return (s && s.data.limits) || {}; };
      if (path === '/patch' && method === 'POST') {
        const p = String(q.path || '');
        if (!STRUCT(p)) return J(400, { code: 'bad_path' });
        if (!member) return J(403, { code: 'permission_denied', message: 'لا تملك صلاحية بيانات المشاريع' });
        const pid = p.startsWith('projects/') ? p.slice(9) : null;
        if (pid && !canOpen(acc, pid)) {
          const exists = await docs.read(p);
          if (exists || acc !== '*' && role !== 'pm') return J(403, { code: 'permission_denied', message: 'لا تملك صلاحية هذا المشروع' });
        }
        const r = await docs.patch(p, json(), { role, uid: u.id, limits: await limits() },
          a => { a.at = new Date().toISOString(); a.uid = u.id; a.role = role === '__owner' ? 'pm' : role; });
        // the creator of a new project gets access to it
        if (r.status === 200 && r.body.created && pid && acc !== '*') {
          const tt = await team(); if (tt.members && tt.members[u.id]) { const m = tt.members[u.id]; m.projects = [...new Set([].concat(Array.isArray(m.projects) ? m.projects : [], pid))]; await store.put('team', 'members', tt); }
        }
        if (r.status === 200) changed(p);
        return J(r.status, r.body);
      }
      if (path === '/delta' && method === 'POST') {
        const p = String(q.path || '');
        if (!STRUCT(p) || !member) return J(403, { code: 'permission_denied' });
        if (p.startsWith('projects/') && !canOpen(acc, p.slice(9))) return J(403, { code: 'permission_denied' });
        return J(200, await docs.delta(p, json().rev || {}));
      }
      // large files (documents, drawings) go straight to storage with a short-lived signed URL
      if (path === '/upload-url' && method === 'POST') {
        if (!member && !isMgr(role)) return J(403, { code: 'not_granted' });
        const b = json(), size = +b.size || 0, ct = String(b.type || 'application/octet-stream').slice(0, 120);
        if (size > 200e6) return J(413, { code: 'too_large', message: 'الحد الأقصى للملف 200 ميجابايت' });
        if (/html|javascript|svg/i.test(ct)) return J(415, { code: 'unsupported_type' });
        const id = tid + '/' + randomBytes(16).toString('hex');
        return J(200, Object.assign({ id, url: '/_blob/' + id }, await presign('_blob/' + id, ct)));
      }

      if (path === '/db') {
        const p = String(q.path || q.col || '');
        if (!PATH_RE.test(p) || p.startsWith('_') || p.split('/').length > 15) return J(400, { code: 'bad_path' });
        const segs = p.split('/'), top = segs[0];
        const openRead = top === 'team' || top === 'requests';
        if (method === 'GET') {
          if (!openRead && !member) return J(403, { code: 'not_member' });
          if (q.col === 'projects' || (q.col && p === 'projects')) {
            const out = [];
            for (const id of await docs.listProjects()) if (canOpen(acc, id)) { const d = await docs.read('projects/' + id); if (d) out.push({ id, data: d.data, rev: d.rev }); }
            return J(200, { docs: out });
          }
          if (!q.col && STRUCT(p)) {
            if (p.startsWith('projects/') && !canOpen(acc, p.slice(9))) return J(403, { code: 'permission_denied' });
            const d = await docs.read(p); return J(200, d ? { exists: true, data: d.data, rev: d.rev } : { exists: false, data: null });
          }
          if (q.col) return J(200, { docs: await store.list(p) });
          const sk = segs.pop(); const d = await store.get(segs.join('/'), sk);
          return J(200, { exists: d != null, data: d });
        }
        const sk = segs[segs.length - 1], pk = segs.slice(0, -1).join('/');
        if (!pk) return J(400, { code: 'bad_path' });
        if (STRUCT(p) || top === 'projects' || top === 'settings') return J(400, { code: 'use_patch', message: 'هذه البيانات تُحفظ عبر /api/patch' });
        let ok = false;
        if (top === 'team') ok = isMgr(role);
        else if (top === 'requests') ok = sk === u.id || isMgr(role);
        else ok = member;
        if (!ok) return J(403, { code: 'permission_denied' });
        if (method === 'PUT') { await store.put(pk, sk, json()); changed(p); return J(200, { ok: true }); }
        if (method === 'DELETE') { await store.del(pk, sk); changed(p); return J(200, { ok: true }); }
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
        if (!member && !(isMgr(role) && !q.tmp)) return J(403, { code: 'not_granted' });
        const b = raw(); const ct = headers['content-type'] || 'application/octet-stream';
        if (b.length > 15e6) return J(413, { code: 'too_large' });
        if (!/^(image\/(jpeg|png|webp|gif)|application\/pdf)/.test(ct)) return J(415, { code: 'unsupported_type' });
        const hex = randomBytes(16).toString('hex'), id = q.tmp ? hex : tid + '/' + hex;
        await blobs.put((q.tmp ? '_tmp/' : '_blob/') + id, b, ct);
        return J(200, { id, url: '/_blob/' + id, sizeBytes: b.length, contentType: ct });
      }

      if (path === '/ai' && method === 'POST') {
        if (!member) return J(403, { code: 'not_granted' });
        const { prompt, images = [], tier } = json();
        if (!prompt) return J(400, { code: 'bad_request' });
        const id = randomBytes(12).toString('hex');
        await gstore.put('_jobs', id, { status: 'running', uid: u.id }, Math.floor(Date.now() / 1000) + 86400);
        await startJob({ id, uid: u.id, prompt: String(prompt), images: images.slice(0, 20), tier });
        return J(200, { job: id });
      }
      if (path === '/ai' && method === 'GET') {
        const d = await gstore.get('_jobs', String(q.job || ''));
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
        const tmap = Object.fromEntries((await gstore.list('_tenantOf')).map(x => [x.id, x.data.tid]));
        const inTenant = d => d.email !== lc(ownerEmail) && (tmap['u_' + d.sub] || DEFAULT_TENANT) === tid;
        const isOwn = d => !!(tt.members['u_' + d.sub] || {}).super;
        if (path === '/users' && method === 'GET') {
          const dir = (await users.list()).filter(inTenant), seen = await store.list('_users'), last = Object.fromEntries(seen.map(x => [x.id, x.data.lastLogin]));
          const projects = []; for (const id of await docs.listProjects()) { const x = await store.get('PRJIDX', id); projects.push({ id, name: (x && x.name) || id }); }
          if (q.withProjects) return J(200, { projects, users: dir.map(d => { const id = 'u_' + d.sub, m = tt.members[id] || {}, own = isOwn(d);
            const status = !d.enabled ? 'disabled' : d.status === 'RESET_REQUIRED' ? 'reset' : d.status === 'FORCE_CHANGE_PASSWORD' ? 'temp' : !last[id] ? 'never' : 'active';
            return { id, email: d.email, name: d.name || m.name || '', role: own ? 'pm' : m.role || null, isOwner: own, status, mfa: !!d.mfa, projects: own ? '*' : m.projects === undefined ? '*' : m.projects, lastLogin: last[id] || null, created: d.created }; }) });
          return J(200, dir.map(d => { const id = 'u_' + d.sub, m = tt.members[id] || {}, own = isOwn(d);
            const status = !d.enabled ? 'disabled' : d.status === 'RESET_REQUIRED' ? 'reset' : d.status === 'FORCE_CHANGE_PASSWORD' ? 'temp' : !last[id] ? 'never' : 'active';
            return { id, email: d.email, name: d.name || m.name || '', role: own ? 'pm' : m.role || null, isOwner: own, status, lastLogin: last[id] || null, created: d.created }; }));
        }
        if (path === '/users' && method === 'POST') {
          const b = json(); const email = lc(b.email), name = String(b.name || '').slice(0, 80);
          if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || !ROLES.includes(b.role)) return J(400, { code: 'bad_request' });
          if ((tt.domains || []).length && !domOk(tt, email)) return J(400, { code: 'domain_not_allowed' });
          if (email === lc(ownerEmail)) return J(400, { code: 'exists' });
          if (!pwOk(b.password)) return J(400, { code: 'weak_password' });
          const ex = (await users.list()).find(x => x.email === email);
          if (ex && !inTenant(ex)) return J(400, { code: 'exists', message: 'هذا البريد مسجّل في شركة أخرى على المنصة' });
          const temporary = b.temporary !== false;
          const sub = await users.create({ email, name, password: b.password, temporary });
          if (tid !== DEFAULT_TENANT) await gstore.put('_tenantOf', 'u_' + sub, { tid });
          const pl = b.projects === '*' ? '*' : [].concat(b.projects || []).map(String).slice(0, 500);
          tt.members['u_' + sub] = { role: b.role, email, name, added: new Date().toISOString().slice(0, 10), via: 'مدير النظام', projects: pl };
          tt.log = (tt.log || []).concat([{ at: new Date().toISOString(), by: u.email, text: `إضافة ${email} بدور ${RN[b.role]}` }]).slice(-300);
          await store.put('team', 'members', tt); changed('team/members');
          let sent = false;
          if (b.sendEmail !== false) try {
            const link = (headers.origin || '').replace(/\/$/, '') + '/', esc = x => String(x).replace(/[<>&"]/g, '');
            const pwLine = b.sendPassword ? `كلمة المرور${temporary ? ' المؤقتة' : ''}: ${b.password}` : 'كلمة المرور: يزوّدك بها مدير النظام';
            await mail({ to: [email], subject: 'حسابك في منصة بنّاء — Bannaa account', text:
              `مرحباً ${name},\n\nأُنشئ لك حساب في منصة بنّاء لإدارة المشاريع الإنشائية.\n\nالرابط: ${link}\nالبريد: ${email}\n${pwLine}\n${temporary ? 'سيُطلب منك اختيار كلمة مرور جديدة عند أول دخول.\n' : ''}نسيت كلمة المرور؟ اضغط "نسيت كلمة المرور؟" في صفحة الدخول.\n\nBannaa account created for ${email}. Sign in at ${link}`,
              html: `<div dir="rtl" style="font-family:Tahoma,Arial,sans-serif;font-size:15px;line-height:1.8;color:#1C1A16;max-width:560px"><div style="background:#14110C;color:#C9983F;padding:16px 20px;border-radius:10px 10px 0 0;font-size:20px;font-weight:bold">بنّاء</div><div style="border:1px solid #E6E2DA;border-top:0;padding:20px;border-radius:0 0 10px 10px"><p>مرحباً ${esc(name)}،</p><p>أُنشئ لك حساب في منصة بنّاء لإدارة المشاريع الإنشائية.</p><p>البريد: <b dir="ltr">${esc(email)}</b><br>${esc(pwLine).replace(/: (.*)$/, ': <b dir="ltr">$1</b>')}</p>${temporary ? '<p>سيُطلب منك اختيار كلمة مرور جديدة عند أول دخول.</p>' : ''}<p style="text-align:center;margin:22px 0"><a href="${esc(link)}" style="background:#94701F;color:#fff;padding:12px 26px;border-radius:8px;text-decoration:none;font-weight:bold">تسجيل الدخول</a></p><p style="color:#6E685E;font-size:13px">نسيت كلمة المرور؟ اضغط «نسيت كلمة المرور؟» في صفحة الدخول.</p></div></div>` });
            sent = true; } catch (e) { console.error('welcome mail', e); }
          return J(200, { id: 'u_' + sub, mail: sent });
        }
        if (path === '/users' && method === 'PATCH') {
          const { id, role: nr } = json();
          if (!tt.members[id] || !ROLES.includes(nr) || tt.members[id].super) return J(400, { code: 'bad_request' });
          const old = tt.members[id].role; tt.members[id].role = nr; await store.put('team', 'members', tt);
          await log(`تغيير دور ${tt.members[id].email}: ${RN[old] || old} ← ${RN[nr]}`); return J(200, { ok: true });
        }
        if (path === '/users/status' && method === 'POST') {
          const { id, on } = json(); const m = tt.members[id]; if (!m || id === u.id) return J(400, { code: 'bad_request' });
          await users.setEnabled(String(id).replace(/^u_/, ''), !!on); await log(`${on ? 'تفعيل' : 'إيقاف'} حساب ${m.email}`); return J(200, { ok: true });
        }
        if (path === '/users/password' && method === 'POST') {
          const { id, password, temporary } = json(); const m = tt.members[id]; if (!m || id === u.id) return J(400, { code: 'bad_request' });
          if (!pwOk(password)) return J(400, { code: 'weak_password' });
          await users.setPassword(String(id).replace(/^u_/, ''), password, temporary !== false);
          await log(`تعيين كلمة مرور ${temporary !== false ? 'مؤقتة ' : ''}لـ ${m.email}`); return J(200, { ok: true });
        }
        if (path === '/users/projects' && method === 'POST') {
          const { id, projects } = json(); const m = tt.members[id]; if (!m) return J(400, { code: 'bad_request' });
          m.projects = projects === '*' ? '*' : [].concat(projects || []).map(String).slice(0, 500); await store.put('team', 'members', tt);
          await log(`مشاريع ${m.email}: ${m.projects === '*' ? 'كل المشاريع' : m.projects.length + ' مشروع'}`); return J(200, { ok: true });
        }
        if (path === '/users/mfa-off' && method === 'POST') {
          const { id } = json(); const m = tt.members[id]; if (!m) return J(400, { code: 'bad_request' });
          await users.mfaOff(String(id).replace(/^u_/, '')); await log(`إلغاء التحقق الثنائي لـ ${m.email}`); return J(200, { ok: true });
        }
        if (path === '/users/reset' && method === 'POST') {
          const { id } = json(); const m = tt.members[id]; if (!m) return J(400, { code: 'bad_request' });
          await users.reset(String(id).replace(/^u_/, '')); await log(`إعادة تعيين كلمة مرور ${m.email}`); return J(200, { ok: true });
        }
        if (path === '/users/domains' && method === 'POST') {
          if (role !== '__owner') return J(403, { code: 'permission_denied' });
          const ds = [...new Set([].concat(json().domains || []).map(lc).filter(x => /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(x)))];
          tt.domains = ds; await store.put('team', 'members', tt); await log(`نطاق البريد: ${ds.join(', ') || 'أي نطاق'}`); changed('team/members'); return J(200, { ok: true });
        }
        return J(404, { code: 'not_found' });
      }

      return J(404, { code: 'not_found' });
    } catch (e) {
      console.error(e);
      return J(e.name === 'InvalidPasswordException' || e.code === 'bad_request' ? 400 : 500, { code: e.code || e.name || 'server_error', message: String(e.message || e) });
    }
  }

  const modelFix = {};
  async function pickModel(H, want) {
    try {
      const r = await fetch('https://api.anthropic.com/v1/models?limit=100', { headers: H }); if (!r.ok) return null;
      const ids = ((await r.json()).data || []).map(x => x.id);   // newest first
      const fam = ['opus', 'sonnet', 'haiku'].find(f => String(want).includes(f)) || 'sonnet';
      return ids.find(i => i.includes(fam)) || ids.find(i => i.includes('sonnet')) || ids[0] || null;
    } catch (e) { return null; }
  }
  async function runJob(j, { getKey, model, modelComplex }) {
    const ttl = Math.floor(Date.now() / 1000) + 86400;
    try {
      const key = await getKey();
      if (!key) { await gstore.put('_jobs', j.id, { status: 'error', code: 'sampling_disabled', uid: j.uid }, ttl); return; }
      const content = [];
      for (const id of j.images || []) {
        if (!/^[a-f0-9]{32}$/.test(id)) continue;
        const o = await blobs.get('_tmp/' + id); if (!o) continue;
        content.push({ type: 'image', source: { type: 'base64', media_type: o.ct || 'image/jpeg', data: o.buf.toString('base64') } });
      }
      content.push({ type: 'text', text: j.prompt });
      // streamed: headers arrive at once, so long drawing reads don't hit fetch's 5-minute header timeout
      const H = { 'x-api-key': key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' };
      const call = m => fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST', signal: AbortSignal.timeout(13.5 * 60e3), headers: H,
        body: JSON.stringify({ model: m, max_tokens: j.tier === 'complex' ? 16000 : 8192, stream: true, system: 'Reply with valid JSON only — no prose, no code fences.', messages: [{ role: 'user', content }] })
      });
      const want = j.tier === 'complex' ? modelComplex : model;
      let res = await call(modelFix[want] || want);
      // a retired or unavailable model id: pick the newest model of the same family this key can use, remember it, retry once
      if (res.status === 404 || res.status === 400) {
        const d0 = await res.clone().json().catch(() => ({}));
        if (/^model:/i.test((d0.error && d0.error.message) || '') || (d0.error && d0.error.type) === 'not_found_error') {
          const alt = await pickModel(H, want);
          if (alt) { console.error('model', want, 'unavailable — using', alt); modelFix[want] = alt; res = await call(alt); }
        }
      }
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        const code = res.status === 429 || res.status === 529 ? 'rate_limited' : res.status === 413 ? 'prompt_too_large' : res.status === 401 ? 'sampling_disabled' : 'upstream_error';
        console.error('anthropic', res.status, d.error && d.error.message);
        await gstore.put('_jobs', j.id, { status: 'error', code, message: (d.error && d.error.message) || String(res.status), uid: j.uid }, ttl); return;
      }
      let text = '', buf = '', stop = null, err = null;
      const dec = new TextDecoder();
      for await (const chunk of res.body) {
        buf += dec.decode(chunk, { stream: true });
        let i;
        while ((i = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
          if (!line.startsWith('data:')) continue;
          let ev; try { ev = JSON.parse(line.slice(5)); } catch (e) { continue; }
          if (ev.type === 'content_block_delta' && ev.delta && ev.delta.type === 'text_delta') text += ev.delta.text;
          else if (ev.type === 'message_delta' && ev.delta) stop = ev.delta.stop_reason || stop;
          else if (ev.type === 'error') err = ev.error || { message: 'stream error' };
        }
      }
      if (err) {
        console.error('anthropic stream', err);
        await gstore.put('_jobs', j.id, { status: 'error', code: err.type === 'overloaded_error' ? 'rate_limited' : 'upstream_error', message: String(err.message || ''), uid: j.uid }, ttl); return;
      }
      if (stop === 'max_tokens') console.error('anthropic: reply cut at max_tokens', j.tier);
      await gstore.put('_jobs', j.id, { status: 'done', text, uid: j.uid }, ttl);
    } catch (e) {
      console.error('job', j.id, e);
      await gstore.put('_jobs', j.id, { status: 'error', code: e && e.name === 'TimeoutError' ? 'timeout' : 'upstream_error', message: String(e.message || e), uid: j.uid }, ttl);
    }
  }

  return { handler, runJob };
}
