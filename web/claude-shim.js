/* Bannaa on AWS — implements the window.claude.use(...) runtime the platform was built on,
   backed by Cognito sign-in and the /api Lambda. Loaded before the app script. */
(function () {
  'use strict';
  const C = window.BANNAA_CONFIG || {};
  const LS = localStorage, TK = 'bannaa.tok';
  const HOME = location.origin + '/';
  const enc = encodeURIComponent;
  const b64url = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const never = () => new Promise(() => {});

  /* ---------- sign-in ---------- */
  async function login() {
    if (C.dev) { devLogin(); return never(); }
    const v = b64url(crypto.getRandomValues(new Uint8Array(32)));
    sessionStorage.setItem('bannaa.pkce', v);
    const ch = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v)));
    location.href = `${C.cognitoDomain}/oauth2/authorize?response_type=code&client_id=${C.clientId}&redirect_uri=${enc(HOME)}` +
      `&scope=${enc('openid email profile aws.cognito.signin.user.admin')}&code_challenge_method=S256&code_challenge=${ch}`;
    return never();
  }
  function devLogin() {
    const box = document.createElement('div');
    box.style.cssText = 'position:fixed;inset:0;z-index:99;background:#14110C;display:grid;place-items:center;font-family:Tahoma,sans-serif';
    box.innerHTML = `<form style="background:#fff;padding:24px;border-radius:12px;width:320px;display:grid;gap:10px;direction:rtl">
      <b style="font-size:18px">بنّاء — دخول تجريبي (محلي)</b><input name="e" type="email" required placeholder="البريد" style="padding:8px" dir="ltr">
      <input name="n" placeholder="الاسم" style="padding:8px"><button style="padding:9px;background:#94701F;color:#fff;border:0;border-radius:8px">دخول</button></form>`;
    const go = () => document.body.append(box);
    document.body ? go() : document.addEventListener('DOMContentLoaded', go);
    box.querySelector('form').onsubmit = e => { e.preventDefault(); const f = e.target;
      LS.setItem(TK, JSON.stringify({ access: 'dev:' + f.e.value.trim().toLowerCase() + ':' + encodeURIComponent(f.n.value.trim()), exp: Date.now() + 864e5 * 30 })); location.reload(); };
  }
  async function tokenReq(params) {
    const r = await fetch(C.cognitoDomain + '/oauth2/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(params) });
    if (!r.ok) throw new Error('token ' + r.status);
    const d = await r.json(), old = JSON.parse(LS.getItem(TK) || '{}');
    const t = { access: d.access_token, refresh: d.refresh_token || old.refresh, exp: Date.now() + (d.expires_in - 60) * 1000 };
    LS.setItem(TK, JSON.stringify(t)); return t;
  }
  async function token(force) {
    const t = JSON.parse(LS.getItem(TK) || 'null');
    if (t && !force && t.exp > Date.now()) return t.access;
    if (t && t.refresh && !C.dev) { try { return (await tokenReq({ grant_type: 'refresh_token', client_id: C.clientId, refresh_token: t.refresh })).access; } catch (e) {} }
    LS.removeItem(TK); return login();
  }
  const ready = (async () => {
    const u = new URL(location.href), code = u.searchParams.get('code');
    if (code && !C.dev) {
      const v = sessionStorage.getItem('bannaa.pkce'); history.replaceState(null, '', HOME);
      try { await tokenReq({ grant_type: 'authorization_code', client_id: C.clientId, code, redirect_uri: HOME, code_verifier: v }); } catch (e) { return login(); }
    }
    await token();
  })();
  window.bannaaLogout = () => {
    LS.removeItem(TK);
    location.href = C.dev ? HOME : `${C.cognitoDomain}/logout?client_id=${C.clientId}&logout_uri=${enc(HOME)}`;
  };

  /* ---------- API ---------- */
  const CODES = { 401: 'session_expired', 403: 'permission_denied', 404: 'not_found', 413: 'too_large', 415: 'unsupported_type', 429: 'rate_limited' };
  async function api(path, opt = {}) {
    await ready;
    const go = t => fetch('/api' + path, Object.assign({}, opt, { headers: Object.assign({ 'x-bannaa-token': t }, opt.headers || {}) }));
    let r = await go(await token());
    if (r.status === 401) r = await go(await token(true));
    let d = null; try { d = await r.json(); } catch (e) {}
    if (!r.ok) throw Object.assign(new Error((d && d.message) || String(r.status)), { code: (d && d.code) || CODES[r.status] || 'unavailable' });
    return d;
  }
  const jpost = (path, body, method = 'POST') => api(path, { method, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

  /* ---------- db: documents with live updates by polling ---------- */
  const subs = new Set(); let timer = null;
  const poll = () => subs.forEach(s => s.run());
  const startPoll = () => { if (!timer) timer = setInterval(() => { if (!document.hidden) poll(); }, 5000); };
  document.addEventListener('visibilitychange', () => { if (!document.hidden) poll(); });
  const copy = x => x == null ? x : JSON.parse(JSON.stringify(x));
  function watch(url, toSnap, cb, err) {
    let last = null, errored = false;
    const s = { run: async () => {
      try { const d = await api(url); const k = JSON.stringify(d); errored = false; if (k !== last) { last = k; cb(toSnap(d)); } }
      catch (e) { if (!errored && err) { errored = true; err(e); } }
    } };
    subs.add(s); s.run(); startPoll(); return () => subs.delete(s);
  }
  function docRef(path) {
    const id = path.split('/').pop(), snap = d => ({ id, exists: !!d.exists, data: () => copy(d.data) });
    return {
      id, path,
      async get() { return snap(await api('/db?path=' + enc(path))); },
      async set(data) { await jpost('/db?path=' + enc(path), data, 'PUT'); setTimeout(poll, 30); },
      async update(data) { const cur = (await api('/db?path=' + enc(path))).data || {}; await this.set(Object.assign(cur, data)); },
      async delete() { await api('/db?path=' + enc(path), { method: 'DELETE' }); setTimeout(poll, 30); },
      onSnapshot(cb, err) { return watch('/db?path=' + enc(path), snap, cb, err); }
    };
  }
  function colRef(path) {
    const snap = d => ({ docs: d.docs.map(x => ({ id: x.id, exists: true, data: () => copy(x.data) })), size: d.docs.length, empty: !d.docs.length });
    return {
      path, doc: id => docRef(path + '/' + id),
      async get() { return snap(await api('/db?col=' + enc(path))); },
      onSnapshot(cb, err) { return watch('/db?col=' + enc(path), snap, cb, err); }
    };
  }
  const db = Object.freeze({ doc: docRef, collection: colRef });

  /* ---------- user ---------- */
  const PAL = ['#94701F', '#2457D6', '#23845A', '#B8402F', '#7A5AA6', '#0E7C86', '#A8670E', '#5B6B7F'];
  const colorOf = id => { let h = 0; for (const c of String(id || '')) h = (h * 31 + c.charCodeAt(0)) >>> 0; return PAL[h % PAL.length]; };
  const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const avatar = (id, name, email) => 'data:image/svg+xml,' + enc(`<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64"><rect width="64" height="64" rx="32" fill="${colorOf(id)}"/><text x="32" y="42" font-size="28" text-anchor="middle" fill="#fff" font-family="Tahoma,sans-serif">${esc((name || email || '?').trim().charAt(0).toUpperCase())}</text></svg>`);
  let meP = null; const getMe = () => meP || (meP = api('/me'));
  const prof = (id, x, meId) => ({ id, name: (x && x.name) || '', email: (x && x.email) || null, avatarUrl: avatar(id, x && x.name, x && x.email), color: colorOf(id), isMe: id === meId, guest: false });
  const user = Object.freeze({
    isOwner: async () => !!(await getMe()).isOwner,
    canEdit: async () => !!(await getMe()).canEdit,
    can: async () => null,
    me: async () => { const m = await getMe(); return { id: m.id, name: m.name || '', email: m.email || null, avatarUrl: avatar(m.id, m.name, m.email), color: colorOf(m.id), isOwner: !!m.isOwner, canEdit: !!m.canEdit }; },
    id: async () => (await getMe()).id,
    name: async () => (await getMe()).name || '',
    email: async () => (await getMe()).email || null,
    avatarUrl: async () => { const m = await getMe(); return avatar(m.id, m.name, m.email); },
    profiles: async ids => { ids = [...new Set([].concat(ids))]; const m = await getMe(); const r = ids.length ? await jpost('/profiles', { ids }) : {};
      return Object.fromEntries(ids.map(i => [i, prof(i, r[i], m.id)])); },
    search: async q => { const m = await getMe(); const r = await api('/search?q=' + enc(q || '')); return r.map(x => prof(x.id, x, m.id)); }
  });

  /* ---------- assets ---------- */
  async function upload(blob, tmp) { return api('/assets' + (tmp ? '?tmp=1' : ''), { method: 'POST', headers: { 'content-type': blob.type || 'application/octet-stream' }, body: blob }); }
  const assets = Object.freeze({ upload: b => upload(b, false), list: async () => ({ assets: [], usage: {} }), delete: async () => {} });

  /* ---------- sample (Claude via the Anthropic API, run as a background job) ---------- */
  const MAX_IMG = 10;
  async function shrink(blob) {
    try { const bm = await createImageBitmap(blob); const s = Math.min(1, 1568 / Math.max(bm.width, bm.height));
      const c = document.createElement('canvas'); c.width = Math.round(bm.width * s); c.height = Math.round(bm.height * s);
      c.getContext('2d').drawImage(bm, 0, 0, c.width, c.height); return await new Promise(r => c.toBlob(r, 'image/jpeg', 0.85)); }
    catch (e) { return blob; }
  }
  function parseJson(t) {
    t = String(t || '').trim().replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '');
    try { return JSON.parse(t); } catch (e) {}
    const a = t.indexOf('{'), b = t.lastIndexOf('}');
    if (a >= 0 && b > a) { try { return JSON.parse(t.slice(a, b + 1)); } catch (e) {} }
    throw Object.assign(new Error('invalid json'), { code: 'invalid_json', text: t });
  }
  async function run(input, opts = {}) {
    const sig = opts.signal, chk = () => { if (sig && sig.aborted) throw { code: 'cancelled', message: 'cancelled' }; };
    const prompt = typeof input === 'string' ? input : [].concat(input).map(m => m.content).join('\n\n');
    const ids = [];
    for (const b of (opts.images || []).slice(0, MAX_IMG)) { chk(); ids.push((await upload(await shrink(b), true)).id); }
    chk();
    const { job } = await jpost('/ai', { prompt, images: ids, tier: opts.modelTier });
    const t0 = Date.now();
    for (;;) {
      chk(); await new Promise(r => setTimeout(r, 2500));
      const d = await api('/ai?job=' + job);
      if (d.status === 'done') { if (opts.onText) try { opts.onText({ text: d.text, delta: d.text }); } catch (e) {} return { text: d.text, truncated: false }; }
      if (d.status === 'error') throw { code: d.code || 'upstream_error', message: d.message || '' };
      if (Date.now() - t0 > 330000) throw { code: 'timeout', message: 'timeout' };
    }
  }
  const sample = Object.freeze(Object.assign((i, o) => run(i, o), {
    json: async (i, o) => parseJson((await run(i, o)).text),
    limits: async () => ({ images: { maxCount: MAX_IMG } })
  }));

  /* ---------- downloads, mail (stands in for the Gmail connector) ---------- */
  const downloads = Object.freeze({ save: async ({ filename, data }) => {
    const blob = data instanceof Blob ? data : new Blob([data]); const u = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = u; a.download = filename || 'download'; document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(u), 5000);
  } });
  const mcp = Object.freeze({ callTool: async (server, tool, input) => {
    if (server !== 'Gmail' || tool !== 'send_message') throw { code: 'server_not_connected', message: server };
    await jpost('/mail', { to: input.to, subject: input.subject, body: input.body, html: input.htmlBody });
    return { payload: { ok: true } };
  } });

  /* ---------- user management (platform owner + admin role) ---------- */
  window.bannaaAdmin = Object.freeze({
    list: () => api('/users'),
    create: b => jpost('/users', b),
    setRole: (id, role) => jpost('/users', { id, role }, 'PATCH').then(r => { setTimeout(poll, 30); return r; }),
    setStatus: (id, on) => jpost('/users/status', { id, on }),
    reset: id => jpost('/users/reset', { id }),
    domains: ds => jpost('/users/domains', { domains: ds }).then(r => { setTimeout(poll, 30); return r; })
  });

  const NS = { db, user, sample, assets, downloads, mcp };
  window.claude = Object.freeze({ use: async name => { try { await ready; } catch (e) {} return NS[name] || null; } });
})();
