/* Bannaa on AWS — implements the window.claude.use(...) runtime the platform was built on,
   backed by Cognito sign-in and the /api Lambda. Loaded before the app script. */
(function () {
  'use strict';
  const C = window.BANNAA_CONFIG || {};
  const LS = localStorage, TK = 'bannaa.tok';
  const enc = encodeURIComponent;

  /* ---------- sign-in: Arabic in-app page, no self sign-up (accounts are created by the admin) ---------- */
  const LOGO = '<svg viewBox="0 0 48 48" width="56" height="56" aria-hidden="true"><rect width="48" height="48" rx="12" fill="#14110C"/><path d="M11.5 37.5V23a12.5 12.5 0 0 1 25 0v14.5" fill="none" stroke="#C9983F" stroke-width="3.2" stroke-linecap="round"/><path d="M18.5 37.5V25a5.5 5.5 0 0 1 11 0v12.5" fill="none" stroke="#C9983F" stroke-width="3.2" stroke-linecap="round" opacity=".55"/><path d="M8.5 37.5h31" stroke="#C9983F" stroke-width="3.2" stroke-linecap="round"/><rect x="21.6" y="7.6" width="4.8" height="4.8" rx="1.2" fill="#C9983F" transform="rotate(45 24 10)"/></svg>';
  const ERR = {
    EnableSoftwareTokenMFAException: 'الرمز غير صحيح — تأكد من وقت جهازك وأعد المحاولة.',
    NotAuthorizedException: 'البريد أو كلمة المرور غير صحيحة.', UserNotFoundException: 'البريد أو كلمة المرور غير صحيحة.',
    CodeMismatchException: 'الرمز غير صحيح.', ExpiredCodeException: 'انتهت صلاحية الرمز — اطلب رمزاً جديداً.',
    InvalidPasswordException: 'كلمة المرور لا تطابق الشروط: 8 أحرف على الأقل، وتحتوي أرقاماً وحروفاً إنجليزية صغيرة.',
    LimitExceededException: 'محاولات كثيرة — انتظر بضع دقائق ثم حاول.', TooManyRequestsException: 'محاولات كثيرة — انتظر قليلاً ثم حاول.',
    TooManyFailedAttemptsException: 'محاولات كثيرة — انتظر بضع دقائق ثم حاول.',
    InvalidParameterException: 'لا يمكن إعادة تعيين كلمة المرور لهذا الحساب من هنا — اطلب من مدير النظام تعيين كلمة مرور جديدة.',
    UserNotConfirmedException: 'الحساب غير مفعّل — تواصل مع مدير النظام.', network: 'تعذّر الاتصال — تحقق من الإنترنت.'
  };
  const errMsg = e => (e && /disabled/i.test(e.message || '')) ? 'هذا الحساب موقوف — تواصل مع مدير النظام.' : ERR[e && e.code] || (e && e.message) || 'حدث خطأ — حاول مرة أخرى.';

  // auth provider: Cognito in production, the dev server locally — same shape
  async function cognito(target, body) {
    let r; try { r = await fetch(`https://cognito-idp.${C.region}.amazonaws.com/`, { method: 'POST', headers: { 'Content-Type': 'application/x-amz-json-1.1', 'X-Amz-Target': 'AWSCognitoIdentityProviderService.' + target }, body: JSON.stringify(body) }); }
    catch (e) { throw { code: 'network' }; }
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw { code: String(d.__type || '').split('#').pop(), message: d.message || '' };
    return d;
  }
  async function devAuth(op, body) {
    let r; try { r = await fetch('/api/auth/' + op, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }); } catch (e) { throw { code: 'network' }; }
    const d = await r.json().catch(() => ({})); if (!r.ok) throw { code: d.code, message: d.message || '' }; return d;
  }
  const save = a => { const old = JSON.parse(LS.getItem(TK) || '{}'); const t = { access: a.AccessToken, refresh: a.RefreshToken || old.refresh, exp: Date.now() + ((a.ExpiresIn || 3600) - 60) * 1000, email: a.email || old.email };
    LS.setItem(TK, JSON.stringify(t)); return t; };
  const AUTH = C.dev ? {
    signIn: async (email, pw) => { const d = await devAuth('signin', { email, password: pw }); return d.challenge ? d : save(d); },
    newPassword: async (email, session, pw) => save(await devAuth('newpw', { email, session, password: pw })),
    forgot: email => devAuth('forgot', { email }),
    confirm: (email, code, pw) => devAuth('confirm', { email, code, password: pw }),
    change: (access, oldPw, newPw) => devAuth('change', { token: access, old: oldPw, password: newPw }),
    refresh: async rt => save(await devAuth('refresh', { refresh: rt })),
    mfaSignIn: async (email, session, code) => save(await devAuth('mfa-signin', { email, session, code })),
    mfaStatus: async access => (await devAuth('mfa-status', { token: access })).enabled,
    mfaAssociate: async access => (await devAuth('mfa-assoc', { token: access })).secret,
    mfaVerify: (access, code) => devAuth('mfa-verify', { token: access, code }),
    mfaOff: access => devAuth('mfa-off', { token: access })
  } : {
    signIn: async (email, pw) => { const d = await cognito('InitiateAuth', { AuthFlow: 'USER_PASSWORD_AUTH', ClientId: C.clientId, AuthParameters: { USERNAME: email, PASSWORD: pw } });
      if (d.ChallengeName === 'NEW_PASSWORD_REQUIRED') return { challenge: 'NEW_PASSWORD', session: d.Session };
      if (d.ChallengeName === 'SOFTWARE_TOKEN_MFA') return { challenge: 'MFA', session: d.Session };
      if (d.ChallengeName) throw { code: 'unsupported', message: 'نوع تحقق غير مدعوم: ' + d.ChallengeName };
      return save(Object.assign({ email }, d.AuthenticationResult)); },
    newPassword: async (email, session, pw) => { const d = await cognito('RespondToAuthChallenge', { ChallengeName: 'NEW_PASSWORD_REQUIRED', ClientId: C.clientId, Session: session, ChallengeResponses: { USERNAME: email, NEW_PASSWORD: pw } });
      return save(Object.assign({ email }, d.AuthenticationResult)); },
    forgot: email => cognito('ForgotPassword', { ClientId: C.clientId, Username: email }),
    confirm: (email, code, pw) => cognito('ConfirmForgotPassword', { ClientId: C.clientId, Username: email, ConfirmationCode: code, Password: pw }),
    change: (access, oldPw, newPw) => cognito('ChangePassword', { AccessToken: access, PreviousPassword: oldPw, ProposedPassword: newPw }),
    refresh: async rt => save((await cognito('InitiateAuth', { AuthFlow: 'REFRESH_TOKEN_AUTH', ClientId: C.clientId, AuthParameters: { REFRESH_TOKEN: rt } })).AuthenticationResult),
    mfaSignIn: async (email, session, code) => save(Object.assign({ email }, (await cognito('RespondToAuthChallenge', { ChallengeName: 'SOFTWARE_TOKEN_MFA', ClientId: C.clientId, Session: session, ChallengeResponses: { USERNAME: email, SOFTWARE_TOKEN_MFA_CODE: code } })).AuthenticationResult)),
    mfaStatus: async access => ((await cognito('GetUser', { AccessToken: access })).UserMFASettingList || []).includes('SOFTWARE_TOKEN_MFA'),
    mfaAssociate: async access => (await cognito('AssociateSoftwareToken', { AccessToken: access })).SecretCode,
    mfaVerify: async (access, code) => { await cognito('VerifySoftwareToken', { AccessToken: access, UserCode: code, FriendlyDeviceName: 'Bannaa' });
      await cognito('SetUserMFAPreference', { AccessToken: access, SoftwareTokenMfaSettings: { Enabled: true, PreferredMfa: true } }); },
    mfaOff: access => cognito('SetUserMFAPreference', { AccessToken: access, SoftwareTokenMfaSettings: { Enabled: false, PreferredMfa: false } })
  };
  const pwOk = p => p.length >= 8 && /\d/.test(p) && /[a-z]/.test(p);

  const CSS = `#bn-auth{position:fixed;inset:0;z-index:1000;background:#14110C radial-gradient(circle at 20% 10%,#2a2215,transparent 60%);display:grid;place-items:center;padding:16px;font-family:"IBM Plex Sans Arabic",Tahoma,sans-serif;direction:rtl}
    #bn-auth .c{background:#fff;color:#1C1A16;border-radius:16px;padding:28px;width:100%;max-width:380px;box-shadow:0 20px 60px rgba(0,0,0,.35);display:grid;gap:12px}
    #bn-auth h1{font-size:20px;margin:6px 0 0;font-family:"Readex Pro","IBM Plex Sans Arabic",Tahoma,sans-serif}#bn-auth p{margin:0;color:#6E685E;font-size:13.5px;line-height:1.7}
    #bn-auth label{font-size:12.5px;color:#6E685E;display:grid;gap:4px}#bn-auth input{font:inherit;padding:10px 12px;border:1px solid #E6E2DA;border-radius:10px;background:#F7F6F3;color:#1C1A16}
    #bn-auth input:focus{outline:2px solid #C9983F;outline-offset:1px}#bn-auth button.p{font:inherit;font-weight:600;padding:11px;border:0;border-radius:10px;background:#94701F;color:#fff;cursor:pointer}
    #bn-auth button.p[disabled]{opacity:.6}#bn-auth .l{background:none;border:0;color:#94701F;cursor:pointer;font:inherit;font-size:13px;padding:0;justify-self:start}
    #bn-auth .e{background:#FBE7E3;color:#B8402F;border-radius:8px;padding:8px 10px;font-size:13px}#bn-auth .ok{background:#E3F4EC;color:#23845A;border-radius:8px;padding:8px 10px;font-size:13px}
    #bn-auth .ltr{direction:ltr;text-align:left}#bn-auth .x{position:absolute;top:10px;left:12px;background:none;border:0;font-size:20px;cursor:pointer;color:#6E685E}`;
  function overlay() {
    let el = document.getElementById('bn-auth'); if (el) return el;
    if (!document.getElementById('bn-auth-css')) { const st = document.createElement('style'); st.id = 'bn-auth-css'; st.textContent = CSS; document.head.append(st); }
    el = document.createElement('div'); el.id = 'bn-auth'; el.innerHTML = '<div class="c" style="position:relative"></div>';
    const add = () => document.body.append(el); document.body ? add() : document.addEventListener('DOMContentLoaded', add);
    return el;
  }
  function form(card, html, onSubmit) {
    card.innerHTML = html; const f = card.querySelector('form'), msg = card.querySelector('[data-msg]');
    const show = (t, ok) => { msg.className = ok ? 'ok' : 'e'; msg.textContent = t; msg.hidden = !t; };
    f.onsubmit = async e => { e.preventDefault(); const b = f.querySelector('button.p'); b.disabled = true; show('');
      try { await onSubmit(new FormData(f), show); } catch (er) { show(errMsg(er)); } finally { b.disabled = false; } };
    const first = f.querySelector('input'); if (first) setTimeout(() => first.focus(), 30);
    return { f, show };
  }
  const head = (t, sub) => `<div style="display:flex;align-items:center;gap:12px">${LOGO}<div><b style="font-family:'Readex Pro',Tahoma;font-size:20px">بنّاء</b><div style="font-size:12px;color:#6E685E">إدارة المشاريع الإنشائية</div></div></div><h1>${t}</h1>${sub ? `<p>${sub}</p>` : ''}<div data-msg hidden></div>`;
  const pwHint = '<p style="font-size:12px">8 أحرف على الأقل، وتحتوي أرقاماً وحروفاً إنجليزية صغيرة.</p>';
  function signInFlow() {
    return new Promise(done => {
      const card = overlay().querySelector('.c'); let email = (JSON.parse(LS.getItem(TK) || '{}').email) || '';
      const login = (note) => form(card, head('تسجيل الدخول', 'الحسابات يُنشئها مدير النظام. إن لم يكن لديك حساب فتواصل معه.') +
        `<form style="display:grid;gap:12px"><label>البريد الإلكتروني<input name="e" type="email" required class="ltr" autocomplete="username" value="${email.replace(/"/g, '')}"></label>
         <label>كلمة المرور<input name="p" type="password" required class="ltr" autocomplete="current-password"></label>
         <button class="p">دخول</button><button type="button" class="l" data-forgot>نسيت كلمة المرور؟</button></form>`,
        async (fd) => { email = String(fd.get('e')).trim().toLowerCase();
          try { const r = await AUTH.signIn(email, String(fd.get('p')));
            if (r.challenge === 'MFA') return mfa(r.session);
            if (r.challenge) return newPw(r.session);
            finish(); }
          catch (e) { if (e.code === 'PasswordResetRequiredException') return confirm('طلب مدير النظام إعادة تعيين كلمة مرورك — أدخل الرمز الذي وصلك بالبريد.'); throw e; } });
      const wire = (o, note, ok) => { if (note) o.show(note, ok); const fb = card.querySelector('[data-forgot]'); if (fb) fb.onclick = () => forgot(); const bk = card.querySelector('[data-back]'); if (bk) bk.onclick = () => wire(login()); return o; };
      const newPw = session => wire(form(card, head('تعيين كلمة مرور جديدة', 'هذه كلمة مرور مؤقتة من مدير النظام — اختر كلمة مرورك الخاصة للمتابعة.') +
        `<form style="display:grid;gap:12px"><label>كلمة المرور الجديدة<input name="a" type="password" required class="ltr" autocomplete="new-password"></label>
         <label>تأكيد كلمة المرور<input name="b" type="password" required class="ltr" autocomplete="new-password"></label>${pwHint}<button class="p">حفظ والدخول</button><button type="button" class="l" data-back>رجوع</button></form>`,
        async (fd, show) => { const a = String(fd.get('a')), b = String(fd.get('b'));
          if (a !== b) return show('كلمتا المرور غير متطابقتين.'); if (!pwOk(a)) return show(ERR.InvalidPasswordException);
          await AUTH.newPassword(email, session, a); finish(); }));
      const mfa = session => wire(form(card, head('التحقق الثنائي', 'أدخل الرمز المكوّن من 6 أرقام من تطبيق المصادقة (Google أو Microsoft Authenticator).') +
        `<form style="display:grid;gap:12px"><label>رمز التحقق<input name="c" required class="ltr" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}"></label>
         <button class="p">تحقق ودخول</button><button type="button" class="l" data-back>رجوع</button></form>`,
        async (fd) => { await AUTH.mfaSignIn(email, session, String(fd.get('c')).trim()); finish(); }));
      const forgot = () => wire(form(card, head('نسيت كلمة المرور', 'اكتب بريدك وسنرسل لك رمزاً لتعيين كلمة مرور جديدة.') +
        `<form style="display:grid;gap:12px"><label>البريد الإلكتروني<input name="e" type="email" required class="ltr" value="${email.replace(/"/g, '')}"></label>
         <button class="p">إرسال الرمز</button><button type="button" class="l" data-back>رجوع لتسجيل الدخول</button></form>`,
        async (fd) => { email = String(fd.get('e')).trim().toLowerCase(); await AUTH.forgot(email); confirm('إن كان البريد مسجلاً فقد أُرسل إليه رمز — تحقق من صندوق الوارد والبريد غير المرغوب.', true); }));
      const confirm = (note, ok) => wire(form(card, head('تعيين كلمة المرور', `الرمز المرسل إلى <b class="ltr" style="display:inline">${email.replace(/[<>&]/g, '')}</b>`) +
        `<form style="display:grid;gap:12px"><label>الرمز<input name="c" required class="ltr" inputmode="numeric" autocomplete="one-time-code"></label>
         <label>كلمة المرور الجديدة<input name="a" type="password" required class="ltr" autocomplete="new-password"></label>
         <label>تأكيد كلمة المرور<input name="b" type="password" required class="ltr" autocomplete="new-password"></label>${pwHint}
         <button class="p">حفظ كلمة المرور</button><button type="button" class="l" data-forgot>إعادة إرسال الرمز</button><button type="button" class="l" data-back>رجوع لتسجيل الدخول</button></form>`,
        async (fd, show) => { const a = String(fd.get('a')), b = String(fd.get('b'));
          if (a !== b) return show('كلمتا المرور غير متطابقتين.'); if (!pwOk(a)) return show(ERR.InvalidPasswordException);
          await AUTH.confirm(email, String(fd.get('c')).trim(), a); wire(login(), 'تم تعيين كلمة المرور — ادخل الآن بكلمة المرور الجديدة.', true); }), note, ok);
      const finish = () => { const el = document.getElementById('bn-auth'); if (el) el.remove(); done(); };
      wire(login());
    });
  }
  let signing = null;
  const signIn = () => signing || (signing = signInFlow().finally(() => { signing = null; }));
  async function token(force) {
    const t = JSON.parse(LS.getItem(TK) || 'null');
    if (t && t.access && !force && t.exp > Date.now()) return t.access;
    if (t && t.refresh) { try { return (await AUTH.refresh(t.refresh)).access; } catch (e) {} }
    LS.setItem(TK, JSON.stringify({ email: t && t.email }));
    await signIn(); return JSON.parse(LS.getItem(TK)).access;
  }
  const ready = token();
  window.bannaaLogout = () => { const t = JSON.parse(LS.getItem(TK) || '{}');
    if (!C.dev && t.access) cognito('GlobalSignOut', { AccessToken: t.access }).catch(() => {});
    LS.setItem(TK, JSON.stringify({ email: t.email })); location.reload(); };
  let qrP = null;
  const loadQr = () => qrP || (qrP = new Promise((res, rej) => { const sc = document.createElement('script'); sc.src = 'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js'; sc.onload = () => res(window.QRCode); sc.onerror = rej; document.head.append(sc); }));
  window.bannaaMfa = async () => {
    const el = overlay(); el.style.background = 'rgba(20,17,12,.7)'; const card = el.querySelector('.c');
    const close = () => el.remove();
    card.innerHTML = head('التحقق الثنائي') + '<p>جارٍ التحميل…</p>';
    let on = false; try { on = await AUTH.mfaStatus(await token()); } catch (e) {}
    if (on) {
      const o = form(card, head('التحقق الثنائي', 'مفعّل على حسابك — يُطلب رمز من تطبيق المصادقة عند كل دخول.') + `<button type="button" class="x" data-close aria-label="إغلاق">×</button>
        <form style="display:grid;gap:12px"><button class="p" style="background:#B8402F">إيقاف التحقق الثنائي</button></form>`,
        async (fd, show) => { await AUTH.mfaOff(await token()); show('أُوقف التحقق الثنائي.', true); setTimeout(close, 1200); });
      card.querySelector('[data-close]').onclick = close; return;
    }
    let secret; try { secret = await AUTH.mfaAssociate(await token()); } catch (e) { card.innerHTML = head('التحقق الثنائي') + `<div class="e">${errMsg(e)}</div>`; return; }
    const email = (JSON.parse(LS.getItem(TK) || '{}').email) || '';
    const uri = `otpauth://totp/${enc('Bannaa:' + email)}?secret=${secret}&issuer=Bannaa`;
    form(card, head('تفعيل التحقق الثنائي', '1) افتح تطبيق المصادقة وامسح الرمز. 2) أدخل الرمز المكوّن من 6 أرقام.') + `<button type="button" class="x" data-close aria-label="إغلاق">×</button>
      <div data-qr style="display:grid;place-items:center;min-height:120px"></div><p style="font-size:12px">أو أدخل المفتاح يدوياً: <b class="ltr" style="display:block;word-break:break-all;font-family:monospace">${secret.replace(/(.{4})/g, '$1 ')}</b></p>
      <form style="display:grid;gap:12px"><label>الرمز من التطبيق<input name="c" required class="ltr" inputmode="numeric" maxlength="6" pattern="[0-9]{6}"></label><button class="p">تفعيل</button></form>`,
      async (fd, show) => { await AUTH.mfaVerify(await token(), String(fd.get('c')).trim()); show('تم تفعيل التحقق الثنائي.', true); setTimeout(close, 1400); });
    card.querySelector('[data-close]').onclick = close;
    loadQr().then(Q => { const box = card.querySelector('[data-qr]'); if (box) new Q(box, { text: uri, width: 180, height: 180 }); }).catch(() => {});
  };
  window.bannaaChangePassword = () => {
    const el = overlay(); el.style.background = 'rgba(20,17,12,.7)'; const card = el.querySelector('.c');
    const o = form(card, head('تغيير كلمة المرور') + `<button type="button" class="x" data-close aria-label="إغلاق">×</button>
      <form style="display:grid;gap:12px"><label>كلمة المرور الحالية<input name="o" type="password" required class="ltr" autocomplete="current-password"></label>
      <label>كلمة المرور الجديدة<input name="a" type="password" required class="ltr" autocomplete="new-password"></label>
      <label>تأكيد كلمة المرور<input name="b" type="password" required class="ltr" autocomplete="new-password"></label>${pwHint}<button class="p">حفظ</button></form>`,
      async (fd, show) => { const a = String(fd.get('a')), b = String(fd.get('b'));
        if (a !== b) return show('كلمتا المرور غير متطابقتين.'); if (!pwOk(a)) return show(ERR.InvalidPasswordException);
        await AUTH.change(await token(), String(fd.get('o')), a); show('تم تغيير كلمة المرور.', true); setTimeout(() => el.remove(), 1200); });
    card.querySelector('[data-close]').onclick = () => el.remove();
  };

  /* ---------- API ---------- */
  const CODES = { 401: 'session_expired', 403: 'permission_denied', 404: 'not_found', 413: 'too_large', 415: 'unsupported_type', 429: 'rate_limited' };
  async function api(path, opt = {}) {
    await ready;
    const go = t => fetch('/api' + path, Object.assign({}, opt, { headers: Object.assign({ 'x-bannaa-token': t }, opt.headers || {}) }));
    let r = await go(await token());
    if (r.status === 401) r = await go(await token(true));
    let d = null; try { d = await r.json(); } catch (e) {}
    if (!r.ok) throw Object.assign(new Error((d && d.message) || String(r.status)), { code: (d && d.code) || CODES[r.status] || 'unavailable', body: d });
    return d;
  }
  const jpost = (path, body, method = 'POST') => api(path, { method, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

  /* ---------- db: documents with live updates by polling ----------
     projects and settings are saved as versioned patches (only what changed), so concurrent edits merge safely */
  const STRUCT = p => /^projects\/[^/]+$/.test(p) || p === 'settings/prices';
  const COLLS = ['works', 'payments', 'cos', 'opcs', 'contractors', 'ctrHolds', 'releases', 'invPending', 'invoices', 'audit', 'reports', 'drawings', 'docs'];
  const DEEP = { 'settings/prices': ['prices'] };
  const BASE = {};   // last server version of each structured doc, with its revision info
  const J1 = x => JSON.stringify(x === undefined ? null : x);
  function mkPatch(path, n, skip) {
    const b = BASE[path] || { doc: {}, rev: {} }, bd = b.doc || {}, rev = b.rev || {}, fvb = rev.fv || {}, rvb = rev.rv || {};
    const colls = path.startsWith('projects/') ? COLLS : [], deep = DEEP[path] || [], P = { fields: {}, fv: {}, ups: {}, dels: {}, rv: {} }; let k0 = 0;
    const sk = skip || new Set();
    for (const k of new Set([...Object.keys(bd), ...Object.keys(n)])) {
      if (colls.includes(k)) continue;
      const fl = deep.includes(k) ? [...new Set([...Object.keys(bd[k] || {}), ...Object.keys(n[k] || {})])].map(s2 => [k + '.' + s2, (bd[k] || {})[s2], (n[k] || {})[s2]]) : [[k, bd[k], n[k]]];
      for (const [f, ov, nv] of fl) if (J1(ov) !== J1(nv) && !sk.has(f)) { P.fields[f] = nv === undefined ? { __del: 1 } : nv; P.fv[f] = fvb[f] || 0; k0++; }
    }
    for (const c of colls) {
      (n[c] || []).forEach(r => { if (r && typeof r === 'object' && !r.id) r.id = 'x' + Math.random().toString(36).slice(2, 11); });
      const bm = new Map((bd[c] || []).map(r => [r.id, r])), nm = new Map((n[c] || []).filter(Boolean).map(r => [r.id, r]));
      const ups = [], dels = [];
      const appendOnly = c === 'audit' || c === 'reports';
      nm.forEach((r, id) => { if (sk.has(c + '/' + id)) return; if (appendOnly ? !bm.has(id) : J1(bm.get(id)) !== J1(r)) ups.push(r); });
      if (!appendOnly) bm.forEach((r, id) => { if (!nm.has(id) && !sk.has(c + '/' + id)) dels.push(id); });
      if (ups.length || dels.length) { if (ups.length) P.ups[c] = ups; if (dels.length) P.dels[c] = dels; P.rv[c] = {}; [...ups.map(r => r.id), ...dels].forEach(id => { P.rv[c][id] = (rvb[c] || {})[id] || 0; }); k0++; }
    }
    return k0 ? P : null;
  }
  const notify = (msg, kind) => { try { window.dispatchEvent(new CustomEvent('bannaa:notice', { detail: { msg, kind } })); } catch (e) {} };
  async function structuredSet(path, data) {
    let p = mkPatch(path, data);
    for (let i = 0; p && i < 3; i++) {
      let r; try { r = await jpost('/patch?path=' + enc(path), p); }
      catch (e) {
        if (e.code === 'conflict' && e.body) {
          BASE[path] = { doc: e.body.data || {}, rev: e.body.rev || {} };
          const sk = new Set(e.body.conflicts || []);
          notify(sk.has('*') ? 'عدّل مستخدم آخر هذه البيانات في نفس اللحظة — حُدّثت الصفحة بأحدث نسخة، أعد تنفيذ الإجراء إن لزم.' : 'عدّل مستخدم آخر نفس السجل في نفس اللحظة — اعتُمدت نسخته ودُمجت بقية تعديلاتك.', 'warn');
          p = mkPatch(path, data, sk); invalidate(); continue;
        }
        if (e.code === 'permission_denied') invalidate();
        throw e;
      }
      BASE[path] = { doc: r.data || {}, rev: r.rev || {} }; p = null;
    }
    setTimeout(poll, 30);
  }
  const subs = new Set(); let timer = null;
  const invalidate = () => { subs.forEach(s => { s.last = null; }); setTimeout(poll, 30); };
  // apply a server delta to the last known version of a document (only changed fields/records travel)
  function applyDelta(path, d) {
    const b = BASE[path]; if (!b) return null;
    const doc = copy(b.doc) || {};
    Object.entries(d.fields || {}).forEach(([f, v]) => { const ks = f.split('.'); let o = doc; ks.slice(0, -1).forEach(k => { if (!o[k] || typeof o[k] !== 'object') o[k] = {}; o = o[k]; }); if (v && v.__del) delete o[ks[ks.length - 1]]; else o[ks[ks.length - 1]] = v; });
    const colls = path.startsWith('projects/') ? COLLS : [];
    colls.forEach(c => { const list = (doc[c] || []).slice(), idx = new Map(list.map((r, i) => [r.id, i]));
      ((d.ups || {})[c] || []).forEach(r => { if (idx.has(r.id)) list[idx.get(r.id)] = r; else list.push(r); });
      const del = new Set((d.dels || {})[c] || []); doc[c] = list.filter(r => !del.has(r.id)); });
    BASE[path] = { doc: copy(doc), rev: d.rev };
    return { exists: true, data: doc, rev: d.rev };
  }
  async function freshDoc(path) {
    if (STRUCT(path) && BASE[path] && BASE[path].rev && BASE[path].rev.fv) {
      const d = await jpost('/delta?path=' + enc(path), { rev: BASE[path].rev });
      return d.exists ? applyDelta(path, d) : { exists: false, data: null };
    }
    const d = await api('/db?path=' + enc(path)); remember(path, d); return d;
  }
  // live connection: the server announces which document changed; we fetch only that one (polling stays as a safety net)
  let ws = null, wsOk = false, wsWait = 2000;
  async function liveConnect() {
    if (!C.wsUrl || typeof WebSocket === 'undefined') return;
    let tk; try { tk = await token(); } catch (e) { return; }
    try { ws = new WebSocket(C.wsUrl + (C.wsUrl.includes('?') ? '&' : '?') + 't=' + enc(tk)); } catch (e) { return setTimeout(liveConnect, wsWait); }
    ws.onopen = () => { wsOk = true; wsWait = 2000; setTimeout(poll, 30); };
    ws.onmessage = ev => { let m; try { m = JSON.parse(ev.data); } catch (e) { return; } if (m && m.type === 'changed') subs.forEach(s => s.onChanged && s.onChanged(m.path)); };
    ws.onclose = () => { wsOk = false; ws = null; setTimeout(liveConnect, wsWait); wsWait = Math.min(30000, wsWait * 2); };
  }
  setInterval(() => { if (ws && wsOk) try { ws.send('{"action":"ping"}'); } catch (e) {} }, 5 * 60e3);
  window.bannaaLive = () => wsOk;
  const poll = () => subs.forEach(s => s.run());
  let ticks = 0;   // live: full re-check every 60 s; no live connection: every 5 s
  const startPoll = () => { if (!timer) { timer = setInterval(() => { ticks++; if (!document.hidden && (!wsOk || ticks % 12 === 0)) poll(); }, 5000); ready.then(liveConnect); } };
  document.addEventListener('visibilitychange', () => { if (!document.hidden) poll(); });
  const copy = x => x == null ? x : JSON.parse(JSON.stringify(x));
  function remember(path, d) { if (d && d.rev && STRUCT(path)) BASE[path] = { doc: copy(d.data) || {}, rev: d.rev }; }
  function watch(url, toSnap, cb, err, onData, onChanged) {
    let errored = false;
    const s = { last: null, deliver: d => { const k = JSON.stringify(d); if (k !== s.last) { s.last = k; cb(toSnap(d)); } }, run: async () => {
      try { const d = await api(url); const k = JSON.stringify(d); errored = false; if (k !== s.last) { s.last = k; if (onData) onData(d); cb(toSnap(d)); } }
      catch (e) { if (!errored && err) { errored = true; err(e); } }
    } };
    if (onChanged) s.onChanged = path => onChanged(path, s);
    subs.add(s); s.run(); startPoll(); return () => subs.delete(s);
  }
  function docRef(path) {
    const id = path.split('/').pop(), snap = d => ({ id, exists: !!d.exists, data: () => copy(d.data) });
    return {
      id, path,
      async get() { const d = await api('/db?path=' + enc(path)); remember(path, d); return snap(d); },
      async set(data) { if (STRUCT(path)) return structuredSet(path, copy(data)); await jpost('/db?path=' + enc(path), data, 'PUT'); setTimeout(poll, 30); },
      async update(data) { const cur = (await api('/db?path=' + enc(path))).data || {}; await this.set(Object.assign(cur, data)); },
      async delete() { await api('/db?path=' + enc(path), { method: 'DELETE' }); setTimeout(poll, 30); },
      onSnapshot(cb, err) { return watch('/db?path=' + enc(path), snap, cb, err, d => remember(path, d),
        async (p2, s) => { if (p2 !== path) return; try { s.deliver(await freshDoc(path)); } catch (e) { s.run(); } }); }
    };
  }
  function colRef(path) {
    const snap = d => ({ docs: d.docs.map(x => ({ id: x.id, exists: true, data: () => copy(x.data) })), size: d.docs.length, empty: !d.docs.length });
    return {
      path, doc: id => docRef(path + '/' + id),
      async get() { return snap(await api('/db?col=' + enc(path))); },
      onSnapshot(cb, err) {
        let docs = null;
        return watch('/db?col=' + enc(path), snap, cb, err, d => { docs = (d.docs || []).slice(); docs.forEach(x => remember(path + '/' + x.id, x)); },
          async (p2, s) => { if (!p2.startsWith(path + '/') || p2.split('/').length !== path.split('/').length + 1) return;
            if (!docs || !STRUCT(p2)) return s.run();
            try { const id = p2.split('/').pop(), r = await freshDoc(p2), i = docs.findIndex(x => x.id === id);
              if (r.exists) { const row = { id, data: r.data, rev: r.rev }; if (i >= 0) docs[i] = row; else docs.push(row); } else if (i >= 0) docs.splice(i, 1);
              s.deliver({ docs: docs.slice() }); } catch (e) { s.run(); } });
      }
    };
  }
  const db = Object.freeze({ doc: docRef, collection: colRef });

  /* ---------- user ---------- */
  const PAL = ['#94701F', '#2457D6', '#23845A', '#B8402F', '#7A5AA6', '#0E7C86', '#A8670E', '#5B6B7F'];
  const colorOf = id => { let h = 0; for (const c of String(id || '')) h = (h * 31 + c.charCodeAt(0)) >>> 0; return PAL[h % PAL.length]; };
  const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const avatar = (id, name, email) => 'data:image/svg+xml,' + enc(`<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64"><rect width="64" height="64" rx="32" fill="${colorOf(id)}"/><text x="32" y="42" font-size="28" text-anchor="middle" fill="#fff" font-family="Tahoma,sans-serif">${esc((name || email || '?').trim().charAt(0).toUpperCase())}</text></svg>`);
  let meP = null; const getMe = () => meP || (meP = api('/me').then(m => { window.bannaaTenant = Object.assign({ isOperator: !!m.isOperator, isPrimary: !!m.isPrimary, isOwner: !!m.isOwner, role: m.role || null }, m.tenant || {}); try { window.dispatchEvent(new CustomEvent('bannaa:tenant')); } catch (e) {} return m; }));
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
  // large files (documents/drawings): signed URL from the API, then PUT straight to storage, with progress
  window.bannaaUpload = async (file, onProgress) => {
    const r = await jpost('/upload-url', { name: file.name, type: file.type || 'application/octet-stream', size: file.size });
    await new Promise((res, rej) => { const x = new XMLHttpRequest(); x.open(r.method || 'PUT', r.uploadUrl);
      Object.entries(r.headers || {}).forEach(([k, v]) => x.setRequestHeader(k, v));
      x.upload.onprogress = e => { if (onProgress && e.lengthComputable) onProgress(e.loaded / e.total); };
      x.onload = () => x.status < 300 ? res() : rej({ code: 'upload_failed', message: 'تعذّر رفع الملف (' + x.status + ')' }); x.onerror = () => rej({ code: 'network', message: 'انقطع الاتصال أثناء الرفع' }); x.send(file); });
    return { id: r.id, url: r.url };
  };

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
      if (Date.now() - t0 > 900000) throw { code: 'timeout', message: 'timeout' };
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
    list: () => api('/users?withProjects=1'),
    setProjects: (id, projects) => jpost('/users/projects', { id, projects }),
    mfaOff: id => jpost('/users/mfa-off', { id }),
    tenants: () => api('/tenants'),
    createTenant: b => jpost('/tenants', b),
    updateTenant: b => jpost('/tenants', b, 'PATCH'),
    tenantAdmins: id => api('/tenants/admins?id=' + enc(id)),
    addTenantAdmin: b => jpost('/tenants/admins', b),
    tenantAdminPassword: (id, uid, password, temporary) => jpost('/tenants/admins/password', { id, uid, password, temporary }),
    tenantAdminStatus: (id, uid, on) => jpost('/tenants/admins/status', { id, uid, on }),
    tenantAdminMfaOff: (id, uid) => jpost('/tenants/admins/mfa-off', { id, uid }),
    platformAdmins: () => api('/platform/admins'),
    addPlatformAdmin: b => jpost('/platform/admins', b),
    platformAdminStatus: (uid, on) => jpost('/platform/admins/status', { uid, on }),
    platformAdminPassword: (uid, password, temporary) => jpost('/platform/admins/password', { uid, password, temporary }),
    branding: b => jpost('/branding', b).then(r => { meP = null; getMe(); return r; }),
    create: b => jpost('/users', b),
    setRole: (id, role) => jpost('/users', { id, role }, 'PATCH').then(r => { setTimeout(poll, 30); return r; }),
    setStatus: (id, on) => jpost('/users/status', { id, on }),
    reset: id => jpost('/users/reset', { id }),
    setPassword: (id, password, temporary) => jpost('/users/password', { id, password, temporary }),
    domains: ds => jpost('/users/domains', { domains: ds }).then(r => { setTimeout(poll, 30); return r; })
  });

  setInterval(() => { if (!document.hidden) api('/blobcookie').catch(() => {}); }, 6 * 3600e3);

  const NS = { db, user, sample, assets, downloads, mcp };
  window.claude = Object.freeze({ use: async name => { try { await ready; } catch (e) {} return NS[name] || null; } });
})();
