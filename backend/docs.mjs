// Structured documents: a project (or settings/prices) is stored as one "meta" item for its plain fields plus one item
// per record (work report, payment, invoice, audit entry…). Every field and record carries a version, writes are
// conditional on those versions (DynamoDB transactions), so two people editing different things never overwrite
// each other, and editing the same thing returns a conflict instead of silently losing data.
import { COLLS, DEEP, checkRecord, checkField, can } from './rules.mjs';

export const STRUCT = p => /^projects\/[A-Za-z0-9_\-.~:@+]+$/.test(p) || p === 'settings/prices';
const pkOf = p => p.startsWith('projects/') ? 'PRJ#' + p.slice(9) : 'SET#' + p.slice(9);
const collsOf = p => p.startsWith('projects/') ? COLLS : [];
const deepOf = p => DEEP[p] || [];
const clone = x => x === undefined ? undefined : JSON.parse(JSON.stringify(x));
const getF = (o, f) => f.split('.').reduce((a, k) => a == null ? undefined : a[k], o);
function setF(o, f, v) { const ks = f.split('.'); let a = o; ks.slice(0, -1).forEach(k => { if (a[k] == null || typeof a[k] !== 'object') a[k] = {}; a = a[k]; }); if (v === undefined) delete a[ks[ks.length - 1]]; else a[ks[ks.length - 1]] = v; }
// all versioned field names of a plain-field object
const fieldsOf = (path, obj) => Object.keys(obj || {}).flatMap(k => deepOf(path).includes(k) && obj[k] && typeof obj[k] === 'object' ? Object.keys(obj[k]).map(s => k + '.' + s) : [k]);

export function makeDocs(store) {
  async function load(path) {
    const pk = pkOf(path), items = await store.items(pk);
    const meta = items.find(i => i.sk === 'meta');
    const recs = {}; collsOf(path).forEach(c => recs[c] = {});
    items.forEach(i => { if (i.sk.startsWith('r#')) { const [, c, id] = i.sk.split('#'); if (recs[c]) recs[c][id] = i; } });
    return { pk, meta, recs };
  }
  function assemble(path, st) {
    if (!st.meta) return null;
    const doc = clone(st.meta.data.fields || {}), rev = { v: st.meta.v, fv: st.meta.data.fv || {}, rv: {} };
    collsOf(path).forEach(c => {
      const list = Object.entries(st.recs[c]).sort((a, b) => a[1].o - b[1].o);
      doc[c] = list.map(([, i]) => i.data); rev.rv[c] = Object.fromEntries(list.map(([id, i]) => [id, i.v]));
    });
    return { data: doc, rev };
  }
  // one-time move of a document written by the older whole-document format (or imported seed data)
  async function migrate(path) {
    const [col, id] = path.split('/'); const legacy = await store.get(col, id); if (!legacy) return false;
    const pk = pkOf(path), fields = {}, fv = {}, ops = []; let o = 0;
    Object.entries(legacy).forEach(([k, v]) => { if (!collsOf(path).includes(k)) fields[k] = v; });
    fieldsOf(path, fields).forEach(f => fv[f] = 1);
    ops.push({ put: { pk, sk: 'meta', data: { fields, fv }, v: 1, o: 0, by: '' }, cond: null });
    collsOf(path).forEach(c => (legacy[c] || []).forEach((r, i) => {
      if (!r.id) r.id = 'm' + c.slice(0, 3) + i;
      ops.push({ put: { pk, sk: `r#${c}#${r.id}`, data: r, v: 1, o: ++o, by: r.byKey && !String(r.byKey).startsWith('role:') ? r.byKey : '' }, cond: null });
    }));
    for (let i = 0; i < ops.length; i += 90) await store.txn(ops.slice(i, i + 90));
    if (path.startsWith('projects/')) await store.put('PRJIDX', id, { name: legacy.name || id });
    await store.put('_legacy', col + '#' + id, legacy); await store.del(col, id);
    return true;
  }
  // lists that used to live inside the project's plain fields (reports, drawings…) become separate records
  async function upgrade(path, st) {
    if (!st.meta) return st;
    const fields = st.meta.data.fields || {}, move = collsOf(path).filter(c => Array.isArray(fields[c]));
    if (!move.length) return st;
    const nf = Object.assign({}, fields), fv = Object.assign({}, st.meta.data.fv || {}), ops = []; let o = 0;
    move.forEach(c => { delete nf[c]; delete fv[c];
      const list = c === 'reports' ? fields[c].slice().reverse() : fields[c];   // reports were stored newest-first
      list.forEach((r, i) => { if (!r || typeof r !== 'object') return; if (!r.id) r.id = 'u' + c.slice(0, 3) + i; if (st.recs[c][r.id]) return;
        ops.push({ put: { pk: st.pk, sk: `r#${c}#${r.id}`, data: r, v: 1, o: ++o, by: '' }, cond: null }); }); });
    ops.unshift({ put: { pk: st.pk, sk: 'meta', data: { fields: nf, fv }, v: st.meta.v + 1, o: 0, by: st.meta.by }, cond: st.meta.v });
    try { for (let i = 0; i < ops.length; i += 99) await store.txn(ops.slice(i, i + 99)); } catch (e) { if (e.code !== 'conflict') throw e; }
    return load(path);
  }
  async function current(path) {
    let st = await load(path);
    if (!st.meta && await migrate(path)) st = await load(path);
    return upgrade(path, st);
  }
  async function read(path) { return assemble(path, await current(path)); }
  // only what changed since the client's revision — keeps live updates small even for very large projects
  async function delta(path, rev) {
    const st = await current(path); if (!st.meta) return { exists: false };
    const fv = st.meta.data.fv || {}, cfv = (rev && rev.fv) || {}, crv = (rev && rev.rv) || {}, fields = {}, ups = {}, dels = {};
    for (const f of new Set([...Object.keys(fv), ...Object.keys(cfv)])) if ((fv[f] || 0) !== (cfv[f] || 0)) { const v = getF(st.meta.data.fields || {}, f); fields[f] = v === undefined ? { __del: 1 } : v; }
    const rv = {};
    collsOf(path).forEach(c => { rv[c] = {}; const mine = crv[c] || {};
      Object.entries(st.recs[c]).sort((a, b) => a[1].o - b[1].o).forEach(([id, i]) => { rv[c][id] = i.v; if (mine[id] !== i.v) (ups[c] = ups[c] || []).push(i.data); });
      Object.keys(mine).forEach(id => { if (!st.recs[c][id]) (dels[c] = dels[c] || []).push(id); }); });
    return { exists: true, rev: { v: st.meta.v, fv, rv }, fields, ups, dels };
  }
  async function listProjects() {
    for (const x of await store.list('projects')) await migrate('projects/' + x.id);
    return (await store.list('PRJIDX')).map(x => x.id);
  }

  /** Apply a patch. ctx: { role, uid, limits }. Returns { status, body }. */
  async function patch(path, p, ctx, stampAudit) {
    for (let attempt = 0; attempt < 3; attempt++) {
      const st = await current(path);
      const creating = !st.meta, fields = clone(st.meta ? st.meta.data.fields : {}) || {}, fv = clone(st.meta ? st.meta.data.fv : {}) || {};
      const conflicts = [], errors = [], ops = [];
      const c = Object.assign({ creating }, ctx);
      // plain fields
      let metaChanged = false;
      for (const [f, val] of Object.entries(p.fields || {})) {
        if (!/^[A-Za-z0-9_]+(\.[A-Za-z0-9_\-.~:@+]+)?$/.test(f) || collsOf(path).includes(f.split('.')[0])) { errors.push('حقل غير صالح'); continue; }
        if ((fv[f] || 0) !== ((p.fv || {})[f] || 0)) { conflicts.push(f); continue; }
        const nv = val && val.__del ? undefined : val, ov = getF(fields, f);
        if (JSON.stringify(ov ?? null) === JSON.stringify(nv ?? null)) continue;
        const e = checkField(path, f, ov, nv, c); if (e) { errors.push(e); continue; }
        setF(fields, f, clone(nv)); fv[f] = (fv[f] || 0) + 1; metaChanged = true;
      }
      // records
      let seq = 0; const now = Date.now() * 1000;
      for (const coll of Object.keys(Object.assign({}, p.ups, p.dels))) {
        if (!collsOf(path).includes(coll)) { errors.push('مجموعة غير صالحة'); continue; }
        const base = (p.rv || {})[coll] || {};
        for (const rec of (p.ups || {})[coll] || []) {
          const id = String(rec && rec.id || ''); if (!/^[A-Za-z0-9_\-]{1,64}$/.test(id)) { errors.push('معرّف سجل غير صالح'); continue; }
          const cur = st.recs[coll][id];
          if ((cur ? cur.v : 0) !== (base[id] || 0)) { conflicts.push(`${coll}/${id}`); continue; }
          const neu = clone(rec);
          if (coll === 'audit') stampAudit(neu);
          if (cur && JSON.stringify(cur.data) === JSON.stringify(neu)) continue;
          const e = checkRecord(coll, cur ? Object.assign({}, cur.data, { __by: cur.by }) : undefined, neu, c); if (e) { errors.push(e); continue; }
          ops.push({ put: { pk: st.pk, sk: `r#${coll}#${id}`, data: neu, v: (cur ? cur.v : 0) + 1, o: cur ? cur.o : now + (++seq), by: cur ? cur.by : ctx.uid }, cond: cur ? cur.v : null });
        }
        for (const id of (p.dels || {})[coll] || []) {
          const cur = st.recs[coll][id]; if (!cur) continue;
          if (cur.v !== (base[id] || 0)) { conflicts.push(`${coll}/${id}`); continue; }
          const ok = coll === 'invPending' && (can(ctx.role, 'approveInv') || cur.by === ctx.uid);
          if (!ok) { errors.push(checkRecord(coll, cur.data, undefined, c)); continue; }
          ops.push({ del: { pk: st.pk, sk: `r#${coll}#${id}` }, cond: cur.v });
        }
      }
      if (conflicts.length) return { status: 409, body: Object.assign({ code: 'conflict', conflicts }, assemble(path, st) || { data: null, rev: {} }) };
      if (errors.length) return { status: 403, body: { code: 'permission_denied', message: errors[0], errors } };
      if (metaChanged || creating) ops.unshift({ put: { pk: st.pk, sk: 'meta', data: { fields, fv }, v: (st.meta ? st.meta.v : 0) + 1, o: 0, by: st.meta ? st.meta.by : ctx.uid }, cond: st.meta ? st.meta.v : null });
      if (!ops.length) return { status: 200, body: assemble(path, st) };
      try { for (let i = 0; i < ops.length; i += 99) await store.txn(ops.slice(i, i + 99)); }
      catch (e) { if (e.code === 'conflict') continue; throw e; }   // someone wrote between our read and write — re-check
      if (creating && path.startsWith('projects/')) await store.put('PRJIDX', path.slice(9), { name: fields.name || '' });
      else if (path.startsWith('projects/') && (p.fields || {}).name !== undefined) await store.put('PRJIDX', path.slice(9), { name: fields.name || '' });
      return { status: 200, body: Object.assign({ created: creating }, await read(path)) };
    }
    return { status: 409, body: Object.assign({ code: 'conflict', conflicts: ['*'] }, await read(path)) };
  }
  return { read, patch, listProjects, delta };
}
