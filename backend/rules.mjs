// Server-side business rules: who may create or change which record, and which status transitions are allowed.
// Mirrors the role matrix in the app (web/index.html → ROLES). '__owner' (platform owner) has every capability,
// but separation-of-duties checks still apply to them.
export const CAPS = {
  pm: ['docs', 'docsAdmin', 'prices', 'invoices', 'approveInv', 'drawings', 'reports', 'submitWork', 'approveWork', 'payApprove', 'contractors', 'coCreate', 'coApprove', 'limits', 'auditView', 'finView', 'opcApprove'],
  eng: ['docs', 'drawings', 'reports', 'invoices', 'submitWork', 'coCreate'],
  owner: ['payOwner', 'coOwner', 'auditView', 'opcClient'],
  acc: ['docs', 'prices', 'invoices', 'approveInv', 'payReq', 'payRecord', 'auditView', 'finView', 'opcBill'],
  admin: ['team']
};
export const can = (role, cap) => role === '__owner' || (CAPS[role] || []).includes(cap);
const any = (role, ...caps) => caps.some(c => can(role, c));

// collections stored as separate records (one DynamoDB item each) inside a project
// every growing list is its own set of records, so a project has no practical size limit
export const COLLS = ['works', 'payments', 'cos', 'opcs', 'contractors', 'ctrHolds', 'releases', 'invPending', 'invoices', 'audit', 'reports', 'drawings', 'docs'];
// fields whose sub-keys are versioned separately (so two people can edit different materials at once)
export const DEEP = { 'settings/prices': ['prices'] };

const same = (a, b, keys) => keys.every(k => JSON.stringify(a[k] ?? null) === JSON.stringify(b[k] ?? null));
const onlyChanged = (a, b, allowed) => Object.keys({ ...a, ...b }).every(k => allowed.includes(k) || JSON.stringify(a[k] ?? null) === JSON.stringify(b[k] ?? null));
const MONEY = { payments: ['contractor', 'works', 'releases', 'ctrHolds', 'gross', 'vat', 'ret', 'holds', 'release', 'net'], opcs: ['lines', 'gross', 'ret', 'vat', 'net', 'upto'], cos: ['contractor', 'value', 'days'] };
const sod = (c, rec, msg) => c.uid === rec.__by ? (msg || 'لا يمكنك اعتماد ما أنشأته بنفسك (فصل المهام)') : null;

/** Returns an Arabic error message if the change is not allowed, otherwise null.
 *  old: current server record (with __by = creator id) or undefined on create; neu: new record or undefined on delete.
 *  c: { role, uid, limits } */
export function checkRecord(coll, old, neu, c) {
  const r = c.role, deny = m => m || 'لا تملك صلاحية هذا الإجراء';
  if (coll === 'audit') return old ? 'سجل التدقيق لا يُعدَّل ولا يُحذف' : null;
  if (!neu) return 'حذف السجلات غير مسموح — استخدم الرفض أو الإلغاء';
  const from = old && old.status, to = neu.status;
  switch (coll) {
    case 'works':
      if (!old) return can(r, 'submitWork') && to === 'submitted' ? null : deny();
      if (from === to) return onlyChanged(old, neu, []) ? null : deny('لا يمكن تعديل تقرير الأعمال في حالته الحالية');
      if (from === 'submitted' && (to === 'approved' || to === 'rejected')) return can(r, 'approveWork') ? sod(c, old) : deny();
      if (from === 'rejected' && to === 'submitted') return can(r, 'submitWork') ? null : deny();
      if (from === 'approved' && to === 'inpay') return can(r, 'payReq') && same(old, neu, ['aQty', 'rate', 'calc', 'holds']) ? null : deny();
      if (from === 'inpay' && to === 'approved') return any(r, 'payApprove', 'payOwner') ? null : deny();
      if (from === 'inpay' && to === 'paid') return can(r, 'payRecord') ? null : deny();
      return deny('انتقال حالة غير مسموح لتقرير الأعمال');
    case 'payments': {
      if (!old) return can(r, 'payReq') && to === 'requested' ? null : deny();
      if (!same(old, neu, MONEY.payments)) return 'لا يمكن تعديل مبالغ طلب الصرف بعد إنشائه';
      const lim = +(c.limits && c.limits.pay) || 100000;
      if (from === 'requested' && to === 'approved') return can(r, 'payApprove') ? (neu.net > lim ? 'الدفعة فوق حد الصلاحية — يجب رفعها للمالك' : sod(c, old)) : deny();
      if (from === 'requested' && to === 'owner') return can(r, 'payApprove') ? sod(c, old) : deny();
      if (from === 'owner' && to === 'approved') return can(r, 'payOwner') ? sod(c, old) : deny();
      if ((from === 'requested' || from === 'owner') && to === 'rejected') return any(r, 'payApprove', 'payOwner') ? null : deny();
      if (from === 'approved' && to === 'paid') return can(r, 'payRecord') ? null : deny();
      return deny('انتقال حالة غير مسموح لطلب الصرف');
    }
    case 'invoices': return old ? 'الفاتورة المعتمدة لا تُعدَّل' : can(r, 'approveInv') ? null : deny('اعتماد الفواتير لمدير المشروع والمحاسب فقط');
    case 'invPending': return old ? deny() : can(r, 'invoices') ? null : deny();
    case 'cos': {
      const lim = +(c.limits && c.limits.co) || 25000;
      if (!old) return can(r, 'coCreate') && (to === 'submitted' || (to === 'owner' && can(r, 'coApprove'))) ? null : deny();
      if (!same(old, neu, MONEY.cos) || JSON.stringify((old.lines || []).map(l => [l.kind, l.qty, l.rate])) !== JSON.stringify((neu.lines || []).map(l => [l.kind, l.qty, l.rate]))) return 'لا يمكن تعديل قيمة الأمر التغييري بعد رفعه';
      if (from === 'submitted' && to === 'owner') return can(r, 'coApprove') ? sod(c, old) : deny();
      if (from === 'submitted' && to === 'approved') return can(r, 'coApprove') ? (Math.abs(neu.value) > lim ? 'الأمر التغييري فوق الحد — يجب رفعه للمالك' : sod(c, old)) : deny();
      if (from === 'owner' && to === 'approved') return can(r, 'coOwner') ? null : deny();
      if (from === 'submitted' && to === 'rejected') return can(r, 'coApprove') ? null : deny();
      if (from === 'owner' && to === 'rejected') return can(r, 'coOwner') ? null : deny();
      return deny('انتقال حالة غير مسموح للأمر التغييري');
    }
    case 'opcs':
      if (!old) return can(r, 'opcBill') && to === 'requested' ? null : deny();
      if (!same(old, neu, MONEY.opcs)) return 'لا يمكن تعديل مبالغ مستخلص المالك بعد إعداده';
      if (from === 'requested' && to === 'client') return can(r, 'opcApprove') ? sod(c, old) : deny();
      if (from === 'requested' && to === 'rejected') return can(r, 'opcApprove') ? null : deny();
      if (from === 'client' && (to === 'approved' || to === 'rejected')) return can(r, 'opcClient') ? null : deny();
      if (from === 'approved' && to === 'paid') return can(r, 'opcBill') ? null : deny();
      return deny('انتقال حالة غير مسموح لمستخلص المالك');
    case 'contractors':
      if (can(r, 'contractors')) return null;
      return old && onlyChanged(old, neu, ['rates']) && any(r, 'coApprove', 'coOwner') ? null : deny();
    case 'ctrHolds':
      if (!old) return can(r, 'approveWork') ? null : deny();
      if (!same(old, neu, ['amount', 'contractor', 'type'])) return deny('لا يمكن تعديل مبلغ الحجز');
      if (to === 'applied' && from === 'open') return can(r, 'payReq') ? null : deny();
      if (to === 'open' && from === 'applied') return any(r, 'payApprove', 'payOwner') ? null : deny();
      if (to === 'released') return can(r, 'approveWork') ? null : deny();
      return from === to ? null : deny();
    case 'releases':
      if (!old) return can(r, 'approveWork') ? null : deny();
      if (!same(old, neu, ['amount', 'contractor', 'type'])) return deny('لا يمكن تعديل مبلغ الإفراج');
      if (from === 'due' && to === 'inpay') return can(r, 'payReq') ? null : deny();
      if (from === 'inpay' && to === 'due') return any(r, 'payApprove', 'payOwner') ? null : deny();
      if (from === 'inpay' && to === 'paid') return can(r, 'payRecord') ? null : deny();
      return from === to ? null : deny();
    case 'reports': return old ? deny('التقرير اليومي لا يُعدَّل بعد إرساله') : can(r, 'reports') ? null : deny();
    case 'drawings': return old ? (can(r, 'drawings') ? null : deny()) : can(r, 'drawings') ? null : deny();
    case 'docs': {
      if (!old) return can(r, 'docs') && Array.isArray(neu.revs) && neu.revs.length === 1 ? null : deny('لا تملك صلاحية رفع المستندات');
      const or = old.revs || [], nr = neu.revs || [];
      if (JSON.stringify(nr.slice(0, or.length)) !== JSON.stringify(or)) return 'لا يمكن تعديل أو حذف مراجعة سابقة للمستند';
      const meta = ['cat', 'no', 'title', 'dir', 'party', 'ref', 'date', 'disc'];
      if (!same(old, neu, meta) && !can(r, 'docsAdmin')) return deny('تعديل بيانات المستند لمدير المشروع');
      if ((old.status || '') !== (neu.status || '') && !can(r, 'docsAdmin')) return deny('تغيير حالة المستند لمدير المشروع');
      if (nr.length > or.length && !can(r, 'docs')) return deny('لا تملك صلاحية رفع مراجعة');
      return null;
    }
  }
  return deny();
}

/** Field-level rules for a project's plain fields and for settings/prices. Returns error or null. */
export function checkField(path, field, oldV, newV, c) {
  const r = c.role, top = field.split('.')[0];
  if (path.startsWith('projects/')) {
    if (c.creating) return can(r, 'limits') ? null : 'إنشاء المشاريع لمدير المشروع فقط';
    switch (top) {
      case 'items': return any(r, 'drawings', 'approveInv', 'coApprove', 'coOwner') ? null : 'لا تملك صلاحية تعديل جدول الكميات';
      case 'takeoff': case 'drawings': return can(r, 'drawings') ? null : 'لا تملك صلاحية المخططات';
      case 'reports': case 'progress': return any(r, 'reports', 'drawings') ? null : 'لا تملك صلاحية التقارير اليومية';
      case 'baseline': return oldV === undefined || can(r, 'limits') ? null : 'تعديل خط الأساس لمدير المشروع فقط';
      case 'owner': return any(r, 'limits', 'opcBill') ? null : 'لا تملك صلاحية شروط عقد المالك';
      case 'site': return can(r, 'approveWork') ? null : 'تحديد موقع المشروع لمدير المشروع';
      default: return can(r, 'limits') ? null : 'تعديل بيانات المشروع لمدير المشروع فقط';
    }
  }
  if (path === 'settings/prices') {
    if (top === 'prices') return any(r, 'prices', 'approveInv', 'coApprove', 'coOwner') ? null : 'لا تملك صلاحية تعديل الأسعار';
    if (top === 'limits') return can(r, 'limits') ? null : 'تعديل حدود الاعتماد لمدير المشروع فقط';
    if (top === 'auto') return any(r, 'prices', 'limits') ? null : 'لا تملك صلاحية الإعدادات';
    return can(r, 'limits') ? null : 'لا تملك الصلاحية';
  }
  return 'مسار غير معروف';
}
