"""Builds web/index.html from the claude.ai version of the platform (bannaa-platform.html).
Usage: python3 tools/build_web.py path/to/bannaa-platform.html"""
import sys, pathlib
src = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else 'bannaa-platform.html').read_text(encoding='utf8')
R = [
 ("</head><body>", '<script src="config.js"></script><script src="claude-shim.js"></script></head><body>'),
 ("const PLATFORM_URL='https://claude.ai/artifact/QG26HSyuAAmbuFMd9ukCfq';", "const PLATFORM_URL=location.origin+'/';"),
 ("if(/^https:\\/\\/claude\\.ai\\//.test(ln))t.link=ln;", "if(/^https:\\/\\//.test(ln))t.link=ln;"),
 ("افتح المنصة من claude.ai واسمح لها باستخدام Claude، أو جرّب المثال التوضيحي.", "تأكد من إعداد مفتاح Anthropic في AWS، أو جرّب المثال التوضيحي."),
 ("سجّل الدخول إلى claude.ai لفتح المنصة.", "سجّل الدخول لفتح المنصة."),
 ("لم تُشارك claude.ai بريدك مع المنصة، فلا يمكن مطابقته بدعوة تلقائياً.", "لا يمكن مطابقة بريدك بدعوة تلقائياً."),
 ("2) سجّل الدخول إلى claude.ai بهذا البريد نفسه: ${email}", "2) أنشئ حساباً (Sign up) بهذا البريد نفسه: ${email} — أو سجّل الدخول إن كان لديك حساب"),
 ("<li>سجّل الدخول إلى claude.ai بهذا البريد نفسه: <b dir=\"ltr\">${h(email)}</b></li>", "<li>أنشئ حساباً (Sign up) بهذا البريد نفسه: <b dir=\"ltr\">${h(email)}</b> — أو سجّل الدخول إن كان لديك حساب</li>"),
 ("server_not_connected:'Gmail غير مربوط بحسابك في claude.ai'", "server_not_connected:'خدمة البريد غير مهيأة'"),
 ("تُرسل الدعوة من بريدك عبر Gmail.", "تُرسل الدعوة من بريد المنصة (Amazon SES)."),
 ("المنصة لا تستطيع منح صلاحية فتح الرابط بنفسها. من قائمة <b>مشاركة</b> أعلى الصفحة: أضف بريد المدعو، أو اختر «أي شخص لديه الرابط». الصلاحيات داخل المنصة تحددها الدعوة.",
  "لا يستطيع إنشاء حساب في المنصة إلا البريد المدعو أو بريد ضمن نطاق الشركة — يُتحقق من ذلك على الخادم."),
 ("الدعوات بالبريد والحسابات الحقيقية تعمل عند فتح المنصة من رابطها على claude.ai مع تسجيل الدخول.", "الدعوات بالبريد والحسابات الحقيقية تعمل بعد تسجيل الدخول."),
 ("حسابات حقيقية: الدعوة بالبريد ← الدخول بحساب claude.ai بنفس البريد ← تفعيل تلقائي بالدور", "حسابات حقيقية: الدعوة بالبريد ← إنشاء حساب بنفس البريد ← تفعيل تلقائي بالدور"),
 ("  t.append(b,sp);d.append(img,t);box.append(d);\n", "  t.append(b,sp);d.append(img,t);box.append(d);\n  if(window.bannaaLogout){const lo=document.createElement('button');lo.className='btn sm';lo.textContent='تسجيل الخروج';lo.style.marginTop='6px';lo.onclick=()=>window.bannaaLogout();box.append(lo)}\n"),
 ("const link=teamDoc().link||PLATFORM_URL,", "const link=(teamDoc().link&&!/claude\\.ai/.test(teamDoc().link))?teamDoc().link:PLATFORM_URL,"),
 ('<div class="rail-foot">نموذج أولي للعرض', '<div class="rail-foot">منصة بنّاء على AWS · نموذج أولي'),
]
for a, b in R:
    n = src.count(a)
    if n != 1: sys.exit(f'pattern found {n} times: {a[:80]}')
    src = src.replace(a, b)
out = pathlib.Path(__file__).resolve().parent.parent / 'web' / 'index.html'
out.write_text(src, encoding='utf8'); print('wrote', out)
