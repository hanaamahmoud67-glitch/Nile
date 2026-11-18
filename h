// functions/index.js  (Node 20, firebase-functions v2)
const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { defineString } = require("firebase-functions/params");
const admin = require("firebase-admin");
const crypto = require("crypto");

admin.initializeApp();
const db = admin.firestore();

// تُضبط في functions/.env  (انظر خطوات النشر) - وليست داخل كود الواجهة
const SUPER_ADMIN_EMAIL = defineString("SUPER_ADMIN_EMAIL");
const APP_ID = defineString("APP_ID", { default: "nile-removal-project-default" });

const opts = { region: "europe-west1", cors: true };
const ROLES = ["admin", "user"];

const base = () => db.collection("artifacts").doc(APP_ID.value()).collection("public").doc("data");
const profiles = () => base().collection("user_profiles");
const logs = () => base().collection("audit_logs");
const superEmail = () => SUPER_ADMIN_EMAIL.value().trim().toLowerCase();

function requireSuper(req) {
  const t = req.auth && req.auth.token;
  if (!t || t.role !== "superadmin" || (t.email || "").toLowerCase() !== superEmail()) {
    throw new HttpsError("permission-denied", "هذه العملية للأدمن الرئيسي فقط.");
  }
}
async function audit(req, action, target, extra = {}) {
  await logs().add({
    action, target,
    by: req.auth.token.email, byUid: req.auth.uid,
    at: admin.firestore.FieldValue.serverTimestamp(), ...extra,
  });
}
async function getTarget(uid) {
  let u;
  try { u = await admin.auth().getUser(uid); } catch { throw new HttpsError("not-found", "المستخدم غير موجود."); }
  if ((u.email || "").toLowerCase() === superEmail())
    throw new HttpsError("permission-denied", "لا يمكن تعديل حساب الأدمن الرئيسي.");
  return u;
}

// يُستدعى بعد كل تسجيل دخول: يضبط claim الأدمن الرئيسي (الحساب منشأ يدوياً من Console)
// ويرجع الدور الحالي. أي حساب بدون claim ولا يطابق البريد الرئيسي يُرفض.
exports.syncMyClaims = onCall(opts, async (req) => {
  if (!req.auth) throw new HttpsError("unauthenticated", "يلزم تسجيل الدخول.");
  const email = (req.auth.token.email || "").toLowerCase();
  if (email === superEmail()) {
    if (req.auth.token.role !== "superadmin")
      await admin.auth().setCustomUserClaims(req.auth.uid, { role: "superadmin" });
    await profiles().doc(req.auth.uid).set(
      { email, name: "الأدمن الرئيسي", role: "superadmin", disabled: false }, { merge: true });
    return { role: "superadmin", refresh: req.auth.token.role !== "superadmin" };
  }
  return { role: req.auth.token.role || null, refresh: false };
});

exports.createManagedUser = onCall(opts, async (req) => {
  requireSuper(req);
  const { email, name, adminName, role } = req.data || {};
  const e = String(email || "").trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)) throw new HttpsError("invalid-argument", "بريد غير صالح.");
  if (!ROLES.includes(role)) throw new HttpsError("invalid-argument", "صلاحية غير صالحة.");
  if (!String(name || "").trim()) throw new HttpsError("invalid-argument", "الاسم مطلوب.");
  if (e === superEmail()) throw new HttpsError("already-exists", "هذا البريد محجوز.");

  let user;
  try {
    // كلمة مرور عشوائية لا يراها أحد؛ المستخدم يضع كلمته عبر رابط إعادة التعيين
    user = await admin.auth().createUser({
      email: e, displayName: name.trim(),
      password: crypto.randomBytes(24).toString("base64"), disabled: false,
    });
  } catch (err) {
    if (err.code === "auth/email-already-exists") throw new HttpsError("already-exists", "البريد مسجل مسبقاً.");
    throw new HttpsError("internal", "تعذر إنشاء الحساب.");
  }
  await admin.auth().setCustomUserClaims(user.uid, { role });
  await profiles().doc(user.uid).set({
    email: e, name: name.trim(), adminName: String(adminName || "").trim(), role, disabled: false,
    createdBy: req.auth.token.email, createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });
  await audit(req, "create_user", e, { role });
  return { uid: user.uid, email: e };
});

exports.updateManagedUser = onCall(opts, async (req) => {
  requireSuper(req);
  const { uid, name, adminName, role, disabled } = req.data || {};
  const u = await getTarget(uid);
  const patch = {};
  if (typeof name === "string" && name.trim()) { patch.name = name.trim(); await admin.auth().updateUser(uid, { displayName: patch.name }); }
  if (typeof adminName === "string") patch.adminName = adminName.trim();
  if (role !== undefined) {
    if (!ROLES.includes(role)) throw new HttpsError("invalid-argument", "صلاحية غير صالحة.");
    await admin.auth().setCustomUserClaims(uid, { role });
    patch.role = role;
  }
  if (typeof disabled === "boolean") {
    await admin.auth().updateUser(uid, { disabled });
    if (disabled) await admin.auth().revokeRefreshTokens(uid); // إبطال الجلسات
    patch.disabled = disabled;
  }
  if (role !== undefined) await admin.auth().revokeRefreshTokens(uid); // يفرض إعادة تحميل الـclaims
  await profiles().doc(uid).set(patch, { merge: true });
  await audit(req, "update_user", u.email, patch);
  return { ok: true };
});

exports.deleteManagedUser = onCall(opts, async (req) => {
  requireSuper(req);
  const u = await getTarget(req.data && req.data.uid);
  await admin.auth().deleteUser(u.uid);
  await profiles().doc(u.uid).delete();   // سجلات البيانات (records) لا تُحذف
  await audit(req, "delete_user", u.email);
  return { ok: true };
});
