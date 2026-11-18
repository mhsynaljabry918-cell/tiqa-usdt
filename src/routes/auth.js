import { Router } from "express";
import { z } from "zod";
import bcrypt from "bcryptjs";
import { pool } from "../db.js";
import { makeOtp, otpHash, randomToken, sha256, safeEqualHex } from "../security.js";
import { deliverOtp } from "../otp-delivery.js";
import { requireUser } from "../middleware/auth.js";

const router = Router();
const contactSchema = z.object({
  kind: z.enum(["email", "phone"]),
  contact: z.string().trim().min(5).max(254),
  country: z.string().length(2).default("MA")
});

function normalizeContact(kind, raw) {
  const value = raw.trim();
  if (kind === "email") {
    const email = value.toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) throw Object.assign(new Error("البريد الإلكتروني غير صالح."), { status: 400 });
    return email;
  }
  const phone = value.replace(/[\s().-]/g, "");
  if (!/^\+[1-9]\d{7,14}$/.test(phone)) throw Object.assign(new Error("أدخل الهاتف بالصيغة الدولية، مثل +2126XXXXXXXX."), { status: 400 });
  return phone;
}

function maskContact(kind, value) {
  if (kind === "email") return value.replace(/^(.{2}).*(@.*)$/, "$1•••$2");
  return `${value.slice(0, 4)}••••${value.slice(-2)}`;
}

async function issueOtp({ kind, contact, purpose, payload }) {
  const code = makeOtp();
  const hash = otpHash(code);
  const minutes = Math.max(1, Number(process.env.OTP_MINUTES || 10));
  await pool.query(
    `INSERT INTO otp_challenges (contact_kind, contact_value, purpose, code_hash, payload, expires_at)
     VALUES ($1,$2,$3,$4,$5,NOW() + ($6 || ' minutes')::interval)`,
    [kind, contact, purpose, hash, JSON.stringify(payload || {}), String(minutes)]
  );
  try {
    await deliverOtp({ kind, destination: contact, code, purpose });
  } catch (error) {
    await pool.query(
      `UPDATE otp_challenges SET consumed_at = NOW() WHERE contact_kind=$1 AND contact_value=$2 AND purpose=$3 AND consumed_at IS NULL`,
      [kind, contact, purpose]
    );
    throw error;
  }
}

async function createSession(accountId, res, admin = false) {
  const token = randomToken();
  const days = Math.max(1, Number(process.env.SESSION_DAYS || 14));
  const table = admin ? "admin_sessions" : "user_sessions";
  const ownerColumn = admin ? "admin_id" : "account_id";
  await pool.query(
    `INSERT INTO ${table} (${ownerColumn}, token_hash, expires_at)
     VALUES ($1,$2,NOW() + ($3 || ' days')::interval)`,
    [accountId, sha256(token), String(days)]
  );
  res.cookie(admin ? "tiqa_admin_session" : "tiqa_session", token, {
    httpOnly: true,
    secure: process.env.COOKIE_SECURE === "true",
    sameSite: process.env.COOKIE_SAME_SITE || "lax",
    maxAge: days * 86400000,
    path: "/"
  });
}

router.post("/signup/request", async (req, res, next) => {
  try {
    const schema = contactSchema.extend({
      alias: z.string().trim().min(3).max(20).regex(/^[\p{L}\p{N}_ ]+$/u),
      consent: z.literal(true)
    });
    const data = schema.parse(req.body);
    const contact = normalizeContact(data.kind, data.contact);
    const existing = await pool.query("SELECT id FROM accounts WHERE contact_kind=$1 AND contact_value=$2", [data.kind, contact]);
    if (existing.rowCount) return res.status(409).json({ error: "ACCOUNT_EXISTS", message: "يوجد حساب بهذه البيانات. سجّل الدخول." });
    const alias = await pool.query("SELECT id FROM accounts WHERE lower(alias)=lower($1)", [data.alias]);
    if (alias.rowCount) return res.status(409).json({ error: "ALIAS_EXISTS", message: "هذا الاسم المستعار مستخدم." });
    await issueOtp({
      kind: data.kind, contact, purpose: "signup",
      payload: { alias: data.alias, country: data.country, consent_version: "v1" }
    });
    res.json({ ok: true, message: "أرسلنا رمز التحقق إلى وسيلة التواصل المحددة.", contactHint: maskContact(data.kind, contact) });
  } catch (error) { next(error); }
});

router.post("/login/request", async (req, res, next) => {
  try {
    const data = contactSchema.parse(req.body);
    const contact = normalizeContact(data.kind, data.contact);
    const account = await pool.query("SELECT id FROM accounts WHERE contact_kind=$1 AND contact_value=$2 AND status='active'", [data.kind, contact]);
    if (!account.rowCount) return res.status(404).json({ error: "ACCOUNT_NOT_FOUND", message: "لا يوجد حساب بهذه البيانات." });
    await issueOtp({ kind: data.kind, contact, purpose: "login", payload: { accountId: account.rows[0].id } });
    res.json({ ok: true, message: "أرسلنا رمز التحقق.", contactHint: maskContact(data.kind, contact) });
  } catch (error) { next(error); }
});

router.post("/verify", async (req, res, next) => {
  const client = await pool.connect();
  try {
    const data = z.object({
      kind: z.enum(["email", "phone"]),
      contact: z.string().min(5).max(254),
      purpose: z.enum(["signup", "login"]),
      code: z.string().regex(/^\d{6}$/)
    }).parse(req.body);
    const contact = normalizeContact(data.kind, data.contact);
    await client.query("BEGIN");
    const challenge = await client.query(
      `SELECT * FROM otp_challenges
       WHERE contact_kind=$1 AND contact_value=$2 AND purpose=$3 AND consumed_at IS NULL
       ORDER BY created_at DESC LIMIT 1 FOR UPDATE`,
      [data.kind, contact, data.purpose]
    );
    if (!challenge.rowCount) throw Object.assign(new Error("رمز التحقق غير صالح أو انتهت صلاحيته."), { status: 400 });
    const row = challenge.rows[0];
    if (new Date(row.expires_at) < new Date()) throw Object.assign(new Error("انتهت صلاحية الرمز. اطلب رمزاً جديداً."), { status: 400 });
    if (row.attempts >= Number(process.env.OTP_MAX_ATTEMPTS || 5)) throw Object.assign(new Error("تجاوزت عدد المحاولات. اطلب رمزاً جديداً."), { status: 429 });
    const valid = safeEqualHex(otpHash(data.code), row.code_hash);
    if (!valid) {
      await client.query("UPDATE otp_challenges SET attempts=attempts+1 WHERE id=$1", [row.id]);
      await client.query("COMMIT");
      throw Object.assign(new Error("رمز التحقق غير صحيح."), { status: 400 });
    }

    let accountId;
    if (data.purpose === "signup") {
      const payload = row.payload || {};
      const inserted = await client.query(
        `INSERT INTO accounts (alias, contact_kind, contact_value, contact_hint, country, consent_version, consented_at)
         VALUES ($1,$2,$3,$4,$5,$6,NOW()) RETURNING id`,
        [payload.alias, data.kind, contact, maskContact(data.kind, contact), payload.country || "MA", payload.consent_version || "v1"]
      );
      accountId = inserted.rows[0].id;
    } else {
      const found = await client.query("SELECT id FROM accounts WHERE contact_kind=$1 AND contact_value=$2 AND status='active'", [data.kind, contact]);
      if (!found.rowCount) throw Object.assign(new Error("الحساب غير موجود أو غير نشط."), { status: 404 });
      accountId = found.rows[0].id;
    }
    await client.query("UPDATE otp_challenges SET consumed_at=NOW() WHERE id=$1", [row.id]);
    await client.query("COMMIT");
    await createSession(accountId, res, false);
    res.json({ ok: true, user: { id: accountId }, message: "تم تسجيل الدخول بنجاح." });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    next(error);
  } finally { client.release(); }
});

router.get("/me", requireUser, (req, res) => {
  res.json({ authenticated: true, user: req.user });
});

router.post("/logout", async (req, res, next) => {
  try {
    const token = req.cookies?.tiqa_session;
    if (token) await pool.query("UPDATE user_sessions SET revoked_at=NOW() WHERE token_hash=$1 AND revoked_at IS NULL", [sha256(token)]);
    res.clearCookie("tiqa_session", { path: "/" });
    res.json({ ok: true });
  } catch (error) { next(error); }
});

export default router;
