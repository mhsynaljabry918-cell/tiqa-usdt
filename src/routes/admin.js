import { Router } from "express";
import bcrypt from "bcryptjs";
import { requireAdmin, requirePermission } from "../middleware/auth.js";
import { pool } from "../db.js";
import { randomToken, sha256 } from "../security.js";

const router = Router();

router.post("/login", async (req, res, next) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = String(req.body?.password || "");
    if (!email || !password) return res.status(400).json({ error: "VALIDATION", message: "أدخل البريد وكلمة المرور." });
    const result = await pool.query(
      "SELECT id, display_name, password_hash FROM admins WHERE lower(email)=lower($1) AND is_active=TRUE",
      [email]
    );
    if (!result.rowCount || !(await bcrypt.compare(password, result.rows[0].password_hash))) {
      return res.status(401).json({ error: "ADMIN_LOGIN_FAILED", message: "بيانات الدخول غير صحيحة." });
    }
    const admin = result.rows[0];
    const token = randomToken();
    const days = Math.max(1, Number(process.env.SESSION_DAYS || 14));
    await pool.query(
      "INSERT INTO admin_sessions(admin_id,token_hash,expires_at) VALUES($1,$2,NOW()+($3 || ' days')::interval)",
      [admin.id, sha256(token), String(days)]
    );
    res.cookie("tiqa_admin_session", token, {
      httpOnly: true, secure: process.env.COOKIE_SECURE === "true",
      sameSite: process.env.COOKIE_SAME_SITE || "lax", maxAge: days * 86400000, path: "/"
    });
    res.json({ ok: true, admin: { id: admin.id, displayName: admin.display_name } });
  } catch (error) { next(error); }
});

router.use(requireAdmin);

router.get("/me", async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT r.code AS role, p.code AS permission
       FROM admin_user_roles ur
       JOIN admin_roles r ON r.id=ur.role_id
       LEFT JOIN admin_role_permissions rp ON rp.role_id=r.id
       LEFT JOIN permissions p ON p.id=rp.permission_id
       WHERE ur.admin_id=$1 ORDER BY r.code,p.code`,
      [req.admin.id]
    );
    res.json({ admin: req.admin, access: result.rows });
  } catch (error) { next(error); }
});

router.get("/overview", requirePermission("admin.read"), async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT
       (SELECT count(*)::int FROM accounts WHERE status='active') AS accounts,
       (SELECT count(*)::int FROM audit_logs) AS audit_events`
    );
    res.json(result.rows[0]);
  } catch (error) { next(error); }
});

router.post("/logout", async (req, res, next) => {
  try {
    const token = req.cookies?.tiqa_admin_session;
    if (token) await pool.query("UPDATE admin_sessions SET revoked_at=NOW() WHERE token_hash=$1 AND revoked_at IS NULL", [sha256(token)]);
    res.clearCookie("tiqa_admin_session", { path: "/" });
    res.json({ ok: true });
  } catch (error) { next(error); }
});

export default router;
