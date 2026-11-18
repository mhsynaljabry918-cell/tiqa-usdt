import { pool } from "../db.js";
import { sha256 } from "../security.js";

export async function requireUser(req, res, next) {
  try {
    const token = req.cookies?.tiqa_session;
    if (!token) return res.status(401).json({ error: "AUTH_REQUIRED", message: "يرجى تسجيل الدخول." });
    const result = await pool.query(
      `SELECT a.id, a.alias, a.contact_kind, a.contact_hint
       FROM user_sessions s JOIN accounts a ON a.id = s.account_id
       WHERE s.token_hash = $1 AND s.expires_at > NOW() AND s.revoked_at IS NULL`,
      [sha256(token)]
    );
    if (!result.rowCount) return res.status(401).json({ error: "SESSION_INVALID", message: "انتهت الجلسة. سجّل الدخول مجدداً." });
    req.user = result.rows[0];
    next();
  } catch (error) { next(error); }
}

export async function requireAdmin(req, res, next) {
  try {
    const token = req.cookies?.tiqa_admin_session;
    if (!token) return res.status(401).json({ error: "ADMIN_AUTH_REQUIRED", message: "دخول الإدارة مطلوب." });
    const result = await pool.query(
      `SELECT ad.id, ad.display_name, ad.is_active
       FROM admin_sessions s JOIN admins ad ON ad.id = s.admin_id
       WHERE s.token_hash = $1 AND s.expires_at > NOW() AND s.revoked_at IS NULL AND ad.is_active = TRUE`,
      [sha256(token)]
    );
    if (!result.rowCount) return res.status(401).json({ error: "ADMIN_SESSION_INVALID", message: "جلسة الإدارة غير صالحة." });
    req.admin = result.rows[0];
    next();
  } catch (error) { next(error); }
}

export function requirePermission(permission) {
  return async (req, res, next) => {
    try {
      const result = await pool.query(
        `SELECT 1 FROM admin_role_permissions arp
         JOIN admin_user_roles aur ON aur.role_id = arp.role_id
         JOIN permissions p ON p.id = arp.permission_id
         WHERE aur.admin_id = $1 AND p.code = $2 LIMIT 1`,
        [req.admin.id, permission]
      );
      if (!result.rowCount) return res.status(403).json({ error: "FORBIDDEN", message: "ليست لديك صلاحية لهذا الإجراء." });
      next();
    } catch (error) { next(error); }
  };
}
