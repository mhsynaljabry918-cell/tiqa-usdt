CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  alias VARCHAR(20) NOT NULL,
  contact_kind VARCHAR(10) NOT NULL CHECK (contact_kind IN ('email','phone')),
  contact_value VARCHAR(254) NOT NULL,
  contact_hint VARCHAR(80) NOT NULL,
  country CHAR(2) NOT NULL DEFAULT 'MA',
  status VARCHAR(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','closed')),
  consent_version VARCHAR(30) NOT NULL,
  consented_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(contact_kind, contact_value)
);
CREATE UNIQUE INDEX IF NOT EXISTS accounts_alias_ci ON accounts (LOWER(alias));

CREATE TABLE IF NOT EXISTS otp_challenges (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  contact_kind VARCHAR(10) NOT NULL CHECK (contact_kind IN ('email','phone')),
  contact_value VARCHAR(254) NOT NULL,
  purpose VARCHAR(10) NOT NULL CHECK (purpose IN ('signup','login')),
  code_hash CHAR(64) NOT NULL,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS otp_lookup_idx ON otp_challenges(contact_kind, contact_value, purpose, created_at DESC);

CREATE TABLE IF NOT EXISTS user_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  token_hash CHAR(64) NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS user_sessions_account_idx ON user_sessions(account_id);

CREATE TABLE IF NOT EXISTS admins (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(254) NOT NULL UNIQUE,
  display_name VARCHAR(100) NOT NULL,
  password_hash TEXT NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS admin_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  admin_id UUID NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  token_hash CHAR(64) NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS admin_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  code VARCHAR(50) NOT NULL UNIQUE,
  title VARCHAR(100) NOT NULL
);
CREATE TABLE IF NOT EXISTS permissions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  code VARCHAR(80) NOT NULL UNIQUE,
  title VARCHAR(120) NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_user_roles (
  admin_id UUID NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  role_id UUID NOT NULL REFERENCES admin_roles(id) ON DELETE CASCADE,
  PRIMARY KEY(admin_id, role_id)
);
CREATE TABLE IF NOT EXISTS admin_role_permissions (
  role_id UUID NOT NULL REFERENCES admin_roles(id) ON DELETE CASCADE,
  permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  PRIMARY KEY(role_id, permission_id)
);
CREATE TABLE IF NOT EXISTS audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_admin_id UUID REFERENCES admins(id),
  action VARCHAR(100) NOT NULL,
  target_type VARCHAR(50),
  target_id VARCHAR(100),
  before_data JSONB,
  after_data JSONB,
  reason TEXT,
  country CHAR(2),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO admin_roles(code,title) VALUES
 ('owner','مشرف عام'), ('reports_mod','مشرف البلاغات'), ('auditor','مدقق للقراءة فقط')
ON CONFLICT(code) DO NOTHING;

INSERT INTO permissions(code,title) VALUES
 ('admin.read','قراءة لوحة الإدارة'),
 ('reports.write','إدارة البلاغات'),
 ('reviews.write','إدارة التقييمات'),
 ('disputes.write','إدارة الاعتراضات'),
 ('verifications.write','مراجعة التوثيق'),
 ('claims.write','إدارة مطالبات الملكية'),
 ('audit.read','قراءة سجل التدقيق')
ON CONFLICT(code) DO NOTHING;

INSERT INTO admin_role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM admin_roles r CROSS JOIN permissions p
WHERE r.code='owner'
ON CONFLICT DO NOTHING;

INSERT INTO admin_role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM admin_roles r JOIN permissions p ON p.code IN ('admin.read','reports.write','disputes.write')
WHERE r.code='reports_mod'
ON CONFLICT DO NOTHING;

INSERT INTO admin_role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM admin_roles r JOIN permissions p ON p.code IN ('admin.read','audit.read')
WHERE r.code='auditor'
ON CONFLICT DO NOTHING;
