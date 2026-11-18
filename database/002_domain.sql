-- Core TiqaUSDT domain: trader identities, public profiles, reviews and moderation.
-- Sensitive channel identifiers are stored as HMAC hashes plus masked hints only.

CREATE TABLE IF NOT EXISTS trader_entities (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  country CHAR(2) NOT NULL,
  source VARCHAR(24) NOT NULL DEFAULT 'user-report'
    CHECK (source IN ('seed','owner','user-report','admin')),
  owner_account_id UUID REFERENCES accounts(id) ON DELETE SET NULL,
  ownership_status VARCHAR(16) NOT NULL DEFAULT 'none'
    CHECK (ownership_status IN ('none','pending','proven','revoked')),
  ownership_method VARCHAR(32),
  ownership_verified_at TIMESTAMPTZ,
  identity_status VARCHAR(16) NOT NULL DEFAULT 'none'
    CHECK (identity_status IN ('none','pending','verified','rejected','expired')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS trader_entities_country_idx ON trader_entities(country);
CREATE INDEX IF NOT EXISTS trader_entities_owner_idx ON trader_entities(owner_account_id);

CREATE TABLE IF NOT EXISTS trader_identifiers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_id UUID NOT NULL REFERENCES trader_entities(id) ON DELETE CASCADE,
  identifier_type VARCHAR(12) NOT NULL CHECK (identifier_type IN ('wa','tg')),
  identifier_hash CHAR(64) NOT NULL,
  masked_hint VARCHAR(80) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(identifier_type, identifier_hash)
);
CREATE INDEX IF NOT EXISTS trader_identifiers_entity_idx ON trader_identifiers(entity_id);

CREATE TABLE IF NOT EXISTS trader_profiles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_id UUID NOT NULL UNIQUE REFERENCES trader_entities(id) ON DELETE CASCADE,
  slug VARCHAR(64) NOT NULL UNIQUE,
  display_name VARCHAR(40) NOT NULL,
  public_handle VARCHAR(40),
  city VARCHAR(80) NOT NULL,
  trade_types JSONB NOT NULL DEFAULT '[]'::jsonb,
  payment_methods JSONB NOT NULL DEFAULT '[]'::jsonb,
  rate NUMERIC(14,4),
  rate_updated_at TIMESTAMPTZ,
  years_active VARCHAR(80),
  bio VARCHAR(240),
  avatar_key TEXT,
  contacts JSONB NOT NULL DEFAULT '[]'::jsonb,
  name_history JSONB NOT NULL DEFAULT '[]'::jsonb,
  profile_status VARCHAR(16) NOT NULL DEFAULT 'draft'
    CHECK (profile_status IN ('draft','published','suspended','archived')),
  is_demo BOOLEAN NOT NULL DEFAULT FALSE,
  joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS trader_profiles_public_country_city_idx
  ON trader_profiles(profile_status, city);
CREATE INDEX IF NOT EXISTS trader_profiles_name_idx ON trader_profiles(LOWER(display_name));

CREATE TABLE IF NOT EXISTS reviews (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_id UUID NOT NULL REFERENCES trader_entities(id) ON DELETE CASCADE,
  account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
  alias_snapshot VARCHAR(20) NOT NULL,
  rating SMALLINT NOT NULL CHECK (rating BETWEEN 1 AND 5),
  outcome VARCHAR(12) NOT NULL CHECK (outcome IN ('ok','issue')),
  body VARCHAR(400) NOT NULL,
  status VARCHAR(16) NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','published','rejected','removed')),
  trust_status VARCHAR(16) NOT NULL DEFAULT 'unverified'
    CHECK (trust_status IN ('unverified','evidenced','trusted')),
  risk_score SMALLINT NOT NULL DEFAULT 0,
  risk_flags JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_key TEXT,
  evidence_verified_at TIMESTAMPTZ,
  country CHAR(2) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS reviews_entity_status_created_idx ON reviews(entity_id,status,created_at DESC);
CREATE INDEX IF NOT EXISTS reviews_account_created_idx ON reviews(account_id,created_at DESC);

CREATE TABLE IF NOT EXISTS review_replies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  review_id UUID NOT NULL UNIQUE REFERENCES reviews(id) ON DELETE CASCADE,
  entity_id UUID NOT NULL REFERENCES trader_entities(id) ON DELETE CASCADE,
  account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
  body VARCHAR(300) NOT NULL,
  status VARCHAR(16) NOT NULL DEFAULT 'published'
    CHECK (status IN ('published','hidden','removed')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  public_code VARCHAR(32) NOT NULL UNIQUE,
  country CHAR(2) NOT NULL,
  entity_id UUID REFERENCES trader_entities(id) ON DELETE SET NULL,
  reporter_account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
  reporter_alias_snapshot VARCHAR(20) NOT NULL,
  report_type VARCHAR(48) NOT NULL,
  reported_name VARCHAR(120),
  description VARCHAR(800) NOT NULL,
  evidence_key TEXT,
  status VARCHAR(16) NOT NULL DEFAULT 'new'
    CHECK (status IN ('new','review','verified','rejected')),
  consent_version VARCHAR(30) NOT NULL,
  consented_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS reports_country_status_created_idx ON reports(country,status,created_at DESC);
CREATE INDEX IF NOT EXISTS reports_entity_idx ON reports(entity_id);
CREATE INDEX IF NOT EXISTS reports_reporter_created_idx ON reports(reporter_account_id,created_at DESC);

CREATE TABLE IF NOT EXISTS report_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  report_id UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
  from_status VARCHAR(16),
  to_status VARCHAR(16) NOT NULL,
  actor_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
  reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS report_events_report_idx ON report_events(report_id,created_at);

CREATE TABLE IF NOT EXISTS disputes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_id UUID NOT NULL REFERENCES trader_entities(id) ON DELETE CASCADE,
  opened_by UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
  target_type VARCHAR(12) NOT NULL CHECK (target_type IN ('review','report')),
  target_review_id UUID REFERENCES reviews(id) ON DELETE CASCADE,
  target_report_id UUID REFERENCES reports(id) ON DELETE CASCADE,
  reason VARCHAR(48) NOT NULL,
  description VARCHAR(800) NOT NULL,
  evidence_key TEXT,
  status VARCHAR(16) NOT NULL DEFAULT 'open'
    CHECK (status IN ('open','review','accepted','rejected','closed')),
  decision_reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK ((target_type='review' AND target_review_id IS NOT NULL AND target_report_id IS NULL)
      OR (target_type='report' AND target_report_id IS NOT NULL AND target_review_id IS NULL))
);
CREATE INDEX IF NOT EXISTS disputes_entity_status_idx ON disputes(entity_id,status);

CREATE TABLE IF NOT EXISTS ownership_claims (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_id UUID NOT NULL REFERENCES trader_entities(id) ON DELETE CASCADE,
  account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
  identifier_id UUID NOT NULL REFERENCES trader_identifiers(id) ON DELETE RESTRICT,
  method VARCHAR(32) NOT NULL CHECK (method IN ('channel-code','manual-review')),
  status VARCHAR(16) NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','approved','rejected','withdrawn')),
  decided_by UUID REFERENCES admins(id) ON DELETE SET NULL,
  decision_reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  decided_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ownership_claims_entity_status_idx ON ownership_claims(entity_id,status);

CREATE TABLE IF NOT EXISTS identity_verifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_id UUID NOT NULL REFERENCES trader_entities(id) ON DELETE CASCADE,
  account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
  status VARCHAR(16) NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','approved','rejected','cancelled')),
  document_storage_key TEXT,
  document_type VARCHAR(40),
  consent_version VARCHAR(30) NOT NULL,
  consented_at TIMESTAMPTZ NOT NULL,
  decided_by UUID REFERENCES admins(id) ON DELETE SET NULL,
  decision_reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  decided_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS identity_verifications_status_idx ON identity_verifications(status,created_at);

-- File metadata only; actual evidence bytes must live in private object storage, never in public HTML.
CREATE TABLE IF NOT EXISTS private_evidence_files (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  uploaded_by UUID REFERENCES accounts(id) ON DELETE SET NULL,
  purpose VARCHAR(24) NOT NULL CHECK (purpose IN ('review','report','dispute','identity')),
  storage_key TEXT NOT NULL UNIQUE,
  original_name VARCHAR(180) NOT NULL,
  mime_type VARCHAR(100) NOT NULL,
  size_bytes BIGINT NOT NULL CHECK (size_bytes > 0),
  sha256 CHAR(64) NOT NULL,
  malware_scan_status VARCHAR(16) NOT NULL DEFAULT 'pending'
    CHECK (malware_scan_status IN ('pending','clean','rejected')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Country scopes are explicit and enforced by server-side authorization.
CREATE TABLE IF NOT EXISTS admin_country_scopes (
  admin_id UUID NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  country CHAR(2) NOT NULL,
  PRIMARY KEY(admin_id,country)
);
