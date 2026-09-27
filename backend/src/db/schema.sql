-- SOC Report Copilot schema. Every domain table carries tenant_id and is
-- always queried with a WHERE tenant_id = $current predicate (tenant isolation).

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS tenants (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'owner',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);

CREATE TABLE IF NOT EXISTS uploads (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  filename     TEXT NOT NULL,
  format       TEXT NOT NULL,               -- 'json' | 'csv'
  source_type  TEXT NOT NULL DEFAULT 'wazuh',
  event_count  INTEGER NOT NULL DEFAULT 0,
  status       TEXT NOT NULL DEFAULT 'pending', -- pending|parsed|failed
  error        TEXT,
  uploaded_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_uploads_tenant ON uploads(tenant_id);

CREATE TABLE IF NOT EXISTS events (
  id               BIGSERIAL PRIMARY KEY,
  tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  upload_id        UUID NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
  event_id         TEXT NOT NULL,           -- Wazuh alert id (or synthesized)
  ts               TIMESTAMPTZ,
  rule_id          TEXT,
  rule_description TEXT,
  rule_level       INTEGER,
  severity         TEXT,                     -- Critical|High|Medium|Low
  groups           JSONB NOT NULL DEFAULT '[]'::jsonb,
  mitre            JSONB NOT NULL DEFAULT '{}'::jsonb, -- {ids, tactics, techniques}
  agent_name       TEXT,
  agent_ip         TEXT,
  src_ip           TEXT,
  dst_ip           TEXT,
  src_user         TEXT,
  dst_user         TEXT,
  full_log         TEXT,
  raw              JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_events_tenant           ON events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_events_tenant_upload    ON events(tenant_id, upload_id);
CREATE INDEX IF NOT EXISTS idx_events_tenant_severity  ON events(tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_events_tenant_ts        ON events(tenant_id, ts);

CREATE TABLE IF NOT EXISTS reports (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  upload_id     UUID NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
  title         TEXT NOT NULL,
  period_start  TIMESTAMPTZ,
  period_end    TIMESTAMPTZ,
  data          JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_reports_tenant ON reports(tenant_id);

-- ============================================================================
-- V1 productization additions (idempotent).
-- ============================================================================

-- Tenant branding + plan (billing-ready; no live billing).
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS company_name   TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS logo_data_url  TEXT;   -- bounded data URI
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS default_client TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS plan           TEXT NOT NULL DEFAULT 'free';
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS plan_status    TEXT NOT NULL DEFAULT 'active';
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS billing_customer_ref TEXT; -- future Stripe id

-- Normalize legacy 'owner' role to 'admin' for RBAC.
UPDATE users SET role='admin' WHERE role='owner';

-- Reports gain client naming + branding snapshot at generation time.
ALTER TABLE reports ADD COLUMN IF NOT EXISTS client_name TEXT;

-- Report share links (read-only, expiring). Tokens are stored HASHED only.
CREATE TABLE IF NOT EXISTS report_shares (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  report_id    UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
  created_by   UUID REFERENCES users(id) ON DELETE SET NULL,
  token_hash   TEXT NOT NULL UNIQUE,           -- sha256(token)
  token_prefix TEXT NOT NULL,                  -- non-secret prefix for display
  expires_at   TIMESTAMPTZ NOT NULL,
  revoked      BOOLEAN NOT NULL DEFAULT false,
  view_count   INTEGER NOT NULL DEFAULT 0,
  last_viewed_at TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_shares_tenant ON report_shares(tenant_id);
CREATE INDEX IF NOT EXISTS idx_shares_report ON report_shares(report_id);

-- Weekly report schedules.
CREATE TABLE IF NOT EXISTS schedules (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
  name          TEXT NOT NULL DEFAULT 'Weekly SOC Report',
  upload_source TEXT NOT NULL DEFAULT 'latest',  -- 'latest' | specific upload_id
  day_of_week   INTEGER NOT NULL DEFAULT 1,       -- 0=Sun .. 6=Sat
  hour          INTEGER NOT NULL DEFAULT 8,
  minute        INTEGER NOT NULL DEFAULT 0,
  timezone      TEXT NOT NULL DEFAULT 'UTC',
  recipients    JSONB NOT NULL DEFAULT '[]'::jsonb,
  client_name   TEXT,
  enabled       BOOLEAN NOT NULL DEFAULT true,
  last_run_at   TIMESTAMPTZ,
  last_status   TEXT,
  next_run_at   TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_schedules_tenant ON schedules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_schedules_due ON schedules(enabled, next_run_at);

-- Email outbox: scheduled-report deliveries are recorded here (and sent via SMTP
-- if configured). Guarantees delivery is auditable and testable without a real
-- mail server, and never blocks report generation.
CREATE TABLE IF NOT EXISTS email_outbox (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID REFERENCES tenants(id) ON DELETE CASCADE,
  to_addrs     JSONB NOT NULL DEFAULT '[]'::jsonb,
  subject      TEXT NOT NULL,
  body         TEXT,
  report_id    UUID REFERENCES reports(id) ON DELETE SET NULL,
  status       TEXT NOT NULL DEFAULT 'queued', -- queued|sent|failed
  error        TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  sent_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_outbox_tenant ON email_outbox(tenant_id);

-- Billing intent log (records upgrade/downgrade requests; no charges).
CREATE TABLE IF NOT EXISTS billing_events (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
  kind       TEXT NOT NULL,           -- 'plan_change_request'
  from_plan  TEXT,
  to_plan    TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_billing_tenant ON billing_events(tenant_id);

-- ============================================================================
-- Professional reporting upgrade: management action plan + audit history.
-- ============================================================================

-- Reports gain optional organization + report-type + comparison linkage.
ALTER TABLE reports ADD COLUMN IF NOT EXISTS organization TEXT;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS previous_report_id UUID;

-- Management action plan. Each action is traceable to evidence/event IDs.
CREATE TABLE IF NOT EXISTS actions (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  report_id         UUID REFERENCES reports(id) ON DELETE SET NULL,
  finding_key       TEXT,                    -- stable key for dedup across reports
  priority          TEXT NOT NULL DEFAULT 'P3',  -- P1|P2|P3|P4
  finding           TEXT NOT NULL,
  recommended_action TEXT NOT NULL,
  owner             TEXT,
  status            TEXT NOT NULL DEFAULT 'open', -- open|investigating|resolved|accepted_risk
  evidence          JSONB NOT NULL DEFAULT '{}'::jsonb, -- {event_ids, source, timestamps, assets}
  ai_assisted       BOOLEAN NOT NULL DEFAULT true,
  created_by        UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_actions_tenant ON actions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_actions_tenant_status ON actions(tenant_id, status);

-- Immutable audit trail of every action status/field change.
CREATE TABLE IF NOT EXISTS action_history (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  action_id    UUID NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
  from_status  TEXT,
  to_status    TEXT,
  note         TEXT,
  changed_by   UUID REFERENCES users(id) ON DELETE SET NULL,
  changed_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_action_history_action ON action_history(action_id);
CREATE INDEX IF NOT EXISTS idx_action_history_tenant ON action_history(tenant_id);

-- ============================================================================
-- v2.1 production-readiness upgrade:
--   M1 scheduled weekly windowing, M2 share disclosure modes, M3 retention.
--   All statements are idempotent.
-- ============================================================================

-- Reports: distinguish manual vs scheduled, and allow window-scoped reports that
-- span multiple uploads (upload_id becomes optional for scheduled window reports).
ALTER TABLE reports ADD COLUMN IF NOT EXISTS report_kind TEXT NOT NULL DEFAULT 'manual'; -- manual|scheduled
ALTER TABLE reports ALTER COLUMN upload_id DROP NOT NULL;

-- Prevent duplicate scheduled reports for the same tenant + reporting window.
CREATE UNIQUE INDEX IF NOT EXISTS uq_reports_scheduled_window
  ON reports(tenant_id, period_start, period_end)
  WHERE report_kind = 'scheduled';

-- Auditable scheduler execution log (status + errors for every run).
CREATE TABLE IF NOT EXISTS schedule_runs (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  schedule_id   UUID REFERENCES schedules(id) ON DELETE SET NULL,
  run_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  window_start  TIMESTAMPTZ,
  window_end    TIMESTAMPTZ,
  event_count   INTEGER NOT NULL DEFAULT 0,
  status        TEXT NOT NULL,          -- sent|skipped_no_data|skipped_duplicate|error
  report_id     UUID REFERENCES reports(id) ON DELETE SET NULL,
  error         TEXT
);
CREATE INDEX IF NOT EXISTS idx_schedule_runs_tenant ON schedule_runs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_schedule_runs_schedule ON schedule_runs(schedule_id);

-- Share links gain a disclosure MODE. Default is executive (least data exposed).
ALTER TABLE report_shares ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'executive'; -- executive|analyst

-- Auditable share lifecycle log: created / accessed / revoked / expired / denied.
CREATE TABLE IF NOT EXISTS share_audit (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID REFERENCES tenants(id) ON DELETE CASCADE,
  share_id    UUID REFERENCES report_shares(id) ON DELETE SET NULL,
  report_id   UUID REFERENCES reports(id) ON DELETE SET NULL,
  event       TEXT NOT NULL,           -- created|accessed|revoked|expired|denied
  mode        TEXT,
  detail      TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_share_audit_tenant ON share_audit(tenant_id);
CREATE INDEX IF NOT EXISTS idx_share_audit_share ON share_audit(share_id);

-- Auditable retention sweeps (what was deleted, per tenant, and when).
CREATE TABLE IF NOT EXISTS retention_runs (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE,
  run_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  retention_days  INTEGER,
  cutoff          TIMESTAMPTZ,
  uploads_deleted INTEGER NOT NULL DEFAULT 0,
  events_deleted  INTEGER NOT NULL DEFAULT 0,
  reports_deleted INTEGER NOT NULL DEFAULT 0,
  status          TEXT NOT NULL DEFAULT 'ok',
  error           TEXT
);
CREATE INDEX IF NOT EXISTS idx_retention_runs_tenant ON retention_runs(tenant_id);
