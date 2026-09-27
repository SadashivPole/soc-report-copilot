'use strict';
require('dotenv').config();

const env = process.env.NODE_ENV || 'development';
const isProd = env === 'production';

const DEV_SECRET = 'dev-insecure-secret-change-me';
const jwtSecret = process.env.JWT_SECRET || (isProd ? '' : DEV_SECRET);

// ---------------------------------------------------------------------------
// Production hardening: fail fast (and loudly) on missing/insecure config.
// Never fall back to development credentials in production.
// ---------------------------------------------------------------------------
const startupErrors = [];
if (isProd) {
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET === DEV_SECRET) {
    startupErrors.push('JWT_SECRET must be set to a strong, non-default value in production.');
  } else if (process.env.JWT_SECRET.length < 24) {
    startupErrors.push('JWT_SECRET is too short for production (min 24 chars).');
  }
  if (!process.env.DATABASE_URL) {
    startupErrors.push('DATABASE_URL must be set explicitly in production.');
  }
}

// ---- CORS allow-list ----
// CORS_ORIGIN is a comma-separated list of allowed origins. '*' allows any origin.
// Development defaults to permissive (localhost / preview). Production requires an
// explicit allow-list — a wildcard or empty value is refused.
const rawCors = (process.env.CORS_ORIGIN || '').trim();
let corsOrigins = rawCors
  ? rawCors.split(',').map((s) => s.trim()).filter(Boolean)
  : [];
let corsAllowAll = corsOrigins.includes('*') || (!isProd && corsOrigins.length === 0);
if (isProd) {
  if (corsOrigins.length === 0) {
    startupErrors.push('CORS_ORIGIN must list explicit allowed origins in production (wildcard not allowed).');
  } else if (corsOrigins.includes('*')) {
    startupErrors.push('CORS_ORIGIN="*" is not allowed in production; list explicit origins.');
  }
}

if (startupErrors.length) {
  // Aggregate all misconfigurations into one clear, actionable error.
  throw new Error(
    'Refusing to start due to invalid production configuration:\n  - ' + startupErrors.join('\n  - ')
  );
}

// Demo mode exposes seed-login hints and permits the demo seeder. OFF in prod
// unless explicitly enabled.
const demoMode =
  process.env.DEMO_MODE === 'true' || (!isProd && process.env.DEMO_MODE !== 'false');

const config = {
  env,
  isProd,
  port: parseInt(process.env.PORT || '3000', 10),
  jwtSecret,
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '12h',
  // Legacy single-origin value kept for reference; app uses cors.* below.
  corsOrigin: rawCors || '*',
  cors: { origins: corsOrigins, allowAll: corsAllowAll },
  // Public base URL used to build shareable links (falls back to request host).
  appBaseUrl: process.env.APP_BASE_URL || '',
  demoMode,
  defaultPlan: process.env.DEFAULT_PLAN || 'pro',
  database: {
    connectionString:
      process.env.DATABASE_URL ||
      'postgres://soc:socpass@127.0.0.1:5432/soc_copilot',
  },
  // Upload safety limits (untrusted input hardening)
  limits: {
    maxUploadBytes: parseInt(process.env.MAX_UPLOAD_BYTES || String(25 * 1024 * 1024), 10),
    maxEvents: parseInt(process.env.MAX_EVENTS || '50000', 10),
    maxFullLogChars: parseInt(process.env.MAX_FULLLOG_CHARS || '4000', 10),
    maxFieldChars: parseInt(process.env.MAX_FIELD_CHARS || '512', 10),
    maxLogoBytes: parseInt(process.env.MAX_LOGO_BYTES || String(256 * 1024), 10),
  },
  // Analysis provider: 'deterministic' (default, no external calls) or 'openai'.
  analysis: {
    provider: process.env.ANALYSIS_PROVIDER || 'deterministic',
    openaiApiKey: process.env.OPENAI_API_KEY || '',
    openaiModel: process.env.OPENAI_MODEL || 'gpt-4o-mini',
  },
  // Email delivery for scheduled reports. If SMTP isn't configured, messages are
  // recorded to an outbox table (dev/testable) instead of being silently lost.
  mail: {
    from: process.env.MAIL_FROM || 'SOC Report Copilot <no-reply@soc-copilot.local>',
    smtpUrl: process.env.SMTP_URL || '', // e.g. smtp://user:pass@host:587
  },
  scheduler: {
    enabled: process.env.SCHEDULER_ENABLED !== 'false',
    tickMs: parseInt(process.env.SCHEDULER_TICK_MS || '60000', 10),
  },
  retention: {
    enabled: process.env.RETENTION_ENABLED !== 'false',
    // How often the background retention sweep runs (default 24h).
    sweepIntervalMs: parseInt(process.env.RETENTION_SWEEP_INTERVAL_MS || String(24 * 60 * 60 * 1000), 10),
  },
};

module.exports = config;
