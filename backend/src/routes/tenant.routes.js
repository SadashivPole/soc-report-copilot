'use strict';
const express = require('express');
const { requireAuth, requireRole, ROLE_RANK } = require('../middleware/auth');
const { query } = require('../db/pool');
const config = require('../config');
const { getPlan, assertEntitled } = require('../services/billing/plans');
const { httpError, isValidEmail, hashPassword } = require('../services/auth.service');
const { runRetentionForTenant } = require('../services/retention');

const router = express.Router();
router.use(requireAuth);

// ---- Data retention (M3) ----
// Show the effective retention policy, the last enforcement run, and a dry-run
// preview of what the NEXT sweep would remove.
router.get('/retention', async (req, res, next) => {
  try {
    const t = await query('SELECT plan FROM tenants WHERE id=$1', [req.auth.tenantId]);
    const retentionDays = getPlan(t.rows[0].plan).limits.retentionDays;
    const last = await query(
      `SELECT run_at, retention_days, cutoff, uploads_deleted, events_deleted, reports_deleted, status
         FROM retention_runs WHERE tenant_id=$1 ORDER BY run_at DESC LIMIT 1`,
      [req.auth.tenantId]
    );
    const preview = await runRetentionForTenant(req.auth.tenantId, { retentionDays, dryRun: true });
    res.json({
      retention_days: retentionDays,
      policy:
        'Uploads and reports older than the retention window are deleted (events cascade with their upload). ' +
        'Management actions and all audit logs are preserved.',
      last_run: last.rows[0] || null,
      next_sweep_preview: preview,
    });
  } catch (e) { next(e); }
});

// Admin can enforce retention immediately.
router.post('/retention/run', requireRole('admin'), async (req, res, next) => {
  try {
    const summary = await runRetentionForTenant(req.auth.tenantId, {});
    res.json({ result: summary });
  } catch (e) { next(e); }
});

// ---- Branding ----
router.get('/branding', async (req, res, next) => {
  try {
    const r = await query('SELECT name, company_name, logo_data_url, default_client FROM tenants WHERE id=$1', [req.auth.tenantId]);
    res.json({ branding: r.rows[0] || {} });
  } catch (e) { next(e); }
});

router.put('/branding', requireRole('admin'), async (req, res, next) => {
  try {
    const tRow = await query('SELECT plan FROM tenants WHERE id=$1', [req.auth.tenantId]);
    assertEntitled(tRow.rows[0].plan, 'branding');

    const company = req.body.company_name != null ? String(req.body.company_name).slice(0, 160) : null;
    const client = req.body.default_client != null ? String(req.body.default_client).slice(0, 160) : null;

    // Validate logo: must be a small PNG/JPEG data URI or null.
    let logo = null;
    if (req.body.logo_data_url) {
      const s = String(req.body.logo_data_url);
      const m = s.match(/^data:image\/(png|jpe?g);base64,([A-Za-z0-9+/=]+)$/);
      if (!m) throw httpError(400, 'Logo must be a PNG or JPEG data URI');
      const bytes = Buffer.from(m[2], 'base64').length;
      if (bytes > config.limits.maxLogoBytes) throw httpError(400, `Logo exceeds ${Math.round(config.limits.maxLogoBytes / 1024)}KB limit`);
      logo = s;
    }

    const r = await query(
      `UPDATE tenants SET company_name=$2, default_client=$3, logo_data_url=$4 WHERE id=$1
       RETURNING name, company_name, logo_data_url, default_client`,
      [req.auth.tenantId, company, client, logo]
    );
    res.json({ branding: r.rows[0] });
  } catch (e) { next(e); }
});

// ---- Plan (billing-ready; records intent, no charge) ----
router.get('/plan', async (req, res, next) => {
  try {
    const r = await query('SELECT plan, plan_status FROM tenants WHERE id=$1', [req.auth.tenantId]);
    const plan = getPlan(r.rows[0].plan);
    // usage snapshot
    const usage = await query(
      `SELECT (SELECT count(*)::int FROM users WHERE tenant_id=$1) AS members,
              (SELECT count(*)::int FROM schedules WHERE tenant_id=$1) AS schedules`,
      [req.auth.tenantId]
    );
    res.json({ plan: r.rows[0].plan, plan_status: r.rows[0].plan_status, entitlements: plan.limits, usage: usage.rows[0] });
  } catch (e) { next(e); }
});

router.put('/plan', requireRole('admin'), async (req, res, next) => {
  try {
    const to = String(req.body.plan || '').toLowerCase();
    if (!['free', 'pro', 'mssp'].includes(to)) throw httpError(400, 'Unknown plan');
    const cur = await query('SELECT plan FROM tenants WHERE id=$1', [req.auth.tenantId]);
    const from = cur.rows[0].plan;
    await query('INSERT INTO billing_events(tenant_id,user_id,kind,from_plan,to_plan) VALUES($1,$2,$3,$4,$5)',
      [req.auth.tenantId, req.auth.userId, 'plan_change_request', from, to]);
    // In V1 there is no charge — we apply the plan immediately. A billing provider
    // would instead flip this after a successful checkout webhook.
    await query('UPDATE tenants SET plan=$2 WHERE id=$1', [req.auth.tenantId, to]);
    res.json({ plan: to, note: 'Plan applied. (Billing integration pending — no charge made.)' });
  } catch (e) { next(e); }
});

// ---- Team / RBAC (Admin only) ----
router.get('/members', requireRole('admin'), async (req, res, next) => {
  try {
    const r = await query('SELECT id, email, role, created_at FROM users WHERE tenant_id=$1 ORDER BY created_at', [req.auth.tenantId]);
    res.json({ members: r.rows });
  } catch (e) { next(e); }
});

router.post('/members', requireRole('admin'), async (req, res, next) => {
  try {
    const email = String(req.body.email || '').toLowerCase().trim();
    const role = String(req.body.role || 'viewer');
    if (!isValidEmail(email)) throw httpError(400, 'A valid email is required');
    if (!['admin', 'analyst', 'viewer'].includes(role)) throw httpError(400, 'Role must be admin, analyst, or viewer');

    // Plan seat limit enforcement.
    const t = await query('SELECT plan FROM tenants WHERE id=$1', [req.auth.tenantId]);
    const limit = getPlan(t.rows[0].plan).limits.maxTeamMembers;
    const count = await query('SELECT count(*)::int c FROM users WHERE tenant_id=$1', [req.auth.tenantId]);
    if (count.rows[0].c >= limit) throw httpError(402, `Your plan allows ${limit} seat(s). Upgrade to add more.`);

    const dup = await query('SELECT 1 FROM users WHERE email=$1', [email]);
    if (dup.rowCount) throw httpError(409, 'Email already registered');

    const passwordHash = await hashPassword(req.body.password || '');
    const r = await query(
      `INSERT INTO users(tenant_id,email,password_hash,role) VALUES($1,$2,$3,$4)
       RETURNING id, email, role, created_at`,
      [req.auth.tenantId, email, passwordHash, role]
    );
    res.status(201).json({ member: r.rows[0] });
  } catch (e) { next(e); }
});

router.put('/members/:id', requireRole('admin'), async (req, res, next) => {
  try {
    const role = String(req.body.role || '');
    if (!['admin', 'analyst', 'viewer'].includes(role)) throw httpError(400, 'Role must be admin, analyst, or viewer');
    // Prevent removing the last admin.
    if (req.params.id === req.auth.userId && role !== 'admin') {
      const admins = await query("SELECT count(*)::int c FROM users WHERE tenant_id=$1 AND role='admin'", [req.auth.tenantId]);
      if (admins.rows[0].c <= 1) throw httpError(400, 'Cannot demote the last admin');
    }
    const r = await query(
      'UPDATE users SET role=$3 WHERE id=$1 AND tenant_id=$2 RETURNING id, email, role',
      [req.params.id, req.auth.tenantId, role]
    );
    if (!r.rowCount) return res.status(404).json({ error: 'Member not found' });
    res.json({ member: r.rows[0] });
  } catch (e) {
    if (String(e.message).includes('invalid input syntax')) return res.status(404).json({ error: 'Member not found' });
    next(e);
  }
});

router.delete('/members/:id', requireRole('admin'), async (req, res, next) => {
  try {
    if (req.params.id === req.auth.userId) throw httpError(400, 'You cannot delete your own account here');
    const r = await query('DELETE FROM users WHERE id=$1 AND tenant_id=$2 RETURNING id', [req.params.id, req.auth.tenantId]);
    if (!r.rowCount) return res.status(404).json({ error: 'Member not found' });
    res.json({ deleted: r.rows[0].id });
  } catch (e) {
    if (String(e.message).includes('invalid input syntax')) return res.status(404).json({ error: 'Member not found' });
    next(e);
  }
});

// ---- Danger zone: delete ALL tenant data (Admin only) ----
router.delete('/data', requireRole('admin'), async (req, res, next) => {
  try {
    // Cascades remove events, reports, shares, schedules for this tenant only.
    await query('DELETE FROM uploads WHERE tenant_id=$1', [req.auth.tenantId]);
    await query('DELETE FROM reports WHERE tenant_id=$1', [req.auth.tenantId]);
    await query('DELETE FROM schedules WHERE tenant_id=$1', [req.auth.tenantId]);
    res.json({ status: 'purged' });
  } catch (e) { next(e); }
});

module.exports = router;
