'use strict';
const express = require('express');
const { requireAuth, requireRole } = require('../middleware/auth');
const { query } = require('../db/pool');
const { getPlan } = require('../services/billing/plans');
const { httpError } = require('../services/auth.service');
const { computeNextRun, runSchedule } = require('../services/scheduler');

const router = express.Router();
router.use(requireAuth);

const isUuidErr = (e) => String(e.message).includes('invalid input syntax');

function validEmails(arr) {
  if (!Array.isArray(arr)) return [];
  return arr
    .map((s) => String(s).toLowerCase().trim())
    .filter((s) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s))
    .slice(0, 20);
}

function sanitizeInput(body) {
  const dow = Math.min(Math.max(parseInt(body.day_of_week, 10) || 0, 0), 6);
  const hour = Math.min(Math.max(parseInt(body.hour, 10) || 0, 0), 23);
  const minute = Math.min(Math.max(parseInt(body.minute, 10) || 0, 0), 59);
  let tz = String(body.timezone || 'UTC');
  try { Intl.DateTimeFormat('en-US', { timeZone: tz }); } catch { tz = 'UTC'; }
  return {
    name: (body.name && String(body.name).slice(0, 160)) || 'Weekly SOC Report',
    upload_source: body.upload_source && body.upload_source !== 'latest' ? String(body.upload_source) : 'latest',
    day_of_week: dow, hour, minute, timezone: tz,
    recipients: validEmails(body.recipients),
    client_name: body.client_name != null ? String(body.client_name).slice(0, 160) : null,
    enabled: body.enabled !== false,
  };
}

router.get('/', async (req, res, next) => {
  try {
    const r = await query(
      `SELECT id, name, upload_source, day_of_week, hour, minute, timezone, recipients,
              client_name, enabled, last_run_at, last_status, next_run_at, created_at
         FROM schedules WHERE tenant_id=$1 ORDER BY created_at DESC`,
      [req.auth.tenantId]
    );
    res.json({ schedules: r.rows });
  } catch (e) { next(e); }
});

router.post('/', requireRole('analyst'), async (req, res, next) => {
  try {
    const t = await query('SELECT plan FROM tenants WHERE id=$1', [req.auth.tenantId]);
    const limits = getPlan(t.rows[0].plan).limits;
    if (limits.maxSchedules <= 0) throw httpError(402, 'Your plan does not include report scheduling. Upgrade to enable it.');
    const count = await query('SELECT count(*)::int c FROM schedules WHERE tenant_id=$1', [req.auth.tenantId]);
    if (count.rows[0].c >= limits.maxSchedules) throw httpError(402, `Your plan allows ${limits.maxSchedules} schedule(s). Upgrade for more.`);

    const s = sanitizeInput(req.body);
    const next = computeNextRun(s);
    const r = await query(
      `INSERT INTO schedules(tenant_id, created_by, name, upload_source, day_of_week, hour, minute, timezone, recipients, client_name, enabled, next_run_at)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
      [req.auth.tenantId, req.auth.userId, s.name, s.upload_source, s.day_of_week, s.hour, s.minute, s.timezone, JSON.stringify(s.recipients), s.client_name, s.enabled, next]
    );
    res.status(201).json({ schedule: r.rows[0] });
  } catch (e) { next(e); }
});

router.put('/:id', requireRole('analyst'), async (req, res, next) => {
  try {
    const existing = await query('SELECT * FROM schedules WHERE id=$1 AND tenant_id=$2', [req.params.id, req.auth.tenantId]);
    if (!existing.rowCount) return res.status(404).json({ error: 'Schedule not found' });
    const s = sanitizeInput({ ...existing.rows[0], ...req.body });
    const next = computeNextRun(s);
    const r = await query(
      `UPDATE schedules SET name=$3, upload_source=$4, day_of_week=$5, hour=$6, minute=$7, timezone=$8,
              recipients=$9, client_name=$10, enabled=$11, next_run_at=$12
        WHERE id=$1 AND tenant_id=$2 RETURNING *`,
      [req.params.id, req.auth.tenantId, s.name, s.upload_source, s.day_of_week, s.hour, s.minute, s.timezone, JSON.stringify(s.recipients), s.client_name, s.enabled, next]
    );
    res.json({ schedule: r.rows[0] });
  } catch (e) {
    if (isUuidErr(e)) return res.status(404).json({ error: 'Schedule not found' });
    next(e);
  }
});

router.delete('/:id', requireRole('analyst'), async (req, res, next) => {
  try {
    const r = await query('DELETE FROM schedules WHERE id=$1 AND tenant_id=$2 RETURNING id', [req.params.id, req.auth.tenantId]);
    if (!r.rowCount) return res.status(404).json({ error: 'Schedule not found' });
    res.json({ deleted: r.rows[0].id });
  } catch (e) {
    if (isUuidErr(e)) return res.status(404).json({ error: 'Schedule not found' });
    next(e);
  }
});

// Run a schedule immediately (Analyst+). Useful to preview delivery.
router.post('/:id/run', requireRole('analyst'), async (req, res, next) => {
  try {
    const r = await query('SELECT * FROM schedules WHERE id=$1 AND tenant_id=$2', [req.params.id, req.auth.tenantId]);
    if (!r.rowCount) return res.status(404).json({ error: 'Schedule not found' });
    const status = await runSchedule(r.rows[0]);
    await query('UPDATE schedules SET last_run_at=now(), last_status=$2 WHERE id=$1', [req.params.id, status]);
    res.json({ status });
  } catch (e) {
    if (isUuidErr(e)) return res.status(404).json({ error: 'Schedule not found' });
    next(e);
  }
});

module.exports = router;
