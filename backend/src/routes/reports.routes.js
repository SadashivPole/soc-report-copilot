'use strict';
const express = require('express');
const { requireAuth, requireRole } = require('../middleware/auth');
const { query } = require('../db/pool');
const { buildReport } = require('../services/report/builder');
const { renderReportPdf } = require('../services/report/pdf');
const { assertEntitled } = require('../services/billing/plans');
const sharing = require('../services/sharing');
const actionsService = require('../services/actions.service');

const router = express.Router();
router.use(requireAuth);

const isUuidErr = (e) => String(e.message).includes('invalid input syntax');

async function tenantBranding(tenantId) {
  const r = await query(
    'SELECT company_name, logo_data_url, default_client, plan FROM tenants WHERE id=$1',
    [tenantId]
  );
  return r.rows[0] || {};
}

// Generate a report for one of the tenant's uploads. (Analyst+)
router.post('/', requireRole('analyst'), async (req, res, next) => {
  try {
    const uploadId = req.body.uploadId;
    if (!uploadId) return res.status(400).json({ error: 'uploadId is required' });

    const up = await query(
      'SELECT id, filename, source_type, event_count FROM uploads WHERE id=$1 AND tenant_id=$2',
      [uploadId, req.auth.tenantId]
    );
    if (!up.rowCount) return res.status(404).json({ error: 'Upload not found' });

    const branding = await tenantBranding(req.auth.tenantId);
    const clientName = (req.body.clientName && String(req.body.clientName).slice(0, 160)) || branding.default_client || null;
    const organization =
      (req.body.organization && String(req.body.organization).slice(0, 160)) || branding.company_name || null;
    const periodLabel = req.body.periodLabel ? String(req.body.periodLabel).slice(0, 120) : null;

    const data = await buildReport(req.auth.tenantId, uploadId, {
      title: (req.body.title && String(req.body.title).slice(0, 160)) || 'Weekly SOC Report',
      filename: up.rows[0].filename,
      source_type: up.rows[0].source_type,
      branding,
      clientName,
      organization,
      periodLabel,
    });

    const prevId = data.comparison && data.comparison.available ? data.comparison.previous.report_id : null;

    const ins = await query(
      `INSERT INTO reports(tenant_id, user_id, upload_id, title, period_start, period_end, client_name, organization, previous_report_id, data)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       RETURNING id, title, client_name, organization, period_start, period_end, created_at`,
      [
        req.auth.tenantId,
        req.auth.userId,
        uploadId,
        data.title,
        data.period_start,
        data.period_end,
        clientName,
        organization,
        prevId,
        JSON.stringify(data),
      ]
    );

    const reportId = ins.rows[0].id;
    // Seed the management action plan from evidence-bound recommended actions.
    let seeded = 0;
    try {
      seeded = await actionsService.seedFromReport(
        req.auth.tenantId,
        req.auth.userId,
        reportId,
        data.recommended_actions
      );
    } catch (seedErr) {
      // Never fail report generation because of action seeding.
      console.error('[reports] action seed failed', seedErr.message);
    }

    res.status(201).json({ report: { ...ins.rows[0], data }, actions_created: seeded });
  } catch (e) {
    if (isUuidErr(e)) return res.status(404).json({ error: 'Upload not found' });
    next(e);
  }
});

router.get('/', async (req, res, next) => {
  try {
    const r = await query(
      `SELECT id, title, client_name, upload_id, period_start, period_end, created_at
         FROM reports WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 200`,
      [req.auth.tenantId]
    );
    res.json({ reports: r.rows });
  } catch (e) {
    next(e);
  }
});

async function loadReport(tenantId, id) {
  const r = await query('SELECT id, title, client_name, data, created_at FROM reports WHERE id=$1 AND tenant_id=$2', [id, tenantId]);
  return r.rows[0] || null;
}

router.get('/:id', async (req, res, next) => {
  try {
    const report = await loadReport(req.auth.tenantId, req.params.id);
    if (!report) return res.status(404).json({ error: 'Report not found' });
    res.json({ report });
  } catch (e) {
    if (isUuidErr(e)) return res.status(404).json({ error: 'Report not found' });
    next(e);
  }
});

router.get('/:id/pdf', async (req, res, next) => {
  try {
    const report = await loadReport(req.auth.tenantId, req.params.id);
    if (!report) return res.status(404).json({ error: 'Report not found' });
    const mode = req.query.mode === 'executive' ? 'executive' : req.query.mode === 'analyst' ? 'analyst' : 'analyst';
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="soc-report-${mode}-${report.id}.pdf"`);
    renderReportPdf(report.data, res, { mode });
  } catch (e) {
    if (isUuidErr(e)) return res.status(404).json({ error: 'Report not found' });
    next(e);
  }
});

// Delete a report (Analyst+).
router.delete('/:id', requireRole('analyst'), async (req, res, next) => {
  try {
    const r = await query('DELETE FROM reports WHERE id=$1 AND tenant_id=$2 RETURNING id', [req.params.id, req.auth.tenantId]);
    if (!r.rowCount) return res.status(404).json({ error: 'Report not found' });
    res.json({ deleted: r.rows[0].id });
  } catch (e) {
    if (isUuidErr(e)) return res.status(404).json({ error: 'Report not found' });
    next(e);
  }
});

// ---- Share links (read-only, expiring) ----

// Create a share (Analyst+, plan must include sharing).
router.post('/:id/shares', requireRole('analyst'), async (req, res, next) => {
  try {
    const branding = await tenantBranding(req.auth.tenantId);
    assertEntitled(branding.plan, 'sharing');

    const own = await query('SELECT id FROM reports WHERE id=$1 AND tenant_id=$2', [req.params.id, req.auth.tenantId]);
    if (!own.rowCount) return res.status(404).json({ error: 'Report not found' });

    // Disclosure mode: executive (default, least data) or analyst (full detail,
    // only when explicitly requested).
    const mode = req.body.mode === 'analyst' ? 'analyst' : 'executive';
    const share = await sharing.createShare({
      tenantId: req.auth.tenantId,
      reportId: req.params.id,
      createdBy: req.auth.userId,
      expiresInHours: req.body.expiresInHours,
      mode,
    });
    const base = req.protocol + '://' + req.get('host');
    res.status(201).json({
      share: {
        id: share.id,
        mode: share.mode,
        expires_at: share.expires_at,
        token_prefix: share.token_prefix,
        url: `${base}/share/${share.token}`,
      },
    });
  } catch (e) {
    if (isUuidErr(e)) return res.status(404).json({ error: 'Report not found' });
    next(e);
  }
});

router.get('/:id/shares', async (req, res, next) => {
  try {
    const own = await query('SELECT id FROM reports WHERE id=$1 AND tenant_id=$2', [req.params.id, req.auth.tenantId]);
    if (!own.rowCount) return res.status(404).json({ error: 'Report not found' });
    const shares = await sharing.listShares(req.auth.tenantId, req.params.id);
    res.json({ shares });
  } catch (e) {
    if (isUuidErr(e)) return res.status(404).json({ error: 'Report not found' });
    next(e);
  }
});

router.delete('/:id/shares/:shareId', requireRole('analyst'), async (req, res, next) => {
  try {
    const ok = await sharing.revokeShare(req.auth.tenantId, req.params.shareId);
    if (!ok) return res.status(404).json({ error: 'Share not found' });
    res.json({ revoked: req.params.shareId });
  } catch (e) {
    if (isUuidErr(e)) return res.status(404).json({ error: 'Share not found' });
    next(e);
  }
});

module.exports = router;
