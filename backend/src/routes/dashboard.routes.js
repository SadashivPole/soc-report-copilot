'use strict';
const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { query } = require('../db/pool');
const stats = require('../services/analysis/stats');
const engine = require('../services/analysis/engine');
const { buildMitreFindings } = require('../services/analysis/mitre');
const actionsService = require('../services/actions.service');

const router = express.Router();
router.use(requireAuth);

async function latestUploadId(tenantId) {
  const r = await query(
    `SELECT id FROM uploads WHERE tenant_id=$1 AND status='parsed' ORDER BY uploaded_at DESC LIMIT 1`,
    [tenantId]
  );
  return r.rowCount ? r.rows[0].id : null;
}

/**
 * Executive Overview — a dedicated, management-facing snapshot. Concise, not
 * overloaded with technical detail. Every number is derived from the tenant's
 * own evidence. Answers: what happened, what changed, what needs attention,
 * what management should know, and the recommended actions.
 */
router.get('/executive', async (req, res, next) => {
  try {
    let uploadId = req.query.uploadId || null;
    if (uploadId) {
      const own = await query('SELECT 1 FROM uploads WHERE id=$1 AND tenant_id=$2', [uploadId, req.auth.tenantId]);
      if (!own.rowCount) return res.status(404).json({ error: 'Upload not found' });
    } else {
      uploadId = await latestUploadId(req.auth.tenantId);
    }

    if (!uploadId) {
      return res.json({ has_data: false, note: 'No parsed uploads yet. Upload a Wazuh export to populate the executive overview.' });
    }

    const [dashboard, analysis, mitre, actionCounts, up] = await Promise.all([
      stats.dashboard(req.auth.tenantId, uploadId),
      engine.analyze(req.auth.tenantId, uploadId),
      buildMitreFindings(req.auth.tenantId, uploadId),
      actionsService.countsByStatus(req.auth.tenantId),
      query('SELECT filename, source_type, uploaded_at FROM uploads WHERE id=$1 AND tenant_id=$2', [uploadId, req.auth.tenantId]),
    ]);

    const sev = dashboard.severity;
    res.json({
      has_data: true,
      upload_id: uploadId,
      data_source: up.rows[0] ? { filename: up.rows[0].filename, source_type: up.rows[0].source_type } : null,
      reporting_period: { start: dashboard.totals.first_seen, end: dashboard.totals.last_seen },
      posture: analysis.posture,
      totals: {
        total: dashboard.totals.total,
        critical: sev.Critical || 0,
        high: sev.High || 0,
        medium: sev.Medium || 0,
        low: sev.Low || 0,
      },
      activity: { recurring_alerts: analysis.recurring_alerts || 0, new_alerts: analysis.new_alerts || 0 },
      trend: dashboard.trend,
      top_hosts: dashboard.top_hosts,
      top_users: dashboard.top_users,
      top_alert_types: dashboard.top_alert_types,
      recurring_source_ips: dashboard.top_source_ips,
      mitre_overview: (mitre.mappings || []).slice(0, 6),
      mitre_note: mitre.note || null,
      false_positive_candidates: (analysis.false_positive_candidates || []).length,
      findings_count: (analysis.findings || []).length,
      open_findings: actionCounts.open_findings,
      resolved_findings: actionCounts.resolved_findings,
      priority_actions: (analysis.recommended_actions || []).slice(0, 5),
    });
  } catch (e) {
    if (String(e.message).includes('invalid input syntax')) return res.status(404).json({ error: 'Upload not found' });
    next(e);
  }
});

router.get('/', async (req, res, next) => {
  try {
    const uploadId = req.query.uploadId || null;
    // If an uploadId is given, verify it belongs to this tenant first.
    if (uploadId) {
      const own = await query('SELECT 1 FROM uploads WHERE id=$1 AND tenant_id=$2', [uploadId, req.auth.tenantId]);
      if (!own.rowCount) return res.status(404).json({ error: 'Upload not found' });
    }
    const data = await stats.dashboard(req.auth.tenantId, uploadId);
    res.json(data);
  } catch (e) {
    if (String(e.message).includes('invalid input syntax')) return res.status(404).json({ error: 'Upload not found' });
    next(e);
  }
});

module.exports = router;
