'use strict';
const { query, withTransaction } = require('../db/pool');
const { getPlan } = require('./billing/plans');

/**
 * Data retention enforcement.
 *
 * Policy (per tenant, driven by the tenant's plan `retentionDays`):
 *   - uploads with uploaded_at < cutoff  -> DELETED (their events cascade-delete)
 *   - events                             -> deleted together with their upload
 *   - reports with created_at   < cutoff -> DELETED (their report_shares cascade)
 *   - actions / action_history           -> PRESERVED (management accountability;
 *                                            action.report_id is set NULL on report delete)
 *   - audit logs (schedule_runs, share_audit, retention_runs, billing_events)
 *                                        -> PRESERVED (security/accountability)
 *
 * Safety: retention only runs when retentionDays is a positive integer, the
 * cutoff is strictly in the past, and every delete is tenant-scoped. Each sweep
 * is recorded in retention_runs (auditable). Deletion is skipped for retentionDays<=0.
 */

function cutoffFor(retentionDays, now = new Date()) {
  const days = parseInt(retentionDays, 10);
  if (!Number.isFinite(days) || days <= 0) return null;
  const c = new Date(now.getTime() - days * 86400000);
  if (c.getTime() >= now.getTime()) return null; // never a future cutoff
  return c;
}

/**
 * Enforce retention for a single tenant.
 * @param {string} tenantId
 * @param {object} opts { retentionDays, now, dryRun }
 * @returns {object} summary { tenantId, retention_days, cutoff, uploads_deleted, events_deleted, reports_deleted, status, dry_run }
 */
async function runRetentionForTenant(tenantId, opts = {}) {
  const now = opts.now || new Date();
  let retentionDays = opts.retentionDays;
  if (retentionDays == null) {
    const t = await query('SELECT plan FROM tenants WHERE id=$1', [tenantId]);
    if (!t.rowCount) return { tenantId, status: 'skipped_no_tenant' };
    retentionDays = getPlan(t.rows[0].plan).limits.retentionDays;
  }
  const cutoff = cutoffFor(retentionDays, now);
  const summary = {
    tenantId,
    retention_days: retentionDays,
    cutoff: cutoff ? cutoff.toISOString() : null,
    uploads_deleted: 0,
    events_deleted: 0,
    reports_deleted: 0,
    status: 'ok',
    dry_run: !!opts.dryRun,
  };
  if (!cutoff) {
    summary.status = 'skipped_no_policy';
    return summary;
  }

  try {
    await withTransaction(async (client) => {
      // Count events that will be removed (for the audit record) before delete.
      const evc = await client.query(
        `SELECT count(*)::int c FROM events e
          JOIN uploads u ON u.id = e.upload_id
         WHERE e.tenant_id=$1 AND u.tenant_id=$1 AND u.uploaded_at < $2`,
        [tenantId, cutoff]
      );
      summary.events_deleted = evc.rows[0].c;

      if (!opts.dryRun) {
        const upd = await client.query(
          `DELETE FROM uploads WHERE tenant_id=$1 AND uploaded_at < $2 RETURNING id`,
          [tenantId, cutoff]
        );
        summary.uploads_deleted = upd.rowCount;

        const rep = await client.query(
          `DELETE FROM reports WHERE tenant_id=$1 AND created_at < $2 RETURNING id`,
          [tenantId, cutoff]
        );
        summary.reports_deleted = rep.rowCount;
      } else {
        const upd = await client.query(
          `SELECT count(*)::int c FROM uploads WHERE tenant_id=$1 AND uploaded_at < $2`,
          [tenantId, cutoff]
        );
        summary.uploads_deleted = upd.rows[0].c;
        const rep = await client.query(
          `SELECT count(*)::int c FROM reports WHERE tenant_id=$1 AND created_at < $2`,
          [tenantId, cutoff]
        );
        summary.reports_deleted = rep.rows[0].c;
      }
    });
  } catch (e) {
    summary.status = 'error';
    summary.error = String(e.message).slice(0, 200);
  }

  // Record the sweep (real deletes only; dry-run is not persisted as a sweep).
  if (!opts.dryRun) {
    try {
      await query(
        `INSERT INTO retention_runs(tenant_id, run_at, retention_days, cutoff, uploads_deleted, events_deleted, reports_deleted, status, error)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [tenantId, now, retentionDays, cutoff, summary.uploads_deleted, summary.events_deleted, summary.reports_deleted, summary.status, summary.error || null]
      );
    } catch (e) {
      console.error('[retention] failed to record run', String(e.message).slice(0, 200));
    }
  }
  return summary;
}

/** Enforce retention across all tenants (called by the background sweep). */
async function runRetentionForAllTenants(now = new Date()) {
  const t = await query('SELECT id FROM tenants', []);
  const results = [];
  for (const row of t.rows) {
    results.push(await runRetentionForTenant(row.id, { now }));
  }
  return results;
}

module.exports = { runRetentionForTenant, runRetentionForAllTenants, cutoffFor };
