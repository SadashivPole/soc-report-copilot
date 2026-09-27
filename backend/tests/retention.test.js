'use strict';
const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');
const h = require('./helper');
const { runRetentionForTenant, cutoffFor } = require('../src/services/retention');

before(async () => { await h.start(); });
after(async () => { await h.stop(); });
beforeEach(async () => { await h.resetDb(); });

function alertAt(iso, id) {
  return { id, timestamp: iso, rule: { id: '5710', level: 12, description: 'ssh fail', groups: ['sshd', 'authentication_failed'], mitre: { id: ['T1110'] } }, agent: { name: 'web01' }, data: { srcip: '203.0.113.1', dstuser: 'root' }, full_log: 'x' };
}

test('M3: cutoffFor returns null for non-positive retention (no accidental deletion)', () => {
  assert.equal(cutoffFor(0), null);
  assert.equal(cutoffFor(-5), null);
  assert.equal(cutoffFor(null), null);
  assert.ok(cutoffFor(30) instanceof Date);
});

test('M3: retention deletes data older than the window and preserves recent data', async () => {
  const A = await h.signup('ret@t.com');
  await h.setPlan(A.tenant.id, 'pro');

  // Two uploads: one old, one recent.
  const oldUp = await h.uploadJson(A.token, [alertAt('2026-01-01T10:00:00Z', 'old')]);
  const newUp = await h.uploadJson(A.token, [alertAt('2026-09-20T10:00:00Z', 'new')]);
  // Backdate the old upload well beyond a 30-day window.
  await h.pool.query("UPDATE uploads SET uploaded_at = now() - interval '200 days' WHERE id=$1", [oldUp.data.upload.id]);

  const summary = await runRetentionForTenant(A.tenant.id, { retentionDays: 30 });
  assert.equal(summary.status, 'ok');
  assert.equal(summary.uploads_deleted, 1);
  assert.equal(summary.events_deleted, 1);

  // Old upload + its events gone; recent upload intact.
  const ups = await h.pool.query('SELECT id FROM uploads WHERE tenant_id=$1', [A.tenant.id]);
  assert.deepEqual(ups.rows.map((r) => r.id), [newUp.data.upload.id]);
  const evc = await h.pool.query('SELECT count(*)::int c FROM events WHERE tenant_id=$1', [A.tenant.id]);
  assert.equal(evc.rows[0].c, 1);

  // Sweep recorded auditable row.
  const run = await h.pool.query('SELECT uploads_deleted, events_deleted, status FROM retention_runs WHERE tenant_id=$1', [A.tenant.id]);
  assert.equal(run.rowCount, 1);
  assert.equal(run.rows[0].status, 'ok');
});

test('M3: retention boundary — an upload just inside the window is kept', async () => {
  const A = await h.signup('ret-bound@t.com');
  const up = await h.uploadJson(A.token, [alertAt('2026-09-20T10:00:00Z', 'x')]);
  await h.pool.query("UPDATE uploads SET uploaded_at = now() - interval '10 days' WHERE id=$1", [up.data.upload.id]);
  const summary = await runRetentionForTenant(A.tenant.id, { retentionDays: 30 });
  assert.equal(summary.uploads_deleted, 0);
  const ups = await h.pool.query('SELECT count(*)::int c FROM uploads WHERE tenant_id=$1', [A.tenant.id]);
  assert.equal(ups.rows[0].c, 1);
});

test('M3: expired reports are deleted but management actions + audit are preserved', async () => {
  const A = await h.signup('ret-actions@t.com');
  await h.setPlan(A.tenant.id, 'pro');
  const up = await h.uploadJson(A.token, [
    alertAt('2026-09-20T10:00:00Z', 'a'), alertAt('2026-09-20T10:01:00Z', 'b'),
    alertAt('2026-09-20T10:02:00Z', 'c'), alertAt('2026-09-20T10:03:00Z', 'd'),
    alertAt('2026-09-20T10:04:00Z', 'e'),
  ]);
  const rep = await h.req('POST', '/api/reports', { token: A.token, body: { uploadId: up.data.upload.id } });
  const reportId = rep.data.report.id;
  // Backdate the report beyond the window.
  await h.pool.query("UPDATE reports SET created_at = now() - interval '400 days' WHERE id=$1", [reportId]);
  const actionsBefore = await h.pool.query('SELECT count(*)::int c FROM actions WHERE tenant_id=$1', [A.tenant.id]);

  const summary = await runRetentionForTenant(A.tenant.id, { retentionDays: 180 });
  assert.ok(summary.reports_deleted >= 1);

  // Report gone; actions preserved with report_id nulled.
  const repRows = await h.pool.query('SELECT count(*)::int c FROM reports WHERE id=$1', [reportId]);
  assert.equal(repRows.rows[0].c, 0);
  const actionsAfter = await h.pool.query('SELECT count(*)::int c FROM actions WHERE tenant_id=$1', [A.tenant.id]);
  assert.equal(actionsAfter.rows[0].c, actionsBefore.rows[0].c);
  assert.ok(actionsAfter.rows[0].c >= 1, 'actions should survive report deletion');
});

test('M3: dry-run preview reports counts without deleting anything', async () => {
  const A = await h.signup('ret-dry@t.com');
  const up = await h.uploadJson(A.token, [alertAt('2026-01-01T10:00:00Z', 'old')]);
  await h.pool.query("UPDATE uploads SET uploaded_at = now() - interval '200 days' WHERE id=$1", [up.data.upload.id]);

  const preview = await runRetentionForTenant(A.tenant.id, { retentionDays: 30, dryRun: true });
  assert.equal(preview.uploads_deleted, 1); // would delete 1
  const ups = await h.pool.query('SELECT count(*)::int c FROM uploads WHERE tenant_id=$1', [A.tenant.id]);
  assert.equal(ups.rows[0].c, 1); // but nothing actually deleted
  const runs = await h.pool.query('SELECT count(*)::int c FROM retention_runs WHERE tenant_id=$1', [A.tenant.id]);
  assert.equal(runs.rows[0].c, 0); // dry-run is not persisted as a sweep
});

test('M3: admin retention endpoints (status + run)', async () => {
  const A = await h.signup('ret-api@t.com');
  await h.setPlan(A.tenant.id, 'pro');
  const status = await h.req('GET', '/api/tenant/retention', { token: A.token });
  assert.equal(status.status, 200);
  assert.equal(status.data.retention_days, 180); // pro
  const run = await h.req('POST', '/api/tenant/retention/run', { token: A.token });
  assert.equal(run.status, 200);
  assert.equal(run.data.result.status, 'ok');
});
