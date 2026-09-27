'use strict';
const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');
const h = require('./helper');

before(async () => { await h.start(); });
after(async () => { await h.stop(); });
beforeEach(async () => { await h.resetDb(); });

const alerts = [
  { id: 'a1', timestamp: '2026-09-20T10:00:00Z', rule: { id: '5710', level: 5, description: 'ssh fail', groups: ['sshd', 'authentication_failed'], mitre: { id: ['T1110'] } }, agent: { name: 'web01' }, data: { srcip: '203.0.113.1', dstuser: 'root' }, full_log: 'x' },
];

async function makeReport(token) {
  const up = await h.uploadJson(token, alerts);
  const rep = await h.req('POST', '/api/reports', { token, body: { uploadId: up.data.upload.id } });
  return rep.data.report.id;
}

// Alerts with clearly-internal identifiers so we can assert executive redaction.
// Enough repetitions (same src IP + rule) to form a correlated finding whose
// title/summary would otherwise embed the source IP — exercising the redaction.
const sensitiveAlerts = Array.from({ length: 8 }, (_, i) => ({
  id: 's' + i,
  timestamp: `2026-09-20T10:0${i}:00Z`,
  rule: { id: '5710', level: 12, description: 'sshd brute force', groups: ['sshd', 'authentication_failed'], mitre: { id: ['T1110'] } },
  agent: { name: 'INTERNAL-DC01' },
  data: { srcip: '10.9.9.9', dstuser: 'svc_admin' },
  full_log: 'SECRET raw log line from INTERNAL-DC01 for svc_admin',
}));

function tokenFromUrl(url) {
  return url.split('/share/')[1];
}

test('sharing requires an entitled plan', async () => {
  const A = await h.signup('share-free@t.com');
  await h.setPlan(A.tenant.id, 'free');
  const reportId = await makeReport(A.token);
  const r = await h.req('POST', '/api/reports/' + reportId + '/shares', { token: A.token, body: { expiresInHours: 24 } });
  assert.equal(r.status, 402);
});

test('create → resolve read-only share works without auth; token stored hashed; default mode is executive', async () => {
  const A = await h.signup('share@t.com');
  await h.setPlan(A.tenant.id, 'pro');
  const reportId = await makeReport(A.token);

  const create = await h.req('POST', '/api/reports/' + reportId + '/shares', { token: A.token, body: { expiresInHours: 24 } });
  assert.equal(create.status, 201);
  assert.equal(create.data.share.mode, 'executive'); // safe default
  const url = create.data.share.url;
  const token = tokenFromUrl(url);
  assert.ok(token && token.length > 10);

  // Public resolve — NO auth header
  const pub = await h.req('GET', '/api/share/' + token);
  assert.equal(pub.status, 200);
  assert.equal(pub.data.shared, true);
  assert.equal(pub.data.mode, 'executive');
  // Executive payload exposes KPIs but NOT the raw dashboard.
  assert.equal(pub.data.report.data.view, 'executive');
  assert.ok(pub.data.report.data.kpis.total >= 1);
  assert.equal(pub.data.report.data.dashboard, undefined);

  // Public PDF works too
  const pdf = await h.req('GET', '/api/share/' + token + '/pdf', { raw: true });
  assert.equal(pdf.status, 200);
  assert.equal(pdf.headers.get('content-type'), 'application/pdf');

  // The plaintext token must NOT be stored — only a sha256 hash.
  const row = await h.pool.query('SELECT token_hash FROM report_shares WHERE tenant_id=$1', [A.tenant.id]);
  assert.equal(row.rowCount, 1);
  assert.notEqual(row.rows[0].token_hash, token);
  assert.equal(row.rows[0].token_hash.length, 64); // sha256 hex
});

test('M2: executive share hides raw logs / hostnames / usernames / event IDs; analyst share reveals them', async () => {
  const A = await h.signup('share-modes@t.com');
  await h.setPlan(A.tenant.id, 'pro');
  const up = await h.uploadJson(A.token, sensitiveAlerts);
  const rep = await h.req('POST', '/api/reports', { token: A.token, body: { uploadId: up.data.upload.id } });
  const reportId = rep.data.report.id;

  // Executive (default) share — sensitive strings must be absent.
  const execCreate = await h.req('POST', '/api/reports/' + reportId + '/shares', { token: A.token, body: {} });
  assert.equal(execCreate.data.share.mode, 'executive');
  const execTok = tokenFromUrl(execCreate.data.share.url);
  const execRes = await h.req('GET', '/api/share/' + execTok);
  const execBlob = JSON.stringify(execRes.data);
  assert.equal(execRes.data.mode, 'executive');
  assert.ok(!execBlob.includes('SECRET raw log'), 'raw logs must not leak in executive share');
  assert.ok(!execBlob.includes('INTERNAL-DC01'), 'internal hostname must not leak');
  assert.ok(!execBlob.includes('svc_admin'), 'internal username must not leak');
  assert.ok(!execBlob.includes('10.9.9.9'), 'internal source IP must not leak');
  assert.equal(execRes.data.report.data.evidence_appendix, undefined);

  // Executive PDF renders (200) — its source is the deep-redacted clone, which
  // we assert directly (PDF byte scanning is unreliable due to stream compression).
  const execPdf = await h.req('GET', '/api/share/' + execTok + '/pdf', { raw: true });
  assert.equal(execPdf.status, 200);
  const { redactReportDataForExecutive } = require('../src/services/report/shareView');
  const full = await h.req('GET', '/api/reports/' + reportId, { token: A.token });
  const redacted = JSON.stringify(redactReportDataForExecutive(full.data.report.data));
  assert.ok(!redacted.includes('10.9.9.9'), 'redacted PDF source must not contain source IP');
  assert.ok(!redacted.includes('SECRET raw log'), 'redacted PDF source must not contain raw logs');
  assert.ok(!redacted.includes('INTERNAL-DC01'), 'redacted PDF source must not contain hostname');

  // Analyst share must be EXPLICITLY requested.
  const anCreate = await h.req('POST', '/api/reports/' + reportId + '/shares', { token: A.token, body: { mode: 'analyst' } });
  assert.equal(anCreate.data.share.mode, 'analyst');
  const anTok = tokenFromUrl(anCreate.data.share.url);
  const anRes = await h.req('GET', '/api/share/' + anTok);
  assert.equal(anRes.data.mode, 'analyst');
  const anBlob = JSON.stringify(anRes.data);
  assert.ok(anBlob.includes('INTERNAL-DC01'), 'analyst share should include technical detail');
  assert.ok(anRes.data.report.data.dashboard.totals.total >= 2);
});

test('M2: an unknown / malicious share token is rejected (no data, no crash)', async () => {
  for (const bad of ['../../etc/passwd', 'x', "'; DROP TABLE report_shares;--", 'a'.repeat(500)]) {
    const r = await h.req('GET', '/api/share/' + encodeURIComponent(bad));
    assert.ok([404, 410].includes(r.status), `token ${bad.slice(0,10)} -> ${r.status}`);
    assert.ok(!r.data || !r.data.shared);
  }
});

test('M2: share lifecycle is written to the audit log', async () => {
  const A = await h.signup('share-audit@t.com');
  await h.setPlan(A.tenant.id, 'pro');
  const reportId = await makeReport(A.token);
  const create = await h.req('POST', '/api/reports/' + reportId + '/shares', { token: A.token, body: {} });
  const token = tokenFromUrl(create.data.share.url);
  await h.req('GET', '/api/share/' + token); // access
  const shares = await h.req('GET', '/api/reports/' + reportId + '/shares', { token: A.token });
  await h.req('DELETE', '/api/reports/' + reportId + '/shares/' + shares.data.shares[0].id, { token: A.token }); // revoke

  const audit = await h.pool.query('SELECT event FROM share_audit WHERE tenant_id=$1 ORDER BY created_at', [A.tenant.id]);
  const events = audit.rows.map((r) => r.event);
  assert.ok(events.includes('created'));
  assert.ok(events.includes('accessed'));
  assert.ok(events.includes('revoked'));
});

test('expired links return 410', async () => {
  const A = await h.signup('share-exp@t.com');
  await h.setPlan(A.tenant.id, 'pro');
  const reportId = await makeReport(A.token);
  const create = await h.req('POST', '/api/reports/' + reportId + '/shares', { token: A.token, body: { expiresInHours: 1 } });
  const token = tokenFromUrl(create.data.share.url);
  // Force expiry
  await h.pool.query("UPDATE report_shares SET expires_at = now() - interval '1 hour' WHERE report_id=$1", [reportId]);
  const pub = await h.req('GET', '/api/share/' + token);
  assert.equal(pub.status, 410);
});

test('revoked links return 410', async () => {
  const A = await h.signup('share-rev@t.com');
  await h.setPlan(A.tenant.id, 'pro');
  const reportId = await makeReport(A.token);
  const create = await h.req('POST', '/api/reports/' + reportId + '/shares', { token: A.token, body: {} });
  const token = tokenFromUrl(create.data.share.url);
  const shares = await h.req('GET', '/api/reports/' + reportId + '/shares', { token: A.token });
  const shareId = shares.data.shares[0].id;
  const del = await h.req('DELETE', '/api/reports/' + reportId + '/shares/' + shareId, { token: A.token });
  assert.equal(del.status, 200);
  const pub = await h.req('GET', '/api/share/' + token);
  assert.equal(pub.status, 410);
});

test('unknown token returns 404', async () => {
  const pub = await h.req('GET', '/api/share/not-a-real-token-value');
  assert.equal(pub.status, 404);
});
