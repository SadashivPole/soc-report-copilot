'use strict';
const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');
const h = require('./helper');

before(async () => { await h.start(); });
after(async () => { await h.stop(); });
beforeEach(async () => { await h.resetDb(); });

const alerts = [
  { id: 'a1', timestamp: '2026-09-20T10:00:00Z', rule: { id: '5710', level: 5, description: 'ssh fail', groups: ['sshd', 'authentication_failed'], mitre: { id: ['T1110'] } }, agent: { name: 'web01' }, data: { srcip: '203.0.113.1', dstuser: 'root' }, full_log: 'x' },
  { id: 'a2', timestamp: '2026-09-21T10:00:00Z', rule: { id: '5710', level: 5, description: 'ssh fail', groups: ['sshd', 'authentication_failed'] }, agent: { name: 'web01' }, data: { srcip: '203.0.113.1', dstuser: 'root' }, full_log: 'x' },
];

test('tenant A cannot read tenant B uploads, dashboard, or reports', async () => {
  const A = await h.signup('a@t.com');
  const B = await h.signup('b@t.com');

  // A uploads and generates a report
  const up = await h.uploadJson(A.token, alerts);
  assert.equal(up.status, 201);
  const uploadId = up.data.upload.id;
  const rep = await h.req('POST', '/api/reports', { token: A.token, body: { uploadId } });
  assert.equal(rep.status, 201);
  const reportId = rep.data.report.id;

  // B sees no uploads / no reports of its own
  const bUploads = await h.req('GET', '/api/uploads', { token: B.token });
  assert.equal(bUploads.data.uploads.length, 0);
  const bReports = await h.req('GET', '/api/reports', { token: B.token });
  assert.equal(bReports.data.reports.length, 0);

  // B cannot fetch A's specific upload/report/dashboard → 404
  assert.equal((await h.req('GET', '/api/uploads/' + uploadId, { token: B.token })).status, 404);
  assert.equal((await h.req('GET', '/api/dashboard?uploadId=' + uploadId, { token: B.token })).status, 404);
  assert.equal((await h.req('GET', '/api/reports/' + reportId, { token: B.token })).status, 404);
  assert.equal((await h.req('GET', '/api/reports/' + reportId + '/pdf', { token: B.token })).status, 404);

  // B cannot generate a report against A's upload
  assert.equal((await h.req('POST', '/api/reports', { token: B.token, body: { uploadId } })).status, 404);

  // A still can access its own
  assert.equal((await h.req('GET', '/api/uploads/' + uploadId, { token: A.token })).status, 200);
  assert.equal((await h.req('GET', '/api/reports/' + reportId, { token: A.token })).status, 200);
});

test('dashboard aggregates only the calling tenant data', async () => {
  const A = await h.signup('a2@t.com');
  const B = await h.signup('b2@t.com');
  await h.uploadJson(A.token, alerts);          // 2 events
  await h.uploadJson(B.token, alerts.slice(0, 1)); // 1 event

  const aDash = await h.req('GET', '/api/dashboard', { token: A.token });
  const bDash = await h.req('GET', '/api/dashboard', { token: B.token });
  assert.equal(aDash.data.totals.total, 2);
  assert.equal(bDash.data.totals.total, 1);
});
