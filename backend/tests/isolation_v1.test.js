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

test('tenant B cannot touch tenant A schedules, shares, reports, or members', async () => {
  const A = await h.signup('iso-a@t.com');
  const B = await h.signup('iso-b@t.com');
  await h.setPlan(A.tenant.id, 'mssp');
  await h.setPlan(B.tenant.id, 'mssp');

  // A sets up data
  const up = await h.uploadJson(A.token, alerts);
  const uploadId = up.data.upload.id;
  const rep = await h.req('POST', '/api/reports', { token: A.token, body: { uploadId } });
  const reportId = rep.data.report.id;
  const sched = await h.req('POST', '/api/schedules', { token: A.token, body: { recipients: ['a@a.com'] } });
  const schedId = sched.data.schedule.id;
  const share = await h.req('POST', '/api/reports/' + reportId + '/shares', { token: A.token, body: {} });
  const shareUrl = share.data.share.url;

  // B sees none of A's resources
  assert.equal((await h.req('GET', '/api/schedules', { token: B.token })).data.schedules.length, 0);
  assert.equal((await h.req('GET', '/api/reports', { token: B.token })).data.reports.length, 0);
  assert.equal((await h.req('GET', '/api/uploads', { token: B.token })).data.uploads.length, 0);
  assert.equal((await h.req('GET', '/api/tenant/members', { token: B.token })).data.members.length, 1); // only B

  // B cannot mutate/delete A's resources → 404
  assert.equal((await h.req('PUT', '/api/schedules/' + schedId, { token: B.token, body: { hour: 9 } })).status, 404);
  assert.equal((await h.req('DELETE', '/api/schedules/' + schedId, { token: B.token })).status, 404);
  assert.equal((await h.req('POST', '/api/schedules/' + schedId + '/run', { token: B.token })).status, 404);
  assert.equal((await h.req('DELETE', '/api/reports/' + reportId, { token: B.token })).status, 404);
  assert.equal((await h.req('DELETE', '/api/uploads/' + uploadId, { token: B.token })).status, 404);
  assert.equal((await h.req('GET', '/api/reports/' + reportId + '/shares', { token: B.token })).status, 404);
  assert.equal((await h.req('POST', '/api/reports/' + reportId + '/shares', { token: B.token, body: {} })).status, 404);

  // But the PUBLIC share link still works for anyone (that is its purpose),
  // and it exposes ONLY the report payload — no tenant identifiers.
  const token = shareUrl.split('/share/')[1];
  const pub = await h.req('GET', '/api/share/' + token);
  assert.equal(pub.status, 200);
  assert.ok(!('tenant_id' in pub.data.report));

  // A's branding change does not affect B
  await h.req('PUT', '/api/tenant/branding', { token: A.token, body: { company_name: 'Acme SOC' } });
  const bBrand = await h.req('GET', '/api/tenant/branding', { token: B.token });
  assert.notEqual(bBrand.data.branding.company_name, 'Acme SOC');
});

test('tenant data deletion purges only the calling tenant', async () => {
  const A = await h.signup('purge-a@t.com');
  const B = await h.signup('purge-b@t.com');
  await h.uploadJson(A.token, alerts);
  await h.uploadJson(B.token, alerts);

  const del = await h.req('DELETE', '/api/tenant/data', { token: A.token });
  assert.equal(del.status, 200);

  assert.equal((await h.req('GET', '/api/uploads', { token: A.token })).data.uploads.length, 0);
  assert.equal((await h.req('GET', '/api/uploads', { token: B.token })).data.uploads.length, 1);
});
