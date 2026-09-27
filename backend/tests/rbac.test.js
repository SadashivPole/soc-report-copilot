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

async function makeMember(adminToken, email, role) {
  const r = await h.req('POST', '/api/tenant/members', { token: adminToken, body: { email, role, password: 'password123' } });
  assert.equal(r.status, 201, `create ${role} should succeed`);
  const login = await h.login(email);
  return login.token;
}

test('first signup user is an admin', async () => {
  const A = await h.signup('admin@rbac.com');
  const me = await h.req('GET', '/api/auth/me', { token: A.token });
  assert.equal(me.data.role, 'admin');
});

test('admin can create analyst and viewer members', async () => {
  const A = await h.signup('admin2@rbac.com');
  await h.setPlan(A.tenant.id, 'pro'); // 5 seats
  const analystTok = await makeMember(A.token, 'analyst@rbac.com', 'analyst');
  const viewerTok = await makeMember(A.token, 'viewer@rbac.com', 'viewer');
  assert.ok(analystTok && viewerTok);
  const members = await h.req('GET', '/api/tenant/members', { token: A.token });
  assert.equal(members.data.members.length, 3);
});

test('viewer is read-only: cannot upload, generate, or manage', async () => {
  const A = await h.signup('admin3@rbac.com');
  await h.setPlan(A.tenant.id, 'pro');
  const viewerTok = await makeMember(A.token, 'viewer3@rbac.com', 'viewer');

  // upload as admin so there is data to read
  const up = await h.uploadJson(A.token, alerts);
  const uploadId = up.data.upload.id;

  // viewer CAN read dashboard & reports list
  assert.equal((await h.req('GET', '/api/dashboard?uploadId=' + uploadId, { token: viewerTok })).status, 200);
  assert.equal((await h.req('GET', '/api/uploads', { token: viewerTok })).status, 200);

  // viewer CANNOT upload
  const vUpload = await h.uploadJson(viewerTok, alerts);
  assert.equal(vUpload.status, 403);

  // viewer CANNOT generate a report
  assert.equal((await h.req('POST', '/api/reports', { token: viewerTok, body: { uploadId } })).status, 403);

  // viewer CANNOT delete an upload
  assert.equal((await h.req('DELETE', '/api/uploads/' + uploadId, { token: viewerTok })).status, 403);

  // viewer CANNOT manage team or branding
  assert.equal((await h.req('GET', '/api/tenant/members', { token: viewerTok })).status, 403);
  assert.equal((await h.req('PUT', '/api/tenant/branding', { token: viewerTok, body: { company_name: 'x' } })).status, 403);
});

test('analyst can upload/generate but cannot manage team/branding', async () => {
  const A = await h.signup('admin4@rbac.com');
  await h.setPlan(A.tenant.id, 'pro');
  const analystTok = await makeMember(A.token, 'analyst4@rbac.com', 'analyst');

  const up = await h.uploadJson(analystTok, alerts);
  assert.equal(up.status, 201);
  const rep = await h.req('POST', '/api/reports', { token: analystTok, body: { uploadId: up.data.upload.id } });
  assert.equal(rep.status, 201);

  // analyst cannot manage team
  assert.equal((await h.req('POST', '/api/tenant/members', { token: analystTok, body: { email: 'x@y.com', role: 'viewer', password: 'password123' } })).status, 403);
  // analyst cannot change branding
  assert.equal((await h.req('PUT', '/api/tenant/branding', { token: analystTok, body: { company_name: 'x' } })).status, 403);
});

test('cannot demote the last admin', async () => {
  const A = await h.signup('admin5@rbac.com');
  const me = await h.req('GET', '/api/auth/me', { token: A.token });
  const r = await h.req('PUT', '/api/tenant/members/' + me.data.id, { token: A.token, body: { role: 'viewer' } });
  assert.equal(r.status, 400);
});

test('plan seat limit is enforced (Free = 1 seat)', async () => {
  const A = await h.signup('admin6@rbac.com');
  await h.setPlan(A.tenant.id, 'free');
  const r = await h.req('POST', '/api/tenant/members', { token: A.token, body: { email: 'seat@rbac.com', role: 'viewer', password: 'password123' } });
  assert.equal(r.status, 402); // upgrade required
});
