'use strict';
const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');
const h = require('./helper');

before(async () => { await h.start(); });
after(async () => { await h.stop(); });
beforeEach(async () => { await h.resetDb(); });

function bruteAlerts() {
  const list = [];
  for (let i = 0; i < 10; i++) {
    list.push({
      id: 'bf-' + i,
      timestamp: '2026-09-2' + (i % 5) + 'T10:00:00Z',
      rule: { id: '5712', level: 10, description: 'sshd: Multiple authentication failures', groups: ['sshd', 'brute_force'], mitre: { id: ['T1110'] } },
      agent: { name: 'bastion01' },
      data: { srcip: '203.0.113.9', dstuser: 'root' },
      full_log: 'Failed password',
    });
  }
  return list;
}

async function makeMember(adminToken, email, role) {
  const r = await h.req('POST', '/api/tenant/members', { token: adminToken, body: { email, role, password: 'password123' } });
  assert.equal(r.status, 201);
  return (await h.login(email)).token;
}

async function generateReport(token) {
  const up = await h.uploadJson(token, bruteAlerts());
  const r = await h.req('POST', '/api/reports', { token, body: { uploadId: up.data.upload.id } });
  return r.data;
}

test('generating a report seeds evidence-bound action-plan items', async () => {
  const A = await h.signup('act1@t.com');
  const rep = await generateReport(A.token);
  assert.ok(rep.actions_created >= 1, 'actions were seeded');

  const list = await h.req('GET', '/api/actions', { token: A.token });
  assert.equal(list.status, 200);
  assert.ok(list.data.actions.length >= 1);
  const a = list.data.actions[0];
  assert.ok(a.finding && a.recommended_action && a.owner && a.priority);
  assert.equal(a.status, 'open');
  assert.ok(a.evidence.event_ids.length > 0, 'action is traceable to event IDs');
});

test('status changes are recorded in an immutable audit history', async () => {
  const A = await h.signup('act2@t.com');
  await generateReport(A.token);
  const id = (await h.req('GET', '/api/actions', { token: A.token })).data.actions[0].id;

  let r = await h.req('PATCH', '/api/actions/' + id, { token: A.token, body: { status: 'investigating', owner: 'Alice', note: 'triage' } });
  assert.equal(r.status, 200);
  assert.equal(r.data.action.status, 'investigating');
  assert.equal(r.data.action.owner, 'Alice');

  r = await h.req('PATCH', '/api/actions/' + id, { token: A.token, body: { status: 'resolved', note: 'blocked ip' } });
  assert.equal(r.data.action.status, 'resolved');

  const full = await h.req('GET', '/api/actions/' + id, { token: A.token });
  const hist = full.data.action.history.map((x) => x.to_status);
  assert.deepEqual(hist, ['open', 'investigating', 'resolved']);

  const summary = await h.req('GET', '/api/actions/summary', { token: A.token });
  assert.equal(summary.data.summary.resolved, 1);
  assert.equal(summary.data.summary.resolved_findings, 1);
});

test('invalid status is rejected', async () => {
  const A = await h.signup('act3@t.com');
  await generateReport(A.token);
  const id = (await h.req('GET', '/api/actions', { token: A.token })).data.actions[0].id;
  const r = await h.req('PATCH', '/api/actions/' + id, { token: A.token, body: { status: 'not_a_status' } });
  assert.equal(r.status, 400);
});

test('RBAC: viewer cannot modify actions, analyst can', async () => {
  const A = await h.signup('act4@t.com');
  await h.setPlan(A.tenant.id, 'pro');
  await generateReport(A.token);
  const id = (await h.req('GET', '/api/actions', { token: A.token })).data.actions[0].id;

  const viewerTok = await makeMember(A.token, 'v4@t.com', 'viewer');
  const analystTok = await makeMember(A.token, 'a4@t.com', 'analyst');

  // viewer can read
  assert.equal((await h.req('GET', '/api/actions', { token: viewerTok })).status, 200);
  // viewer cannot patch
  assert.equal((await h.req('PATCH', '/api/actions/' + id, { token: viewerTok, body: { status: 'resolved' } })).status, 403);
  // analyst can patch
  assert.equal((await h.req('PATCH', '/api/actions/' + id, { token: analystTok, body: { status: 'investigating' } })).status, 200);
  // only admin can delete
  assert.equal((await h.req('DELETE', '/api/actions/' + id, { token: analystTok })).status, 403);
  assert.equal((await h.req('DELETE', '/api/actions/' + id, { token: A.token })).status, 200);
});

test('actions are tenant-isolated', async () => {
  const A = await h.signup('act5a@t.com', 'password123', 'OrgA');
  const B = await h.signup('act5b@t.com', 'password123', 'OrgB');
  await generateReport(A.token);
  const idA = (await h.req('GET', '/api/actions', { token: A.token })).data.actions[0].id;

  // B sees none of A's actions
  const bList = await h.req('GET', '/api/actions', { token: B.token });
  assert.equal(bList.data.actions.length, 0);
  // B cannot read or patch A's action
  assert.equal((await h.req('GET', '/api/actions/' + idA, { token: B.token })).status, 404);
  assert.equal((await h.req('PATCH', '/api/actions/' + idA, { token: B.token, body: { status: 'resolved' } })).status, 404);
});
