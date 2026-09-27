'use strict';
const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');
const h = require('./helper');

before(async () => { await h.start(); });
after(async () => { await h.stop(); });
beforeEach(async () => { await h.resetDb(); });

test('signup creates tenant + user and returns a token', async () => {
  const r = await h.req('POST', '/api/auth/signup', { body: { email: 'a@x.com', password: 'password123', tenantName: 'Acme' } });
  assert.equal(r.status, 201);
  assert.ok(r.data.token);
  assert.equal(r.data.user.email, 'a@x.com');
  assert.ok(r.data.tenant.id);
});

test('signup rejects short password and bad email', async () => {
  const r1 = await h.req('POST', '/api/auth/signup', { body: { email: 'a@x.com', password: 'short' } });
  assert.equal(r1.status, 400);
  const r2 = await h.req('POST', '/api/auth/signup', { body: { email: 'notanemail', password: 'password123' } });
  assert.equal(r2.status, 400);
});

test('duplicate email is rejected', async () => {
  await h.signup('dup@x.com');
  const r = await h.req('POST', '/api/auth/signup', { body: { email: 'dup@x.com', password: 'password123' } });
  assert.equal(r.status, 409);
});

test('login succeeds with correct creds, fails otherwise', async () => {
  await h.signup('b@x.com', 'password123');
  const ok = await h.req('POST', '/api/auth/login', { body: { email: 'b@x.com', password: 'password123' } });
  assert.equal(ok.status, 200);
  assert.ok(ok.data.token);
  const bad = await h.req('POST', '/api/auth/login', { body: { email: 'b@x.com', password: 'wrongpass' } });
  assert.equal(bad.status, 401);
});

test('protected route requires a valid Bearer token', async () => {
  const none = await h.req('GET', '/api/uploads');
  assert.equal(none.status, 401);
  const bad = await h.req('GET', '/api/uploads', { token: 'garbage.token.here' });
  assert.equal(bad.status, 401);
  const { token } = await h.signup('c@x.com');
  const good = await h.req('GET', '/api/uploads', { token });
  assert.equal(good.status, 200);
});

test('/auth/me returns the current user + tenant', async () => {
  const { token } = await h.signup('me@x.com', 'password123', 'MyOrg');
  const r = await h.req('GET', '/api/auth/me', { token });
  assert.equal(r.status, 200);
  assert.equal(r.data.email, 'me@x.com');
  assert.equal(r.data.tenant_name, 'MyOrg');
});
