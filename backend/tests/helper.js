'use strict';
// Test harness: point at the test DB, migrate, and expose a fetch-based client.
process.env.DATABASE_URL =
  process.env.TEST_DATABASE_URL || 'postgres://soc:socpass@127.0.0.1:5432/soc_copilot_test';
process.env.JWT_SECRET = 'test-secret';
process.env.NODE_ENV = 'test';

const { createApp } = require('../src/app');
const { pool } = require('../src/db/pool');
const { migrate } = require('../src/db/migrate');

let server, baseUrl;

async function start() {
  await migrate();
  const app = createApp();
  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', resolve);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
  return baseUrl;
}

async function stop() {
  if (server) await new Promise((r) => server.close(r));
  await pool.end();
}

async function resetDb() {
  await pool.query('TRUNCATE reports, events, uploads, users, tenants RESTART IDENTITY CASCADE');
}

async function req(method, path, { token, body, raw } = {}) {
  const headers = {};
  if (token) headers.Authorization = 'Bearer ' + token;
  let payload = body;
  if (body && !(body instanceof Buffer) && !(body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(body);
  }
  const res = await fetch(baseUrl + path, { method, headers, body: payload });
  if (raw) return res;
  const ct = res.headers.get('content-type') || '';
  const data = ct.includes('json') ? await res.json() : await res.text();
  return { status: res.status, data };
}

async function signup(email, password = 'password123', tenantName = 'Org') {
  const r = await req('POST', '/api/auth/signup', { body: { email, password, tenantName } });
  return r.data;
}

async function login(email, password = 'password123') {
  const r = await req('POST', '/api/auth/login', { body: { email, password } });
  return r.data;
}

async function setPlan(tenantId, plan) {
  await pool.query('UPDATE tenants SET plan=$2 WHERE id=$1', [tenantId, plan]);
}

// Upload a JS object array as a JSON file via multipart.
async function uploadJson(token, alerts, filename = 'test.json') {
  const fd = new FormData();
  fd.append('file', new Blob([JSON.stringify(alerts)], { type: 'application/json' }), filename);
  fd.append('sourceType', 'wazuh');
  const res = await fetch(baseUrl + '/api/uploads', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + token },
    body: fd,
  });
  return { status: res.status, data: await res.json() };
}

// Upload arbitrary raw bytes/text with a chosen filename (for robustness tests).
async function uploadRaw(token, content, filename = 'test.json', sourceType = 'wazuh') {
  const fd = new FormData();
  const blob = content instanceof Buffer ? new Blob([content]) : new Blob([String(content)]);
  fd.append('file', blob, filename);
  fd.append('sourceType', sourceType);
  const res = await fetch(baseUrl + '/api/uploads', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + token },
    body: fd,
  });
  let data;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  return { status: res.status, data };
}

module.exports = { start, stop, resetDb, req, signup, login, setPlan, uploadJson, uploadRaw, pool };
