'use strict';
// Health checks + fail-safe DB behavior.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('node:child_process');
const path = require('node:path');
const h = require('./helper');

before(async () => { await h.start(); });
after(async () => { await h.stop(); });

test('API health endpoint reports ok and database up when reachable', async () => {
  const r = await h.req('GET', '/api/health');
  assert.equal(r.status, 200);
  assert.equal(r.data.status, 'ok');
  assert.equal(r.data.db, 'up');
});

test('the app fails safely when PostgreSQL is unavailable (waitForDb returns false)', () => {
  // Fresh process pointed at a dead DB port; waitForDb must give up gracefully
  // (return false) rather than hang or crash — index.js then exits non-zero.
  const script =
    "const {waitForDb}=require('./src/db/pool');" +
    "waitForDb({retries:2,delayMs:100}).then(ok=>{process.stdout.write('READY='+ok);process.exit(0);});";
  const out = execFileSync('node', ['-e', script], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, NODE_ENV: 'test', DATABASE_URL: 'postgres://soc:socpass@127.0.0.1:59999/nope' },
    encoding: 'utf8',
    timeout: 15000,
  });
  assert.match(out, /READY=false/);
});
