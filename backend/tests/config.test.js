'use strict';
// Production configuration hardening (M4 CORS + secret/DB validation).
// config.js validates at require-time, so each case runs in a fresh child process.
const { test } = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

const BACKEND = path.join(__dirname, '..');

function loadConfig(env) {
  const script =
    "try{const c=require('./src/config');process.stdout.write('OK '+JSON.stringify(c.cors));}" +
    "catch(e){process.stdout.write('ERR '+e.message);}";
  try {
    return execFileSync('node', ['-e', script], {
      cwd: BACKEND,
      env: { ...process.env, ...env },
      encoding: 'utf8',
    });
  } catch (e) {
    return 'THROW ' + (e.stderr || e.message);
  }
}

test('M4: production refuses to start without a strong JWT secret', () => {
  const out = loadConfig({ NODE_ENV: 'production', JWT_SECRET: '', CORS_ORIGIN: 'https://app.example.com', DATABASE_URL: 'postgres://x' });
  assert.match(out, /JWT_SECRET/);
  assert.match(out, /^ERR|THROW/);
});

test('M4: production refuses a wildcard CORS origin', () => {
  const out = loadConfig({ NODE_ENV: 'production', JWT_SECRET: 'a-strong-secret-value-1234567890', CORS_ORIGIN: '*', DATABASE_URL: 'postgres://x' });
  assert.match(out, /CORS_ORIGIN/);
});

test('M4: production refuses an empty CORS origin (must be explicit)', () => {
  const out = loadConfig({ NODE_ENV: 'production', JWT_SECRET: 'a-strong-secret-value-1234567890', CORS_ORIGIN: '', DATABASE_URL: 'postgres://x' });
  assert.match(out, /CORS_ORIGIN/);
});

test('M4: production requires DATABASE_URL', () => {
  const out = loadConfig({ NODE_ENV: 'production', JWT_SECRET: 'a-strong-secret-value-1234567890', CORS_ORIGIN: 'https://app.example.com', DATABASE_URL: '' });
  assert.match(out, /DATABASE_URL/);
});

test('M4: production accepts an explicit CORS allow-list', () => {
  const out = loadConfig({ NODE_ENV: 'production', JWT_SECRET: 'a-strong-secret-value-1234567890', CORS_ORIGIN: 'https://app.example.com, https://portal.example.com', DATABASE_URL: 'postgres://x' });
  assert.match(out, /^OK/);
  const cors = JSON.parse(out.slice(3));
  assert.equal(cors.allowAll, false);
  assert.deepEqual(cors.origins, ['https://app.example.com', 'https://portal.example.com']);
});

test('M4: development defaults to a permissive CORS policy', () => {
  const out = loadConfig({ NODE_ENV: 'development', JWT_SECRET: '', CORS_ORIGIN: '' });
  assert.match(out, /^OK/);
  const cors = JSON.parse(out.slice(3));
  assert.equal(cors.allowAll, true);
});
