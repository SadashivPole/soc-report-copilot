'use strict';
const { Pool } = require('pg');
const config = require('../config');

const pool = new Pool({ connectionString: config.database.connectionString });

pool.on('error', (err) => {
  // Log and keep the process alive; a dead idle client should not crash the API.
  console.error('[db] unexpected idle client error', err.message);
});

async function query(text, params) {
  return pool.query(text, params);
}

/** Lightweight readiness probe: is the database reachable right now? */
async function pingDb() {
  try {
    await pool.query('SELECT 1');
    return { ok: true };
  } catch (e) {
    return { ok: false, error: String(e.message).slice(0, 200) };
  }
}

/**
 * Wait for the database to accept connections, retrying with backoff. Used at
 * startup so the API fails safely (clear error) instead of crash-looping when
 * Postgres is not yet available.
 */
async function waitForDb({ retries = 15, delayMs = 2000 } = {}) {
  for (let i = 1; i <= retries; i++) {
    const r = await pingDb();
    if (r.ok) return true;
    console.error(`[db] not ready (attempt ${i}/${retries}): ${r.error}`);
    if (i < retries) await new Promise((res) => setTimeout(res, delayMs));
  }
  return false;
}

/**
 * Run a function inside a transaction. The callback receives a dedicated client.
 */
async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { pool, query, withTransaction, pingDb, waitForDb };
