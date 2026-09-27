'use strict';
const crypto = require('crypto');
const { query } = require('../db/pool');

/** Hash a share token before storage — the plaintext token is shown to the
 *  creator exactly once and never persisted. */
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

const VALID_MODES = ['executive', 'analyst'];
function normalizeMode(mode) {
  return VALID_MODES.includes(mode) ? mode : 'executive'; // safe default
}

/** Append a row to the share audit log (best-effort; never blocks the request). */
async function audit({ tenantId, shareId, reportId, event, mode, detail }) {
  try {
    await query(
      `INSERT INTO share_audit(tenant_id, share_id, report_id, event, mode, detail)
       VALUES($1,$2,$3,$4,$5,$6)`,
      [tenantId || null, shareId || null, reportId || null, event, mode || null, detail ? String(detail).slice(0, 200) : null]
    );
  } catch (e) {
    console.error('[share] audit write failed', String(e.message).slice(0, 120));
  }
}

/**
 * Create a read-only, expiring share for a report the tenant owns.
 * `mode` controls disclosure: 'executive' (default, least data) or 'analyst'
 * (full technical detail — only when explicitly requested).
 * Returns the one-time plaintext token; only its hash is stored.
 */
async function createShare({ tenantId, reportId, createdBy, expiresInHours = 168, mode = 'executive' }) {
  const hours = Math.min(Math.max(parseInt(expiresInHours, 10) || 168, 1), 24 * 90);
  const safeMode = normalizeMode(mode);
  const token = crypto.randomBytes(24).toString('base64url'); // ~32 chars, URL-safe
  const tokenHash = hashToken(token);
  const prefix = token.slice(0, 6);
  const r = await query(
    `INSERT INTO report_shares(tenant_id, report_id, created_by, token_hash, token_prefix, mode, expires_at)
     VALUES($1,$2,$3,$4,$5,$6, now() + ($7 || ' hours')::interval)
     RETURNING id, token_prefix, mode, expires_at, created_at`,
    [tenantId, reportId, createdBy, tokenHash, prefix, safeMode, String(hours)]
  );
  await audit({ tenantId, shareId: r.rows[0].id, reportId, event: 'created', mode: safeMode });
  return { ...r.rows[0], token };
}

/**
 * Resolve a share token to its report WITHOUT any tenant context (public link).
 * Enforces existence, not-revoked, and not-expired. Bumps view counters and
 * writes an audit event. Returns { report, mode, expires_at } or an error marker.
 */
async function resolveShare(token) {
  if (!token || typeof token !== 'string' || token.length < 10 || token.length > 200) return null;
  const tokenHash = hashToken(token);
  const r = await query(
    `SELECT s.id AS share_id, s.tenant_id, s.mode, s.expires_at, s.revoked,
            r.id AS report_id, r.title, r.client_name, r.data, r.created_at
       FROM report_shares s JOIN reports r ON r.id = s.report_id
      WHERE s.token_hash = $1`,
    [tokenHash]
  );
  const row = r.rows[0];
  if (!row) return null;
  if (row.revoked) {
    await audit({ tenantId: row.tenant_id, shareId: row.share_id, reportId: row.report_id, event: 'denied', mode: row.mode, detail: 'revoked' });
    return { error: 'revoked' };
  }
  if (new Date(row.expires_at).getTime() < Date.now()) {
    await audit({ tenantId: row.tenant_id, shareId: row.share_id, reportId: row.report_id, event: 'expired', mode: row.mode });
    return { error: 'expired' };
  }

  await query(
    `UPDATE report_shares SET view_count = view_count + 1, last_viewed_at = now() WHERE id = $1`,
    [row.share_id]
  );
  await audit({ tenantId: row.tenant_id, shareId: row.share_id, reportId: row.report_id, event: 'accessed', mode: row.mode });

  return {
    mode: normalizeMode(row.mode),
    report: {
      id: row.report_id,
      title: row.title,
      client_name: row.client_name,
      created_at: row.created_at,
      data: row.data,
    },
    expires_at: row.expires_at,
  };
}

async function listShares(tenantId, reportId) {
  const r = await query(
    `SELECT id, token_prefix, mode, expires_at, revoked, view_count, last_viewed_at, created_at
       FROM report_shares WHERE tenant_id=$1 AND report_id=$2 ORDER BY created_at DESC`,
    [tenantId, reportId]
  );
  return r.rows;
}

async function revokeShare(tenantId, shareId) {
  const r = await query(
    `UPDATE report_shares SET revoked=true WHERE id=$1 AND tenant_id=$2 RETURNING id, report_id, mode`,
    [shareId, tenantId]
  );
  if (r.rowCount > 0) {
    await audit({ tenantId, shareId: r.rows[0].id, reportId: r.rows[0].report_id, event: 'revoked', mode: r.rows[0].mode });
  }
  return r.rowCount > 0;
}

module.exports = { createShare, resolveShare, listShares, revokeShare, hashToken, normalizeMode, VALID_MODES };
