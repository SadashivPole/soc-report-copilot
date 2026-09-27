'use strict';
const { query } = require('../../db/pool');
const { buildScope } = require('./scope');

/**
 * All aggregations are tenant-scoped (tenant_id is always the first predicate)
 * and optionally narrowed to a single upload and/or a reporting time window.
 * The `window` ({start,end}) is used by scheduled weekly reports so they only
 * analyze the requested period, never the whole historical upload.
 */
function scope(tenantId, uploadId, window) {
  return buildScope(tenantId, uploadId, window);
}

async function totals(tenantId, uploadId, window) {
  const { where, params } = scope(tenantId, uploadId, window);
  const r = await query(
    `SELECT count(*)::int AS total,
            min(ts) AS first_seen,
            max(ts) AS last_seen
       FROM events WHERE ${where}`,
    params
  );
  return r.rows[0];
}

async function bySeverity(tenantId, uploadId, window) {
  const { where, params } = scope(tenantId, uploadId, window);
  const r = await query(
    `SELECT severity, count(*)::int AS count
       FROM events WHERE ${where}
      GROUP BY severity`,
    params
  );
  const out = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  for (const row of r.rows) if (row.severity in out) out[row.severity] = row.count;
  return out;
}

async function topN(tenantId, uploadId, column, limit = 10, window) {
  const allowed = ['rule_description', 'src_ip', 'dst_ip', 'src_user', 'dst_user', 'agent_name'];
  if (!allowed.includes(column)) throw new Error('Invalid aggregation column');
  const { where, params } = scope(tenantId, uploadId, window);
  params.push(limit);
  const r = await query(
    `SELECT ${column} AS key, count(*)::int AS count,
            array_agg(DISTINCT event_id) FILTER (WHERE event_id IS NOT NULL) AS sample_ids
       FROM events
      WHERE ${where} AND ${column} IS NOT NULL AND ${column} <> ''
      GROUP BY ${column}
      ORDER BY count DESC, key ASC
      LIMIT $${params.length}`,
    params
  );
  return r.rows.map((row) => ({
    key: row.key,
    count: row.count,
    // cap cited evidence ids to keep payloads bounded
    evidence_event_ids: (row.sample_ids || []).slice(0, 15),
  }));
}

async function trend(tenantId, uploadId, window) {
  const { where, params } = scope(tenantId, uploadId, window);
  const r = await query(
    `SELECT to_char(date_trunc('day', ts), 'YYYY-MM-DD') AS day,
            count(*)::int AS count
       FROM events
      WHERE ${where} AND ts IS NOT NULL
      GROUP BY 1 ORDER BY 1`,
    params
  );
  return r.rows;
}

async function topMitre(tenantId, uploadId, limit = 10, window) {
  const { where, params } = scope(tenantId, uploadId, window);
  params.push(limit);
  const r = await query(
    `SELECT mid AS technique_id, count(*)::int AS count,
            array_agg(DISTINCT event_id) FILTER (WHERE event_id IS NOT NULL) AS sample_ids
       FROM events, jsonb_array_elements_text(mitre->'ids') AS mid
      WHERE ${where}
      GROUP BY mid
      ORDER BY count DESC, technique_id ASC
      LIMIT $${params.length}`,
    params
  );
  return r.rows.map((row) => ({
    technique_id: row.technique_id,
    count: row.count,
    evidence_event_ids: (row.sample_ids || []).slice(0, 15),
  }));
}

/** Full dashboard payload used by /api/dashboard and the report builder. */
async function dashboard(tenantId, uploadId, window) {
  const [t, sev, types, srcIps, users, hosts, tr, mitre] = await Promise.all([
    totals(tenantId, uploadId, window),
    bySeverity(tenantId, uploadId, window),
    topN(tenantId, uploadId, 'rule_description', 10, window),
    topN(tenantId, uploadId, 'src_ip', 10, window),
    topN(tenantId, uploadId, 'src_user', 10, window),
    topN(tenantId, uploadId, 'agent_name', 10, window),
    trend(tenantId, uploadId, window),
    topMitre(tenantId, uploadId, 10, window),
  ]);
  return {
    totals: t,
    severity: sev,
    top_alert_types: types,
    top_source_ips: srcIps,
    top_users: users,
    top_hosts: hosts,
    trend: tr,
    top_mitre: mitre,
  };
}

module.exports = { dashboard, totals, bySeverity, topN, trend, topMitre };
