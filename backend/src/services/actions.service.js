'use strict';
const { query, withTransaction } = require('../db/pool');

/**
 * Management action-plan store. Every action is tenant-scoped and traceable to
 * evidence/event IDs. Status changes are written to an immutable audit trail
 * (action_history) inside the same transaction as the update.
 */

const STATUSES = ['open', 'investigating', 'resolved', 'accepted_risk'];
const PRIORITIES = ['P1', 'P2', 'P3', 'P4'];

function normStatus(s) {
  const v = String(s || '').toLowerCase().replace(/\s+/g, '_');
  return STATUSES.includes(v) ? v : null;
}
function normPriority(p) {
  const v = String(p || '').toUpperCase();
  return PRIORITIES.includes(v) ? v : 'P3';
}

async function listActions(tenantId, { status } = {}) {
  const params = [tenantId];
  let where = 'tenant_id = $1';
  const st = status ? normStatus(status) : null;
  if (st) {
    params.push(st);
    where += ` AND status = $${params.length}`;
  }
  const r = await query(
    `SELECT id, report_id, finding_key, priority, finding, recommended_action, owner, status,
            evidence, ai_assisted, created_at, updated_at
       FROM actions WHERE ${where}
      ORDER BY array_position(ARRAY['P1','P2','P3','P4']::text[], priority), updated_at DESC
      LIMIT 500`,
    params
  );
  return r.rows;
}

async function countsByStatus(tenantId) {
  const r = await query(
    `SELECT status, count(*)::int c FROM actions WHERE tenant_id=$1 GROUP BY status`,
    [tenantId]
  );
  const out = { open: 0, investigating: 0, resolved: 0, accepted_risk: 0, total: 0 };
  for (const row of r.rows) {
    if (row.status in out) out[row.status] = row.c;
    out.total += row.c;
  }
  out.open_findings = out.open + out.investigating;
  out.resolved_findings = out.resolved + out.accepted_risk;
  return out;
}

async function getAction(tenantId, id) {
  const a = await query(
    `SELECT id, report_id, finding_key, priority, finding, recommended_action, owner, status,
            evidence, ai_assisted, created_at, updated_at
       FROM actions WHERE id=$1 AND tenant_id=$2`,
    [id, tenantId]
  );
  if (!a.rowCount) return null;
  const h = await query(
    `SELECT id, from_status, to_status, note, changed_by, changed_at
       FROM action_history WHERE action_id=$1 AND tenant_id=$2 ORDER BY changed_at ASC`,
    [id, tenantId]
  );
  return { ...a.rows[0], history: h.rows };
}

async function createAction(tenantId, userId, input) {
  const status = normStatus(input.status) || 'open';
  const priority = normPriority(input.priority);
  return withTransaction(async (client) => {
    const ins = await client.query(
      `INSERT INTO actions(tenant_id, report_id, finding_key, priority, finding, recommended_action, owner, status, evidence, ai_assisted, created_by)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       RETURNING id`,
      [
        tenantId,
        input.report_id || null,
        input.finding_key || null,
        priority,
        String(input.finding || '').slice(0, 500),
        String(input.recommended_action || '').slice(0, 2000),
        input.owner ? String(input.owner).slice(0, 160) : null,
        status,
        JSON.stringify(input.evidence || {}),
        input.ai_assisted !== false,
        userId || null,
      ]
    );
    const id = ins.rows[0].id;
    await client.query(
      `INSERT INTO action_history(tenant_id, action_id, from_status, to_status, note, changed_by)
       VALUES($1,$2,$3,$4,$5,$6)`,
      [tenantId, id, null, status, 'Action created', userId || null]
    );
    return id;
  });
}

/** Update status / owner / priority / recommended_action. Records audit history on status change. */
async function updateAction(tenantId, userId, id, patch) {
  return withTransaction(async (client) => {
    const cur = await client.query('SELECT status FROM actions WHERE id=$1 AND tenant_id=$2 FOR UPDATE', [id, tenantId]);
    if (!cur.rowCount) return null;
    const fromStatus = cur.rows[0].status;

    const sets = [];
    const params = [];
    const add = (col, val) => {
      params.push(val);
      sets.push(`${col}=$${params.length}`);
    };

    let toStatus = fromStatus;
    if (patch.status !== undefined) {
      const s = normStatus(patch.status);
      if (!s) throw Object.assign(new Error('Invalid status'), { statusCode: 400 });
      toStatus = s;
      add('status', s);
    }
    if (patch.owner !== undefined) add('owner', patch.owner ? String(patch.owner).slice(0, 160) : null);
    if (patch.priority !== undefined) add('priority', normPriority(patch.priority));
    if (patch.recommended_action !== undefined) add('recommended_action', String(patch.recommended_action).slice(0, 2000));
    if (patch.finding !== undefined) add('finding', String(patch.finding).slice(0, 500));

    if (!sets.length) {
      // nothing to change
      return getActionTx(client, tenantId, id);
    }
    add('updated_at', new Date());
    params.push(id, tenantId);
    await client.query(`UPDATE actions SET ${sets.join(', ')} WHERE id=$${params.length - 1} AND tenant_id=$${params.length}`, params);

    if (toStatus !== fromStatus || patch.note) {
      await client.query(
        `INSERT INTO action_history(tenant_id, action_id, from_status, to_status, note, changed_by)
         VALUES($1,$2,$3,$4,$5,$6)`,
        [tenantId, id, fromStatus, toStatus, patch.note ? String(patch.note).slice(0, 1000) : null, userId || null]
      );
    }
    return getActionTx(client, tenantId, id);
  });
}

async function getActionTx(client, tenantId, id) {
  const a = await client.query(
    `SELECT id, report_id, finding_key, priority, finding, recommended_action, owner, status,
            evidence, ai_assisted, created_at, updated_at FROM actions WHERE id=$1 AND tenant_id=$2`,
    [id, tenantId]
  );
  const h = await client.query(
    `SELECT id, from_status, to_status, note, changed_by, changed_at
       FROM action_history WHERE action_id=$1 AND tenant_id=$2 ORDER BY changed_at ASC`,
    [id, tenantId]
  );
  return { ...a.rows[0], history: h.rows };
}

async function deleteAction(tenantId, id) {
  const r = await query('DELETE FROM actions WHERE id=$1 AND tenant_id=$2 RETURNING id', [id, tenantId]);
  return r.rowCount ? r.rows[0].id : null;
}

/**
 * Seed action-plan items from a report's recommended actions. Deduplicates by
 * finding_key against actions that are still active (open/investigating) so we
 * do not create duplicates when the same finding recurs across reports.
 * Returns the number of new actions created.
 */
async function seedFromReport(tenantId, userId, reportId, recommendedActions) {
  if (!Array.isArray(recommendedActions) || !recommendedActions.length) return 0;
  const existing = await query(
    `SELECT finding_key FROM actions
      WHERE tenant_id=$1 AND status IN ('open','investigating') AND finding_key IS NOT NULL`,
    [tenantId]
  );
  const active = new Set(existing.rows.map((r) => r.finding_key));
  let created = 0;
  for (const ra of recommendedActions) {
    if (ra.finding_key && active.has(ra.finding_key)) continue;
    await createAction(tenantId, userId, {
      report_id: reportId,
      finding_key: ra.finding_key,
      priority: ra.priority,
      finding: ra.finding,
      recommended_action: ra.recommended_action,
      owner: ra.owner,
      status: 'open',
      evidence: ra.evidence,
      ai_assisted: true,
    });
    if (ra.finding_key) active.add(ra.finding_key);
    created++;
  }
  return created;
}

module.exports = {
  STATUSES,
  PRIORITIES,
  listActions,
  countsByStatus,
  getAction,
  createAction,
  updateAction,
  deleteAction,
  seedFromReport,
};
