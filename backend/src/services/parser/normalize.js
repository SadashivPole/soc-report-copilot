'use strict';
const { safeString, truncate } = require('../../utils/sanitize');

/** Map Wazuh rule.level (0-16) to a severity band. Documented in DESIGN.md. */
function severityFromLevel(level) {
  const n = Number(level);
  if (!Number.isFinite(n)) return 'Low';
  if (n >= 12) return 'Critical';
  if (n >= 9) return 'High';
  if (n >= 6) return 'Medium';
  return 'Low';
}

const SEVERITY_ORDER = { Critical: 4, High: 3, Medium: 2, Low: 1 };

function toArray(v) {
  if (v === null || v === undefined) return [];
  if (Array.isArray(v)) return v.filter((x) => x !== null && x !== undefined);
  if (typeof v === 'string') {
    // Wazuh CSV often comma-joins groups.
    return v.split(',').map((s) => s.trim()).filter(Boolean);
  }
  return [v];
}

/**
 * Build the canonical normalized event from already-extracted primitive fields.
 * `raw` is the original (bounded) object retained for evidence/audit.
 */
function buildNormalized(fields, raw, index) {
  const level = fields.rule_level;
  const groups = toArray(fields.groups).map((g) => safeString(g, 120)).filter(Boolean);
  const mitreIds = toArray(fields.mitre_ids).map((g) => safeString(g, 40)).filter(Boolean);
  const mitreTactics = toArray(fields.mitre_tactics).map((g) => safeString(g, 80)).filter(Boolean);
  const mitreTechniques = toArray(fields.mitre_techniques).map((g) => safeString(g, 160)).filter(Boolean);

  let ts = null;
  if (fields.timestamp) {
    const d = new Date(fields.timestamp);
    if (!Number.isNaN(d.getTime())) ts = d.toISOString();
  }

  return {
    event_id: safeString(fields.event_id, 128) || `evt-${index}`,
    timestamp: ts,
    rule_id: safeString(fields.rule_id, 40),
    rule_description: safeString(fields.rule_description, 512),
    rule_level: Number.isFinite(Number(level)) ? Number(level) : null,
    severity: severityFromLevel(level),
    groups,
    mitre_ids: mitreIds,
    mitre_tactics: mitreTactics,
    mitre_techniques: mitreTechniques,
    agent_name: safeString(fields.agent_name, 200),
    agent_ip: safeString(fields.agent_ip, 64),
    src_ip: safeString(fields.src_ip, 64),
    dst_ip: safeString(fields.dst_ip, 64),
    src_user: safeString(fields.src_user, 200),
    dst_user: safeString(fields.dst_user, 200),
    full_log: truncate(fields.full_log),
    decoder: safeString(fields.decoder, 120),
    location: safeString(fields.location, 256),
    raw,
  };
}

module.exports = { buildNormalized, severityFromLevel, SEVERITY_ORDER, toArray };
