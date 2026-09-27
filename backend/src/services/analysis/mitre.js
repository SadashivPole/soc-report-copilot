'use strict';
const { query } = require('../../db/pool');
const { buildScope } = require('./scope');

/**
 * MITRE ATT&CK mapping — EVIDENCE-GATED.
 *
 * Primary evidence: the Wazuh alert's own `rule.mitre` metadata (highest
 * confidence — the mapping ships with the detection rule).
 *
 * Secondary evidence: a small curated, conservative map from Wazuh rule *groups*
 * to techniques, applied ONLY when the alert explicitly carries that group.
 *
 * If neither source yields a technique for an alert cluster, we DO NOT guess —
 * the caller surfaces "Not enough evidence."
 */
const GROUP_TECHNIQUE_MAP = {
  authentication_failures: { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
  authentication_failed: { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
  brute_force: { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
  web_scan: { id: 'T1595', name: 'Active Scanning', tactic: 'Reconnaissance' },
  recon: { id: 'T1595', name: 'Active Scanning', tactic: 'Reconnaissance' },
  privilege_escalation: { id: 'T1548', name: 'Abuse Elevation Control Mechanism', tactic: 'Privilege Escalation' },
  sudo: { id: 'T1548.003', name: 'Sudo and Sudo Caching', tactic: 'Privilege Escalation' },
};

const TECHNIQUE_NAMES = {
  T1110: 'Brute Force',
  'T1110.001': 'Password Guessing',
  T1595: 'Active Scanning',
  T1548: 'Abuse Elevation Control Mechanism',
  'T1548.003': 'Sudo and Sudo Caching',
  T1078: 'Valid Accounts',
  T1046: 'Network Service Discovery',
  T1071: 'Application Layer Protocol',
  T1059: 'Command and Scripting Interpreter',
  T1021: 'Remote Services',
  T1190: 'Exploit Public-Facing Application',
};

// Tactic (kill-chain phase) for each known technique, so the report can show
// Tactic / Technique / ID with cited evidence.
const TECHNIQUE_TACTICS = {
  T1110: 'Credential Access',
  'T1110.001': 'Credential Access',
  T1595: 'Reconnaissance',
  T1548: 'Privilege Escalation',
  'T1548.003': 'Privilege Escalation',
  T1078: 'Defense Evasion / Initial Access',
  T1046: 'Discovery',
  T1071: 'Command and Control',
  T1059: 'Execution',
  T1021: 'Lateral Movement',
  T1190: 'Initial Access',
};

/**
 * Build MITRE findings for an upload from real, cited evidence only.
 * Returns { mappings: [...], note } where each mapping cites event_ids.
 */
async function buildMitreFindings(tenantId, uploadId, window) {
  const declaredScope = buildScope(tenantId, uploadId, window);
  // 1) Techniques the alerts themselves declare (rule.mitre.id).
  const declared = await query(
    `SELECT mid AS technique_id, count(*)::int AS count,
            array_agg(DISTINCT event_id) FILTER (WHERE event_id IS NOT NULL) AS ids,
            array_agg(DISTINCT rule_description) FILTER (WHERE rule_description IS NOT NULL) AS descs
       FROM events, jsonb_array_elements_text(mitre->'ids') AS mid
      WHERE ${declaredScope.where}
      GROUP BY mid
      ORDER BY count DESC`,
    declaredScope.params
  );

  const mappings = declared.rows.map((row) => ({
    technique_id: row.technique_id,
    technique_name: TECHNIQUE_NAMES[row.technique_id] || null,
    tactic: TECHNIQUE_TACTICS[row.technique_id] || null,
    alert_count: row.count,
    evidence_event_ids: (row.ids || []).slice(0, 25),
    example_rules: (row.descs || []).slice(0, 3),
    evidence_source: 'wazuh_rule_mitre_metadata',
    confidence: 'high',
  }));

  const seen = new Set(mappings.map((m) => m.technique_id));

  // 2) Conservative group-based inference (secondary evidence).
  for (const [group, tech] of Object.entries(GROUP_TECHNIQUE_MAP)) {
    if (seen.has(tech.id)) continue;
    const gs = buildScope(tenantId, uploadId, window);
    gs.params.push(group);
    const r = await query(
      `SELECT count(*)::int AS count,
              array_agg(DISTINCT event_id) FILTER (WHERE event_id IS NOT NULL) AS ids
         FROM events
        WHERE ${gs.where}
          AND groups ? $${gs.params.length}`,
      gs.params
    );
    const row = r.rows[0];
    if (row && row.count > 0) {
      seen.add(tech.id);
      mappings.push({
        technique_id: tech.id,
        technique_name: tech.name,
        tactic: tech.tactic,
        alert_count: row.count,
        evidence_event_ids: (row.ids || []).slice(0, 25),
        example_rules: [],
        evidence_source: `wazuh_rule_group:${group}`,
        confidence: 'medium',
      });
    }
  }

  mappings.sort((a, b) => b.alert_count - a.alert_count);

  return {
    mappings,
    note:
      mappings.length === 0
        ? 'Not enough evidence. No uploaded alert carried MITRE ATT&CK metadata or a mappable rule group.'
        : null,
  };
}

module.exports = { buildMitreFindings, GROUP_TECHNIQUE_MAP, TECHNIQUE_NAMES, TECHNIQUE_TACTICS };
