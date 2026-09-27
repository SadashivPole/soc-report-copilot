'use strict';
const { query } = require('../../db/pool');
const config = require('../../config');
const { buildScope } = require('./scope');

const AI_LABEL = 'AI-assisted analysis (evidence-bound)';

/**
 * Evidence-bound analysis engine.
 *
 * Contract for every finding: it MUST reference the underlying `event_id`s that
 * justify it (`evidence_event_ids`). The engine only reports what the aggregated
 * data supports; it never invents incidents, IOCs, techniques, or conclusions.
 * False-positive items are explicitly framed as *candidates for analyst review*,
 * not determinations.
 *
 * Providers:
 *   - 'deterministic' (default): pure functions over the tenant's events. No
 *     external calls, fully reproducible, cannot hallucinate.
 *   - 'openai' (optional): given ONLY the extracted evidence bundle; its output
 *     is post-validated so any sentence that does not cite a real event_id is
 *     dropped. Falls back to deterministic if unavailable.
 */

async function gatherEvidence(tenantId, uploadId, window) {
  // Tenant-scoped, optionally narrowed to one upload and/or a reporting window.
  const { where, params } = buildScope(tenantId, uploadId, window);

  const totals = (
    await query(
      `SELECT count(*)::int total, min(ts) first_seen, max(ts) last_seen
         FROM events WHERE ${where}`,
      params
    )
  ).rows[0];

  const severity = (
    await query(
      `SELECT severity, count(*)::int c FROM events
        WHERE ${where} GROUP BY severity`,
      params
    )
  ).rows;

  // Recurring rule signatures.
  const recurringRules = (
    await query(
      `SELECT rule_id, rule_description, severity, count(*)::int c,
              min(ts) first_ts, max(ts) last_ts,
              array_agg(DISTINCT event_id) FILTER (WHERE event_id IS NOT NULL) ids,
              array_agg(DISTINCT src_ip) FILTER (WHERE src_ip IS NOT NULL) src_ips,
              array_agg(DISTINCT agent_name) FILTER (WHERE agent_name IS NOT NULL) hosts,
              array_agg(DISTINCT dst_user) FILTER (WHERE dst_user IS NOT NULL) users
         FROM events WHERE ${where} AND rule_description IS NOT NULL
        GROUP BY rule_id, rule_description, severity
       HAVING count(*) >= 3
        ORDER BY c DESC LIMIT 15`,
      params
    )
  ).rows;

  // (source IP + rule) clusters — classic brute-force / scan shape.
  const ipRuleClusters = (
    await query(
      `SELECT src_ip, rule_description, severity, count(*)::int c,
              min(ts) first_ts, max(ts) last_ts,
              array_agg(DISTINCT event_id) FILTER (WHERE event_id IS NOT NULL) ids,
              array_agg(DISTINCT COALESCE(dst_user, agent_name)) FILTER (WHERE COALESCE(dst_user, agent_name) IS NOT NULL) targets,
              array_agg(DISTINCT agent_name) FILTER (WHERE agent_name IS NOT NULL) hosts
         FROM events
        WHERE ${where} AND src_ip IS NOT NULL AND rule_description IS NOT NULL
        GROUP BY src_ip, rule_description, severity
       HAVING count(*) >= 5
        ORDER BY c DESC LIMIT 15`,
      params
    )
  ).rows;

  // Recurring alert volume: alerts whose rule signature fired >= 3 times.
  const recurringVol = (
    await query(
      `WITH r AS (
         SELECT rule_description FROM events
          WHERE ${where} AND rule_description IS NOT NULL
          GROUP BY rule_description HAVING count(*) >= 3)
       SELECT count(*)::int c FROM events
        WHERE ${where}
          AND rule_description IN (SELECT rule_description FROM r)`,
      params
    )
  ).rows[0];
  const recurring_alerts = (recurringVol && recurringVol.c) || 0;

  // Low-severity high-volume single rule -> false-positive candidate signal.
  const noisyLowSev = (
    await query(
      `SELECT rule_id, rule_description, severity, count(*)::int c,
              array_agg(DISTINCT event_id) FILTER (WHERE event_id IS NOT NULL) ids
         FROM events
        WHERE ${where} AND severity IN ('Low','Medium')
          AND rule_description IS NOT NULL
        GROUP BY rule_id, rule_description, severity
       HAVING count(*) >= 10
        ORDER BY c DESC LIMIT 15`,
      params
    )
  ).rows;

  return { totals, severity, recurringRules, ipRuleClusters, noisyLowSev, recurring_alerts };
}

// ---------------------------------------------------------------------------
// Evidence-bound classification, findings, posture and recommended actions.
// All of these are pure functions over the evidence bundle — nothing invented.
// ---------------------------------------------------------------------------

/** Classify an alert cluster into a coarse category using ONLY its rule text. */
function classify(desc = '', groups = []) {
  const s = `${desc} ${(groups || []).join(' ')}`.toLowerCase();
  if (/(brute|failed password|authentication fail|login fail|invalid user|multiple auth)/.test(s)) return 'brute_force';
  if (/(scan|nmap|recon|probe|enumerat|port sweep)/.test(s)) return 'recon_scan';
  if (/(sudo|privilege|escalat|to root|setuid)/.test(s)) return 'privilege_escalation';
  if (/(malware|virus|trojan|ransom|rootkit|yara|malicious file)/.test(s)) return 'malware';
  if (/(sql injection|sqli|xss|web attack|exploit|rce|command injection|traversal|web shell)/.test(s)) return 'web_exploit';
  if (/(dropped|firewall|denied connection|blocked)/.test(s)) return 'network_block';
  return 'other';
}

// AI-assisted recommendation playbook. These are generic, evidence-triggered
// recommendations for a human analyst — they are NOT statements of fact and
// NOT automated actions. Every action produced is tied to real event IDs.
const PLAYBOOK = {
  brute_force: {
    action:
      'Review authentication activity from the cited source(s); consider temporary blocking at the firewall/WAF; ' +
      'confirm account-lockout thresholds are enforced and check whether any authentication succeeded after the attempts.',
    owner: 'SOC Analyst / Identity Team',
  },
  recon_scan: {
    action:
      'Confirm which scanned services are internet-exposed; verify rate-limiting/WAF coverage; monitor the source IP for follow-on activity.',
    owner: 'SOC Analyst / AppSec',
  },
  privilege_escalation: {
    action:
      'Validate whether the privilege/sudo activity maps to an authorized change; review the affected host and the acting account with its owner.',
    owner: 'IT / Infrastructure',
  },
  malware: {
    action:
      'Triage the affected host per the incident-response runbook; run a full anti-malware scan; verify containment and remediation.',
    owner: 'Incident Response',
  },
  web_exploit: {
    action:
      'Review web/application logs for signs of successful exploitation; ensure the public-facing application is patched; engage AppSec.',
    owner: 'AppSec / Incident Response',
  },
  network_block: {
    action:
      'Confirm the blocks are expected policy enforcement; if volume is unusual, review the source and destination for misconfiguration or abuse.',
    owner: 'Network / SOC Analyst',
  },
  other: {
    action: 'Analyst to review the cited events and determine disposition.',
    owner: 'SOC Analyst',
  },
};

const SEV_PRIORITY = { Critical: 'P1', High: 'P2', Medium: 'P3', Low: 'P4' };
const SEV_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1 };

/** Build structured, evidence-cited security findings from the evidence bundle. */
function buildFindings(ev) {
  const findings = [];
  const seen = new Set();

  const push = (f) => {
    if (seen.has(f.key)) return;
    seen.add(f.key);
    findings.push(f);
  };

  // High-confidence: correlated (source IP + rule) attack-shaped clusters.
  for (const c of ev.ipRuleClusters) {
    const category = classify(c.rule_description);
    const assets = ids([...(c.targets || []), ...(c.hosts || [])], 8);
    push({
      key: `cluster:${c.src_ip}:${c.rule_description}`,
      title: `Repeated "${c.rule_description}" from ${c.src_ip}`,
      category,
      severity: c.severity || 'Medium',
      confidence: 'High',
      description:
        `${c.c} alerts share source IP ${c.src_ip} and the rule "${c.rule_description}", a correlated ` +
        `pattern consistent with ${category.replace('_', ' ')} activity against ${assets.length || 'the'} asset(s).`,
      evidence: {
        source: 'wazuh',
        event_ids: ids(c.ids, 25),
        first_seen: c.first_ts || null,
        last_seen: c.last_ts || null,
        assets,
        source_ip: c.src_ip,
      },
    });
  }

  // Medium-confidence: recurring High/Critical rule signatures not already covered.
  for (const r of ev.recurringRules) {
    if ((SEV_RANK[r.severity] || 0) < 3) continue; // High/Critical only as standalone findings
    const category = classify(r.rule_description);
    const assets = ids([...(r.hosts || []), ...(r.users || [])], 8);
    push({
      key: `rule:${r.rule_id || r.rule_description}`,
      title: `Recurring ${r.severity} alert: "${r.rule_description}"`,
      category,
      severity: r.severity || 'High',
      confidence: 'Medium',
      description:
        `Rule "${r.rule_description}" (${r.rule_id || 'n/a'}) fired ${r.c} times in the reporting window across ` +
        `${(r.hosts || []).length || 'one or more'} host(s).`,
      evidence: {
        source: 'wazuh',
        event_ids: ids(r.ids, 25),
        first_seen: r.first_ts || null,
        last_seen: r.last_ts || null,
        assets,
        source_ips: ids(r.src_ips, 5),
      },
    });
  }

  findings.sort((a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0) || b.evidence.event_ids.length - a.evidence.event_ids.length);
  return findings.slice(0, 15);
}

/** Derive management recommended actions from findings (AI-assisted, evidence-bound). */
function buildRecommendedActions(findings) {
  return findings.map((f) => {
    const pb = PLAYBOOK[f.category] || PLAYBOOK.other;
    return {
      finding_key: f.key,
      priority: SEV_PRIORITY[f.severity] || 'P3',
      finding: f.title,
      severity: f.severity,
      recommended_action: pb.action,
      owner: pb.owner,
      status: 'open',
      label: 'AI-assisted recommendation',
      evidence: {
        source: 'wazuh',
        event_ids: (f.evidence.event_ids || []).slice(0, 25),
        first_seen: f.evidence.first_seen,
        last_seen: f.evidence.last_seen,
        assets: f.evidence.assets || [],
      },
    };
  });
}

/** Overall security posture — a derived label with a numeric rationale (no invention). */
function computePosture(sev, clusters, total) {
  const crit = sev.Critical || 0;
  const high = sev.High || 0;
  let label, level;
  if (crit > 0) {
    label = 'Critical attention required';
    level = 'critical';
  } else if (high > 0) {
    label = 'Elevated';
    level = 'elevated';
  } else if ((sev.Medium || 0) > 0) {
    label = 'Guarded';
    level = 'guarded';
  } else {
    label = 'Stable';
    level = 'stable';
  }
  return {
    label,
    level,
    counts: { ...sev },
    rationale:
      `Derived from ${total} analyzed alerts (${crit} Critical, ${high} High, ${sev.Medium || 0} Medium, ` +
      `${sev.Low || 0} Low) and ${clusters} correlated attack-shaped source/rule cluster(s).`,
  };
}

function severityMap(rows) {
  const out = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  for (const r of rows) if (r.severity in out) out[r.severity] = r.c;
  return out;
}

function ids(arr, n = 20) {
  return (arr || []).filter(Boolean).slice(0, n);
}

function deterministicAnalysis(ev) {
  const total = ev.totals.total || 0;
  const sev = severityMap(ev.severity);

  // --- Recurring patterns (each cites evidence) ---
  const recurring_patterns = [];
  for (const r of ev.ipRuleClusters) {
    recurring_patterns.push({
      pattern: `Repeated "${r.rule_description}" from source IP ${r.src_ip}`,
      alert_count: r.c,
      severity: r.severity,
      targets: ids(r.targets, 5),
      evidence_event_ids: ids(r.ids),
      rationale: `${r.c} alerts share the same source IP and rule signature, indicating a repeating pattern.`,
    });
  }
  for (const r of ev.recurringRules) {
    // Avoid duplicating clusters already captured by ipRuleClusters at high overlap.
    recurring_patterns.push({
      pattern: `Recurring rule "${r.rule_description}" (rule ${r.rule_id || 'n/a'})`,
      alert_count: r.c,
      severity: r.severity,
      hosts: ids(r.hosts, 5),
      source_ips: ids(r.src_ips, 5),
      evidence_event_ids: ids(r.ids),
      rationale: `This rule fired ${r.c} times across the uploaded window.`,
    });
  }
  // De-dup by (pattern) keeping the higher count; keep top 10.
  const seenP = new Set();
  const patterns = recurring_patterns
    .sort((a, b) => b.alert_count - a.alert_count)
    .filter((p) => (seenP.has(p.pattern) ? false : (seenP.add(p.pattern), true)))
    .slice(0, 10);

  // --- False-positive CANDIDATES (analyst review, not determinations) ---
  const false_positive_candidates = ev.noisyLowSev
    .filter((r) => total > 0 && r.c / total >= 0.05) // dominates >=5% of volume
    .map((r) => ({
      rule: r.rule_description,
      rule_id: r.rule_id,
      severity: r.severity,
      alert_count: r.c,
      share_of_total: Number((r.c / total).toFixed(3)),
      evidence_event_ids: ids(r.ids),
      reason:
        `High-volume ${r.severity.toLowerCase()}-severity rule accounting for ` +
        `${((r.c / total) * 100).toFixed(1)}% of all alerts. Flagged as a possible ` +
        `false-positive / tuning candidate for analyst review — this is NOT a determination.`,
    }))
    .slice(0, 10);

  // --- Key observations (numbers straight from evidence) ---
  const key_observations = [];
  key_observations.push(
    `${total} total alerts were normalized from the upload` +
      (ev.totals.first_seen
        ? ` spanning ${new Date(ev.totals.first_seen).toISOString().slice(0, 10)} to ${new Date(
            ev.totals.last_seen
          ).toISOString().slice(0, 10)}.`
        : '.')
  );
  key_observations.push(
    `Severity breakdown — Critical: ${sev.Critical}, High: ${sev.High}, Medium: ${sev.Medium}, Low: ${sev.Low}.`
  );
  if (ev.ipRuleClusters[0]) {
    const c = ev.ipRuleClusters[0];
    key_observations.push(
      `The most active source/rule cluster is ${c.src_ip} -> "${c.rule_description}" with ${c.c} alerts (evidence: ${ids(
        c.ids,
        5
      ).join(', ')}).`
    );
  }

  // --- Executive summary (composed strictly from the above evidence) ---
  const highCrit = sev.Critical + sev.High;
  const summaryLines = [];
  summaryLines.push(
    `This report covers ${total} Wazuh alerts. Of these, ${highCrit} are High or Critical severity ` +
      `(${sev.Critical} Critical, ${sev.High} High) and warrant analyst attention.`
  );
  if (patterns.length) {
    const p = patterns[0];
    summaryLines.push(
      `The dominant recurring pattern is "${p.pattern}" (${p.alert_count} alerts; evidence ${ids(
        p.evidence_event_ids,
        4
      ).join(', ')}).`
    );
  } else {
    summaryLines.push('No recurring multi-alert pattern met the reporting threshold in this window.');
  }
  if (false_positive_candidates.length) {
    summaryLines.push(
      `${false_positive_candidates.length} high-volume low/medium-severity rule(s) are flagged as ` +
        `false-positive / tuning candidates for analyst review.`
    );
  }
  summaryLines.push(
    'All statements above are derived solely from the uploaded evidence; no external threat intelligence, ' +
      'IOCs, or incident conclusions have been added.'
  );

  // --- Structured findings, recommended actions, posture, recurring vs new ---
  const findings = buildFindings(ev);
  const recommended_actions = buildRecommendedActions(findings);
  const posture = computePosture(sev, ev.ipRuleClusters.length, total);
  const recurring_alerts = ev.recurring_alerts || 0;
  const new_alerts = Math.max(0, total - recurring_alerts);

  return {
    label: AI_LABEL,
    provider: 'deterministic',
    disclaimer:
      'This analysis is generated automatically from the uploaded alerts only. It assists — but does ' +
      'not replace — a human analyst. Every finding cites the underlying event IDs. It contains no ' +
      'fabricated incidents, IOCs, or techniques.',
    summary: summaryLines.join(' '),
    key_observations,
    recurring_patterns: patterns,
    false_positive_candidates,
    findings,
    recommended_actions,
    posture,
    recurring_alerts,
    new_alerts,
  };
}

/**
 * Optional LLM provider. Feeds ONLY the evidence bundle and validates that each
 * returned finding cites a real event_id present in the evidence; otherwise the
 * finding is discarded. Falls back to deterministic output on any error.
 */
async function openaiAnalysis(ev) {
  // Kept intentionally conservative and optional. If not configured, fall back.
  if (!config.analysis.openaiApiKey) return deterministicAnalysis(ev);
  try {
    const validIds = new Set();
    for (const group of [ev.recurringRules, ev.ipRuleClusters, ev.noisyLowSev]) {
      for (const r of group) for (const id of r.ids || []) validIds.add(id);
    }
    const prompt = {
      role: 'user',
      content:
        'You are a SOC analyst assistant. Using ONLY the JSON evidence provided, write a concise ' +
        'summary. Never invent incidents, IOCs, or techniques. Every claim must reference event IDs ' +
        'from the evidence. Return JSON {summary, key_observations[]}.\n\nEVIDENCE:\n' +
        JSON.stringify(ev),
    };
    const resp = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${config.analysis.openaiApiKey}`,
      },
      body: JSON.stringify({
        model: config.analysis.openaiModel,
        messages: [prompt],
        temperature: 0,
        response_format: { type: 'json_object' },
      }),
    });
    if (!resp.ok) throw new Error(`openai ${resp.status}`);
    const json = await resp.json();
    const parsed = JSON.parse(json.choices[0].message.content);
    // Post-validate: keep the deterministic structured findings (already cited),
    // but allow the LLM to provide the prose summary — only if it cites an id.
    const base = deterministicAnalysis(ev);
    const citesReal = [...validIds].some((id) => (parsed.summary || '').includes(id));
    return {
      ...base,
      provider: 'openai (evidence-validated)',
      summary: citesReal ? parsed.summary : base.summary,
      key_observations: Array.isArray(parsed.key_observations) && parsed.key_observations.length
        ? parsed.key_observations
        : base.key_observations,
    };
  } catch (e) {
    const base = deterministicAnalysis(ev);
    base.provider = `deterministic (openai fallback: ${e.message})`;
    return base;
  }
}

async function analyze(tenantId, uploadId, window) {
  const ev = await gatherEvidence(tenantId, uploadId, window);
  if (config.analysis.provider === 'openai') return openaiAnalysis(ev);
  return deterministicAnalysis(ev);
}

module.exports = {
  analyze,
  gatherEvidence,
  deterministicAnalysis,
  buildFindings,
  buildRecommendedActions,
  computePosture,
  classify,
  AI_LABEL,
};
