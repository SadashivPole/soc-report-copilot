'use strict';
const { query } = require('../../db/pool');
const stats = require('../analysis/stats');
const engine = require('../analysis/engine');
const { buildMitreFindings } = require('../analysis/mitre');
const { compareReports } = require('../analysis/comparison');
const { buildScope } = require('../analysis/scope');

const SEV_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1 };

/** Bounded, control-char-stripped excerpt of a raw log line (rendered as text only). */
function excerpt(s, n = 240) {
  if (!s) return null;
  return String(s)
    .replace(/[\u0000-\u001f\u007f]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, n);
}

/** Evidence appendix: representative raw events, most severe / most recent first. */
async function buildAppendix(tenantId, uploadId, limit = 80, window) {
  const { where, params } = buildScope(tenantId, uploadId, window);
  params.push(limit);
  const r = await query(
    `SELECT event_id, ts, severity, rule_id, rule_description, agent_name, src_user, dst_user, src_ip, full_log
       FROM events
      WHERE ${where}
      ORDER BY (CASE severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 1 ELSE 0 END) DESC,
               ts DESC NULLS LAST
      LIMIT $${params.length}`,
    params
  );
  return r.rows.map((e) => ({
    event_id: e.event_id,
    source: 'wazuh',
    timestamp: e.ts,
    host: e.agent_name || null,
    user: e.dst_user || e.src_user || null,
    src_ip: e.src_ip || null,
    severity: e.severity || null,
    rule: e.rule_description || e.rule_id || null,
    evidence: excerpt(e.full_log),
  }));
}

/**
 * Assemble the full professional report object for an upload. Pure aggregation
 * over the tenant's own data — every section is evidence-derived. The object is
 * a SUPERSET: legacy keys (dashboard, ai_analysis, mitre_attack, title,
 * client_name, branding) are preserved for backward compatibility, and the new
 * professional sections are added alongside.
 */
async function buildReport(tenantId, uploadId, meta = {}) {
  // Optional reporting window ({start,end}) — used by scheduled weekly reports so
  // the report covers a defined period (never the entire historical upload).
  const window = meta.window || null;
  const [dashboard, analysis, mitre, appendix] = await Promise.all([
    stats.dashboard(tenantId, uploadId, window),
    engine.analyze(tenantId, uploadId, window),
    buildMitreFindings(tenantId, uploadId, window),
    buildAppendix(tenantId, uploadId, 80, window),
  ]);

  // When an explicit window is supplied, the report PERIOD is that window
  // (stored explicitly). Otherwise it is the min/max event timestamp of the data.
  const period_start = window && window.start ? new Date(window.start) : dashboard.totals.first_seen || null;
  const period_end = window && window.end ? new Date(window.end) : dashboard.totals.last_seen || null;

  // Historical comparison MUST compare against the chronologically previous
  // reporting period — i.e. the most recent prior report whose period ends
  // before this report's period. Selecting by created_at (generation time)
  // produces reversed/false trends when data is uploaded out of order.
  let prevReport = null;
  if (period_end) {
    const pr = await query(
      `SELECT id, data, created_at, period_end
         FROM reports
        WHERE tenant_id = $1
          AND period_end IS NOT NULL
          AND period_end < $2
        ORDER BY period_end DESC, created_at DESC
        LIMIT 1`,
      [tenantId, period_end]
    );
    prevReport = pr.rows[0] || null;
  }

  const branding = meta.branding || {};
  const generated_at = new Date().toISOString();

  const title = meta.title || 'Weekly SOC Report';
  const organization = meta.organization || branding.company_name || null;
  const client_name = meta.clientName || branding.default_client || null;

  const sev = dashboard.severity;
  const total = dashboard.totals.total || 0;

  const data = {
    // ---- legacy / backward-compatible keys ----
    title,
    generated_at,
    source_type: meta.source_type || 'wazuh',
    filename: meta.filename || null,
    client_name,
    branding: {
      company_name: branding.company_name || null,
      logo_data_url: branding.logo_data_url || null,
    },
    period_start,
    period_end,
    dashboard,
    ai_analysis: analysis,
    mitre_attack: mitre,

    // ---- v2 professional report structure ----
    meta: {
      title,
      organization,
      client_name,
      source_type: meta.source_type || 'wazuh',
      filename: meta.filename || null,
      period_start,
      period_end,
      period_label: meta.periodLabel || null,
      generated_at,
      posture: analysis.posture,
    },
    kpis: {
      total,
      critical: sev.Critical || 0,
      high: sev.High || 0,
      medium: sev.Medium || 0,
      low: sev.Low || 0,
      recurring_alerts: analysis.recurring_alerts || 0,
      new_alerts: analysis.new_alerts || 0,
      false_positive_candidates: (analysis.false_positive_candidates || []).length,
      findings: (analysis.findings || []).length,
    },
    executive_summary: {
      posture: analysis.posture,
      period: { start: period_start, end: period_end, label: meta.periodLabel || null },
      headline: analysis.summary,
      key_stats: [
        `Total alerts: ${total}`,
        `Critical / High: ${sev.Critical || 0} / ${sev.High || 0}`,
        `Alert frequency: ${analysis.recurring_alerts || 0} repeated (rule seen 3+ times), ${analysis.new_alerts || 0} lower-frequency (seen 1-2 times)`,
        `Findings requiring attention: ${(analysis.findings || []).length}`,
      ],
      major_observations: analysis.key_observations || [],
      priority_actions: (analysis.recommended_actions || []).slice(0, 5),
    },
    security_posture: {
      posture: analysis.posture,
      severity: sev,
      total,
      recurring_alerts: analysis.recurring_alerts || 0,
      new_alerts: analysis.new_alerts || 0,
      trend: dashboard.trend,
    },
    analysis_section: {
      top_alert_types: dashboard.top_alert_types,
      top_source_ips: dashboard.top_source_ips,
      top_hosts: dashboard.top_hosts,
      top_users: dashboard.top_users,
      trend: dashboard.trend,
    },
    findings: analysis.findings || [],
    recurring_patterns: analysis.recurring_patterns || [],
    false_positive_candidates: analysis.false_positive_candidates || [],
    mitre_section: mitre,
    recommended_actions: analysis.recommended_actions || [],
    evidence_appendix: appendix,
    comparison: compareReports({ dashboard }, prevReport),

    integrity: {
      ai_label: engine.AI_LABEL,
      evidence_policy:
        'Every AI-generated finding references the underlying alert/event IDs. ' +
        'MITRE mappings are shown only with sufficient evidence; otherwise "Not enough evidence." ' +
        'Recommended actions are AI-assisted recommendations for a human analyst, not statements of fact.',
    },
  };

  return data;
}

module.exports = { buildReport, buildAppendix, excerpt };
