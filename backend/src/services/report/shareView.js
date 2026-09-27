'use strict';

/**
 * Build the data payload served through a PUBLIC share link, according to the
 * share's disclosure mode.
 *
 *   - 'analyst'   : the full report (only ever produced when explicitly created).
 *   - 'executive' : a WHITELISTED subset. Raw logs, the evidence appendix, internal
 *                   hostnames/usernames/source IPs, and per-finding event IDs are
 *                   NEVER included. Management gets posture, KPIs, the executive
 *                   summary, trend, MITRE overview (names/counts only) and the
 *                   data-supported historical comparison.
 *
 * The executive view is built by explicit whitelist (not by deleting fields), so
 * a future field added to the full report cannot accidentally leak.
 */

/**
 * Redact IOC-level detail (IP addresses, cited event-ID lists) that can appear
 * inside analyst-oriented prose / finding titles, so it never surfaces in the
 * executive disclosure level.
 */
function redactText(s) {
  if (s == null) return s;
  let t = String(s);
  // Strip cited-evidence fragments first (they contain event IDs).
  t = t.replace(/\(evidence[^)]*\)/gi, '');
  t = t.replace(/evidence(?:\s+event\s+ids)?:?\s*[0-9a-fA-F.\-,\s]+/gi, '');
  // Mask IPv4 and (rough) IPv6 addresses.
  t = t.replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, '[redacted-ip]');
  t = t.replace(/\b(?:[a-f0-9]{1,4}:){2,7}[a-f0-9]{1,4}\b/gi, '[redacted-ip]');
  return t.replace(/\s{2,}/g, ' ').trim();
}
function redactList(arr) {
  return (arr || []).map(redactText);
}

function executiveComparison(c) {
  if (!c || !c.available) return c || { available: false };
  return {
    available: true,
    previous: { period_end: c.previous && c.previous.period_end },
    alert_volume: c.alert_volume,
    severity: c.severity,
    assessment: c.assessment,
    note: c.note,
    // set-deltas containing IPs / hostnames are intentionally omitted.
  };
}

function executiveView(data) {
  const d = data || {};
  const dash = d.dashboard || {};
  const es = d.executive_summary || {};
  return {
    view: 'executive',
    title: d.title || (d.meta && d.meta.title) || 'SOC Report',
    client_name: d.client_name || null,
    organization: (d.meta && d.meta.organization) || d.organization || null,
    period_start: d.period_start || null,
    period_end: d.period_end || null,
    generated_at: (d.meta && d.meta.generated_at) || null,
    posture: es.posture || (d.security_posture && d.security_posture.posture) || null,
    kpis: {
      total: (dash.totals && dash.totals.total) || (d.kpis && d.kpis.total) || 0,
      severity: dash.severity || (d.security_posture && d.security_posture.severity) || {},
    },
    executive_summary: {
      headline: redactText(es.headline) || null,
      key_stats: redactList(es.key_stats),
      major_observations: redactList(es.major_observations),
      // Priority actions WITHOUT event-level evidence / assets, IOCs masked.
      priority_actions: (es.priority_actions || []).map((a) => ({
        priority: a.priority,
        finding: redactText(a.finding),
        severity: a.severity,
        recommended_action: redactText(a.recommended_action),
        owner: a.owner,
        label: a.label,
      })),
    },
    trend: dash.trend || [],
    comparison: executiveComparison(d.comparison),
    mitre_overview: ((d.mitre_section && d.mitre_section.mappings) || []).map((m) => ({
      technique_id: m.technique_id,
      technique_name: m.technique_name,
      tactic: m.tactic,
      alert_count: m.alert_count,
      confidence: m.confidence,
    })),
    mitre_note: (d.mitre_section && d.mitre_section.note) || null,
    integrity: d.integrity || null,
    disclosure_note:
      'Executive view — technical detail (raw logs, hostnames, usernames, source IPs, event IDs) is intentionally omitted or masked in this shared link.',
  };
}

function buildShareView(data, mode) {
  return mode === 'analyst' ? data : executiveView(data);
}

/**
 * Deep-redacted clone of the FULL report data for rendering an EXECUTIVE share
 * PDF. Keeps the report shape the PDF renderer expects, but strips/masks every
 * IOC-level field (raw logs, hostnames, usernames, source IPs, event IDs) so the
 * shared executive PDF discloses no technical detail.
 */
// Internal keys embed IOCs (e.g. "cluster:10.9.9.9:...") — drop them.
function stripKeys(obj) {
  if (obj) { delete obj.key; delete obj.finding_key; }
  return obj;
}

function redactReportDataForExecutive(data) {
  const d = JSON.parse(JSON.stringify(data || {}));
  d.evidence_appendix = [];
  if (d.dashboard) { d.dashboard.top_source_ips = []; d.dashboard.top_hosts = []; d.dashboard.top_users = []; }
  if (d.analysis_section) { d.analysis_section.top_source_ips = []; d.analysis_section.top_hosts = []; d.analysis_section.top_users = []; }
  if (d.executive_summary) {
    d.executive_summary.headline = redactText(d.executive_summary.headline);
    d.executive_summary.key_stats = redactList(d.executive_summary.key_stats);
    d.executive_summary.major_observations = redactList(d.executive_summary.major_observations);
    (d.executive_summary.priority_actions || []).forEach((a) => { stripKeys(a); a.finding = redactText(a.finding); a.recommended_action = redactText(a.recommended_action); a.evidence = {}; });
  }
  if (d.ai_analysis) {
    d.ai_analysis.summary = redactText(d.ai_analysis.summary);
    d.ai_analysis.key_observations = redactList(d.ai_analysis.key_observations);
    (d.ai_analysis.recurring_patterns || []).forEach((p) => { stripKeys(p); p.pattern = redactText(p.pattern); p.rationale = redactText(p.rationale); p.evidence_event_ids = []; p.source_ips = []; p.hosts = []; p.targets = []; });
    (d.ai_analysis.findings || []).forEach((f) => { stripKeys(f); f.title = redactText(f.title); f.description = redactText(f.description); f.evidence = { source: 'wazuh' }; });
    (d.ai_analysis.false_positive_candidates || []).forEach((f) => { stripKeys(f); f.reason = redactText(f.reason); f.evidence_event_ids = []; });
    (d.ai_analysis.recommended_actions || []).forEach((a) => { stripKeys(a); a.finding = redactText(a.finding); a.recommended_action = redactText(a.recommended_action); a.evidence = {}; });
  }
  (d.findings || []).forEach((f) => { stripKeys(f); f.title = redactText(f.title); f.description = redactText(f.description); f.evidence = { source: 'wazuh' }; });
  (d.recommended_actions || []).forEach((a) => { stripKeys(a); a.finding = redactText(a.finding); a.recommended_action = redactText(a.recommended_action); a.evidence = {}; });
  (d.recurring_patterns || []).forEach((p) => { stripKeys(p); p.pattern = redactText(p.pattern); p.rationale = redactText(p.rationale); p.evidence_event_ids = []; p.source_ips = []; p.hosts = []; p.targets = []; });
  if (d.mitre_section && d.mitre_section.mappings) d.mitre_section.mappings.forEach((m) => { m.evidence_event_ids = []; });
  if (d.mitre_attack && d.mitre_attack.mappings) d.mitre_attack.mappings.forEach((m) => { m.evidence_event_ids = []; });
  d.comparison = executiveComparison(d.comparison);
  return d;
}

module.exports = { buildShareView, executiveView, redactReportDataForExecutive, redactText };
