'use strict';

/**
 * Historical comparison between the current report and the previous report for
 * the same tenant. Every conclusion is derived strictly from the two data
 * snapshots — we only claim "improved" / "deteriorated" when the numbers
 * support it. If there is no previous report, comparison is unavailable and we
 * say so plainly rather than inventing a trend.
 */

const UNAVAILABLE = {
  available: false,
  note: 'Historical comparison unavailable. No previous report exists for this data source yet.',
};

function keysOf(list) {
  return new Set((list || []).map((x) => String(x.key != null ? x.key : x.technique_id)).filter(Boolean));
}

function setDelta(curr, prev) {
  const c = keysOf(curr);
  const p = keysOf(prev);
  const added = [...c].filter((k) => !p.has(k));
  const removed = [...p].filter((k) => !c.has(k));
  const persistent = [...c].filter((k) => p.has(k));
  return { added, removed, persistent };
}

function direction(delta) {
  if (delta > 0) return 'increased';
  if (delta < 0) return 'decreased';
  return 'unchanged';
}

/**
 * @param currData full report data (superset) being generated now
 * @param prevReport { id, created_at, data } previous report row (or null)
 */
function compareReports(currData, prevReport) {
  if (!prevReport || !prevReport.data || !prevReport.data.dashboard) return { ...UNAVAILABLE };

  const cur = currData.dashboard;
  const prev = prevReport.data.dashboard;

  const curTotal = (cur.totals && cur.totals.total) || 0;
  const prevTotal = (prev.totals && prev.totals.total) || 0;
  const volDelta = curTotal - prevTotal;

  const curSev = cur.severity || {};
  const prevSev = prev.severity || {};
  const curHC = (curSev.Critical || 0) + (curSev.High || 0);
  const prevHC = (prevSev.Critical || 0) + (prevSev.High || 0);
  const hcDelta = curHC - prevHC;

  // Data-supported assessment. Improvement requires high/critical to fall (and
  // not be masked by a large total increase); deterioration requires it to rise.
  let assessment = 'stable';
  if (hcDelta < 0 && volDelta <= 0) assessment = 'improved';
  else if (hcDelta > 0 || (hcDelta === 0 && volDelta > 0)) assessment = 'deteriorated';
  else if (hcDelta < 0 && volDelta > 0) assessment = 'mixed';

  return {
    available: true,
    previous: {
      report_id: prevReport.id,
      generated_at: (prevReport.data.meta && prevReport.data.meta.generated_at) || prevReport.created_at || null,
      period_end: (prevReport.data.meta && prevReport.data.meta.period_end) || prevReport.data.period_end || null,
    },
    alert_volume: { current: curTotal, previous: prevTotal, delta: volDelta, direction: direction(volDelta) },
    severity: {
      current: { Critical: curSev.Critical || 0, High: curSev.High || 0, Medium: curSev.Medium || 0, Low: curSev.Low || 0 },
      previous: { Critical: prevSev.Critical || 0, High: prevSev.High || 0, Medium: prevSev.Medium || 0, Low: prevSev.Low || 0 },
      high_critical_delta: hcDelta,
      direction: direction(hcDelta),
    },
    top_categories: setDelta(cur.top_alert_types, prev.top_alert_types),
    recurring_source_ips: setDelta(cur.top_source_ips, prev.top_source_ips),
    top_assets: setDelta(cur.top_hosts, prev.top_hosts),
    mitre_techniques: setDelta(cur.top_mitre, prev.top_mitre),
    assessment,
    note:
      assessment === 'improved'
        ? `High/Critical alerts fell from ${prevHC} to ${curHC} and total volume did not rise — an improvement supported by the data.`
        : assessment === 'deteriorated'
        ? `High/Critical alerts moved from ${prevHC} to ${curHC} (total ${prevTotal}->${curTotal}) — a deterioration supported by the data.`
        : assessment === 'mixed'
        ? `High/Critical alerts fell (${prevHC}->${curHC}) but total volume rose (${prevTotal}->${curTotal}); the trend is mixed.`
        : `No material change in High/Critical alerts (${prevHC}->${curHC}); posture is broadly stable versus the previous report.`,
  };
}

module.exports = { compareReports };
