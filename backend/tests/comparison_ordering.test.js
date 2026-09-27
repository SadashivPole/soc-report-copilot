'use strict';
// Regression tests for the audit HIGH findings:
//  H1 - historical comparison must select the CHRONOLOGICALLY previous report
//       (by reporting period), not the most recently generated one. Generating
//       reports out of order must not produce a reversed/false trend.
//  H2 - "new vs recurring" is an in-dataset frequency measure; true novelty
//       across periods must come from the comparison category delta.
const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');
const h = require('./helper');

before(async () => { await h.start(); });
after(async () => { await h.stop(); });
beforeEach(async () => { await h.resetDb(); });

// n alerts of a given rule/severity within a specific month, from one IP.
function batch(month, n, level, desc, ruleId, ip) {
  const list = [];
  for (let i = 0; i < n; i++) {
    list.push({
      id: `${ruleId}-${month}-${i}`,
      timestamp: `2026-${String(month).padStart(2, '0')}-01T10:${String(i % 60).padStart(2, '0')}:00Z`,
      rule: { id: String(ruleId), level, description: desc, groups: ['sshd'], mitre: { id: ['T1110'] } },
      agent: { name: `host${i % 3}` },
      data: { srcip: ip, dstuser: 'root' },
      full_log: 'Failed password',
    });
  }
  return list;
}

async function genReport(token, uploadId) {
  const r = await h.req('POST', '/api/reports', { token, body: { uploadId } });
  assert.equal(r.status, 201, JSON.stringify(r.data));
  return r.data.report.data;
}

test('H1: previous report is chosen by reporting period, not creation order', async () => {
  const A = await h.signup('cmp1@t.com');

  // JAN: worse (30 critical). FEB: better (5 medium).
  const jan = await h.uploadJson(A.token, batch(1, 30, 13, 'sshd: auth failures', 5712, '10.0.0.1'), 'jan.json');
  const feb = await h.uploadJson(A.token, batch(2, 5, 6, 'sshd: auth failures', 5712, '10.0.0.2'), 'feb.json');
  assert.equal(jan.status, 201);
  assert.equal(feb.status, 201);

  // Generate FEB (later period) FIRST, then JAN (earlier period) SECOND — out of order.
  const febData = await genReport(A.token, feb.data.upload.id);
  const janData = await genReport(A.token, jan.data.upload.id);

  // FEB is the earliest-created but latest-period report; when generated first it
  // has no chronologically-prior report -> comparison unavailable.
  assert.equal(febData.comparison.available, false,
    'FEB (latest period, generated first) must have no prior-period comparison');

  // JAN's period ends BEFORE FEB's. JAN must NOT pick FEB as "previous" (that
  // would be a future period). No prior period exists for JAN -> unavailable.
  assert.equal(janData.comparison.available, false,
    'JAN must not compare against a later reporting period (FEB)');
});

test('H1: in-order generation compares against the true prior period', async () => {
  const A = await h.signup('cmp2@t.com');

  const jan = await h.uploadJson(A.token, batch(1, 5, 6, 'sshd: auth failures', 5712, '10.0.0.1'), 'jan.json');
  const feb = await h.uploadJson(A.token, batch(2, 30, 13, 'sshd: auth failures', 5712, '10.0.0.2'), 'feb.json');

  const janData = await genReport(A.token, jan.data.upload.id);       // earliest -> no prior
  const febData = await genReport(A.token, feb.data.upload.id);       // should compare to JAN

  assert.equal(janData.comparison.available, false);
  assert.equal(febData.comparison.available, true);

  // previous must be the JAN period (ends before FEB).
  const prevEnd = new Date(febData.comparison.previous.period_end).getTime();
  const curEnd = new Date(febData.period_end).getTime();
  assert.ok(prevEnd < curEnd, 'previous.period_end must precede current period_end');

  // JAN(5 medium) -> FEB(30 critical) is a data-supported deterioration.
  assert.equal(febData.comparison.assessment, 'deteriorated');
  assert.equal(febData.comparison.severity.current.Critical, 30);
  assert.equal(febData.comparison.severity.previous.Critical, 0);
});

test('H2: true novelty across periods surfaces via comparison category delta', async () => {
  const A = await h.signup('cmp3@t.com');

  // JAN: only brute-force. FEB: brute-force + a genuinely NEW category.
  const jan = await h.uploadJson(A.token, batch(1, 6, 10, 'sshd: auth failures', 5712, '10.0.0.1'), 'jan.json');
  const febAlerts = batch(2, 6, 10, 'sshd: auth failures', 5712, '10.0.0.2')
    .concat(batch(2, 4, 12, 'Web server 400 error code', 31101, '10.0.0.3'));
  const feb = await h.uploadJson(A.token, febAlerts, 'feb.json');

  await genReport(A.token, jan.data.upload.id);
  const febData = await genReport(A.token, feb.data.upload.id);

  assert.equal(febData.comparison.available, true);
  const added = febData.comparison.top_categories.added;
  assert.ok(added.some((c) => /Web server 400/.test(c)),
    'newly-appearing category must be reported as added: ' + JSON.stringify(added));

  // And the in-dataset frequency measure remains a plain count (not novelty).
  assert.equal(typeof febData.security_posture.recurring_alerts, 'number');
  assert.equal(typeof febData.security_posture.new_alerts, 'number');
});
