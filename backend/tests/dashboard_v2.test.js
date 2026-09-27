'use strict';
const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');
const h = require('./helper');

before(async () => { await h.start(); });
after(async () => { await h.stop(); });
beforeEach(async () => { await h.resetDb(); });

function alerts(n, level, ip, mon = 9) {
  const list = [];
  const mm = String(mon).padStart(2, '0');
  for (let i = 0; i < n; i++) {
    list.push({
      id: `${ip}-${mon}-${i}`,
      timestamp: '2026-' + mm + '-2' + (i % 5) + 'T10:00:00Z',
      rule: { id: '5712', level, description: 'sshd: Multiple authentication failures', groups: ['sshd', 'brute_force'], mitre: { id: ['T1110'] } },
      agent: { name: 'host0' + (i % 3) },
      data: { srcip: ip, dstuser: 'root' },
      full_log: 'Failed password',
    });
  }
  return list;
}

test('executive dashboard computes posture, totals, activity and MITRE overview', async () => {
  const A = await h.signup('exec@t.com');
  const up = await h.uploadJson(A.token, alerts(12, 13, '203.0.113.5')); // level 13 => Critical
  const uploadId = up.data.upload.id;

  const r = await h.req('GET', '/api/dashboard/executive?uploadId=' + uploadId, { token: A.token });
  assert.equal(r.status, 200);
  const d = r.data;
  assert.equal(d.has_data, true);
  assert.equal(d.totals.total, 12);
  assert.equal(d.totals.critical, 12);
  assert.equal(d.posture.level, 'critical');
  assert.equal(d.activity.recurring_alerts + d.activity.new_alerts, 12);
  assert.ok(d.mitre_overview.length >= 1 && d.mitre_overview[0].technique_id === 'T1110');
  // findings/actions counts exist
  assert.ok('open_findings' in d && 'resolved_findings' in d);
  assert.ok(Array.isArray(d.priority_actions));
});

test('executive dashboard reflects seeded actions after a report is generated', async () => {
  const A = await h.signup('exec2@t.com');
  const up = await h.uploadJson(A.token, alerts(10, 10, '203.0.113.6'));
  const uploadId = up.data.upload.id;

  let d = (await h.req('GET', '/api/dashboard/executive?uploadId=' + uploadId, { token: A.token })).data;
  assert.equal(d.open_findings, 0);

  await h.req('POST', '/api/reports', { token: A.token, body: { uploadId } });
  d = (await h.req('GET', '/api/dashboard/executive?uploadId=' + uploadId, { token: A.token })).data;
  assert.ok(d.open_findings >= 1, 'open findings reflect seeded actions');
});

test('executive dashboard reports no-data cleanly for an empty tenant', async () => {
  const A = await h.signup('empty@t.com');
  const r = await h.req('GET', '/api/dashboard/executive', { token: A.token });
  assert.equal(r.status, 200);
  assert.equal(r.data.has_data, false);
});

test('historical comparison is unavailable for the first report, available for the next', async () => {
  const A = await h.signup('cmp@t.com');

  // Report 1 (Aug period): no prior → unavailable, stated plainly (no invented trend).
  const up1 = await h.uploadJson(A.token, alerts(20, 13, '203.0.113.7', 8)); // 20 Critical
  const r1 = await h.req('POST', '/api/reports', { token: A.token, body: { uploadId: up1.data.upload.id } });
  assert.equal(r1.data.report.data.comparison.available, false);
  assert.match(r1.data.report.data.comparison.note, /unavailable/i);

  // Report 2 (Sep period, later): fewer High/Critical than before → data supports "improved".
  const up2 = await h.uploadJson(A.token, alerts(8, 6, '203.0.113.7', 9)); // 8 Medium, 0 High/Critical
  const r2 = await h.req('POST', '/api/reports', { token: A.token, body: { uploadId: up2.data.upload.id } });
  const c = r2.data.report.data.comparison;
  assert.equal(c.available, true);
  assert.equal(c.alert_volume.previous, 20);
  assert.equal(c.alert_volume.current, 8);
  assert.equal(c.severity.high_critical_delta, -20);
  assert.equal(c.assessment, 'improved');
});

test('comparison only claims deterioration when High/Critical actually rises', async () => {
  const A = await h.signup('cmp2@t.com');
  await h.req('POST', '/api/reports', { token: A.token, body: { uploadId: (await h.uploadJson(A.token, alerts(5, 6, '10.0.0.1', 8))).data.upload.id } }); // Aug baseline: 0 HC
  const up2 = await h.uploadJson(A.token, alerts(10, 12, '10.0.0.1', 9)); // Sep: 10 Critical
  const r2 = await h.req('POST', '/api/reports', { token: A.token, body: { uploadId: up2.data.upload.id } });
  assert.equal(r2.data.report.data.comparison.assessment, 'deteriorated');
});
